from __future__ import annotations

import os
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from services.azure_rbac import list_role_assignments
from services.entra_apps import list_service_principals_with_graph_critical_permissions
from services.entra_users import list_users
from services.entra_workload_identities import list_managed_identities, list_service_principals
from services.iam_common import (
    graph_list,
    is_mock_mode,
    load_mock_iam,
    resource_graph_query,
    safe_collect,
    sanitize_assignment,
)
from services.identity_risk import correlate_privileged_identities
from services.role_risk import role_risk_score

CRITICAL_GRAPH_PERMISSIONS = {
    "directory.readwrite.all",
    "user.readwrite.all",
    "group.readwrite.all",
    "application.readwrite.all",
    "approleassignment.readwrite.all",
    "rolemanagement.readwrite.directory",
}
DEFAULT_MAX_LIVE_CANDIDATES = 120
DEFAULT_MAX_LIVE_OWNER_LOOKUPS = 0
DEFAULT_MAX_LIVE_RBAC_ASSIGNMENTS = 1200
DEFAULT_AGENT_TOP_RESULTS = 10
KNOWN_AZURE_ROLE_GUIDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets Officer",
}
NON_EVALUATED_STATUSES = {"NOT_EVALUATED", "INSUFFICIENT_PERMISSIONS", "UNSUPPORTED"}


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _contains_agent_hint(name: str) -> bool:
    n = _normalize(name)
    hints = [
        "agent",
        "copilot",
        "bot",
        "automation",
        "workflow",
        "runner",
        "pipeline",
        "terraform",
        "github",
        "devops",
    ]
    return any(hint in n for hint in hints)


def _classify_object(name: str, identity_type: str) -> tuple[str, str, str]:
    n = _normalize(name)
    if identity_type.lower() == "managedidentity":
        return "Managed Identity", "Typed Object", "High"
    if "blueprint" in n:
        return "Agent Identity Blueprint", "Heuristic Candidate", "Low"
    if "microsoft" in n and "agent" in n:
        return "Microsoft-managed / First-party identity", "Heuristic Candidate", "Medium"
    if "agentidentity" in n:
        return "Heuristic Candidate", "Heuristic Candidate", "Medium"
    if _contains_agent_hint(name):
        return "Heuristic Candidate", "Heuristic Candidate", "Low"
    return "Unknown", "Heuristic Candidate", "Low"


def _live_owner_ids_for_sp(sp_object_id: str) -> list[str]:
    owners = graph_list(
        f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_object_id}/owners"
        "?$select=id,displayName,userPrincipalName,mail"
    )
    return [str(item.get("id")) for item in owners if item.get("id")]


def _live_role_definitions_map() -> dict[str, dict[str, Any]]:
    rows = resource_graph_query(
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/roledefinitions' "
        "| extend roleType=tostring(properties.roleType), permissions=todynamic(properties.permissions) "
        "| project roleDefinitionId=tolower(id), roleName=tostring(properties.roleName), roleType, permissions"
    )
    return {
        str(item.get("roleDefinitionId", "")).lower(): {
            "roleName": str(item.get("roleName") or ""),
            "roleType": str(item.get("roleType") or ""),
            "permissions": item.get("permissions") or [],
        }
        for item in rows
        if item.get("roleDefinitionId")
    }


def _role_guid_from_id(role_definition_id: str | None) -> str | None:
    if not role_definition_id:
        return None
    rid = str(role_definition_id).strip().lower()
    if "/" not in rid:
        return rid
    marker = "/roledefinitions/"
    if marker in rid:
        return rid.split(marker, 1)[1].strip().lower()
    return None


def _resolve_role_name(
    role_definition_id: str | None, roles_map: dict[str, dict[str, Any]]
) -> tuple[str, str, list[dict[str, Any]]]:
    rid = str(role_definition_id or "")
    key = rid.lower()
    if key in roles_map and roles_map[key]:
        metadata = roles_map[key]
        role_name = str(metadata.get("roleName") or rid)
        role_type = str(metadata.get("roleType") or "")
        mapped_type = "Custom" if role_type.lower() == "customrole" else "Built-in"
        return role_name, mapped_type, list(metadata.get("permissions") or [])
    guid = _role_guid_from_id(rid)
    if guid and guid in KNOWN_AZURE_ROLE_GUIDS:
        return KNOWN_AZURE_ROLE_GUIDS[guid], "Built-in", []
    return rid or "N/A", "Unknown", []


def _live_sp_role_assignments(max_items: int) -> list[dict[str, Any]]:
    query = (
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/roleassignments' "
        "| extend principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), "
        "roleDefinitionId=tolower(tostring(properties.roleDefinitionId)), scope=tostring(properties.scope) "
        "| where principalType =~ 'ServicePrincipal' or principalType =~ 'ManagedIdentity' "
        "| project principalId, principalType, roleDefinitionId, scope "
        f"| take {max_items}"
    )
    rows = resource_graph_query(query)
    roles_map = _live_role_definitions_map()
    out: list[dict[str, Any]] = []
    for item in rows:
        role_definition_id = str(item.get("roleDefinitionId") or "")
        role_name, role_type, permissions = _resolve_role_name(role_definition_id, roles_map)
        out.append(
            {
                "principalId": item.get("principalId"),
                "principalType": item.get("principalType"),
                "role": role_name,
                "roleDefinitionId": role_definition_id,
                "roleType": role_type,
                "rolePermissions": permissions,
                "scope": item.get("scope"),
                "assignmentType": "Direct",
                "inherited": False,
                "subscription": None,
                "resourceGroup": None,
                "resource": None,
                "origin": "Azure RBAC",
            }
        )
    return out


def _build_live_agent_like_source() -> dict[str, Any]:
    source_warnings: list[str] = []

    sp_rows: list[dict[str, Any]] = []
    mi_rows: list[dict[str, Any]] = []
    try:
        sp_rows = list_service_principals()
    except Exception as exc:
        source_warnings.append(f"Falha ao listar service principals no Graph: {exc}")
    try:
        mi_rows = list_managed_identities()
    except Exception as exc:
        source_warnings.append(f"Falha ao listar managed identities no Graph: {exc}")

    all_workloads = [*sp_rows, *mi_rows]
    by_id = {str(row.get("id")): row for row in all_workloads if row.get("id")}

    include_graph_critical = os.getenv("AGENT_LIVE_INCLUDE_GRAPH_CRITICAL", "false").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    graph_evaluation_status = "NOT_EVALUATED"
    critical_graph: list[dict[str, Any]] = []
    if include_graph_critical:
        try:
            critical_graph = list_service_principals_with_graph_critical_permissions()
            graph_evaluation_status = "PASS"
        except Exception as exc:
            source_warnings.append(f"Falha ao correlacionar permissões críticas de Graph: {exc}")
            graph_evaluation_status = "INSUFFICIENT_PERMISSIONS" if "403" in str(exc) else "FAIL"
    critical_by_principal: dict[str, set[str]] = defaultdict(set)
    for row in critical_graph:
        principal_id = str(row.get("objectId") or "")
        permission = str(row.get("permission") or "")
        if principal_id and permission:
            critical_by_principal[principal_id].add(permission.lower())

    azure_by_principal: dict[str, list[dict[str, Any]]] = defaultdict(list)
    azure_rbac_evaluation_status = "NOT_EVALUATED"
    try:
        max_live_assignments = max(
            100,
            int(os.getenv("AGENT_LIVE_MAX_RBAC_ASSIGNMENTS", str(DEFAULT_MAX_LIVE_RBAC_ASSIGNMENTS))),
        )
        for assignment in _live_sp_role_assignments(max_live_assignments):
            principal_id = str(assignment.get("principalId") or "")
            if principal_id:
                azure_by_principal[principal_id].append(assignment)
        azure_rbac_evaluation_status = "PASS"
    except Exception as exc:
        source_warnings.append(f"Falha ao listar role assignments no Azure RBAC: {exc}")
        azure_rbac_evaluation_status = "INSUFFICIENT_PERMISSIONS" if "403" in str(exc) else "FAIL"

    candidate_ids: set[str] = set()
    for item in all_workloads:
        principal_id = str(item.get("id") or "")
        if not principal_id:
            continue
        if _contains_agent_hint(str(item.get("displayName") or "")):
            candidate_ids.add(principal_id)
            continue
        if principal_id in critical_by_principal:
            candidate_ids.add(principal_id)
            continue
        privileged_roles = {"owner", "user access administrator", "contributor"}
        if any(str(a.get("role") or "").lower() in privileged_roles for a in azure_by_principal.get(principal_id, [])):
            candidate_ids.add(principal_id)

    for principal_id, assignments in azure_by_principal.items():
        principal_types = {str(a.get("principalType") or "").lower() for a in assignments}
        if "serviceprincipal" in principal_types or "managedidentity" in principal_types:
            candidate_ids.add(principal_id)

    if not candidate_ids and by_id:
        source_warnings.append(
            "Nenhuma identidade com sinal forte de Agent foi encontrada; exibindo inventário de workloads para investigação."
        )
        for principal_id in sorted(by_id.keys())[:200]:
            candidate_ids.add(principal_id)

    max_candidates = max(1, int(os.getenv("AGENT_LIVE_MAX_CANDIDATES", str(DEFAULT_MAX_LIVE_CANDIDATES))))
    if len(candidate_ids) > max_candidates:
        source_warnings.append(
            f"Inventário live limitado para {max_candidates} identidades para evitar timeout."
        )
        candidate_ids = set(sorted(candidate_ids)[:max_candidates])

    agents: list[dict[str, Any]] = []
    graph_rows: list[dict[str, Any]] = []
    max_owner_lookups = max(0, int(os.getenv("AGENT_LIVE_MAX_OWNER_LOOKUPS", str(DEFAULT_MAX_LIVE_OWNER_LOOKUPS))))
    for idx, principal_id in enumerate(sorted(candidate_ids)):
        workload = by_id.get(principal_id, {})
        name = str(workload.get("displayName") or principal_id)
        identity_type = "ManagedIdentity" if str(workload.get("servicePrincipalType")) == "ManagedIdentity" else "ServicePrincipal"
        object_classification, identification, confidence = _classify_object(name, identity_type)
        owner_ids: list[str] = []
        owner_lookup_status = "OWNER_NOT_EVALUATED"
        owner_lookup_reason = "Lookup de owner não executado para evitar timeout."
        if idx < max_owner_lookups:
            try:
                owner_ids = _live_owner_ids_for_sp(principal_id)
                owner_lookup_status = "OWNER_CONFIGURED" if owner_ids else "NO_OWNER_CONFIGURED"
                owner_lookup_reason = None
            except Exception as exc:
                source_warnings.append(f"{name}: falha ao resolver owners ({exc})")
                owner_lookup_status = "INSUFFICIENT_PERMISSIONS" if "403" in str(exc) else "OWNER_NOT_EVALUATED"
                owner_lookup_reason = str(exc)

        agent_id = f"live-agent-{principal_id}"
        agents.append(
            {
                "id": agent_id,
                "name": name,
                "enabled": bool(workload.get("accountEnabled", True)),
                "identityId": principal_id,
                "ownerIds": owner_ids,
                "ownerLookupStatus": owner_lookup_status,
                "ownerLookupReason": owner_lookup_reason,
                "objectClassification": object_classification,
                "identification": identification,
                "confidence": confidence,
                "identificationSource": "live_workload_heuristic",
                "inference": (
                    "Nome/padrão do workload sugere relação com Agent Identity; finalidade não confirmada."
                    if identification == "Heuristic Candidate"
                    else None
                ),
                "identityType": identity_type,
                "blueprintId": None,
                "createdDateTime": None,
            }
        )
        graph_rows.append(
            {
                "agentId": agent_id,
                "applicationPermissions": sorted(list(critical_by_principal.get(principal_id, set()))),
                "delegatedPermissions": [],
                "adminConsent": False,
            }
        )

    return {
        "sourceMode": "live_workload_heuristic",
        "sourceNote": (
            "Inventário baseado em Service Principals/Managed Identities + permissões Graph/RBAC, "
            "pois API específica de Agent Identities não está integrada neste projeto."
        ),
        "sourceWarnings": source_warnings,
        "agents": agents,
        "agent_graph_permissions": graph_rows,
        "agent_blueprints": [],
        "workloadsById": by_id,
        "azureRoleAssignmentsByPrincipal": dict(azure_by_principal),
        "graphEvaluationStatus": graph_evaluation_status,
        "azureRbacEvaluationStatus": azure_rbac_evaluation_status,
        "agentIdApiStatus": "NOT_INTEGRATED",
    }


def _require_agent_source() -> dict[str, Any]:
    if is_mock_mode():
        data = load_mock_iam()
        if not data.get("agents"):
            raise RuntimeError("Base mock sem coleção `agents` para avaliação de Agent Identities.")
        data["sourceMode"] = "mock"
        data["graphEvaluationStatus"] = data.get("graphEvaluationStatus", "PASS")
        data["azureRbacEvaluationStatus"] = data.get("azureRbacEvaluationStatus", "PASS")
        data["agentIdApiStatus"] = data.get("agentIdApiStatus", "INTEGRATED")
        return data
    return _build_live_agent_like_source()


def _users_index() -> dict[str, dict[str, Any]]:
    return {str(u.get("id")): u for u in list_users() if u.get("id")}


def _sp_index() -> dict[str, dict[str, Any]]:
    rows = [*list_service_principals(), *list_managed_identities()]
    return {str(sp.get("id")): sp for sp in rows if sp.get("id")}


def _extract_scope_level(scope: str | None) -> str:
    if not scope:
        return "Unknown"
    normalized = str(scope).strip().lower()
    if normalized.startswith("/providers/microsoft.management/managementgroups/"):
        return "Management Group"
    if "/providers/" in normalized and "/resourcegroups/" in normalized:
        return "Resource"
    if normalized.startswith("/subscriptions/") and "/resourcegroups/" in normalized and "/providers/" not in normalized:
        return "Resource Group"
    if normalized.startswith("/subscriptions/"):
        return "Subscription"
    return "Unknown"


def _extract_scope_name(scope: str | None, segment: str) -> str | None:
    if not scope:
        return None
    parts = str(scope).split("/")
    for idx, part in enumerate(parts):
        if part.lower() == segment.lower() and idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _extract_resource_info(scope: str | None) -> tuple[str | None, str | None]:
    if not scope:
        return None, None
    parts = str(scope).split("/")
    if "/providers/" not in str(scope).lower():
        return None, None
    try:
        pidx = next(i for i, p in enumerate(parts) if p.lower() == "providers")
    except StopIteration:
        return None, None
    if pidx + 2 >= len(parts):
        return None, None
    resource_type = f"{parts[pidx + 1]}/{parts[pidx + 2]}"
    resource_name = parts[-1] if len(parts) > pidx + 2 else None
    return resource_name, resource_type


def _classify_privilege_type(role: str) -> str:
    r = _normalize(role)
    if "owner" in r or "user access administrator" in r:
        return "High Administrative Privilege"
    if "contributor" in r and "data" not in r:
        return "Administrative Privilege"
    if "reader" in r:
        return "Read Only"
    if "key vault secrets officer" in r:
        return "Sensitive Data Access"
    if "data" in r or "blob" in r or "secret" in r:
        return "Data Access Privilege"
    return "Standard Access"


def _role_permissions_flatten(role_permissions: list[dict[str, Any]]) -> dict[str, list[str]]:
    actions: list[str] = []
    not_actions: list[str] = []
    data_actions: list[str] = []
    not_data_actions: list[str] = []
    for perm in role_permissions or []:
        actions.extend([str(v) for v in perm.get("actions", []) or []])
        not_actions.extend([str(v) for v in perm.get("notActions", []) or []])
        data_actions.extend([str(v) for v in perm.get("dataActions", []) or []])
        not_data_actions.extend([str(v) for v in perm.get("notDataActions", []) or []])
    return {
        "actions": actions,
        "notActions": not_actions,
        "dataActions": data_actions,
        "notDataActions": not_data_actions,
    }


def _infer_access_plane(role: str, role_permissions: list[dict[str, Any]]) -> tuple[str, str]:
    flattened = _role_permissions_flatten(role_permissions)
    has_data_actions = len(flattened["dataActions"]) > 0
    has_actions = len(flattened["actions"]) > 0
    if has_data_actions and has_actions:
        return "Mixed", "A role possui DataActions e também Actions de gerenciamento."
    if has_data_actions:
        return "Data Plane", "A role possui DataActions para acesso a dados."
    if has_actions:
        return "Control Plane", "A role possui Actions administrativas/gerenciamento."
    return "Unknown", "Plano não determinado: role definition sem Actions/DataActions disponíveis."


def _infer_data_capability(role: str, role_permissions: list[dict[str, Any]]) -> tuple[str, str]:
    flattened = _role_permissions_flatten(role_permissions)
    data_actions = [a.lower() for a in flattened["dataActions"]]
    actions = [a.lower() for a in flattened["actions"]]

    if "storage blob data contributor" in _normalize(role):
        return (
            "Read / Write / Delete Blob Data",
            "Can read, write and delete blob data within the assigned Storage Account.",
        )
    if "key vault secrets officer" in _normalize(role):
        return (
            "Read / Write / Delete Secret Data",
            "Can read, write and delete secrets within the assigned Key Vault scope.",
        )

    verbs: list[str] = []
    if any("/read" in a for a in data_actions):
        verbs.append("Read")
    if any("/write" in a or "/action" in a for a in data_actions):
        verbs.append("Write")
    if any("/delete" in a for a in data_actions):
        verbs.append("Delete")

    target = "Data"
    if any("blobservices/containers/blobs" in a for a in data_actions):
        target = "Blob Data"
    elif any("vaults/secrets" in a for a in data_actions):
        target = "Secret Data"

    if verbs:
        capability = " / ".join(dict.fromkeys(verbs)) + f" {target}"
        effect = f"Can {capability.lower()} within the assigned scope."
    else:
        capability = "No DataActions identified"
        effect = "No explicit data capability was identified from role definition."

    if actions:
        management = "Management actions present"
    else:
        management = "Limited management/read actions"
    return capability + f" | {management}", effect


def _owner_status(agent: dict[str, Any], owners: list[dict[str, Any]], unresolved: list[str]) -> tuple[str, str | None]:
    status_hint = str(agent.get("ownerLookupStatus") or "").strip()
    reason_hint = agent.get("ownerLookupReason")
    if status_hint:
        return status_hint, str(reason_hint) if reason_hint else None
    if unresolved:
        return "OWNER_NOT_RESOLVED", "Owner referenciado não foi resolvido no tenant visível."
    if owners:
        return "OWNER_CONFIGURED", None
    return "NO_OWNER_CONFIGURED", None


def _friendly_status(status: str | None) -> str:
    mapping = {
        "PASS": "Avaliado",
        "FAIL": "Falha na avaliação",
        "NOT_EVALUATED": "Não avaliado",
        "NOT_APPLICABLE": "Não aplicável",
        "COMPLETE": "Completo",
        "PARTIAL": "Parcial",
        "INSUFFICIENT_PERMISSIONS": "Permissões insuficientes",
        "UNSUPPORTED": "Não suportado",
        "NOT_INTEGRATED": "Não integrado",
        "INTEGRATED": "Integrado",
        "OWNER_CONFIGURED": "Owner configurado",
        "NO_OWNER_CONFIGURED": "Sem owner configurado",
        "OWNER_NOT_RESOLVED": "Owner não resolvido",
        "OWNER_NOT_EVALUATED": "Owner não avaliado",
        "LOW": "Baixo",
        "MEDIUM": "Médio",
        "HIGH": "Alto",
        "CRITICAL": "Crítico",
        "Low": "Baixo",
        "Medium": "Médio",
        "High": "Alto",
        "Critical": "Crítico",
    }
    key = str(status or "").strip()
    return mapping.get(key, key or "N/A")


def _coverage_label(status: str | None) -> str:
    normalized = str(status or "").strip()
    mapping = {
        "PASS": "EVALUATED",
        "PARTIAL": "PARTIAL",
        "NOT_EVALUATED": "NOT_EVALUATED",
        "INSUFFICIENT_PERMISSIONS": "NOT_EVALUATED",
        "UNSUPPORTED": "NOT_EVALUATED",
    }
    return mapping.get(normalized, normalized or "NOT_EVALUATED")


def _inventory_sentence(total: int) -> str:
    if total == 1:
        return "1 objeto candidato relacionado a Agent Identities foi identificado."
    return f"{total} objetos candidatos relacionados a Agent Identities foram identificados."


def _coverage_status(values: list[str], evaluated_value: str = "PASS") -> str:
    normalized = [str(value or "").strip() for value in values if str(value or "").strip()]
    if not normalized:
        return "NOT_EVALUATED"
    all_evaluated = all(value == evaluated_value for value in normalized)
    any_evaluated = any(value == evaluated_value for value in normalized)
    if all_evaluated:
        return "PASS"
    if any_evaluated:
        return "PARTIAL"
    return "NOT_EVALUATED"


def _ownership_coverage_status(rows: list[dict[str, Any]]) -> str:
    owner_statuses = [str(row.get("ownerStatus") or "").strip() for row in rows]
    evaluated_owner_statuses = [status for status in owner_statuses if status and status not in NON_EVALUATED_STATUSES and status != "OWNER_NOT_EVALUATED"]
    if not owner_statuses:
        return "NOT_EVALUATED"
    if evaluated_owner_statuses and len(evaluated_owner_statuses) == len(owner_statuses):
        return "PASS"
    if evaluated_owner_statuses:
        return "PARTIAL"
    return "NOT_EVALUATED"


def _friendly_confidence(value: str | None) -> str:
    mapping = {"High": "Alta", "Medium": "Média", "Low": "Baixa"}
    return mapping.get(str(value or "").strip(), str(value or "N/A"))


def _inventory_mode_text(source_mode: str, agent_id_api_status: str) -> str:
    if source_mode == "live_workload_heuristic" and agent_id_api_status == "NOT_INTEGRATED":
        return "Heurístico"
    return "Integrado"


def _is_heuristic_inventory(source_mode: str, agent_id_api_status: str) -> bool:
    return source_mode == "live_workload_heuristic" and agent_id_api_status == "NOT_INTEGRATED"


def _is_graph_critical(permission: str) -> bool:
    return permission.lower() in CRITICAL_GRAPH_PERMISSIONS


def _resolve_owners(owner_ids: list[str], user_by_id: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    owners: list[dict[str, Any]] = []
    unresolved: list[str] = []
    for owner_id in owner_ids:
        user = user_by_id.get(str(owner_id))
        if not user:
            unresolved.append(str(owner_id))
            continue
        owners.append(
            sanitize_assignment(
                {
                    "name": user.get("displayName"),
                    "displayName": user.get("displayName"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "mail": user.get("mail") or user.get("userPrincipalName"),
                    "objectId": user.get("id"),
                    "identityType": "User",
                    "accountEnabled": user.get("accountEnabled"),
                    "userType": user.get("userType"),
                }
            )
        )
    return owners, unresolved


def _agent_graph_permissions(agent_id: str, data: dict[str, Any]) -> dict[str, Any]:
    for item in data.get("agent_graph_permissions", []):
        if str(item.get("agentId")) == str(agent_id):
            app = item.get("applicationPermissions", []) or []
            delegated = item.get("delegatedPermissions", []) or []
            critical = sorted([p for p in app + delegated if _is_graph_critical(str(p))])
            return {
                "applicationPermissions": app,
                "delegatedPermissions": delegated,
                "criticalPermissions": critical,
                "adminConsent": bool(item.get("adminConsent")),
            }
    return {"applicationPermissions": [], "delegatedPermissions": [], "criticalPermissions": [], "adminConsent": False}


def _agent_azure_assignments(identity_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in list_role_assignments():
        if str(item.get("principalId")) != str(identity_id):
            continue
        risk = role_risk_score(str(item.get("role")), "Azure", scope=item.get("scope"))
        rows.append(
            sanitize_assignment(
                {
                    "principalId": item.get("principalId"),
                    "principalType": item.get("principalType"),
                    "role": item.get("role"),
                    "scope": item.get("scope"),
                    "assignmentType": item.get("assignmentType"),
                    "origin": item.get("origin"),
                    "subscription": item.get("subscription"),
                    "resourceGroup": item.get("resourceGroup"),
                    "resource": item.get("resource"),
                    "scopeLevel": _extract_scope_level(item.get("scope")),
                    "risk": risk["level"],
                    "riskScore": risk["score"],
                }
            )
        )
    return rows


def _agent_risk(
    agent: dict[str, Any],
    owners: list[dict[str, Any]],
    unresolved_owners: list[str],
    graph: dict[str, Any],
    graph_status: str,
    azure: list[dict[str, Any]],
    azure_status: str,
) -> dict[str, Any]:
    findings: list[str] = []
    owner_status, _owner_reason = _owner_status(agent, owners, unresolved_owners)

    evaluated_scores: list[int] = []
    risk_factors: list[str] = []
    evaluated_domains: list[str] = []
    not_evaluated_domains: list[str] = []

    azure_risk = "NOT_EVALUATED"
    if azure_status == "PASS":
        evaluated_domains.append("Azure RBAC")
        if azure:
            azure_score = max([int(row.get("riskScore") or 0) for row in azure], default=0)
            evaluated_scores.append(azure_score)
            azure_risk = "Critical" if azure_score >= 90 else "High" if azure_score >= 75 else "Medium" if azure_score >= 55 else "Low"
            findings.append("Azure RBAC avaliado com acesso identificado.")
            risk_factors.append("Azure RBAC com role assignment identificado.")
        else:
            evaluated_scores.append(20)
            azure_risk = "Low"
            findings.append("Não foi identificado Azure RBAC para esta identidade na cobertura avaliada.")
    else:
        not_evaluated_domains.append("Azure RBAC")

    graph_risk = "NOT_EVALUATED"
    if graph_status == "PASS":
        evaluated_domains.append("Microsoft Graph/API")
        critical_graph = graph.get("criticalPermissions", [])
        app_permissions = graph.get("applicationPermissions", [])
        graph_score = 15
        if critical_graph:
            graph_score = min(100, 70 + (12 * len(critical_graph)))
            findings.append(f"Permissões Graph críticas: {', '.join(critical_graph[:4])}")
            risk_factors.append("Permissões críticas de Microsoft Graph identificadas.")
        elif app_permissions:
            graph_score = 45
            findings.append("Permissões Microsoft Graph identificadas.")
            risk_factors.append("Permissões de Microsoft Graph identificadas.")
        evaluated_scores.append(graph_score)
        graph_risk = "Critical" if graph_score >= 90 else "High" if graph_score >= 75 else "Medium" if graph_score >= 55 else "Low"
    else:
        not_evaluated_domains.append("Microsoft Graph/API")

    ownership_risk = "NOT_EVALUATED"
    if owner_status not in {"OWNER_NOT_EVALUATED", "INSUFFICIENT_PERMISSIONS", "UNSUPPORTED"}:
        evaluated_domains.append("Ownership")
        ownership_score = 15
        if owner_status == "NO_OWNER_CONFIGURED":
            ownership_score = 80
            findings.append("Nenhum owner configurado para o agent.")
            risk_factors.append("Ausência de owner configurado.")
        elif owner_status == "OWNER_NOT_RESOLVED":
            ownership_score = 65
            findings.append("Owner não resolvido no tenant.")
            risk_factors.append("Owner não resolvido no tenant.")
        elif any(owner.get("accountEnabled") is False for owner in owners):
            ownership_score = 60
            findings.append("Owner desabilitado.")
            risk_factors.append("Owner desabilitado.")
        elif any(str(owner.get("userType", "")).lower() == "guest" for owner in owners):
            ownership_score = 55
            findings.append("Owner convidado (guest).")
            risk_factors.append("Owner convidado.")
        evaluated_scores.append(ownership_score)
        ownership_risk = (
            "Critical"
            if ownership_score >= 90
            else "High"
            if ownership_score >= 75
            else "Medium"
            if ownership_score >= 55
            else "Low"
        )
    else:
        findings.append("Ownership não pôde ser avaliado com as permissões/fontes atuais.")
        not_evaluated_domains.append("Ownership")

    evaluated_domain_count = sum(
        1 for status in [azure_status == "PASS", graph_status == "PASS", owner_status not in {"OWNER_NOT_EVALUATED", "INSUFFICIENT_PERMISSIONS", "UNSUPPORTED"}] if status
    )
    if evaluated_domain_count == 0:
        completeness = "NOT_EVALUATED"
    elif evaluated_domain_count < 3:
        completeness = "PARTIAL"
    else:
        completeness = "COMPLETE"

    if not evaluated_scores:
        overall_score = 0
        overall_risk = "NOT_EVALUATED"
    else:
        overall_score = max(evaluated_scores)
        if completeness != "COMPLETE":
            overall_risk = "PARTIAL"
        else:
            overall_risk = (
                "Critical"
                if overall_score >= 90
                else "High"
                if overall_score >= 75
                else "Medium"
                if overall_score >= 55
                else "Low"
            )

    return {
        "riskScore": overall_score,
        "risk": overall_risk,
        "riskLevel": overall_risk,
        "findings": findings,
        "riskFactors": risk_factors,
        "evaluatedDomains": evaluated_domains,
        "notEvaluatedDomains": not_evaluated_domains,
        "evaluationCompleteness": completeness,
        "azureRbacRisk": azure_risk,
        "graphApiRisk": graph_risk,
        "ownershipRisk": ownership_risk,
        "overallRisk": overall_risk,
    }


def _build_enrichment_context(data: dict[str, Any]) -> dict[str, Any]:
    users = _users_index()
    source_sps = data.get("workloadsById")
    sps = source_sps if isinstance(source_sps, dict) and source_sps else _sp_index()
    blueprints = {str(b.get("id")): b for b in data.get("agent_blueprints", [])}
    azure_by_identity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    source_azure = data.get("azureRoleAssignmentsByPrincipal")
    if isinstance(source_azure, dict) and source_azure:
        for pid, items in source_azure.items():
            if isinstance(items, list):
                azure_by_identity[str(pid)].extend(items)
    else:
        for item in list_role_assignments():
            pid = str(item.get("principalId") or "")
            if pid:
                azure_by_identity[pid].append(item)
    return {
        "users": users,
        "sps": sps,
        "blueprints": blueprints,
        "azure_by_identity": azure_by_identity,
    }


def _enrich_agent(agent: dict[str, Any], data: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    users = context["users"]
    sps = context["sps"]
    blueprints = context["blueprints"]

    owners, unresolved = _resolve_owners([str(v) for v in agent.get("ownerIds", [])], users)
    owner_status, owner_reason = _owner_status(agent, owners, unresolved)
    identity = sps.get(str(agent.get("identityId")))
    blueprint = blueprints.get(str(agent.get("blueprintId")))
    graph = _agent_graph_permissions(str(agent.get("id")), data)
    graph_status = str(data.get("graphEvaluationStatus", "PASS"))
    azure_status = str(data.get("azureRbacEvaluationStatus", "PASS"))
    azure_raw = context["azure_by_identity"].get(str(agent.get("identityId")), [])
    azure: list[dict[str, Any]] = []
    for item in azure_raw:
        risk = role_risk_score(str(item.get("role")), "Azure", scope=item.get("scope"))
        role = str(item.get("role") or "")
        scope = item.get("scope")
        resource_name, resource_type = _extract_resource_info(scope)
        access_path = "Inherited" if bool(item.get("inherited")) or str(item.get("assignmentType", "")).lower().startswith("inherited") else "Direct"
        role_permissions = item.get("rolePermissions") or []
        primary_plane, plane_reason = _infer_access_plane(role, role_permissions)
        data_capability, effective_capability = _infer_data_capability(role, role_permissions)
        azure.append(
            sanitize_assignment(
                {
                    "principalId": item.get("principalId"),
                    "principalType": item.get("principalType"),
                    "role": role,
                    "roleDefinitionId": item.get("roleDefinitionId"),
                    "roleType": item.get("roleType") or ("Custom" if "/providers/microsoft.authorization/roledefinitions/" not in str(item.get("roleDefinitionId") or "").lower() else "Built-in"),
                    "scope": scope,
                    "assignmentType": item.get("assignmentType"),
                    "accessPath": access_path,
                    "inheritedFrom": item.get("inheritedFrom"),
                    "origin": item.get("origin"),
                    "scopeType": _extract_scope_level(scope),
                    "assignmentScope": scope,
                    "managementGroup": _extract_scope_name(scope, "managementGroups"),
                    "subscription": item.get("subscription") or _extract_scope_name(scope, "subscriptions"),
                    "resourceGroup": item.get("resourceGroup") or _extract_scope_name(scope, "resourceGroups"),
                    "resource": item.get("resource") or resource_name,
                    "resourceType": resource_type,
                    "primaryAccessPlane": primary_plane,
                    "accessPlaneReason": plane_reason,
                    "dataCapability": data_capability,
                    "effectiveCapability": effective_capability,
                    "privilegeType": _classify_privilege_type(role),
                    "risk": risk["level"],
                    "riskScore": risk["score"],
                }
            )
        )
    risk = _agent_risk(agent, owners, unresolved, graph, graph_status, azure, azure_status)
    identity_type_hint = agent.get("identityType") or ("ManagedIdentity" if (identity or {}).get("servicePrincipalType") == "ManagedIdentity" else "ServicePrincipal")
    object_classification = str(agent.get("objectClassification") or ("Agent Identity" if is_mock_mode() else "Unknown"))
    managed_identity_type = (
        str(agent.get("managedIdentityType") or "Unknown")
        if str(identity_type_hint) == "ManagedIdentity"
        else "Not Applicable"
    )
    if str(identity_type_hint) == "ManagedIdentity":
        identity_category = "Managed Identity"
    elif object_classification == "Agent Identity":
        identity_category = "Agent Identity"
    elif object_classification == "Microsoft-managed / First-party identity":
        identity_category = "Microsoft/First-party identity"
    elif object_classification == "Heuristic Candidate":
        identity_category = "Heuristic Candidate"
    else:
        identity_category = "Unknown"

    return sanitize_assignment(
        {
            "agentId": agent.get("id"),
            "name": agent.get("name"),
            "displayName": agent.get("name"),
            "objectClassification": object_classification,
            "identification": agent.get("identification", "Confirmed" if is_mock_mode() else "Heuristic Candidate"),
            "confidence": agent.get("confidence", "High" if is_mock_mode() else "Low"),
            "identificationSource": agent.get(
                "identificationSource",
                "integrated_agent_inventory" if is_mock_mode() else "live_workload_heuristic",
            ),
            "inference": agent.get("inference"),
            "enabled": agent.get("enabled", True),
            "createdDateTime": agent.get("createdDateTime"),
            "identity": {
                "objectId": identity.get("id") if identity else agent.get("identityId"),
                "displayName": identity.get("displayName") if identity else None,
                "appId": identity.get("appId") if identity else None,
                "identityType": "ServicePrincipal",
                "identityCategory": identity_category,
                "directoryObjectType": "ServicePrincipal",
                "managedIdentityType": managed_identity_type,
            },
            "blueprint": {
                "id": blueprint.get("id") if blueprint else agent.get("blueprintId"),
                "name": blueprint.get("name") if blueprint else None,
                "ownerIds": blueprint.get("ownerIds", []) if blueprint else [],
            },
            "owners": owners,
            "ownerStatus": owner_status,
            "ownerStatusReason": owner_reason,
            "unresolvedOwnerIds": unresolved,
            "ownerCount": len(owners),
            "graphPermissions": graph,
            "graphPermissionsStatus": graph_status,
            "azureRoleAssignments": azure,
            "azureRbacStatus": azure_status,
            "azureAccess": len(azure) > 0,
            "criticalGraphPermissionCount": len(graph.get("criticalPermissions", [])),
            "risk": risk["risk"],
            "riskScore": risk["riskScore"],
            "riskLevel": risk["riskLevel"],
            "findings": risk["findings"],
            "riskFactors": risk["riskFactors"],
            "evaluatedDomains": risk["evaluatedDomains"],
            "notEvaluatedDomains": risk["notEvaluatedDomains"],
            "evaluationCompleteness": risk["evaluationCompleteness"],
            "azureRbacRisk": risk["azureRbacRisk"],
            "graphApiRisk": risk["graphApiRisk"],
            "ownershipRisk": risk["ownershipRisk"],
            "overallRisk": risk["overallRisk"],
            "sourceMode": data.get("sourceMode", "mock"),
            "sourceNote": data.get("sourceNote"),
            "agentIdApiStatus": data.get("agentIdApiStatus", "INTEGRATED" if is_mock_mode() else "NOT_INTEGRATED"),
        }
    )


def list_agents(status: str = "all", limit: int = 50) -> list[dict[str, Any]]:
    data = _require_agent_source()
    context = _build_enrichment_context(data)
    rows = [_enrich_agent(agent, data, context) for agent in data.get("agents", [])]
    if status.lower() == "active":
        rows = [row for row in rows if row.get("enabled") is True]
    elif status.lower() == "disabled":
        rows = [row for row in rows if row.get("enabled") is False]
    rows.sort(key=lambda r: (-(int(r.get("riskScore") or 0)), str(r.get("name") or "")))
    return rows[: max(1, min(int(limit), 500))]


def get_agent_relationships(agent_identifier: str) -> dict[str, Any]:
    data = _require_agent_source()
    context = _build_enrichment_context(data)
    query = _normalize(agent_identifier)
    for agent in data.get("agents", []):
        if query in {_normalize(str(agent.get("id") or "")), _normalize(str(agent.get("name") or ""))}:
            return _enrich_agent(agent, data, context)
    for agent in data.get("agents", []):
        if query and query in _normalize(str(agent.get("name") or "")):
            return _enrich_agent(agent, data, context)
    raise RuntimeError(f"Agent `{agent_identifier}` não encontrado na fonte disponível.")


def get_agents_by_owner(owner_identifier: str, limit: int = 50) -> dict[str, Any]:
    data = _require_agent_source()
    context = _build_enrichment_context(data)
    users = list_users()
    owner_q = _normalize(owner_identifier)
    owner = None
    for user in users:
        if owner_q in {
            _normalize(str(user.get("id") or "")),
            _normalize(str(user.get("userPrincipalName") or "")),
            _normalize(str(user.get("displayName") or "")),
        }:
            owner = user
            break
    if owner is None and "@" in owner_identifier:
        raise RuntimeError(f"Usuário `{owner_identifier}` não foi encontrado no tenant visível.")
    if owner is None:
        raise RuntimeError(f"Owner `{owner_identifier}` não encontrado.")

    owner_id = str(owner.get("id"))
    rows = []
    for agent in data.get("agents", []):
        if owner_id in [str(v) for v in agent.get("ownerIds", [])]:
            rows.append(_enrich_agent(agent, data, context))
    rows.sort(key=lambda r: (-(int(r.get("riskScore") or 0)), str(r.get("name") or "")))
    owner_view = sanitize_assignment(
        {
            "name": owner.get("displayName"),
            "displayName": owner.get("displayName"),
            "userPrincipalName": owner.get("userPrincipalName"),
            "mail": owner.get("mail") or owner.get("userPrincipalName"),
            "objectId": owner.get("id"),
            "identityType": "User",
            "accountEnabled": owner.get("accountEnabled"),
            "userType": owner.get("userType"),
        }
    )
    return {"owner": owner_view, "count": len(rows), "agents": rows[: max(1, min(int(limit), 500))]}


def analyze_user_with_agents(owner_identifier: str, limit: int = 20) -> dict[str, Any]:
    owners_agents = get_agents_by_owner(owner_identifier, limit=500)
    owner = owners_agents["owner"]
    direct_rows = [
        item
        for item in correlate_privileged_identities()
        if str(item.get("objectId")) == str(owner.get("objectId"))
    ]
    return {
        "owner": owner,
        "directPrivileges": direct_rows,
        "ownedAgents": owners_agents["agents"][: max(1, min(int(limit), 500))],
    }


def assess_all_agents(top: int = 10) -> dict[str, Any]:
    data = _require_agent_source()
    context = _build_enrichment_context(data)
    rows = [_enrich_agent(agent, data, context) for agent in data.get("agents", [])]
    rows.sort(key=lambda r: (-(int(r.get("riskScore") or 0)), str(r.get("name") or "")))
    assessable_rows = _agent_identities_only(rows)
    class_summary = _classification_summary(rows)
    findings: list[dict[str, Any]] = []
    no_owner = [a for a in assessable_rows if str(a.get("ownerStatus")) == "NO_OWNER_CONFIGURED"]
    owner_not_evaluated = [
        a
        for a in assessable_rows
        if str(a.get("ownerStatus")) in {"OWNER_NOT_EVALUATED", "INSUFFICIENT_PERMISSIONS", "UNSUPPORTED"}
    ]
    unresolved_owner = [a for a in assessable_rows if a.get("unresolvedOwnerIds")]
    critical_graph = [a for a in assessable_rows if int(a.get("criticalGraphPermissionCount") or 0) > 0]
    azure_owner_or_uaa = [
        a
        for a in assessable_rows
        if any(
            str(r.get("role")) in {"Owner", "User Access Administrator"}
            for r in a.get("azureRoleAssignments", [])
        )
    ]

    if no_owner:
        findings.append({"risk": "Agents sem owner", "severity": "High", "count": len(no_owner)})
    if owner_not_evaluated:
        findings.append(
            {
                "risk": "Ownership não avaliado com segurança",
                "severity": "Medium",
                "count": len(owner_not_evaluated),
                "evaluationStatus": "NOT_EVALUATED",
            }
        )
    if unresolved_owner:
        findings.append({"risk": "Agents com owner não resolvido", "severity": "High", "count": len(unresolved_owner)})
    if critical_graph:
        findings.append({"risk": "Agents com permissões Graph críticas", "severity": "High", "count": len(critical_graph)})
    if azure_owner_or_uaa:
        findings.append(
            {
                "risk": "Agents com Owner/User Access Administrator no Azure",
                "severity": "High",
                "count": len(azure_owner_or_uaa),
            }
        )

    by_owner = Counter()
    for agent in assessable_rows:
        for owner in agent.get("owners", []):
            by_owner[str(owner.get("userPrincipalName") or owner.get("displayName") or owner.get("objectId"))] += 1

    top_agents = assessable_rows[: max(1, min(int(top), 100))]
    top_owners = [{"owner": owner, "agentsCount": count} for owner, count in by_owner.most_common(max(1, min(int(top), 100)))]
    narrative = [
        "Resumo do assessment de Agent Identities:",
        f"- Objetos descobertos: **{len(rows)}**",
        f"- Agent identities avaliadas: **{len(assessable_rows)}**",
        f"- Agent Identity Blueprints: **{class_summary['agent_identity_blueprints']}**",
        f"- Agents sem owner configurado: **{len(no_owner)}**",
        f"- Ownership não avaliado: **{len(owner_not_evaluated)}**",
        f"- Agents com owner não resolvido: **{len(unresolved_owner)}**",
        f"- Agents com Graph crítico: **{len(critical_graph)}**",
        "",
        "Top Agents por risco:",
    ]
    for idx, agent in enumerate(top_agents, start=1):
        narrative.append(
            f"{idx}. {agent.get('name')} | Risco: {agent.get('risk')} ({agent.get('riskScore')}/100) "
            f"| Owners: {agent.get('ownerCount')}"
        )
    return {
        "summary": {
            "objects_discovered": len(rows),
            "agents_evaluated": len(assessable_rows),
            "classification": class_summary,
            "agents_without_owner": len(no_owner),
            "owner_not_evaluated": len(owner_not_evaluated),
            "agents_with_unresolved_owner": len(unresolved_owner),
            "agents_with_critical_graph_permissions": len(critical_graph),
        },
        "findings": findings,
        "top_agents": top_agents,
        "top_owners": top_owners,
        "narrative": "\n".join(narrative),
        "sourceMode": data.get("sourceMode", "mock"),
        "sourceNote": data.get("sourceNote"),
        "sourceWarnings": data.get("sourceWarnings", []),
    }


def _format_agent_lines(rows: list[dict[str, Any]], limit: int = 20) -> str:
    lines: list[str] = []
    for agent in rows[: max(1, limit)]:
        owners = agent.get("owners") or []
        owner_names = ", ".join(
            [str(owner.get("displayName") or owner.get("userPrincipalName") or owner.get("objectId")) for owner in owners]
        )
        lines.append(f"- **{agent.get('name') or 'N/A'}**")
        lines.append(f"  - Agent ID: {agent.get('agentId') or 'N/A'}")
        lines.append(f"  - Status: {'Ativo' if agent.get('enabled') else 'Desabilitado'}")
        lines.append(f"  - Owner status: {_friendly_status(agent.get('ownerStatus'))}")
        lines.append(f"  - Owners: {owner_names or 'Nenhum identificado'}")
        lines.append(f"  - Blueprint: {agent.get('blueprint', {}).get('name') or 'N/A'}")
        lines.append(f"  - Graph crítico: {agent.get('criticalGraphPermissionCount', 0)}")
        lines.append(f"  - Azure RBAC identificado: {'Sim' if agent.get('azureAccess') else 'Não'}")
        lines.append(f"  - Risco: {agent.get('risk') or 'N/A'} ({agent.get('riskScore') or 0}/100)")
        lines.append("")
    return "\n".join(lines) if lines else "- Nenhum resultado."


def _format_agents_with_access_blocks(rows: list[dict[str, Any]], limit: int = 20) -> str:
    lines: list[str] = []
    for item in rows[: max(1, limit)]:
        identity = item.get("identity") or {}
        azure = (item.get("azureRoleAssignments") or [])
        first = azure[0] if azure else {}
        scope_value = (
            first.get("resource")
            or first.get("resourceGroup")
            or first.get("assignmentScope")
            or "N/A"
        )
        lines.append(f"- **{item.get('name') or 'N/A'}**")
        lines.append(f"  - Identity Category: {identity.get('identityCategory') or 'N/A'}")
        lines.append(f"  - Directory Object Type: {identity.get('directoryObjectType') or 'N/A'}")
        lines.append(f"  - Role: {first.get('role') or 'N/A'}")
        lines.append(f"  - Capability: {first.get('effectiveCapability') or 'N/A'}")
        lines.append(f"  - Assignment: {first.get('accessPath') or 'N/A'}")
        lines.append(f"  - Scope: {scope_value}")
        lines.append(f"  - Scope Type: {first.get('scopeType') or 'N/A'}")
        lines.append(f"  - Primary Plane: {first.get('primaryAccessPlane') or 'N/A'}")
        lines.append(f"  - Azure RBAC Risk: {str(item.get('azureRbacRisk') or 'N/A').upper()}")
        lines.append("")
    return "\n".join(lines).strip() if lines else "Nenhum objeto com Azure RBAC identificado dentro da cobertura avaliada."


def _agent_access_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    azure_count = sum(1 for row in rows if row.get("azureRoleAssignments"))
    graph_count = sum(
        1
        for row in rows
        if (row.get("graphPermissions") or {}).get("applicationPermissions")
        or (row.get("graphPermissions") or {}).get("delegatedPermissions")
    )
    both = sum(
        1
        for row in rows
        if row.get("azureRoleAssignments")
        and (
            (row.get("graphPermissions") or {}).get("applicationPermissions")
            or (row.get("graphPermissions") or {}).get("delegatedPermissions")
        )
    )
    any_access = sum(
        1
        for row in rows
        if row.get("azureRoleAssignments")
        or (row.get("graphPermissions") or {}).get("applicationPermissions")
        or (row.get("graphPermissions") or {}).get("delegatedPermissions")
    )
    return {
        "total": len(rows),
        "any_access": any_access,
        "no_access": max(0, len(rows) - any_access),
        "azure_rbac": azure_count,
        "graph_api": graph_count,
        "both": both,
    }


def _classification_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter([str(row.get("objectClassification") or "Unknown") for row in rows])
    return {
        "confirmed_agent_identities": counter.get("Agent Identity", 0),
        "agent_identity_blueprints": counter.get("Agent Identity Blueprint", 0),
        "microsoft_first_party_identities": counter.get("Microsoft-managed / First-party identity", 0)
        + counter.get("Microsoft-managed Agent", 0),
        "managed_identities": counter.get("Managed Identity", 0),
        "heuristic_candidates": counter.get("Heuristic Candidate", 0) + counter.get("Heuristic Agent Candidate", 0),
        "unknown": counter.get("Unknown", 0),
    }


def _agent_identities_only(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Blueprints are intentionally excluded from identity assessment counts.
    return [row for row in rows if str(row.get("objectClassification")) != "Agent Identity Blueprint"]


def _has_identified_access(row: dict[str, Any]) -> bool:
    graph = row.get("graphPermissions") or {}
    return bool(
        row.get("azureRoleAssignments")
        or graph.get("applicationPermissions")
        or graph.get("delegatedPermissions")
    )


def _format_agent_technical_details(rows: list[dict[str, Any]], limit: int) -> str:
    lines: list[str] = []
    for row in rows[: max(1, limit)]:
        lines.extend(
            [
                f"Agent: {row.get('name')}",
                f"Agent Object ID: {row.get('agentId')}",
                f"Classificação do objeto: {row.get('objectClassification') or 'Unknown'}",
                f"Identificação: {row.get('identification') or 'Heuristic Candidate'}",
                f"Confiança: {_friendly_confidence(row.get('confidence') or 'Low')}",
                f"Identification Source: {row.get('identificationSource') or 'N/A'}",
                f"Nome da identidade: {(row.get('identity') or {}).get('displayName') or 'N/A'}",
                f"Principal ID: {(row.get('identity') or {}).get('objectId') or 'N/A'}",
                f"Tipo do principal: {(row.get('identity') or {}).get('identityType') or 'ServicePrincipal'}",
                f"Categoria da identidade: {(row.get('identity') or {}).get('identityCategory') or 'N/A'}",
                f"Tipo de objeto no diretório: {(row.get('identity') or {}).get('directoryObjectType') or 'ServicePrincipal'}",
                f"Managed Identity Type: {(row.get('identity') or {}).get('managedIdentityType') or 'Unknown'}",
                f"Status do owner: {_friendly_status(row.get('ownerStatus'))}",
            ]
        )
        if row.get("inference"):
            lines.append(f"Inference: {row.get('inference')}")
        if row.get("ownerStatusReason"):
            lines.append(f"Motivo (owner): {row.get('ownerStatusReason')}")
        azure = row.get("azureRoleAssignments", [])
        if azure:
            lines.append("AZURE RBAC:")
            for idx, a in enumerate(azure, start=1):
                lines.extend(
                    [
                        f"  {idx}. Azure Role: {a.get('role') or 'N/A'}",
                        f"     Role Definition ID: {a.get('roleDefinitionId') or 'N/A'}",
                        f"     Role Type: {a.get('roleType') or 'N/A'}",
                        f"     Primary Access Plane: {a.get('primaryAccessPlane') or 'N/A'}",
                        f"     Justificativa do plano: {a.get('accessPlaneReason') or 'N/A'}",
                        f"     Data Capability: {a.get('dataCapability') or 'N/A'}",
                        f"     Effective Capability: {a.get('effectiveCapability') or 'N/A'}",
                        f"     Privilege Type: {a.get('privilegeType') or 'N/A'}",
                        f"     Access Path: {a.get('accessPath') or 'Direct'}",
                        f"     Assignment Scope: {a.get('assignmentScope') or a.get('scope') or 'N/A'}",
                        f"     Scope Type: {a.get('scopeType') or 'N/A'}",
                        f"     Subscription: {a.get('subscription') or 'N/A'}",
                        f"     Resource Group: {a.get('resourceGroup') or 'N/A'}",
                        f"     Resource: {a.get('resource') or 'N/A'}",
                        f"     Resource Type: {a.get('resourceType') or 'N/A'}",
                    ]
                )
        graph = row.get("graphPermissions", {})
        graph_status = str(row.get("graphPermissionsStatus") or "NOT_EVALUATED")
        app_count = len(graph.get("applicationPermissions", []) or [])
        delegated_count = len(graph.get("delegatedPermissions", []) or [])
        critical_count = len(graph.get("criticalPermissions", []) or [])
        if graph_status == "PASS" or app_count or delegated_count or critical_count:
            lines.append("MICROSOFT GRAPH/API PERMISSIONS:")
            lines.append(f"  - Status de avaliação: {_friendly_status(graph_status)}")
            lines.append(f"  - Permissões de aplicação: {app_count}")
            lines.append(f"  - Permissões delegadas: {delegated_count}")
            lines.append(f"  - Permissões críticas: {critical_count}")
            lines.append(f"  - Admin Consent: {'Concedido' if graph.get('adminConsent') else 'Não identificado'}")
        lines.append(f"Azure RBAC Risk: {_friendly_status(row.get('azureRbacRisk'))}")
        lines.append(f"Graph/API Risk: {_friendly_status(row.get('graphApiRisk'))}")
        lines.append(f"Ownership Risk: {_friendly_status(row.get('ownershipRisk'))}")
        lines.append(f"Overall Risk: {_friendly_status(row.get('overallRisk'))}")
        lines.append(f"Overall Assessment: {_friendly_status(row.get('evaluationCompleteness'))}")
        lines.append(
            f"Coverage: Azure RBAC={_friendly_status(row.get('azureRbacStatus'))}; "
            f"Graph/API={_friendly_status(row.get('graphPermissionsStatus'))}; "
            f"Ownership={_friendly_status('PASS' if row.get('ownershipRisk') not in NON_EVALUATED_STATUSES else 'NOT_EVALUATED')}"
        )
        lines.append(f"Risco (score): {row.get('riskScore')}/100")
        lines.append("")
    return "\n".join(lines).strip() if lines else "Sem detalhes técnicos."


def _format_agent_summary_table(rows: list[dict[str, Any]], limit: int) -> str:
    header = [
        "| Agent | Classificação | Confiança | Tipo de identidade | Fonte de permissão | Role / Permissão | Tipo de privilégio | Scope | Caminho de acesso | Status do owner | Risco |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    body: list[str] = []
    for row in rows[: max(1, limit)]:
        identity_type = (row.get("identity") or {}).get("identityType") or "ServicePrincipal"
        owner_status = _friendly_status(str(row.get("ownerStatus") or "N/A"))
        risk = f"{_friendly_status(row.get('riskLevel') or row.get('risk'))} ({row.get('riskScore') or 0}/100)"

        azure = row.get("azureRoleAssignments", [])
        graph = row.get("graphPermissions", {})
        app_perms = graph.get("applicationPermissions", []) or []
        delegated = graph.get("delegatedPermissions", []) or []

        if azure:
            role_names = [str(a.get("role") or "N/A") for a in azure]
            shown_roles = ", ".join(role_names[:2])
            if len(role_names) > 2:
                shown_roles += f" (+{len(role_names) - 2})"
            first = azure[0]
            body.append(
                "| "
                f"{row.get('name') or 'N/A'} | "
                f"{row.get('objectClassification') or 'Unknown'} | "
                f"{_friendly_confidence(row.get('confidence') or 'Low')} | "
                f"{identity_type} | "
                "Azure RBAC | "
                f"{shown_roles} | "
                f"{first.get('privilegeType') or 'Standard Access'} | "
                f"{first.get('assignmentScope') or first.get('scope') or 'N/A'} | "
                f"{first.get('accessPath') or 'Direct'} | "
                f"{owner_status} | "
                f"{risk} |"
            )
        if app_perms or delegated:
            total_graph = len(app_perms) + len(delegated)
            first_perm = str((app_perms + delegated)[0])
            perm_text = first_perm if total_graph == 1 else f"{first_perm} (+{total_graph - 1})"
            body.append(
                "| "
                f"{row.get('name') or 'N/A'} | "
                f"{row.get('objectClassification') or 'Unknown'} | "
                f"{_friendly_confidence(row.get('confidence') or 'Low')} | "
                f"{identity_type} | "
                "Microsoft Graph/API | "
                f"{perm_text} | "
                "API Permission | "
                "Microsoft Graph | "
                "Direct | "
                f"{owner_status} | "
                f"{risk} |"
            )
        if not azure and not app_perms and not delegated:
            body.append(
                "| "
                f"{row.get('name') or 'N/A'} | "
            f"{row.get('objectClassification') or 'Unknown'} | "
            f"{_friendly_confidence(row.get('confidence') or 'Low')} | "
            f"{identity_type} | "
            "No identified access | "
                "N/A | "
                "N/A | "
            "N/A | "
            "N/A | "
            f"{owner_status} | "
            f"{risk} |"
            )
    if not body:
        body.append("| N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |")
    return "\n".join([*header, *body])


def answer_agent_question(question: str, limit: int = 20) -> dict[str, Any]:
    q = _normalize(question)
    if "assessment" in q or "risco" in q or "maior risco" in q or "top 10" in q:
        result = assess_all_agents(top=max(1, limit))
        return {"intent": "agent_assessment", "narrative": result["narrative"], "data": result}

    email_match = re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", q)
    if email_match and ("owner" in q or "responsavel" in q or "analise o usuario" in q):
        owner_upn = email_match.group(0)
        merged = analyze_user_with_agents(owner_upn, limit=limit)
        direct = merged.get("directPrivileges", [])
        agents = merged.get("ownedAgents", [])
        narrative = [
            f"Análise do usuário {merged['owner'].get('userPrincipalName')}:",
            "",
            "PRIVILÉGIOS DO USUÁRIO:",
            (
                "- Sem privilégios diretos identificados nas fontes avaliadas."
                if not direct
                else f"- Privilégios diretos identificados: {len(direct)}."
            ),
            "",
            "PRIVILÉGIOS DOS AGENTS SOB RESPONSABILIDADE DO USUÁRIO:",
            f"- Agents encontrados: **{len(agents)}**",
            _format_agent_lines(agents, limit=limit),
            "",
            "Observação: ownership indica responsabilidade, não concessão automática das permissões do Agent ao usuário.",
        ]
        return {
            "intent": "agent_user_analysis",
            "narrative": "\n".join(narrative),
            "data": merged,
        }

    if "owner" in q and ("quantos" in q or "top" in q or "responsave" in q):
        rows = list_agents(status="all", limit=500)
        owner_counter = Counter()
        for agent in rows:
            for owner in agent.get("owners", []):
                owner_counter[
                    str(owner.get("displayName") or owner.get("userPrincipalName") or owner.get("objectId"))
                ] += 1
        top = [{"owner": name, "agentsCount": count} for name, count in owner_counter.most_common(max(1, limit))]
        lines = ["Owners por quantidade de Agents:", ""]
        for item in top[: max(1, limit)]:
            lines.append(f"- {item['owner']}: {item['agentsCount']} agent(s)")
        return {"intent": "agent_owners_ranking", "narrative": "\n".join(lines), "data": {"owners": top}}

    if ("sem owner" in q) or ("sem responsavel" in q) or ("nao possuem owner" in q):
        rows = [a for a in list_agents(status="all", limit=500) if int(a.get("ownerCount") or 0) == 0]
        return {
            "intent": "agents_without_owner",
            "narrative": f"Agents sem owner: **{len(rows)}**\n\n{_format_agent_lines(rows, limit=limit)}",
            "data": {"count": len(rows), "rows": rows[: max(1, limit)]},
        }

    if ("possuem owner" in q) or ("com owner" in q):
        rows = [a for a in list_agents(status="all", limit=500) if int(a.get("ownerCount") or 0) > 0]
        return {
            "intent": "agents_with_owner",
            "narrative": f"Agents com owner: **{len(rows)}**\n\n{_format_agent_lines(rows, limit=limit)}",
            "data": {"count": len(rows), "rows": rows[: max(1, limit)]},
        }

    if ("owner nao pode ser resolvido" in q) or ("owner nao resolvido" in q) or ("owner nao existe" in q):
        rows = [a for a in list_agents(status="all", limit=500) if a.get("unresolvedOwnerIds")]
        return {
            "intent": "agents_with_unresolved_owner",
            "narrative": f"Agents com owner não resolvido: **{len(rows)}**\n\n{_format_agent_lines(rows, limit=limit)}",
            "data": {"count": len(rows), "rows": rows[: max(1, limit)]},
        }

    if ("criados recentemente" in q) or ("recentes" in q):
        threshold = _now_utc().timestamp() - (45 * 24 * 60 * 60)
        rows = []
        for agent in list_agents(status="all", limit=500):
            dt = _parse_dt(str(agent.get("createdDateTime") or ""))
            if dt and dt.timestamp() >= threshold:
                rows.append(agent)
        return {
            "intent": "recent_agents",
            "narrative": f"Agents criados recentemente: **{len(rows)}**\n\n{_format_agent_lines(rows, limit=limit)}",
            "data": {"count": len(rows), "rows": rows[: max(1, limit)]},
        }

    if ("mais privilegiad" in q) or ("privilegiad" in q):
        rows = list_agents(status="all", limit=500)
        return {
            "intent": "most_privileged_agents",
            "narrative": f"Agents mais privilegiados: **{len(rows[: max(1, limit)])}**\n\n{_format_agent_lines(rows, limit=limit)}",
            "data": {"count": len(rows), "rows": rows[: max(1, limit)]},
        }

    if "agent" in q and ("quem e responsavel" in q or "quais permissoes" in q or "detalhe" in q):
        data = _require_agent_source()
        context = _build_enrichment_context(data)
        for agent in data.get("agents", []):
            if _normalize(str(agent.get("name") or "")) in q:
                row = _enrich_agent(agent, data, context)
                narrative = [
                    f"Agent: {row.get('name')}",
                    f"ID: {row.get('agentId')}",
                    f"Blueprint: {row.get('blueprint', {}).get('name') or 'N/A'}",
                    f"Status do owner: {_friendly_status(row.get('ownerStatus'))}",
                    f"Permissões Graph críticas: {row.get('criticalGraphPermissionCount')}",
                    f"Azure RBAC identificado: {'Sim' if row.get('azureAccess') else 'Não'}",
                    f"Risco: {row.get('risk')} ({row.get('riskScore')}/100)",
                    "",
                    _format_agent_technical_details([row], limit=1),
                    "",
                    "Observação: ownership indica responsabilidade, não concessão automática das permissões do Agent ao usuário.",
                ]
                return {"intent": "agent_relationship_detail", "narrative": "\n".join(narrative), "data": row}

    status = "all"
    if "ativo" in q or "ativos" in q:
        status = "active"
    elif "desabilitad" in q:
        status = "disabled"

    rows = list_agents(status=status, limit=limit)
    class_summary = _classification_summary(rows)
    assessable_rows = _agent_identities_only(rows)
    summary_access = _agent_access_summary(assessable_rows)
    summary = Counter([str(r.get("risk")) for r in rows])
    source_mode = str(rows[0].get("sourceMode")) if rows else ("mock" if is_mock_mode() else "live_workload_heuristic")
    source_note = str(rows[0].get("sourceNote") or "") if rows else (
        "Inventário em modo live pode usar heurística de workload identities quando a API nativa de Agents não está disponível."
        if not is_mock_mode()
        else ""
    )
    owner_not_evaluated = sum(
        1 for r in assessable_rows if str(r.get("ownerStatus")) in {"OWNER_NOT_EVALUATED", "INSUFFICIENT_PERMISSIONS", "UNSUPPORTED"}
    )
    owner_without = sum(1 for r in assessable_rows if str(r.get("ownerStatus")) == "NO_OWNER_CONFIGURED")
    owner_with = sum(1 for r in assessable_rows if str(r.get("ownerStatus")) == "OWNER_CONFIGURED")
    graph_status = _coverage_status([str(r.get("graphPermissionsStatus") or "") for r in assessable_rows])
    azure_status = _coverage_status([str(r.get("azureRbacStatus") or "") for r in assessable_rows])
    ownership_status = _ownership_coverage_status(assessable_rows)
    agent_id_api_status = assessable_rows[0].get("agentIdApiStatus") if assessable_rows else "NOT_INTEGRATED"
    inventory_mode = _inventory_mode_text(source_mode, str(agent_id_api_status))
    azure_access_line = (
        f"- Azure RBAC atribuído identificado: **{summary_access['azure_rbac']}**"
        if azure_status == "PASS"
        else "- Azure RBAC atribuído identificado: **NOT_EVALUATED**"
    )
    graph_access_line = (
        f"- Microsoft Graph/API identificado: **{summary_access['graph_api']}**"
        if graph_status == "PASS"
        else "- Microsoft Graph/API identificado: **NOT_EVALUATED**"
    )
    owner_access_lines = (
        [
            f"- Owner configurado: **{owner_with}**",
            f"- Sem owner configurado: **{owner_without}**",
            f"- Owner não avaliado: **{owner_not_evaluated}**",
        ]
        if ownership_status in {"PASS", "PARTIAL"}
        else ["- Ownership details: **NOT_EVALUATED**"]
    )
    wants_more = any(token in q for token in ["mostrar mais", "mais detalhes", "todos", "completo"])
    top_default = max(1, int(os.getenv("AGENT_DEFAULT_TOP_RESULTS", str(DEFAULT_AGENT_TOP_RESULTS))))
    display_count = max(1, min(limit, len(assessable_rows))) if wants_more else max(1, min(top_default, limit, len(assessable_rows)))
    display_rows = assessable_rows[:display_count]

    if ("quantos" in q or "quantas" in q) and ("permiss" in q or "acesso" in q):
        with_azure_access = [r for r in assessable_rows if r.get("azureRoleAssignments")]
        with_azure_access = with_azure_access[: max(1, min(5, len(with_azure_access)))] if with_azure_access else []
        without_azure_rbac = max(0, summary_access["total"] - summary_access["azure_rbac"])
        heuristic_inventory = _is_heuristic_inventory(source_mode, str(agent_id_api_status))
        inventory_line = _inventory_sentence(len(rows))
        overall_assessment = "PARTIAL" if (graph_status != "PASS" or ownership_status != "PASS" or azure_status != "PASS") else "COMPLETE"
        principal_finding = "Nenhuma identidade com Azure RBAC identificado dentro da cobertura avaliada."
        principal_risk = "NOT_EVALUATED"
        if with_azure_access:
            principal = with_azure_access[0]
            assignment = (principal.get("azureRoleAssignments") or [{}])[0]
            role = assignment.get("role") or "N/A"
            scope_name = assignment.get("resource") or assignment.get("resourceGroup") or assignment.get("assignmentScope") or "N/A"
            scope_type = assignment.get("resourceType") or assignment.get("scopeType") or "scope"
            principal_finding = (
                f"Uma {((principal.get('identity') or {}).get('identityCategory') or 'identidade')} associada ao objeto "
                f"{principal.get('name') or 'N/A'} possui acesso {role} em {scope_type} {scope_name}."
            )
            principal_risk = str(principal.get("azureRbacRisk") or "NOT_EVALUATED").upper()
        graph_line = (
            "Microsoft Graph/API permissions foi avaliado."
            if graph_status == "PASS"
            else "Microsoft Graph/API permissions não foi avaliado."
        )
        ownership_line = (
            "Ownership foi avaliado."
            if ownership_status == "PASS"
            else "Ownership não foi avaliado."
        )
        managed_count = class_summary["managed_identities"]
        first_party_count = class_summary["microsoft_first_party_identities"]
        blueprint_count = class_summary["agent_identity_blueprints"]
        heuristic_count = class_summary["heuristic_candidates"]
        confirmed_count = class_summary["confirmed_agent_identities"]
        azure_access_phrase = (
            "1 identidade possui acesso Azure RBAC identificado."
            if summary_access["azure_rbac"] == 1
            else f"{summary_access['azure_rbac']} identidades possuem acesso Azure RBAC identificado."
        )
        narrative = [
            "AGENT IDENTITY SECURITY ASSESSMENT",
            "",
            "Executive Summary",
            "────────────────────────────────────",
            "",
            inventory_line,
            "",
            (
                "O inventário atual é heurístico, pois a API dedicada de Agent Identity ainda não está integrada."
                if heuristic_inventory
                else "O inventário atual usa integração dedicada de Agent Identity."
            ),
            f"Inventory Mode: {'HEURISTIC' if heuristic_inventory else 'INTEGRATED'}",
            f"Agent ID API: {'NOT INTEGRATED' if str(agent_id_api_status) == 'NOT_INTEGRATED' else 'INTEGRATED'}",
            "",
            "Dos objetos avaliados:",
            "",
            (
                f"- {blueprint_count} é Agent Identity Blueprint"
                if blueprint_count == 1
                else f"- {blueprint_count} são Agent Identity Blueprints"
            ),
            (
                f"- {managed_count} é Managed Identity"
                if managed_count == 1
                else f"- {managed_count} são Managed Identities"
            ),
            (
                f"- {first_party_count} é identidade Microsoft/First-party"
                if first_party_count == 1
                else f"- {first_party_count} são identidades Microsoft/First-party"
            ),
            (
                f"- {heuristic_count} é candidato heurístico ainda não classificado"
                if heuristic_count == 1
                else f"- {heuristic_count} são candidatos heurísticos ainda não classificados"
            ),
            (
                f"- {confirmed_count} Agent Identity foi confirmada por API dedicada"
                if confirmed_count == 1
                else f"- {confirmed_count} Agent Identities foram confirmadas por API dedicada"
            ),
            "",
            "Assessment Coverage",
            "Azure RBAC foi avaliado." if azure_status == "PASS" else "Azure RBAC não foi avaliado.",
            graph_line,
            ownership_line,
            "",
            azure_access_phrase,
            "",
            "Overall Assessment:",
            overall_assessment,
            "",
            "Principal Finding:",
            principal_finding,
            "",
            "Risk:",
            principal_risk,
            "",
        ]
        return {
            "intent": "agents_permissions_count",
            "narrative": "\n".join([line for line in narrative if line]),
            "data": {"summary": summary_access, "rows": rows},
        }

    if any(token in q for token in ["quais", "liste", "listar", "mostre"]) and any(
        token in q for token in ["permiss", "acesso"]
    ):
        rows_with_access = [row for row in rows if _has_identified_access(row)]
        rows_with_access = [row for row in rows_with_access if str(row.get("objectClassification")) != "Agent Identity Blueprint"]
        display_rows = rows_with_access[:display_count]
        if not display_rows and rows_with_access:
            display_rows = rows_with_access[:1]
        if not display_rows:
            heuristic_inventory = _is_heuristic_inventory(source_mode, str(agent_id_api_status))
            narrative = [
                "AGENT IDENTITY SECURITY ASSESSMENT",
                "",
                "Executive Summary",
                "────────────────────────────────────",
                "",
                _inventory_sentence(len(rows)),
                (
                    "O inventário atual é heurístico, pois a API dedicada de Agent Identity ainda não está integrada."
                    if heuristic_inventory
                    else "O inventário atual usa integração dedicada de Agent Identity."
                ),
                f"Inventory Mode: {'HEURISTIC' if heuristic_inventory else 'INTEGRATED'}",
                f"Agent ID API: {'NOT INTEGRATED' if str(agent_id_api_status) == 'NOT_INTEGRATED' else 'INTEGRATED'}",
                "",
                "Nenhum Agent com acesso identificado foi encontrado dentro da cobertura avaliada.",
                "",
                "Assessment Coverage:",
                f"- Azure RBAC: {_coverage_label(azure_status)}",
                f"- Microsoft Graph/API: {_coverage_label(graph_status)}",
                f"- Ownership: {_coverage_label(ownership_status)}",
                "",
                "Access Summary:",
                azure_access_line,
                graph_access_line,
                "",
                "Overall Assessment:",
                ("PARTIAL" if (graph_status != "PASS" or ownership_status != "PASS" or azure_status != "PASS") else "COMPLETE"),
            ]
            return {
                "intent": "agents_permissions_list",
                "narrative": "\n".join([line for line in narrative if line]),
                "data": {"summary": summary_access, "rows": []},
            }

        showing_hint = (
            f"Mostrando Top {len(display_rows)} por risco de {len(rows_with_access)} Agents com acesso identificado."
            if len(rows_with_access) > len(display_rows)
            else f"Mostrando {len(display_rows)} Agents com acesso identificado."
        )
        heuristic_inventory = _is_heuristic_inventory(source_mode, str(agent_id_api_status))
        overall_assessment = "PARTIAL" if (graph_status != "PASS" or ownership_status != "PASS" or azure_status != "PASS") else "COMPLETE"
        managed_count = class_summary["managed_identities"]
        first_party_count = class_summary["microsoft_first_party_identities"]
        blueprint_count = class_summary["agent_identity_blueprints"]
        heuristic_count = class_summary["heuristic_candidates"]
        confirmed_count = class_summary["confirmed_agent_identities"]
        top_agent = display_rows[0] if display_rows else None
        principal_finding = "Nenhum Agent com acesso identificado foi encontrado."
        principal_risk = "NOT_EVALUATED"
        if top_agent:
            assignment = (top_agent.get("azureRoleAssignments") or [{}])[0]
            role = assignment.get("role") or "N/A"
            scope_name = assignment.get("resource") or assignment.get("resourceGroup") or assignment.get("assignmentScope") or "N/A"
            scope_type = assignment.get("resourceType") or assignment.get("scopeType") or "scope"
            principal_finding = (
                f"{top_agent.get('name') or 'N/A'} possui acesso {role} em {scope_type} {scope_name}."
            )
            principal_risk = str(top_agent.get("azureRbacRisk") or top_agent.get("overallRisk") or "NOT_EVALUATED").upper()
        narrative = [
            "AGENT IDENTITY SECURITY ASSESSMENT",
            "",
            "Executive Summary",
            "────────────────────────────────────",
            "",
            _inventory_sentence(len(rows)),
            (
                "O inventário atual é heurístico, pois a API dedicada de Agent Identity ainda não está integrada."
                if heuristic_inventory
                else "O inventário atual usa integração dedicada de Agent Identity."
            ),
            f"Inventory Mode: {'HEURISTIC' if heuristic_inventory else 'INTEGRATED'}",
            f"Agent ID API: {'NOT INTEGRATED' if str(agent_id_api_status) == 'NOT_INTEGRATED' else 'INTEGRATED'}",
            "",
            "Dos objetos avaliados:",
            "",
            (
                f"- {blueprint_count} é Agent Identity Blueprint"
                if blueprint_count == 1
                else f"- {blueprint_count} são Agent Identity Blueprints"
            ),
            (
                f"- {managed_count} é Managed Identity"
                if managed_count == 1
                else f"- {managed_count} são Managed Identities"
            ),
            (
                f"- {first_party_count} é identidade Microsoft/First-party"
                if first_party_count == 1
                else f"- {first_party_count} são identidades Microsoft/First-party"
            ),
            (
                f"- {heuristic_count} é candidato heurístico ainda não classificado"
                if heuristic_count == 1
                else f"- {heuristic_count} são candidatos heurísticos ainda não classificados"
            ),
            (
                f"- {confirmed_count} Agent Identity foi confirmada por API dedicada"
                if confirmed_count == 1
                else f"- {confirmed_count} Agent Identities foram confirmadas por API dedicada"
            ),
            "",
            "Assessment Coverage",
            "Azure RBAC foi avaliado." if azure_status == "PASS" else "Azure RBAC não foi avaliado.",
            "Microsoft Graph/API permissions foi avaliado." if graph_status == "PASS" else "Microsoft Graph/API permissions não foi avaliado.",
            "Ownership foi avaliado." if ownership_status == "PASS" else "Ownership não foi avaliado.",
            "",
            (
                "1 identidade possui acesso Azure RBAC identificado."
                if summary_access["azure_rbac"] == 1
                else f"{summary_access['azure_rbac']} identidades possuem acesso Azure RBAC identificado."
            ),
            "",
            showing_hint,
            (
                "Para mostrar mais resultados, peça: `mostrar mais agents com permissão`."
                if len(rows_with_access) > len(display_rows)
                else ""
            ),
            "",
            "Identidades com acesso identificado",
            _format_agents_with_access_blocks(display_rows, limit=len(display_rows)),
            "",
            "Overall Assessment:",
            overall_assessment,
            "",
            "Principal Finding:",
            principal_finding,
            "",
            "Risk:",
            principal_risk,
            "",
            *(
                [
                    "DETALHES TÉCNICOS",
                    _format_agent_technical_details(display_rows, limit=len(display_rows)),
                    "",
                ]
                if wants_more
                else []
            ),
            f"API de Agent ID: {_friendly_status(display_rows[0].get('agentIdApiStatus') if display_rows else 'NOT_INTEGRATED')}.",
            f"Fonte: {source_mode}.",
            (source_note if source_note else ""),
        ]
        return {
            "intent": "agents_permissions_list",
            "narrative": "\n".join([line for line in narrative if line]),
            "data": {"summary": summary_access, "rows": rows},
        }

    heuristic_inventory = _is_heuristic_inventory(source_mode, str(agent_id_api_status))
    overall_assessment = "PARTIAL" if (graph_status != "PASS" or ownership_status != "PASS" or azure_status != "PASS") else "COMPLETE"
    managed_count = class_summary["managed_identities"]
    first_party_count = class_summary["microsoft_first_party_identities"]
    blueprint_count = class_summary["agent_identity_blueprints"]
    heuristic_count = class_summary["heuristic_candidates"]
    confirmed_count = class_summary["confirmed_agent_identities"]
    narrative = [
        "AGENT IDENTITY SECURITY ASSESSMENT",
        "",
        "Executive Summary",
        "────────────────────────────────────",
        "",
        _inventory_sentence(len(rows)),
        (
            "O inventário atual é heurístico, pois a API dedicada de Agent Identity ainda não está integrada."
            if heuristic_inventory
            else "O inventário atual usa integração dedicada de Agent Identity."
        ),
        f"Inventory Mode: {'HEURISTIC' if heuristic_inventory else 'INTEGRATED'}",
        f"Agent ID API: {'NOT INTEGRATED' if str(agent_id_api_status) == 'NOT_INTEGRATED' else 'INTEGRATED'}",
        "",
        "Dos objetos avaliados:",
        "",
        (
            f"- {blueprint_count} é Agent Identity Blueprint"
            if blueprint_count == 1
            else f"- {blueprint_count} são Agent Identity Blueprints"
        ),
        (
            f"- {managed_count} é Managed Identity"
            if managed_count == 1
            else f"- {managed_count} são Managed Identities"
        ),
        (
            f"- {first_party_count} é identidade Microsoft/First-party"
            if first_party_count == 1
            else f"- {first_party_count} são identidades Microsoft/First-party"
        ),
        (
            f"- {heuristic_count} é candidato heurístico ainda não classificado"
            if heuristic_count == 1
            else f"- {heuristic_count} são candidatos heurísticos ainda não classificados"
        ),
        (
            f"- {confirmed_count} Agent Identity foi confirmada por API dedicada"
            if confirmed_count == 1
            else f"- {confirmed_count} Agent Identities foram confirmadas por API dedicada"
        ),
        "",
        "Assessment Coverage:",
        f"- Azure RBAC: {_coverage_label(azure_status)}",
        f"- Microsoft Graph/API: {_coverage_label(graph_status)}",
        f"- Ownership: {_coverage_label(ownership_status)}",
        "",
        "Access Summary:",
        f"- Agents com acesso identificado: {summary_access['any_access']}",
        f"- Agents sem acesso identificado: {summary_access['no_access']}",
        (
            "1 identidade possui acesso Azure RBAC identificado."
            if summary_access["azure_rbac"] == 1
            else f"{summary_access['azure_rbac']} identidades possuem acesso Azure RBAC identificado."
        ),
        "",
        "Distribuição de risco:",
        f"- Critical: {summary.get('Critical', 0)}",
        f"- High: {summary.get('High', 0)}",
        f"- Medium: {summary.get('Medium', 0)}",
        f"- Low: {summary.get('Low', 0)}",
        "",
        "Overall Assessment:",
        overall_assessment,
        "",
        "Agents (amostra):",
        _format_agent_lines(assessable_rows, limit=limit),
        "",
        "Observação: ownership indica responsabilidade, não concessão automática das permissões do Agent ao usuário.",
    ]
    return {
        "intent": "agent_inventory",
        "narrative": "\n".join(narrative),
        "data": {"count": len(rows), "rows": rows},
    }


def safe_list_agents() -> dict[str, Any]:
    return safe_collect("agent-identities-inventory", lambda: list_agents(status="all", limit=500))
