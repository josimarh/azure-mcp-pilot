from __future__ import annotations

import unicodedata
from collections import Counter, defaultdict
from typing import Any, Callable

from services.azure_rbac import list_privileged_role_assignments
from services.entra_roles import list_privileged_directory_role_members
from services.entra_users import list_users
from services.entra_workload_identities import list_managed_identities, list_service_principals
from services.iam_common import graph_list, is_mock_mode, load_mock_iam, resource_graph_query, safe_collect, sanitize_assignment
from services.role_risk import role_risk_score


def _normalize(text: str) -> str:
    norm = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in norm if not unicodedata.combining(ch)).lower()


def _identity_map() -> dict[str, dict[str, Any]]:
    identities: dict[str, dict[str, Any]] = {}
    for user in list_users():
        user_id = user.get("id")
        if not user_id:
            continue
        identities[str(user_id)] = {
            "name": user.get("displayName"),
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
            "mail": user.get("mail") or user.get("userPrincipalName"),
            "objectId": user_id,
            "identityType": "User",
        }
    for sp in list_service_principals():
        sp_id = sp.get("id")
        if not sp_id:
            continue
        identities.setdefault(
            str(sp_id),
            {
                "name": sp.get("displayName"),
                "displayName": sp.get("displayName"),
                "objectId": sp_id,
                "identityType": "ServicePrincipal",
            },
        )
    for mi in list_managed_identities():
        mi_id = mi.get("id")
        if not mi_id:
            continue
        identities.setdefault(
            str(mi_id),
            {
                "name": mi.get("displayName"),
                "displayName": mi.get("displayName"),
                "objectId": mi_id,
                "identityType": "ManagedIdentity",
            },
        )
    return identities


def _resolve_identity(principal_id: str | None, principal_type: str | None, identities: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if principal_id and str(principal_id) in identities:
        return identities[str(principal_id)]
    return {
        "name": principal_id,
        "displayName": principal_id,
        "userPrincipalName": None,
        "mail": None,
        "objectId": principal_id,
        "identityType": principal_type or "Unknown",
    }


def _provider_label(provider: str | None) -> str:
    if str(provider).lower() == "entra":
        return "Entra ID PIM"
    return "Azure PIM RBAC"


def _scope_level(scope: str | None) -> str:
    if not scope or scope == "/":
        return "Tenant"
    lower = scope.lower()
    if "/providers/microsoft.management/managementgroups/" in lower:
        return "Management Group"
    if "/resourcegroups/" in lower:
        return "Resource Group"
    if "/providers/" in lower:
        return "Resource"
    if "/subscriptions/" in lower:
        return "Subscription"
    return "Unknown"


def _mock_pim_assignments() -> list[dict[str, Any]]:
    rows = list(load_mock_iam().get("pim_assignments", []))
    normalized: list[dict[str, Any]] = []
    for item in rows:
        row = dict(item)
        if not row.get("role") and row.get("roleName"):
            row["role"] = row.get("roleName")
        if not row.get("origin"):
            row["origin"] = "PIM"
        normalized.append(row)
    return normalized


def _entra_role_name_map() -> dict[str, str]:
    definitions = graph_list(
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName"
    )
    return {str(item.get("id")): str(item.get("displayName")) for item in definitions if item.get("id")}


def _entra_pim_schedule_rows(state: str) -> list[dict[str, Any]]:
    if state == "Eligible":
        url = (
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
            "?$select=id,principalId,roleDefinitionId,directoryScopeId"
        )
    else:
        url = (
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances"
            "?$select=id,principalId,roleDefinitionId,directoryScopeId"
        )
    role_map = _entra_role_name_map()
    rows = graph_list(url)
    output: list[dict[str, Any]] = []
    for item in rows:
        role_id = str(item.get("roleDefinitionId") or "")
        output.append(
            {
                "id": item.get("id"),
                "provider": "Entra",
                "principalId": item.get("principalId"),
                "principalType": "User",
                "role": role_map.get(role_id, role_id),
                "scope": item.get("directoryScopeId") or "/",
                "state": state,
                "assignmentType": state,
                "origin": "PIM",
            }
        )
    return output


def _azure_role_definition_map() -> dict[str, str]:
    from services.azure_role_definitions import role_definitions_map

    return {guid: str(data.get("roleName") or "") for guid, data in role_definitions_map().items()}


def _azure_pim_schedule_rows(state: str) -> list[dict[str, Any]]:
    """Mantido para compatibilidade. A cobertura vem de _azure_pim_source."""
    return _azure_pim_source(state)[0]


def _azure_pim_source(state: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from services.azure_pim import STATUS_EVALUATED, azure_pim_instances
    from services.azure_role_definitions import resolve_role

    result = azure_pim_instances(state)
    output: list[dict[str, Any]] = []
    for item in result["rows"]:
        role_id = str(item.get("roleDefinitionId") or "")
        resolved = resolve_role(role_id)
        output.append(
            {
                "id": item.get("id"),
                "provider": "Azure",
                "principalId": item.get("principalId"),
                "principalType": item.get("principalType"),
                "role": resolved.get("roleName") or role_id,
                "roleName": resolved.get("roleName"),
                "roleDefinitionId": role_id,
                "roleResolution": resolved.get("resolution"),
                "scope": item.get("scope"),
                "state": state,
                "assignmentType": state,
                "origin": "PIM",
            }
        )

    coverage: dict[str, Any] = {
        "source": f"Azure PIM ({state})",
        "status": STATUS_EVALUATED if result["status"] == STATUS_EVALUATED else "NOT_EVALUATED",
        "count": len(output),
    }
    if result.get("detail"):
        coverage["detail"] = result["detail"]
    if result.get("notEvaluatedSubscriptions"):
        coverage["notEvaluatedSubscriptions"] = result["notEvaluatedSubscriptions"]
        coverage["evaluatedSubscriptions"] = result.get("evaluatedSubscriptions")
    return output, coverage


def _collect_source(source: str, collector: Callable[[], list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Coleta uma fonte PIM sem deixar que a falha de uma invalide as demais."""
    try:
        rows = collector()
        return rows, {"source": source, "status": "EVALUATED", "count": len(rows)}
    except Exception as exc:
        detail = str(exc)
        status = "PERMISSION_DENIED" if ("403" in detail or "PermissionScopeNotGranted" in detail) else "ERROR"
        return [], {"source": source, "status": status, "count": 0, "detail": detail[:300]}


def list_pim_assignments_with_coverage() -> dict[str, Any]:
    """Atribuições PIM com cobertura declarada por fonte.

    Uma fonte inacessível vira `PERMISSION_DENIED`/`ERROR`, nunca zero silencioso.
    """
    if is_mock_mode():
        rows = _mock_pim_assignments()
        return {
            "rows": rows,
            "coverage": [{"source": "mock", "status": "EVALUATED", "count": len(rows)}],
        }

    rows: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []

    entra_sources: list[tuple[str, Callable[[], list[dict[str, Any]]]]] = [
        ("Entra PIM (Eligible)", lambda: _entra_pim_schedule_rows("Eligible")),
        ("Entra PIM (Active)", lambda: _entra_pim_schedule_rows("Active")),
    ]
    for source, collector in entra_sources:
        source_rows, status = _collect_source(source, collector)
        rows.extend(source_rows)
        coverage.append(status)

    # O caminho Azure ja devolve a propria cobertura, porque um retorno vazio
    # so pode ser afirmado como ausencia apos confirmacao na API autoritativa.
    for state in ("Eligible", "Active"):
        try:
            azure_rows, azure_coverage = _azure_pim_source(state)
        except Exception as exc:
            rows_out: list[dict[str, Any]] = []
            azure_rows, azure_coverage = rows_out, {
                "source": f"Azure PIM ({state})",
                "status": "ERROR",
                "count": 0,
                "detail": str(exc)[:300],
            }
        rows.extend(azure_rows)
        coverage.append(azure_coverage)

    return {"rows": rows, "coverage": coverage}


def pim_coverage() -> list[dict[str, Any]]:
    return list_pim_assignments_with_coverage()["coverage"]


def list_pim_assignments() -> list[dict[str, Any]]:
    return list_pim_assignments_with_coverage()["rows"]


def list_permanent_privileged_assignments() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in list_privileged_directory_role_members():
        rows.append(
            {
                "provider": "Entra",
                "principalId": item.get("principalId"),
                "principalType": item.get("identityType"),
                "role": item.get("role"),
                "scope": "/",
                "state": "Permanent",
                "assignmentType": "Permanent",
                "origin": "Direct role assignment",
            }
        )
    for item in list_privileged_role_assignments():
        rows.append(
            {
                "provider": "Azure",
                "principalId": item.get("principalId"),
                "principalType": item.get("principalType"),
                "role": item.get("role"),
                "scope": item.get("scope"),
                "state": "Permanent",
                "assignmentType": "Permanent",
                "origin": "Direct RBAC role assignment",
            }
        )
    return rows


def list_pim_role_states(include_permanent: bool = True) -> list[dict[str, Any]]:
    identities = _identity_map()
    rows = list_pim_assignments()
    if include_permanent:
        rows.extend(list_permanent_privileged_assignments())

    unique = {}
    for item in rows:
        key = (
            str(item.get("provider")),
            str(item.get("principalId")),
            str(item.get("role")),
            str(item.get("scope")),
            str(item.get("state")),
        )
        unique[key] = item
    output: list[dict[str, Any]] = []
    for item in unique.values():
        identity = _resolve_identity(item.get("principalId"), item.get("principalType"), identities)
        risk = role_risk_score(
            str(item.get("role")),
            str(item.get("provider")),
            scope=str(item.get("scope") or ""),
            state=str(item.get("state") or ""),
        )
        output.append(
            sanitize_assignment(
                {
                    "name": identity.get("name"),
                    "displayName": identity.get("displayName"),
                    "userPrincipalName": identity.get("userPrincipalName"),
                    "mail": identity.get("mail"),
                    "objectId": identity.get("objectId"),
                    "identityType": identity.get("identityType"),
                    "role": item.get("role"),
                    "scope": item.get("scope"),
                    "assignmentType": item.get("assignmentType"),
                    "origin": item.get("origin"),
                    "provider": item.get("provider"),
                    "state": item.get("state"),
                    "riskScore": risk["score"],
                    "risk": risk["level"],
                    "riskSource": risk["source"],
                    "inherited": False,
                }
            )
        )
    return output


def get_pim_state_summary(rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    data = rows or list_pim_role_states(include_permanent=True)
    by_state = Counter([str(item.get("state")) for item in data])
    users_by_state: dict[str, set[str]] = defaultdict(set)
    roles_by_state: dict[str, Counter[str]] = defaultdict(Counter)
    provider_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    azure_scope_levels = Counter()
    for item in data:
        state = str(item.get("state"))
        provider_label = _provider_label(str(item.get("provider")))
        provider_buckets[provider_label].append(item)
        if str(item.get("identityType", "")).lower() == "user" and item.get("objectId"):
            users_by_state[state].add(str(item.get("objectId")))
        role = item.get("role")
        if role:
            roles_by_state[state][str(role)] += 1
        if provider_label == "Azure PIM RBAC":
            azure_scope_levels[_scope_level(str(item.get("scope") or ""))] += 1

    by_provider: dict[str, dict[str, Any]] = {}
    for provider_label in ["Entra ID PIM", "Azure PIM RBAC"]:
        provider_rows = provider_buckets.get(provider_label, [])
        provider_states = Counter([str(item.get("state")) for item in provider_rows])
        provider_users_by_state: dict[str, set[str]] = defaultdict(set)
        provider_roles_by_state: dict[str, Counter[str]] = defaultdict(Counter)
        provider_scope_levels = Counter()
        for item in provider_rows:
            state = str(item.get("state"))
            if str(item.get("identityType", "")).lower() == "user" and item.get("objectId"):
                provider_users_by_state[state].add(str(item.get("objectId")))
            role = item.get("role")
            if role:
                provider_roles_by_state[state][str(role)] += 1
            if provider_label == "Azure PIM RBAC":
                provider_scope_levels[_scope_level(str(item.get("scope") or ""))] += 1
        by_provider[provider_label] = {
            "total_assignments": len(provider_rows),
            "states": dict(provider_states),
            "unique_users_by_state": {k: len(v) for k, v in provider_users_by_state.items()},
            "top_roles_by_state": {
                state: [{"role": role, "count": count} for role, count in counter.most_common(10)]
                for state, counter in provider_roles_by_state.items()
            },
        }
        if provider_label == "Azure PIM RBAC":
            by_provider[provider_label]["scope_levels"] = dict(provider_scope_levels)

    return {
        "total_assignments": len(data),
        "states": dict(by_state),
        "unique_users_by_state": {k: len(v) for k, v in users_by_state.items()},
        "azure_scope_levels": dict(azure_scope_levels),
        "by_provider": by_provider,
        "top_roles_by_state": {
            state: [{"role": role, "count": count} for role, count in counter.most_common(10)]
            for state, counter in roles_by_state.items()
        },
    }


def _filter_rows(
    rows: list[dict[str, Any]],
    states: set[str] | None = None,
    role_keywords: list[str] | None = None,
    identity_type: str | None = None,
) -> list[dict[str, Any]]:
    out = rows
    if states:
        out = [r for r in out if str(r.get("state")) in states]
    if role_keywords:
        lowered = [k.lower() for k in role_keywords]
        out = [
            r
            for r in out
            if any(k in str(r.get("role", "")).lower() for k in lowered)
        ]
    if identity_type:
        out = [r for r in out if str(r.get("identityType", "")).lower() == identity_type.lower()]
    return out


def _rows_to_narrative(rows: list[dict[str, Any]], title: str, limit: int = 20) -> str:
    lines = [f"{title}: **{len(rows)}**", ""]
    rows_by_provider: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in rows:
        rows_by_provider[_provider_label(str(item.get("provider")))].append(item)

    for provider_label in ["Entra ID PIM", "Azure PIM RBAC"]:
        provider_rows = rows_by_provider.get(provider_label, [])
        lines.append(f"{provider_label}: **{len(provider_rows)}**")
        if provider_label == "Azure PIM RBAC":
            scope_levels = Counter(
                [_scope_level(str(item.get("scope") or "")) for item in provider_rows]
            )
            if scope_levels:
                lines.append(
                    "Escopos Azure: "
                    + ", ".join([f"{level}: {count}" for level, count in scope_levels.items()])
                )
        if not provider_rows:
            lines.append("- Nenhum resultado.")
            lines.append("")
            continue
        for item in provider_rows[: max(1, limit)]:
            score_text = ""
            if item.get("riskScore") is not None:
                score_text = f" ({item.get('riskScore')}/100)"
            lines.append(
                "- "
                f"{item.get('displayName') or item.get('name') or 'N/A'} | "
                f"Tipo: {item.get('identityType') or 'N/A'} | "
                f"UPN: {item.get('userPrincipalName') or 'N/A'} | "
                f"E-mail: {item.get('mail') or 'N/A'} | "
                f"Role: {item.get('role') or 'N/A'} | "
                f"Estado: {item.get('state') or 'N/A'} | "
                f"Escopo: {item.get('scope') or 'N/A'} ({_scope_level(str(item.get('scope') or ''))}) | "
                f"Assignment: {item.get('assignmentType') or 'N/A'} | "
                f"Origem: {item.get('origin') or 'N/A'} | "
                f"Risco: {item.get('risk') or 'N/A'}"
                f"{score_text}"
            )
        lines.append("")
    return "\n".join(lines)


def answer_pim_question(question: str, limit: int = 20) -> dict[str, Any]:
    q = _normalize(question)
    rows = list_pim_role_states(include_permanent=True)

    states: set[str] | None = None
    if "eligible" in q or "elegivel" in q or "elegive" in q:
        states = {"Eligible"}
    if "ativa" in q or "ativo" in q or "ativas" in q or "ativos" in q:
        states = {"Active"}
    if "permanente" in q or "permanent" in q:
        states = {"Permanent"}

    role_keywords: list[str] = []
    for role_term in [
        "global administrator",
        "privileged role administrator",
        "user access administrator",
        "owner",
        "contributor",
    ]:
        if role_term in q:
            role_keywords.append(role_term)

    identity_type = "User" if "usuario" in q else None
    filtered = _filter_rows(rows, states=states, role_keywords=role_keywords or None, identity_type=identity_type)

    if "compare" in q or "vs" in q:
        summary = get_pim_state_summary(rows)
        lines = [
            "Comparativo Active vs Eligible vs Permanent:",
            f"- Assignments totais: **{summary.get('total_assignments', 0)}**",
        ]
        for state in ["Active", "Eligible", "Permanent"]:
            lines.append(f"- {state}: {summary.get('states', {}).get(state, 0)} assignments")
            lines.append(f"  - Usuários: {summary.get('unique_users_by_state', {}).get(state, 0)}")
        lines.append("")
        for provider_label in ["Entra ID PIM", "Azure PIM RBAC"]:
            provider = summary.get("by_provider", {}).get(provider_label, {})
            lines.append(f"{provider_label}:")
            lines.append(f"- Assignments: **{provider.get('total_assignments', 0)}**")
            for state in ["Active", "Eligible", "Permanent"]:
                lines.append(
                    f"  - {state}: {provider.get('states', {}).get(state, 0)}"
                    f" | Usuários: {provider.get('unique_users_by_state', {}).get(state, 0)}"
                )
            if provider_label == "Azure PIM RBAC":
                scope_levels = provider.get("scope_levels", {})
                if scope_levels:
                    lines.append(
                        "- Escopos Azure: "
                        + ", ".join([f"{k}: {v}" for k, v in scope_levels.items()])
                    )
            lines.append("")
        return {"intent": "pim_compare_states", "narrative": "\n".join(lines), "data": summary}

    if "mais de uma" in q and "eligible" in q:
        by_user: dict[str, set[str]] = defaultdict(set)
        for item in _filter_rows(rows, states={"Eligible"}, identity_type="User"):
            if item.get("objectId") and item.get("role"):
                by_user[str(item["objectId"])].add(str(item["role"]))
        multi_ids = {uid for uid, roles in by_user.items() if len(roles) > 1}
        filtered = [item for item in rows if str(item.get("objectId")) in multi_ids and item.get("state") == "Eligible"]
    elif "mais de uma" in q and ("ativa" in q or "ativo" in q):
        by_user = defaultdict(set)
        for item in _filter_rows(rows, states={"Active"}, identity_type="User"):
            if item.get("objectId") and item.get("role"):
                by_user[str(item["objectId"])].add(str(item["role"]))
        multi_ids = {uid for uid, roles in by_user.items() if len(roles) > 1}
        filtered = [item for item in rows if str(item.get("objectId")) in multi_ids and item.get("state") == "Active"]

    if "quant" in q and "identidade" in q and ("ativa" in q or "ativo" in q):
        unique = {str(item.get("objectId")) for item in _filter_rows(rows, states={"Active"}) if item.get("objectId")}
        narrative = f"Identidades com privilégio ativo agora: **{len(unique)}**."
        return {"intent": "pim_active_identity_count", "narrative": narrative, "data": {"count": len(unique)}}

    if "quant" in q and "usuario" in q and ("eligible" in q or "elegivel" in q):
        unique = {str(item.get("objectId")) for item in _filter_rows(rows, states={"Eligible"}, identity_type="User") if item.get("objectId")}
        return {
            "intent": "pim_eligible_users_count",
            "narrative": f"Usuários com roles elegíveis: **{len(unique)}**.",
            "data": {"count": len(unique)},
        }
    if "quant" in q and "usuario" in q and ("ativa" in q or "ativo" in q):
        unique = {str(item.get("objectId")) for item in _filter_rows(rows, states={"Active"}, identity_type="User") if item.get("objectId")}
        return {
            "intent": "pim_active_users_count",
            "narrative": f"Usuários com roles ativas: **{len(unique)}**.",
            "data": {"count": len(unique)},
        }

    if "roles de um" in q or "todas as roles de" in q:
        tokens = question.split()
        name_token = tokens[-1].strip().lower()
        filtered = [
            item
            for item in rows
            if name_token in str(item.get("displayName", "")).lower()
            or name_token in str(item.get("userPrincipalName", "")).lower()
        ]

    if "active + permanent" in q or "active e permanent" in q:
        score = defaultdict(int)
        by_identity: dict[str, dict[str, Any]] = {}
        for item in rows:
            obj_id = item.get("objectId")
            if not obj_id:
                continue
            by_identity[str(obj_id)] = item
            if item.get("state") == "Active":
                score[str(obj_id)] += 2
            if item.get("state") == "Permanent":
                score[str(obj_id)] += 3
        top_ids = sorted(score, key=lambda k: score[k], reverse=True)[: max(1, limit)]
        filtered = [by_identity[i] for i in top_ids if i in by_identity]

    title = "Resultados de PIM"
    if states == {"Eligible"}:
        title = "Atribuições PIM elegíveis"
    elif states == {"Active"}:
        title = "Atribuições PIM ativas"
    elif states == {"Permanent"}:
        title = "Atribuições permanentes privilegiadas"
    narrative = _rows_to_narrative(filtered, title=title, limit=limit)

    summary = get_pim_state_summary(rows)
    return {
        "intent": "pim_natural_query",
        "narrative": narrative,
        "data": {"summary": summary, "count": len(filtered), "rows": filtered[: max(1, limit)]},
    }


def safe_list_pim_assignments() -> dict[str, Any]:
    return safe_collect("pim-assignments-all-states", lambda: list_pim_role_states(include_permanent=True))
