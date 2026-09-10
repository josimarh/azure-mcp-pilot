"""Normalização e correlação de objetos de identidade.

Objetivo: transformar respostas heterogêneas (Microsoft Graph, Azure Resource
Graph, Azure Management) em um formato comum, e permitir correlacionar a mesma
identidade entre domínios diferentes sem misturar as fontes.
"""

from __future__ import annotations

from typing import Any, Iterable

from services.azure_graph import sanitize_enabled
from services.graph_capabilities import (
    SOURCE_AZURE_AUTHORIZATION,
    SOURCE_AZURE_MANAGEMENT,
    SOURCE_GRAPH,
    SOURCE_RESOURCE_GRAPH,
    Capability,
)
from services.iam_common import mask, sanitize_assignment, sanitize_scope

# Tipos normalizados de principal
PRINCIPAL_USER = "User"
PRINCIPAL_GROUP = "Group"
PRINCIPAL_SERVICE_PRINCIPAL = "ServicePrincipal"
PRINCIPAL_MANAGED_IDENTITY = "ManagedIdentity"
PRINCIPAL_APPLICATION = "Application"
PRINCIPAL_DEVICE = "Device"
PRINCIPAL_UNKNOWN = "Unknown"

_ODATA_TYPE_MAP = {
    "#microsoft.graph.user": PRINCIPAL_USER,
    "#microsoft.graph.group": PRINCIPAL_GROUP,
    "#microsoft.graph.serviceprincipal": PRINCIPAL_SERVICE_PRINCIPAL,
    "#microsoft.graph.application": PRINCIPAL_APPLICATION,
    "#microsoft.graph.device": PRINCIPAL_DEVICE,
}

_DOMAIN_DEFAULT_TYPE = {
    "users": PRINCIPAL_USER,
    "external_identities": PRINCIPAL_USER,
    "groups": PRINCIPAL_GROUP,
    "service_principals": PRINCIPAL_SERVICE_PRINCIPAL,
    "workload_identities": PRINCIPAL_SERVICE_PRINCIPAL,
    "applications": PRINCIPAL_APPLICATION,
    "devices": PRINCIPAL_DEVICE,
}

# Domínios cujos objetos NÃO são principals; rotulá-los como identidade seria incorreto.
_NON_PRINCIPAL_DOMAIN_TYPE = {
    "directory_roles": "DirectoryRole",
    "role_management": "RoleDefinition",
    "pim": "RoleScheduleInstance",
    "azure_pim": "RoleScheduleInstance",
    "azure_rbac": "RoleAssignment",
    "conditional_access": "Policy",
    "azure_subscriptions": "Subscription",
    "azure_management_groups": "ManagementGroup",
    "azure_resources": "AzureResource",
    "administrative_units": "AdministrativeUnit",
    "access_reviews": "AccessReview",
    "entitlement_management": "AccessPackage",
    "lifecycle_workflows": "Workflow",
    "audit_logs": "AuditEvent",
    "sign_ins": "SignInEvent",
    "oauth2_permission_grants": "PermissionGrant",
    "app_role_assignments": "AppRoleAssignment",
    "authentication": "AuthenticationRegistration",
    "organization": "Tenant",
}


def _principal_type(row: dict[str, Any], cap: Capability) -> str:
    odata = str(row.get("@odata.type") or "").strip().lower()
    if odata in _ODATA_TYPE_MAP:
        return _ODATA_TYPE_MAP[odata]

    sp_type = str(row.get("servicePrincipalType") or "").strip()
    if sp_type:
        return PRINCIPAL_MANAGED_IDENTITY if sp_type.lower() == "managedidentity" else PRINCIPAL_SERVICE_PRINCIPAL

    declared = str(row.get("principalType") or "").strip()
    if declared:
        lowered = declared.lower()
        if lowered == "user":
            return PRINCIPAL_USER
        if lowered == "group":
            return PRINCIPAL_GROUP
        if lowered == "serviceprincipal":
            return PRINCIPAL_SERVICE_PRINCIPAL
        return declared

    if row.get("userType"):
        return PRINCIPAL_USER

    if cap.domain in _NON_PRINCIPAL_DOMAIN_TYPE:
        return _NON_PRINCIPAL_DOMAIN_TYPE[cap.domain]

    return _DOMAIN_DEFAULT_TYPE.get(cap.domain, PRINCIPAL_UNKNOWN)


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", []):
            return value
    return None


def _sanitize_normalized(normalized: dict[str, Any]) -> dict[str, Any]:
    """Mascara identificadores no objeto normalizado quando SANITIZE_FOR_LLM=true.

    A normalização copia id/userPrincipalName/mail/scope do row bruto para o
    nível superior do objeto retornado ao modelo; sem isso, esses campos
    escapavam da sanitização mesmo quando ``raw`` já estava mascarado.
    """
    if not sanitize_enabled():
        return normalized
    out = dict(normalized)
    if out.get("id"):
        out["id"] = mask(str(out["id"]), "obj")
    if out.get("userPrincipalName"):
        out["userPrincipalName"] = mask(str(out["userPrincipalName"]), "upn")
    if out.get("mail"):
        out["mail"] = mask(str(out["mail"]), "mail")
    if out.get("scope"):
        out["scope"] = sanitize_scope(str(out["scope"]))
    return out


def normalize_row(row: dict[str, Any], cap: Capability) -> dict[str, Any]:
    """Converte um item bruto em um objeto de identidade normalizado."""
    if not isinstance(row, dict):
        return {
            "id": None,
            "displayName": str(row),
            "principalType": PRINCIPAL_UNKNOWN,
            "source": cap.source,
            "domain": cap.domain,
            "raw": row,
        }

    identifier = _first(row, "id", "objectId", "principalId", "subscriptionId", "name")
    display = _first(
        row,
        "displayName",
        "principalDisplayName",
        "userPrincipalName",
        "name",
        "activityDisplayName",
    )

    normalized: dict[str, Any] = {
        "id": str(identifier) if identifier is not None else None,
        "displayName": str(display) if display is not None else None,
        "principalType": _principal_type(row, cap),
        "source": cap.source,
        "domain": cap.domain,
        "capability_id": cap.id,
    }

    upn = _first(row, "userPrincipalName")
    if upn:
        normalized["userPrincipalName"] = str(upn)

    mail = _first(row, "mail")
    if mail:
        normalized["mail"] = str(mail)

    app_id = _first(row, "appId")
    if app_id:
        normalized["appId"] = str(app_id)

    if "accountEnabled" in row:
        normalized["accountEnabled"] = bool(row.get("accountEnabled"))

    if "userType" in row and row.get("userType"):
        normalized["userType"] = str(row.get("userType"))

    scope = _first(row, "scope", "directoryScopeId")
    if scope:
        normalized["scope"] = str(scope)

    role_definition = _first(row, "roleDefinitionId")
    if role_definition:
        normalized["roleDefinitionId"] = str(role_definition)

    for time_field in ("startDateTime", "endDateTime", "createdDateTime", "activityDateTime"):
        if row.get(time_field):
            normalized[time_field] = str(row.get(time_field))

    for extra in ("assignmentType", "memberType", "state", "riskLevel", "riskState", "consentType", "scope"):
        if extra in row and row.get(extra) not in (None, ""):
            normalized.setdefault(extra, row.get(extra))

    normalized["raw"] = sanitize_assignment(dict(row))
    return _sanitize_normalized(normalized)


def normalize_rows(rows: Iterable[dict[str, Any]], cap: Capability) -> list[dict[str, Any]]:
    return [normalize_row(row, cap) for row in rows or []]


# --------------------------------------------------------------------------
# Correlação entre domínios
# --------------------------------------------------------------------------


def _correlation_keys(item: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    for field_name in ("id", "appId", "userPrincipalName", "mail"):
        value = item.get(field_name)
        if value:
            keys.append(str(value).strip().lower())
    return keys


def correlate_identities(*result_sets: dict[str, Any]) -> dict[str, Any]:
    """Correlaciona resultados normalizados de capacidades diferentes.

    Mantém a origem de cada evidência para que Microsoft Graph e Azure RBAC
    não sejam apresentados como se fossem a mesma fonte.
    """
    index: dict[str, dict[str, Any]] = {}
    alias: dict[str, str] = {}
    sources_used: set[str] = set()
    domains_used: set[str] = set()

    for result in result_sets:
        if not isinstance(result, dict) or not result.get("ok"):
            continue
        source = str(result.get("source") or "unknown")
        domain = str(result.get("domain") or "unknown")
        capability_id = str(result.get("capability_id") or "unknown")
        sources_used.add(source)
        domains_used.add(domain)

        for item in result.get("items", []) or []:
            keys = _correlation_keys(item)
            if not keys:
                continue

            anchor = next((alias[k] for k in keys if k in alias), keys[0])
            for key in keys:
                alias[key] = anchor

            bucket = index.setdefault(
                anchor,
                {
                    "identity": {
                        "id": item.get("id"),
                        "displayName": item.get("displayName"),
                        "principalType": item.get("principalType"),
                        "userPrincipalName": item.get("userPrincipalName"),
                        "mail": item.get("mail"),
                        "appId": item.get("appId"),
                    },
                    "evidence": [],
                    "domains": [],
                    "sources": [],
                },
            )

            identity = bucket["identity"]
            for field_name in ("displayName", "userPrincipalName", "mail", "appId"):
                if not identity.get(field_name) and item.get(field_name):
                    identity[field_name] = item.get(field_name)
            if identity.get("principalType") in (None, PRINCIPAL_UNKNOWN) and item.get("principalType"):
                identity["principalType"] = item.get("principalType")

            bucket["evidence"].append(
                {
                    "domain": domain,
                    "source": source,
                    "capability_id": capability_id,
                    "scope": item.get("scope"),
                    "roleDefinitionId": item.get("roleDefinitionId"),
                    "assignmentType": item.get("assignmentType"),
                }
            )
            if domain not in bucket["domains"]:
                bucket["domains"].append(domain)
            if source not in bucket["sources"]:
                bucket["sources"].append(source)

    correlated = sorted(
        index.values(),
        key=lambda row: (-len(row["domains"]), str(row["identity"].get("displayName") or "")),
    )

    cross_source = [row for row in correlated if len(row["sources"]) > 1]

    return {
        "ok": True,
        "correlated_identities": len(correlated),
        "cross_source_identities": len(cross_source),
        "sources_used": sorted(sources_used),
        "domains_used": sorted(domains_used),
        "items": correlated,
        "note": (
            "Evidências mantêm a fonte original. Microsoft Graph descreve identidade/diretório; "
            "APIs Azure descrevem Azure RBAC e recursos."
        ),
    }


def summarize_result(result: dict[str, Any]) -> dict[str, Any]:
    """Resumo compacto por tipo de principal, útil para respostas executivas."""
    if not result.get("ok"):
        return result

    by_type: dict[str, int] = {}
    enabled = 0
    disabled = 0
    for item in result.get("items", []) or []:
        ptype = str(item.get("principalType") or PRINCIPAL_UNKNOWN)
        by_type[ptype] = by_type.get(ptype, 0) + 1
        if item.get("accountEnabled") is True:
            enabled += 1
        elif item.get("accountEnabled") is False:
            disabled += 1

    return {
        "capability_id": result.get("capability_id"),
        "domain": result.get("domain"),
        "source": result.get("source"),
        "count": result.get("count"),
        "truncated": result.get("truncated"),
        "by_principal_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "accounts_enabled": enabled,
        "accounts_disabled": disabled,
    }
