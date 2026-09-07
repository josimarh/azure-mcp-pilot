from __future__ import annotations

from typing import Any

from services.azure_roles import PRIVILEGED_AZURE_ROLES
from services.azure_role_definitions import RESOLUTION_UNRESOLVED, resolve_role, role_guid
from services.iam_common import is_mock_mode, load_mock_iam, resource_graph_query, sanitize_assignment
from services.role_risk import role_risk_score


def _live_role_definitions_map() -> dict[str, str]:
    from services.azure_role_definitions import role_definitions_map

    return {guid: str(data.get("roleName") or "") for guid, data in role_definitions_map().items()}


def list_role_assignments() -> list[dict[str, Any]]:
    if is_mock_mode():
        rows: list[dict[str, Any]] = []
        for item in load_mock_iam().get("azure_role_assignments", []):
            role_name = item.get("role") or item.get("roleName")
            rows.append(
                {
                    "principalId": item.get("principalId"),
                    "principalType": item.get("principalType"),
                    "role": role_name,
                    "roleName": role_name,
                    "roleGuid": role_guid(item.get("roleDefinitionId")),
                    "roleType": item.get("roleType"),
                    "roleDefinitionId": item.get("roleDefinitionId"),
                    "roleResolution": "MockData",
                    "scope": item.get("scope"),
                    "assignmentType": item.get("assignmentType", "Direct"),
                    "inherited": item.get("inherited", False),
                    "subscription": item.get("subscription"),
                    "resourceGroup": item.get("resourceGroup"),
                    "resource": item.get("resource"),
                    "origin": item.get("origin") or "Azure RBAC",
                }
            )
        return rows

    rows = resource_graph_query(
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/roleassignments' "
        "| extend principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), "
        "roleDefinitionId=tolower(tostring(properties.roleDefinitionId)), scope=tostring(properties.scope) "
        "| project id, principalId, principalType, roleDefinitionId, scope"
    )
    output: list[dict[str, Any]] = []
    for item in rows:
        scope = str(item.get("scope") or "")
        role_definition_id = item.get("roleDefinitionId")
        resolved = resolve_role(role_definition_id)
        role_name = resolved.get("roleName")
        output.append(
            {
                "assignmentId": item.get("id"),
                "principalId": item.get("principalId"),
                "principalType": item.get("principalType"),
                "role": role_name or role_definition_id,
                "roleName": role_name,
                "roleGuid": resolved.get("roleGuid"),
                "roleType": resolved.get("roleType"),
                "roleDefinitionId": role_definition_id,
                "roleResolution": resolved.get("resolution"),
                "scope": scope,
                "assignmentType": "Direct",
                "inherited": False,
                "subscription": _extract_scope_name(scope, "subscriptions"),
                "resourceGroup": _extract_scope_name(scope, "resourceGroups"),
                "resource": scope.split("/")[-1] if "/providers/" in scope else None,
                "origin": "Azure RBAC",
            }
        )
    return output


def _extract_scope_name(scope: str, segment: str) -> str | None:
    parts = scope.split("/")
    for idx, part in enumerate(parts):
        if part == segment and idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def list_privileged_role_assignments() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in list_role_assignments():
        role = item.get("roleName") or item.get("role")
        if role not in PRIVILEGED_AZURE_ROLES:
            continue
        risk = role_risk_score(str(role), "Azure", scope=item.get("scope"))
        row = dict(item)
        row["risk"] = risk["level"]
        row["riskScore"] = risk["score"]
        row["riskSource"] = risk["source"]
        rows.append(row)
    return rows


def unresolved_role_assignments() -> list[dict[str, Any]]:
    """Assignments cujo nome de role não pôde ser resolvido.

    Existe para evitar falso zero: sem resolução não é possível afirmar que a
    role não é privilegiada.
    """
    return [
        item
        for item in list_role_assignments()
        if item.get("roleResolution") == RESOLUTION_UNRESOLVED or not item.get("roleName")
    ]


def list_deny_assignments() -> list[dict[str, Any]]:
    if is_mock_mode():
        return list(load_mock_iam().get("deny_assignments", []))
    return resource_graph_query(
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/denyassignments' "
        "| project id, scope=tostring(properties.scope), displayName=tostring(properties.denyAssignmentName)"
    )


def present_assignments(rows: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    return [sanitize_assignment(item) for item in rows[: max(1, limit)]]
