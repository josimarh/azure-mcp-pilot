from __future__ import annotations

from typing import Any

from services.azure_roles import PRIVILEGED_AZURE_ROLES
from services.iam_common import is_mock_mode, load_mock_iam, resource_graph_query, sanitize_assignment
from services.role_risk import role_risk_score


def _live_role_definitions_map() -> dict[str, str]:
    rows = resource_graph_query(
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/roledefinitions' "
        "| project roleDefinitionId=tolower(id), roleName=tostring(properties.roleName)"
    )
    return {
        str(item.get("roleDefinitionId", "")).lower(): str(item.get("roleName", ""))
        for item in rows
        if item.get("roleDefinitionId")
    }


def list_role_assignments() -> list[dict[str, Any]]:
    if is_mock_mode():
        rows: list[dict[str, Any]] = []
        for item in load_mock_iam().get("azure_role_assignments", []):
            rows.append(
                {
                    "principalId": item.get("principalId"),
                    "principalType": item.get("principalType"),
                    "role": item.get("role") or item.get("roleName"),
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

    roles_map = _live_role_definitions_map()
    rows = resource_graph_query(
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/roleassignments' "
        "| extend principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), "
        "roleDefinitionId=tolower(tostring(properties.roleDefinitionId)), scope=tostring(properties.scope) "
        "| project principalId, principalType, roleDefinitionId, scope"
    )
    output: list[dict[str, Any]] = []
    for item in rows:
        scope = str(item.get("scope") or "")
        output.append(
            {
                "principalId": item.get("principalId"),
                "principalType": item.get("principalType"),
                "role": roles_map.get(str(item.get("roleDefinitionId", "")).lower())
                or item.get("roleDefinitionId"),
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
        role = item.get("role")
        if role not in PRIVILEGED_AZURE_ROLES:
            continue
        risk = role_risk_score(str(role), "Azure", scope=item.get("scope"))
        row = dict(item)
        row["risk"] = risk["level"]
        row["riskScore"] = risk["score"]
        row["riskSource"] = risk["source"]
        rows.append(row)
    return rows


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
