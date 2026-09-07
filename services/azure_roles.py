from __future__ import annotations

from typing import Any

from services.iam_common import is_mock_mode, load_mock_iam, resource_graph_query

PRIVILEGED_AZURE_ROLES = {"Owner", "User Access Administrator", "Contributor"}


def list_role_definitions() -> list[dict[str, Any]]:
    if is_mock_mode():
        return list(load_mock_iam().get("custom_roles", []))
    return resource_graph_query(
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/roledefinitions' "
        "| extend roleName=tostring(properties.roleName), isCustom=tobool(properties.roleType =~ 'CustomRole'), "
        "permissions=todynamic(properties.permissions) "
        "| project id, roleName, isCustom, permissions"
    )


def list_dangerous_custom_roles() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if is_mock_mode():
        for role in load_mock_iam().get("custom_roles", []):
            actions = role.get("actions", [])
            if "*" in actions:
                rows.append(
                    {
                        "roleName": role.get("roleName"),
                        "objectId": role.get("id"),
                        "risk": "High",
                        "reason": "Custom role com action wildcard (*)",
                    }
                )
        return rows

    for role in list_role_definitions():
        if not role.get("isCustom"):
            continue
        permissions = role.get("permissions", []) or []
        wildcard = False
        for perm in permissions:
            for action in perm.get("actions", []) or []:
                if action == "*":
                    wildcard = True
                    break
            if wildcard:
                break
        if wildcard:
            rows.append(
                {
                    "roleName": role.get("roleName"),
                    "objectId": role.get("id"),
                    "risk": "High",
                    "reason": "Custom role com action wildcard (*)",
                }
            )
    return rows
