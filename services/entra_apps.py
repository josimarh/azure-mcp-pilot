from __future__ import annotations

from datetime import timedelta
from typing import Any

from services.iam_common import (
    graph_list,
    is_mock_mode,
    load_mock_iam,
    parse_iso_datetime,
    safe_collect,
    sanitize_assignment,
    utc_now,
)

APPS_URL = (
    "https://graph.microsoft.com/v1.0/applications"
    "?$select=id,displayName,appId,passwordCredentials,keyCredentials&$top=999"
)
SPS_URL = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,servicePrincipalType&$top=999"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
CRITICAL_GRAPH_PERMISSIONS = {
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
}


def list_applications() -> list[dict[str, Any]]:
    if is_mock_mode():
        return list(load_mock_iam().get("applications", []))
    return graph_list(APPS_URL)


def _app_owners_live(app_id: str) -> list[dict[str, Any]]:
    return graph_list(
        f"https://graph.microsoft.com/v1.0/applications/{app_id}/owners?$select=id,displayName,userPrincipalName,mail"
    )


def list_applications_without_owners() -> list[dict[str, Any]]:
    apps = list_applications()
    rows: list[dict[str, Any]] = []
    if is_mock_mode():
        for app in apps:
            if not app.get("owners"):
                rows.append(app)
        return rows
    for app in apps:
        app_id = app.get("id")
        if not app_id:
            continue
        owners = _app_owners_live(str(app_id))
        if not owners:
            rows.append(app)
    return rows


def list_secrets_expiring(days: int = 30) -> list[dict[str, Any]]:
    cutoff = utc_now() + timedelta(days=max(1, int(days)))
    rows: list[dict[str, Any]] = []
    for app in list_applications():
        app_name = app.get("displayName")
        app_object_id = app.get("id")
        app_id = app.get("appId")
        secrets = []
        if is_mock_mode():
            secrets = app.get("secrets", [])
        else:
            for pwd in app.get("passwordCredentials", []) or []:
                secrets.append(
                    {
                        "displayName": pwd.get("displayName"),
                        "endDateTime": pwd.get("endDateTime"),
                    }
                )
            for key in app.get("keyCredentials", []) or []:
                secrets.append(
                    {
                        "displayName": key.get("displayName"),
                        "endDateTime": key.get("endDateTime"),
                    }
                )
        for secret in secrets:
            end_dt = parse_iso_datetime(secret.get("endDateTime"))
            if end_dt is None:
                continue
            if end_dt <= cutoff:
                expired = end_dt <= utc_now()
                rows.append(
                    sanitize_assignment(
                        {
                            "name": app_name,
                            "displayName": app_name,
                            "objectId": app_object_id,
                            "identityType": "Application",
                            "permission": "Credential",
                            "role": None,
                            "assignmentType": "Direct",
                            "origin": "Application credential",
                            "secretName": secret.get("displayName"),
                            "expiresAt": end_dt.isoformat(),
                            "risk": "High" if expired else "Medium",
                            "mail": None,
                            "userPrincipalName": None,
                            "appId": app_id,
                        }
                    )
                )
    return rows


def list_service_principals_with_graph_critical_permissions() -> list[dict[str, Any]]:
    if is_mock_mode():
        rows: list[dict[str, Any]] = []
        for app in load_mock_iam().get("applications", []):
            for permission in app.get("graphAppPermissions", []):
                if permission in CRITICAL_GRAPH_PERMISSIONS:
                    rows.append(
                        {
                            "name": app.get("displayName"),
                            "displayName": app.get("displayName"),
                            "objectId": app.get("id"),
                            "identityType": "Application",
                            "permission": permission,
                            "origin": "Microsoft Graph Application Permission",
                            "risk": "High",
                        }
                    )
        return rows

    graph_sp = graph_list(
        "https://graph.microsoft.com/v1.0/servicePrincipals"
        f"?$filter=appId eq '{GRAPH_APP_ID}'&$select=id,appRoles"
    )
    if not graph_sp:
        return []
    graph_resource = graph_sp[0]
    graph_sp_id = graph_resource.get("id")
    role_map = {
        r.get("id"): r.get("value")
        for r in graph_resource.get("appRoles", []) or []
        if r.get("id")
    }
    if not graph_sp_id:
        return []
    assignments = graph_list(
        f"https://graph.microsoft.com/v1.0/servicePrincipals/{graph_sp_id}/appRoleAssignedTo"
        "?$select=principalId,principalDisplayName,principalType,appRoleId"
    )
    rows: list[dict[str, Any]] = []
    for item in assignments:
        permission = role_map.get(item.get("appRoleId"))
        if permission not in CRITICAL_GRAPH_PERMISSIONS:
            continue
        rows.append(
            {
                "name": item.get("principalDisplayName"),
                "displayName": item.get("principalDisplayName"),
                "objectId": item.get("principalId"),
                "identityType": item.get("principalType"),
                "permission": permission,
                "origin": "Microsoft Graph Application Permission",
                "risk": "High",
            }
        )
    return rows


def safe_apps_without_owners() -> dict[str, Any]:
    return safe_collect("applications-without-owners", list_applications_without_owners)
