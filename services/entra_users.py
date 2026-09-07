from __future__ import annotations

from typing import Any

from services.iam_common import graph_list, is_mock_mode, load_mock_iam, sanitize_identity

USERS_URL = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,userType,accountEnabled&$top=999"


def list_users() -> list[dict[str, Any]]:
    if is_mock_mode():
        return list(load_mock_iam().get("users", []))
    return graph_list(USERS_URL)


def list_guest_users() -> list[dict[str, Any]]:
    return [u for u in list_users() if str(u.get("userType", "")).lower() == "guest"]


def list_disabled_users() -> list[dict[str, Any]]:
    return [u for u in list_users() if u.get("accountEnabled") is False]


def present_users(users: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    rows = []
    for item in users[: max(1, limit)]:
        row = {
            "name": item.get("displayName"),
            "displayName": item.get("displayName"),
            "userPrincipalName": item.get("userPrincipalName"),
            "mail": item.get("mail") or item.get("userPrincipalName"),
            "objectId": item.get("id"),
            "identityType": "User",
            "accountEnabled": item.get("accountEnabled"),
            "userType": item.get("userType"),
        }
        rows.append(sanitize_identity(row))
    return rows
