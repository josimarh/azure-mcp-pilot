from __future__ import annotations

from typing import Any

from services.iam_common import graph_list, is_mock_mode, load_mock_iam, sanitize_identity

GROUPS_URL = "https://graph.microsoft.com/v1.0/groups?$select=id,displayName&$top=999"


def list_groups() -> list[dict[str, Any]]:
    if is_mock_mode():
        return list(load_mock_iam().get("groups", []))
    return graph_list(GROUPS_URL)


def list_group_members(group_id: str) -> list[dict[str, Any]]:
    if is_mock_mode():
        data = load_mock_iam()
        users = {str(u.get("id")): u for u in data.get("users", []) if u.get("id")}
        rows: list[dict[str, Any]] = []
        for rel in data.get("group_memberships", []):
            if str(rel.get("groupId")) != str(group_id):
                continue
            user = users.get(str(rel.get("memberId")), {})
            rows.append(
                {
                    "id": user.get("id") or rel.get("memberId"),
                    "displayName": user.get("displayName"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "mail": user.get("mail") or user.get("userPrincipalName"),
                }
            )
        return rows
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members?$select=id,displayName,userPrincipalName,mail"
    return graph_list(url)


def list_user_group_ids(user_id: str) -> list[str]:
    if is_mock_mode():
        data = load_mock_iam()
        return [
            str(rel.get("groupId"))
            for rel in data.get("group_memberships", [])
            if str(rel.get("memberId")) == str(user_id)
        ]
    rows = graph_list(
        f"https://graph.microsoft.com/v1.0/users/{user_id}/transitiveMemberOf?$select=id"
    )
    return [str(item.get("id")) for item in rows if item.get("id")]


def list_group_owner_ids(group_id: str) -> list[str]:
    if is_mock_mode():
        for group in load_mock_iam().get("groups", []):
            if str(group.get("id")) == str(group_id):
                return [str(o) for o in group.get("ownerIds", [])]
        return []
    rows = graph_list(
        f"https://graph.microsoft.com/v1.0/groups/{group_id}/owners?$select=id"
    )
    return [str(item.get("id")) for item in rows if item.get("id")]


def is_role_assignable_group(group: dict[str, Any]) -> bool:
    return bool(group.get("isAssignableToRole"))


def present_groups(groups: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    rows = []
    for item in groups[: max(1, limit)]:
        rows.append(
            sanitize_identity(
                {
                    "name": item.get("displayName"),
                    "displayName": item.get("displayName"),
                    "objectId": item.get("id"),
                    "identityType": "Group",
                }
            )
        )
    return rows
