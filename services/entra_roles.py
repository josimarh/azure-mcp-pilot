from __future__ import annotations

from typing import Any

from services.iam_common import graph_list, is_mock_mode, load_mock_iam, sanitize_assignment
from services.role_risk import role_risk_score

PRIVILEGED_ENTRA_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Authentication Administrator",
    "User Administrator",
}


def _live_directory_role_members() -> list[dict[str, Any]]:
    roles = graph_list("https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName")
    rows: list[dict[str, Any]] = []
    for role in roles:
        role_id = role.get("id")
        role_name = role.get("displayName")
        if not role_id:
            continue
        members = graph_list(
            f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members?$select=id,displayName,userPrincipalName,mail"
        )
        for member in members:
            principal_type = "User"
            odata_type = str(member.get("@odata.type") or "")
            if "servicePrincipal" in odata_type:
                principal_type = "ServicePrincipal"
            elif "group" in odata_type:
                principal_type = "Group"
            rows.append(
                {
                    "principalId": member.get("id"),
                    "name": member.get("displayName"),
                    "displayName": member.get("displayName"),
                    "userPrincipalName": member.get("userPrincipalName"),
                    "mail": member.get("mail") or member.get("userPrincipalName"),
                    "objectId": member.get("id"),
                    "identityType": principal_type,
                    "role": role_name,
                    "assignmentType": "Direct",
                    "inherited": False,
                    "origin": "Microsoft Entra ID role",
                }
            )
    return rows


def list_directory_role_members() -> list[dict[str, Any]]:
    if is_mock_mode():
        data = load_mock_iam()
        users = {u.get("id"): u for u in data.get("users", [])}
        rows: list[dict[str, Any]] = []
        for item in data.get("directory_role_assignments", []):
            principal_id = item.get("principalId")
            user = users.get(principal_id, {})
            rows.append(
                {
                    "principalId": principal_id,
                    "name": user.get("displayName"),
                    "displayName": user.get("displayName"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "mail": user.get("mail") or user.get("userPrincipalName"),
                    "objectId": principal_id,
                    "identityType": item.get("principalType", "User"),
                    "role": item.get("roleName"),
                    "assignmentType": item.get("assignmentType", "Direct"),
                    "inherited": False,
                    "origin": "Microsoft Entra ID role",
                }
            )
        return rows
    return _live_directory_role_members()


def list_privileged_directory_role_members() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in list_directory_role_members():
        role = item.get("role")
        if role not in PRIVILEGED_ENTRA_ROLES:
            continue
        risk = role_risk_score(str(role), "Entra")
        row = dict(item)
        row["risk"] = risk["level"]
        row["riskScore"] = risk["score"]
        row["riskSource"] = risk["source"]
        rows.append(row)
    return rows


def present_role_assignments(rows: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    return [sanitize_assignment(r) for r in rows[: max(1, limit)]]
