from __future__ import annotations

import unicodedata
from typing import Any

from services.azure_rbac import list_role_assignments
from services.entra_groups import list_groups, list_user_group_ids
from services.entra_users import list_users
from services.entra_workload_identities import list_managed_identities, list_service_principals
from services.iam_common import sanitize_assignment
from services.role_risk import role_risk_score


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower()


def _resolve_user(user_identifier: str) -> dict[str, Any]:
    q = _normalize(user_identifier)
    for user in list_users():
        if q in {
            _normalize(str(user.get("id") or "")),
            _normalize(str(user.get("displayName") or "")),
            _normalize(str(user.get("userPrincipalName") or "")),
            _normalize(str(user.get("mail") or "")),
        }:
            return user
    raise RuntimeError(f"Usuário `{user_identifier}` não encontrado no escopo atual.")


def _group_index() -> dict[str, dict[str, Any]]:
    return {str(group.get("id")): group for group in list_groups() if group.get("id")}


def get_user_effective_azure_access(user_identifier: str, limit: int = 200) -> dict[str, Any]:
    user = _resolve_user(user_identifier)
    user_id = str(user.get("id"))
    group_ids = set(list_user_group_ids(user_id))
    groups = _group_index()

    direct_rows: list[dict[str, Any]] = []
    inherited_rows: list[dict[str, Any]] = []
    for assignment in list_role_assignments():
        principal_id = str(assignment.get("principalId") or "")
        principal_type = str(assignment.get("principalType") or "")
        if principal_id == user_id and principal_type.lower() == "user":
            risk = role_risk_score(str(assignment.get("role")), "Azure", scope=assignment.get("scope"))
            direct_rows.append(
                sanitize_assignment(
                    {
                        "name": user.get("displayName"),
                        "displayName": user.get("displayName"),
                        "userPrincipalName": user.get("userPrincipalName"),
                        "mail": user.get("mail") or user.get("userPrincipalName"),
                        "objectId": user.get("id"),
                        "identityType": "User",
                        "role": assignment.get("role"),
                        "scope": assignment.get("scope"),
                        "assignmentType": "Direct",
                        "inherited": False,
                        "origin": assignment.get("origin") or "Azure RBAC",
                        "subscription": assignment.get("subscription"),
                        "resourceGroup": assignment.get("resourceGroup"),
                        "resource": assignment.get("resource"),
                        "risk": risk["level"],
                        "riskScore": risk["score"],
                    }
                )
            )
        if principal_type.lower() == "group" and principal_id in group_ids:
            group = groups.get(principal_id, {})
            risk = role_risk_score(str(assignment.get("role")), "Azure", scope=assignment.get("scope"))
            inherited_rows.append(
                sanitize_assignment(
                    {
                        "name": user.get("displayName"),
                        "displayName": user.get("displayName"),
                        "userPrincipalName": user.get("userPrincipalName"),
                        "mail": user.get("mail") or user.get("userPrincipalName"),
                        "objectId": user.get("id"),
                        "identityType": "User",
                        "role": assignment.get("role"),
                        "scope": assignment.get("scope"),
                        "assignmentType": "InheritedFromGroup",
                        "inherited": True,
                        "origin": f"Azure RBAC via group {group.get('displayName') or principal_id}",
                        "subscription": assignment.get("subscription"),
                        "resourceGroup": assignment.get("resourceGroup"),
                        "resource": assignment.get("resource"),
                        "viaGroupId": principal_id,
                        "viaGroupName": group.get("displayName"),
                        "risk": risk["level"],
                        "riskScore": risk["score"],
                    }
                )
            )

    rows = (direct_rows + inherited_rows)[: max(1, min(int(limit), 1000))]
    return {
        "user": sanitize_assignment(
            {
                "name": user.get("displayName"),
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "mail": user.get("mail") or user.get("userPrincipalName"),
                "objectId": user.get("id"),
                "identityType": "User",
            }
        ),
        "directAssignmentsCount": len(direct_rows),
        "inheritedAssignmentsCount": len(inherited_rows),
        "totalAssignmentsCount": len(direct_rows) + len(inherited_rows),
        "assignments": rows,
    }


def list_orphan_role_assignments(limit: int = 200) -> list[dict[str, Any]]:
    known_ids = {str(item.get("id")) for item in list_users() if item.get("id")}
    known_ids.update({str(item.get("id")) for item in list_groups() if item.get("id")})
    known_ids.update({str(item.get("id")) for item in list_service_principals() if item.get("id")})
    known_ids.update({str(item.get("id")) for item in list_managed_identities() if item.get("id")})

    rows: list[dict[str, Any]] = []
    for item in list_role_assignments():
        principal_id = str(item.get("principalId") or "")
        if principal_id and principal_id not in known_ids:
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
                        "orphanReason": "Principal não resolvido no tenant visível",
                        "risk": risk["level"],
                        "riskScore": risk["score"],
                    }
                )
            )
    rows.sort(key=lambda row: (-(int(row.get("riskScore") or 0))))
    return rows[: max(1, min(int(limit), 1000))]

