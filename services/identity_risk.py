from __future__ import annotations

from collections import defaultdict
from typing import Any

from services.azure_rbac import list_privileged_role_assignments
from services.entra_roles import list_privileged_directory_role_members
from services.entra_users import list_users
from services.entra_workload_identities import list_managed_identities, list_service_principals
from services.iam_common import sanitize_assignment
from services.role_risk import role_risk_score


def _identity_index() -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for user in list_users():
        obj_id = user.get("id")
        if obj_id:
            index[str(obj_id)] = {
                "name": user.get("displayName"),
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "mail": user.get("mail") or user.get("userPrincipalName"),
                "objectId": obj_id,
                "identityType": "User",
                "accountEnabled": user.get("accountEnabled"),
                "userType": user.get("userType"),
            }
    for sp in list_service_principals():
        obj_id = sp.get("id")
        if obj_id and str(obj_id) not in index:
            index[str(obj_id)] = {
                "name": sp.get("displayName"),
                "displayName": sp.get("displayName"),
                "objectId": obj_id,
                "identityType": "ServicePrincipal",
                "appId": sp.get("appId"),
            }
    for mi in list_managed_identities():
        obj_id = mi.get("id")
        if obj_id and str(obj_id) not in index:
            index[str(obj_id)] = {
                "name": mi.get("displayName"),
                "displayName": mi.get("displayName"),
                "objectId": obj_id,
                "identityType": "ManagedIdentity",
                "appId": mi.get("appId"),
            }
    return index


def correlate_privileged_identities() -> list[dict[str, Any]]:
    index = _identity_index()
    entra = list_privileged_directory_role_members()
    azure = list_privileged_role_assignments()
    aggregate: dict[str, dict[str, Any]] = defaultdict(dict)

    for item in entra:
        principal_id = item.get("principalId")
        if not principal_id:
            continue
        pid = str(principal_id)
        base = aggregate[pid]
        base.update(index.get(pid, {"objectId": pid, "identityType": item.get("identityType", "Unknown")}))
        base.setdefault("entraRoles", set()).add(item.get("role"))
        base.setdefault("entraScores", []).append(role_risk_score(str(item.get("role")), "Entra")["score"])
        base.setdefault("azureRoles", set())
        base.setdefault("azureScores", [])

    for item in azure:
        principal_id = item.get("principalId")
        if not principal_id:
            continue
        pid = str(principal_id)
        base = aggregate[pid]
        base.update(index.get(pid, {"objectId": pid, "identityType": item.get("principalType", "Unknown")}))
        base.setdefault("entraRoles", set())
        base.setdefault("entraScores", [])
        base.setdefault("azureRoles", set()).add(item.get("role"))
        base.setdefault("azureScores", []).append(
            role_risk_score(str(item.get("role")), "Azure", scope=item.get("scope"))["score"]
        )

    rows: list[dict[str, Any]] = []
    for pid, data in aggregate.items():
        entra_roles = sorted([r for r in data.get("entraRoles", set()) if r])
        azure_roles = sorted([r for r in data.get("azureRoles", set()) if r])
        both = bool(entra_roles and azure_roles)
        privileged_count = len(entra_roles) + len(azure_roles)
        role_scores = [int(v) for v in data.get("entraScores", []) + data.get("azureScores", []) if isinstance(v, int)]
        peak_score = max(role_scores) if role_scores else (95 if both else 78 if privileged_count >= 3 else 65)
        score = min(100, peak_score + (5 if both else 0) + (3 if privileged_count >= 3 else 0))
        risk = "Critical" if score >= 90 else "High" if score >= 75 else "Medium"
        rows.append(
            sanitize_assignment(
                {
                    "name": data.get("name") or data.get("displayName"),
                    "displayName": data.get("displayName"),
                    "userPrincipalName": data.get("userPrincipalName"),
                    "mail": data.get("mail"),
                    "objectId": data.get("objectId") or pid,
                    "identityType": data.get("identityType"),
                    "permission": ", ".join(entra_roles + azure_roles),
                    "role": None,
                    "scope": "Entra + Azure" if both else ("Entra" if entra_roles else "Azure"),
                    "assignmentType": "Mixed",
                    "inherited": False,
                    "origin": "Correlation",
                    "risk": risk,
                    "riskScore": score,
                    "riskSource": "IAM Scope (Tier/Risk Tier) + correlation boost",
                    "entraPrivilegedRoles": entra_roles,
                    "azurePrivilegedRoles": azure_roles,
                    "privilegedRolesCount": privileged_count,
                }
            )
        )
    rows.sort(key=lambda x: (-(int(x.get("riskScore") or 0)), -(x.get("privilegedRolesCount") or 0)))
    return rows
