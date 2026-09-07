from __future__ import annotations

import unicodedata
from typing import Any

from services.azure_rbac import list_role_assignments
from services.entra_groups import list_user_group_ids
from services.entra_users import list_users
from services.entra_workload_identities import list_managed_identities, list_service_principals
from services.iam_common import sanitize_assignment
from services.identity_risk import correlate_privileged_identities
from services.ownership import _collect_ownership_records
from services.role_risk import role_risk_score


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower()


def _scope_parts(scope: str | None) -> dict[str, str | None]:
    if not scope:
        return {"managementGroup": None, "subscription": None, "resourceGroup": None, "resource": None}
    parts = scope.split("/")
    result: dict[str, str | None] = {
        "managementGroup": None,
        "subscription": None,
        "resourceGroup": None,
        "resource": None,
    }
    for idx, part in enumerate(parts):
        low = part.lower()
        if low == "managementgroups" and idx + 1 < len(parts):
            result["managementGroup"] = parts[idx + 1]
        elif low == "subscriptions" and idx + 1 < len(parts):
            result["subscription"] = parts[idx + 1]
        elif low == "resourcegroups" and idx + 1 < len(parts):
            result["resourceGroup"] = parts[idx + 1]
    if "/providers/" in scope and not scope.lower().endswith("managementgroups/" + str(result["managementGroup"] or "")):
        result["resource"] = parts[-1]
    return result


def _identity_assignments(object_id: str, group_ids: set[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in list_role_assignments():
        pid = str(item.get("principalId") or "")
        ptype = str(item.get("principalType") or "").lower()
        if pid == object_id:
            rows.append({**item, "via": "Direct"})
        elif ptype == "group" and pid in group_ids:
            rows.append({**item, "via": "Group"})
    return rows


def compute_identity_blast_radius(identity_identifier: str) -> dict[str, Any]:
    q = _normalize(identity_identifier)

    # resolve identity across users, SPs, MIs
    resolved: dict[str, Any] | None = None
    identity_type = "Unknown"
    for user in list_users():
        if q in {
            _normalize(str(user.get("id") or "")),
            _normalize(str(user.get("displayName") or "")),
            _normalize(str(user.get("userPrincipalName") or "")),
            _normalize(str(user.get("mail") or "")),
        }:
            resolved = user
            identity_type = "User"
            break
    if resolved is None:
        for sp in list_service_principals():
            if q in {_normalize(str(sp.get("id") or "")), _normalize(str(sp.get("displayName") or ""))}:
                resolved = sp
                identity_type = "ServicePrincipal"
                break
    if resolved is None:
        for mi in list_managed_identities():
            if q in {_normalize(str(mi.get("id") or "")), _normalize(str(mi.get("displayName") or ""))}:
                resolved = mi
                identity_type = "ManagedIdentity"
                break
    if resolved is None:
        raise RuntimeError(f"Identidade `{identity_identifier}` não encontrada no escopo atual.")

    object_id = str(resolved.get("id"))
    group_ids = set(list_user_group_ids(object_id)) if identity_type == "User" else set()
    assignments = _identity_assignments(object_id, group_ids)

    subscriptions: set[str] = set()
    management_groups: set[str] = set()
    resource_groups: set[str] = set()
    max_score = 0
    can_grant = False
    detailed: list[dict[str, Any]] = []
    for item in assignments:
        scope = item.get("scope")
        parts = _scope_parts(scope)
        if parts["subscription"]:
            subscriptions.add(str(parts["subscription"]))
        if parts["managementGroup"]:
            management_groups.add(str(parts["managementGroup"]))
        if parts["resourceGroup"]:
            resource_groups.add(str(parts["resourceGroup"]))
        risk = role_risk_score(str(item.get("role")), "Azure", scope=scope)
        max_score = max(max_score, risk["score"])
        if str(item.get("role")) in {"Owner", "User Access Administrator"}:
            can_grant = True
        detailed.append(
            sanitize_assignment(
                {
                    "role": item.get("role"),
                    "scope": scope,
                    "via": item.get("via"),
                    "riskScore": risk["score"],
                }
            )
        )

    # ownership contribution (managed objects extend blast radius)
    owned_privileged = 0
    try:
        for record in _collect_ownership_records():
            if object_id in record.get("ownerIds", []) and record.get("privileged"):
                owned_privileged += 1
    except Exception:
        owned_privileged = 0

    # Management Group assignment cascades to all subscriptions conceptually
    mg_boost = 15 if management_groups else 0
    blast_score = min(
        100,
        max_score
        + 6 * len(subscriptions)
        + 3 * len(resource_groups)
        + mg_boost
        + 4 * owned_privileged,
    )
    level = "Critical" if blast_score >= 90 else "High" if blast_score >= 75 else "Medium" if blast_score >= 50 else "Low"

    return {
        "identity": sanitize_assignment(
            {
                "displayName": resolved.get("displayName"),
                "name": resolved.get("displayName"),
                "userPrincipalName": resolved.get("userPrincipalName"),
                "mail": resolved.get("mail") or resolved.get("userPrincipalName"),
                "objectId": object_id,
                "identityType": identity_type,
            }
        ),
        "managementGroupsAffected": sorted(management_groups),
        "subscriptionsAffected": sorted(subscriptions),
        "resourceGroupsAffected": sorted(resource_groups),
        "canGrantAccess": can_grant,
        "ownedPrivilegedObjects": owned_privileged,
        "assignments": detailed,
        "blastRadiusScore": blast_score,
        "blastRadiusLevel": level,
    }


def top_blast_radius(limit: int = 10) -> list[dict[str, Any]]:
    from services.entra_roles import list_privileged_directory_role_members
    from services.azure_rbac import list_privileged_role_assignments

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    raw_ids: list[str] = []
    for member in list_privileged_directory_role_members():
        pid = str(member.get("principalId") or "")
        if pid:
            raw_ids.append(pid)
    for item in list_privileged_role_assignments():
        pid = str(item.get("principalId") or "")
        if pid:
            raw_ids.append(pid)

    for obj_id in raw_ids:
        if not obj_id or obj_id in seen:
            continue
        seen.add(obj_id)
        try:
            radius = compute_identity_blast_radius(obj_id)
        except Exception:
            continue
        results.append(radius)
    results.sort(key=lambda r: -(int(r.get("blastRadiusScore") or 0)))
    return results[: max(1, min(int(limit), 100))]


def _format_blast(rows: list[dict[str, Any]], limit: int = 20) -> str:
    lines: list[str] = []
    for item in rows[: max(1, limit)]:
        ident = item.get("identity", {})
        lines.append(f"- **{ident.get('displayName') or ident.get('objectId') or 'N/A'}**")
        lines.append(f"  - Tipo: {ident.get('identityType') or 'N/A'}")
        lines.append(f"  - Subscriptions afetadas: {len(item.get('subscriptionsAffected', []))}")
        lines.append(f"  - Management Groups afetados: {len(item.get('managementGroupsAffected', []))}")
        lines.append(f"  - Pode conceder acesso: {'Sim' if item.get('canGrantAccess') else 'Não'}")
        lines.append(f"  - Blast Radius: {item.get('blastRadiusLevel')} ({item.get('blastRadiusScore')}/100)")
        lines.append("")
    return "\n".join(lines) if lines else "- Nenhum resultado."


def answer_blast_radius_question(question: str, limit: int = 20) -> dict[str, Any]:
    import re

    q = _normalize(question)
    email_match = re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", q)
    if email_match:
        radius = compute_identity_blast_radius(email_match.group(0))
        ident = radius.get("identity", {})
        narrative = [
            f"Blast radius de {ident.get('userPrincipalName') or ident.get('displayName') or email_match.group(0)}:",
            f"- Nível: **{radius.get('blastRadiusLevel')}** ({radius.get('blastRadiusScore')}/100)",
            f"- Management Groups afetados: **{len(radius.get('managementGroupsAffected', []))}**",
            f"- Subscriptions afetadas: **{len(radius.get('subscriptionsAffected', []))}**",
            f"- Resource Groups afetados: **{len(radius.get('resourceGroupsAffected', []))}**",
            f"- Pode conceder novos privilégios: **{'Sim' if radius.get('canGrantAccess') else 'Não'}**",
        ]
        return {"intent": "identity_blast_radius", "narrative": "\n".join(narrative), "data": radius}

    rows = top_blast_radius(limit=limit)
    narrative = [
        f"Identidades por maior blast radius: **{len(rows)}**",
        "",
        _format_blast(rows, limit),
    ]
    return {"intent": "top_blast_radius", "narrative": "\n".join(narrative), "data": {"count": len(rows), "rows": rows}}
