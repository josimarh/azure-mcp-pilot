from __future__ import annotations

import unicodedata
from typing import Any

from services.identity_risk import correlate_privileged_identities
from services.ownership import _collect_ownership_records
from services.iam_common import sanitize_assignment

ENTRA_ADMIN_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "User Administrator",
}
GRANT_CAPABLE_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "User Access Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
}
AZURE_HIGH_ROLES = {"Owner", "User Access Administrator"}


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower()


def _owned_by_user() -> dict[str, list[dict[str, Any]]]:
    mapping: dict[str, list[dict[str, Any]]] = {}
    try:
        records = _collect_ownership_records()
    except Exception:
        return mapping
    for record in records:
        for owner_id in record.get("ownerIds", []):
            mapping.setdefault(str(owner_id), []).append(record)
    return mapping


def detect_toxic_combinations(limit: int = 50) -> list[dict[str, Any]]:
    """
    Identifica combinações potencialmente críticas (toxic combinations / SoD)
    correlacionando privilégios Entra + Azure + ownership de objetos privilegiados.
    """
    identities = correlate_privileged_identities()
    owned = _owned_by_user()
    rows: list[dict[str, Any]] = []

    for identity in identities:
        obj_id = str(identity.get("objectId"))
        entra_roles = set(identity.get("entraPrivilegedRoles", []) or [])
        azure_roles = set(identity.get("azurePrivilegedRoles", []) or [])
        combinations: list[str] = []

        if entra_roles & ENTRA_ADMIN_ROLES and azure_roles & AZURE_HIGH_ROLES:
            combinations.append(
                "Privilégio administrativo no Entra ID + Owner/User Access Administrator no Azure"
            )
        if entra_roles & GRANT_CAPABLE_ROLES and azure_roles:
            combinations.append(
                "Capacidade de conceder privilégios (grant) combinada com acesso Azure privilegiado"
            )
        if {"Application Administrator", "Cloud Application Administrator"} & entra_roles:
            combinations.append(
                "Administração de aplicações com capacidade de conceder credenciais/consent"
            )

        owned_objects = owned.get(obj_id, [])
        privileged_owned = [o for o in owned_objects if o.get("privileged")]
        if (entra_roles or azure_roles) and privileged_owned:
            names = ", ".join(
                [f"{o.get('objectType')}:{o.get('objectName')}" for o in privileged_owned[:3]]
            )
            combinations.append(
                f"Usuário privilegiado também é owner de objetos privilegiados ({names})"
            )

        if not combinations:
            continue

        score = int(identity.get("riskScore") or 0)
        score = min(100, score + 4 * len(combinations))
        level = "Critical" if score >= 90 else "High" if score >= 75 else "Medium"
        rows.append(
            sanitize_assignment(
                {
                    "name": identity.get("name") or identity.get("displayName"),
                    "displayName": identity.get("displayName"),
                    "userPrincipalName": identity.get("userPrincipalName"),
                    "mail": identity.get("mail"),
                    "objectId": identity.get("objectId"),
                    "identityType": identity.get("identityType"),
                    "entraPrivilegedRoles": sorted(entra_roles),
                    "azurePrivilegedRoles": sorted(azure_roles),
                    "ownedPrivilegedObjects": [
                        {"type": o.get("objectType"), "name": o.get("objectName")}
                        for o in privileged_owned
                    ],
                    "toxicCombinations": combinations,
                    "risk": level,
                    "riskScore": score,
                    "origin": "SoD correlation",
                }
            )
        )
    rows.sort(key=lambda r: -(int(r.get("riskScore") or 0)))
    return rows[: max(1, min(int(limit), 500))]


def _format_toxic(rows: list[dict[str, Any]], limit: int = 20) -> str:
    lines: list[str] = []
    for item in rows[: max(1, limit)]:
        combos = "; ".join(item.get("toxicCombinations", []))
        lines.append(
            "- "
            f"{item.get('displayName') or item.get('name') or item.get('objectId') or 'N/A'} | "
            f"UPN: {item.get('userPrincipalName') or 'N/A'} | "
            f"Tipo: {item.get('identityType') or 'N/A'} | "
            f"Risco: {item.get('risk') or 'N/A'} ({item.get('riskScore') or 0}/100)\n"
            f"    Combinações: {combos}"
        )
    return "\n".join(lines) if lines else "- Nenhuma combinação tóxica identificada."


def answer_toxic_question(question: str, limit: int = 20) -> dict[str, Any]:
    rows = detect_toxic_combinations(limit=limit)
    narrative = (
        f"Combinações tóxicas / violações potenciais de Separation of Duties: **{len(rows)}**\n\n"
        f"{_format_toxic(rows, limit)}\n\n"
        "Observação: cada combinação é apresentada com evidência; avalie o contexto operacional antes de remediar."
    )
    return {
        "intent": "toxic_combinations",
        "narrative": narrative,
        "data": {"count": len(rows), "rows": rows},
    }


def safe_toxic_combinations() -> dict[str, Any]:
    from services.iam_common import safe_collect

    return safe_collect("toxic-combinations", lambda: detect_toxic_combinations(limit=500))
