from __future__ import annotations

import unicodedata
from typing import Any

from services.entra_groups import list_group_owner_ids, list_groups
from services.entra_users import list_users
from services.iam_common import is_mock_mode, load_mock_iam, sanitize_assignment
from services.identity_risk import correlate_privileged_identities


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower()


def _users_index() -> dict[str, dict[str, Any]]:
    return {str(u.get("id")): u for u in list_users() if u.get("id")}


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


def _collect_ownership_records() -> list[dict[str, Any]]:
    """
    Consolida ownership de múltiplos tipos de objeto em uma estrutura única:
    Groups, Applications, Service Principals, Agents, Agent Blueprints.
    Cada registro: objectType, objectId, objectName, ownerIds.
    """
    if not is_mock_mode():
        raise RuntimeError(
            "Ownership 360 em modo live ainda não está habilitado neste projeto. "
            "É necessário integrar owners via Microsoft Graph para cada tipo de objeto."
        )
    data = load_mock_iam()
    records: list[dict[str, Any]] = []

    for group in data.get("groups", []):
        records.append(
            {
                "objectType": "Group",
                "objectId": group.get("id"),
                "objectName": group.get("displayName"),
                "ownerIds": [str(o) for o in group.get("ownerIds", [])],
                "privileged": bool(group.get("isAssignableToRole")),
            }
        )
    for app in data.get("applications", []):
        records.append(
            {
                "objectType": "Application",
                "objectId": app.get("id"),
                "objectName": app.get("displayName"),
                "ownerIds": [str(o) for o in app.get("owners", [])],
                "privileged": bool(app.get("graphAppPermissions")),
            }
        )
    for sp in data.get("service_principals", []):
        records.append(
            {
                "objectType": "ServicePrincipal",
                "objectId": sp.get("id"),
                "objectName": sp.get("displayName"),
                "ownerIds": [str(o) for o in sp.get("owners", [])],
                "privileged": False,
            }
        )
    for agent in data.get("agents", []):
        records.append(
            {
                "objectType": "Agent",
                "objectId": agent.get("id"),
                "objectName": agent.get("name"),
                "ownerIds": [str(o) for o in agent.get("ownerIds", [])],
                "privileged": True,
            }
        )
    for bp in data.get("agent_blueprints", []):
        records.append(
            {
                "objectType": "AgentBlueprint",
                "objectId": bp.get("id"),
                "objectName": bp.get("name"),
                "ownerIds": [str(o) for o in bp.get("ownerIds", [])],
                "privileged": False,
            }
        )
    return records


def get_owned_objects(user_identifier: str, limit: int = 100) -> dict[str, Any]:
    user = _resolve_user(user_identifier)
    user_id = str(user.get("id"))
    owned: list[dict[str, Any]] = []
    for record in _collect_ownership_records():
        if user_id in record.get("ownerIds", []):
            owned.append(
                {
                    "objectType": record.get("objectType"),
                    "objectId": record.get("objectId"),
                    "objectName": record.get("objectName"),
                    "privileged": record.get("privileged"),
                }
            )
    owned.sort(key=lambda r: (not r.get("privileged"), str(r.get("objectType"))))
    return {
        "owner": sanitize_assignment(
            {
                "name": user.get("displayName"),
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "mail": user.get("mail") or user.get("userPrincipalName"),
                "objectId": user.get("id"),
                "identityType": "User",
            }
        ),
        "count": len(owned),
        "ownedObjects": owned[: max(1, min(int(limit), 500))],
    }


def list_objects_without_owner(limit: int = 200) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in _collect_ownership_records():
        if not record.get("ownerIds"):
            rows.append(
                {
                    "objectType": record.get("objectType"),
                    "objectId": record.get("objectId"),
                    "objectName": record.get("objectName"),
                    "privileged": record.get("privileged"),
                    "finding": "Objeto sem owner definido",
                }
            )
    rows.sort(key=lambda r: (not r.get("privileged"), str(r.get("objectType"))))
    return rows[: max(1, min(int(limit), 1000))]


def list_objects_with_risky_owner(limit: int = 200) -> list[dict[str, Any]]:
    """Objetos cujo único owner está desabilitado ou é Guest."""
    users = _users_index()
    rows: list[dict[str, Any]] = []
    for record in _collect_ownership_records():
        owner_ids = record.get("ownerIds", [])
        if not owner_ids:
            continue
        resolved = [users.get(oid) for oid in owner_ids]
        resolved = [u for u in resolved if u]
        if len(resolved) != 1:
            continue
        owner = resolved[0]
        reason = None
        if owner.get("accountEnabled") is False:
            reason = "Único owner está desabilitado"
        elif str(owner.get("userType", "")).lower() == "guest":
            reason = "Único owner é convidado (guest)"
        if reason:
            rows.append(
                {
                    "objectType": record.get("objectType"),
                    "objectId": record.get("objectId"),
                    "objectName": record.get("objectName"),
                    "ownerDisplayName": owner.get("displayName"),
                    "ownerUpn": owner.get("userPrincipalName"),
                    "finding": reason,
                }
            )
    return rows[: max(1, min(int(limit), 1000))]


def _format_owned(rows: list[dict[str, Any]], limit: int = 20) -> str:
    lines: list[str] = []
    for item in rows[: max(1, limit)]:
        lines.append(f"- **{item.get('objectName') or 'N/A'}**")
        lines.append(f"  - Tipo: {item.get('objectType') or 'N/A'}")
        lines.append(f"  - ID: {item.get('objectId') or 'N/A'}")
        lines.append(f"  - Privilegiado: {'Sim' if item.get('privileged') else 'Não'}")
        if item.get("finding"):
            lines.append(f"  - Finding: {item.get('finding')}")
        lines.append("")
    return "\n".join(lines) if lines else "- Nenhum resultado."


def _users_with_direct_ownership_risk(limit: int = 20) -> dict[str, Any]:
    try:
        records = _collect_ownership_records()
    except Exception as exc:
        return {
            "status": "NOT_EVALUATED",
            "ownershipCoverage": "NOT_EVALUATED",
            "countUsersWithDirectOwnership": 0,
            "users": [],
            "note": "Ownership não pôde ser avaliado com as fontes atuais.",
            "error": str(exc),
        }

    users_by_id = _users_index()
    risk_rows: list[dict[str, Any]] = []
    risk_correlation_status = "EVALUATED"
    try:
        risk_rows = [
            row
            for row in correlate_privileged_identities()
            if str(row.get("identityType", "")).lower() == "user"
        ]
    except Exception:
        risk_correlation_status = "NOT_EVALUATED"
    risk_by_user = {str(row.get("objectId")): row for row in risk_rows if row.get("objectId")}

    owners_map: dict[str, dict[str, Any]] = {}
    for record in records:
        for owner_id in [str(v) for v in record.get("ownerIds", []) if v]:
            row = owners_map.setdefault(
                owner_id,
                {
                    "objectId": owner_id,
                    "ownedObjectsCount": 0,
                    "privilegedOwnedObjectsCount": 0,
                },
            )
            row["ownedObjectsCount"] += 1
            if record.get("privileged"):
                row["privilegedOwnedObjectsCount"] += 1

    users: list[dict[str, Any]] = []
    for owner_id, stats in owners_map.items():
        user = users_by_id.get(owner_id, {})
        correlated = risk_by_user.get(owner_id)
        has_correlated_privileged = correlated is not None
        if has_correlated_privileged:
            risk_score = correlated.get("riskScore")
            risk_level = correlated.get("risk")
            risk_evidence = "Correlated privileged roles across Entra and Azure RBAC."
            entra_roles = correlated.get("entraPrivilegedRoles", [])
            azure_roles = correlated.get("azurePrivilegedRoles", [])
            user_risk_coverage = "EVALUATED"
        elif risk_correlation_status == "EVALUATED":
            risk_score = 20
            risk_level = "Low"
            risk_evidence = "No privileged role correlation identified in evaluated sources."
            entra_roles = []
            azure_roles = []
            user_risk_coverage = "EVALUATED"
        else:
            risk_score = None
            risk_level = "NOT_EVALUATED"
            risk_evidence = "Risk correlation could not be evaluated with current sources."
            entra_roles = []
            azure_roles = []
            user_risk_coverage = "NOT_EVALUATED"

        users.append(
            sanitize_assignment(
                {
                    "name": user.get("displayName") or owner_id,
                    "displayName": user.get("displayName"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "mail": user.get("mail") or user.get("userPrincipalName"),
                    "objectId": owner_id,
                    "identityType": "User",
                    "ownedObjectsCount": int(stats.get("ownedObjectsCount", 0)),
                    "privilegedOwnedObjectsCount": int(stats.get("privilegedOwnedObjectsCount", 0)),
                    "riskScore": risk_score,
                    "risk": risk_level,
                    "riskEvidence": risk_evidence,
                    "entraPrivilegedRoles": entra_roles,
                    "azurePrivilegedRoles": azure_roles,
                    "riskCoverage": user_risk_coverage,
                }
            )
        )
    users.sort(
        key=lambda r: (
            -(int(r.get("riskScore") or -1)),
            -int(r.get("privilegedOwnedObjectsCount") or 0),
            -int(r.get("ownedObjectsCount") or 0),
        )
    )
    return {
        "status": "PASS",
        "ownershipCoverage": "EVALUATED",
        "riskCoverage": risk_correlation_status,
        "countUsersWithDirectOwnership": len(users),
        "users": users[: max(1, min(int(limit), 500))],
    }


def answer_ownership_question(question: str, limit: int = 20) -> dict[str, Any]:
    import re

    q = _normalize(question)
    email_match = re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", q)

    direct_owner_user_terms = [
        "quantos usuarios tem dono direto",
        "quantos usuarios têm dono direto",
        "usuarios com dono direto",
        "usuários com dono direto",
        "usuarios com owner direto",
        "usuários com owner direto",
        "usuarios responsaveis diretos",
        "usuários responsáveis diretos",
    ]
    if any(term in q for term in direct_owner_user_terms) or (
        ("usuario" in q or "usuarios" in q) and ("dono direto" in q or "owner direto" in q)
    ):
        result = _users_with_direct_ownership_risk(limit=limit)
        if result.get("status") != "PASS":
            return {
                "intent": "users_with_direct_ownership_unavailable",
                "narrative": (
                    "Não foi possível avaliar usuários com ownership direto nas fontes atuais. "
                    "Posso executar um assessment completo dos usuários quando a fonte de ownership estiver disponível."
                ),
                "data": result,
            }
        rows = result.get("users", [])
        lines = [
            f"Usuários com ownership direto identificado: **{result.get('countUsersWithDirectOwnership', 0)}**",
            "Coverage:",
            f"- Ownership: **{result.get('ownershipCoverage', 'NOT_EVALUATED')}**",
            f"- Risk correlation (Entra + Azure RBAC privilegiado): **{result.get('riskCoverage', 'NOT_EVALUATED')}**",
            "",
            "Top usuários por risco (com ownership direto):",
        ]
        for user in rows[: max(1, limit)]:
            score = user.get("riskScore")
            risk_text = f"{user.get('risk')} ({score}/100)" if score is not None else "NOT_EVALUATED"
            lines.append(f"- **{user.get('displayName') or user.get('name') or user.get('objectId')}**")
            lines.append(f"  - UPN: {user.get('userPrincipalName') or 'N/A'}")
            lines.append(f"  - Objetos sob ownership: {user.get('ownedObjectsCount', 0)}")
            lines.append(f"  - Objetos privilegiados: {user.get('privilegedOwnedObjectsCount', 0)}")
            lines.append(f"  - Risk score: {risk_text}")
            lines.append("")
        lines.extend(
            [
                "",
                "Observação: ownership indica responsabilidade; não concede automaticamente permissões. "
                "O risk score reflete correlação de privilégios técnicos identificados.",
            ]
        )
        return {"intent": "users_with_direct_ownership_risk", "narrative": "\n".join(lines), "data": result}

    if ("sem owner" in q or "sem responsavel" in q or "nao possuem owner" in q) and "objeto" in q:
        rows = list_objects_without_owner(limit=limit)
        return {
            "intent": "objects_without_owner",
            "narrative": f"Objetos sem owner: **{len(rows)}**\n\n{_format_owned(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    if ("owner desabilitado" in q or "owner guest" in q or "unico owner" in q or "único owner" in q):
        rows = list_objects_with_risky_owner(limit=limit)
        return {
            "intent": "objects_with_risky_owner",
            "narrative": f"Objetos com owner em risco (único owner desabilitado/guest): **{len(rows)}**\n\n{_format_owned(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    if email_match:
        result = get_owned_objects(email_match.group(0), limit=limit)
        owner = result.get("owner", {})
        narrative = [
            f"Objetos sob responsabilidade de {owner.get('userPrincipalName') or owner.get('displayName') or email_match.group(0)}:",
            f"- Total: **{result.get('count', 0)}**",
            "",
            _format_owned(result.get("ownedObjects", []), limit),
            "",
            "Observação: ownership indica responsabilidade e não concede automaticamente as permissões do objeto.",
        ]
        return {"intent": "owned_objects", "narrative": "\n".join(narrative), "data": result}

    rows = list_objects_without_owner(limit=limit)
    return {
        "intent": "objects_without_owner",
        "narrative": f"Objetos sem owner: **{len(rows)}**\n\n{_format_owned(rows, limit)}",
        "data": {"count": len(rows), "rows": rows},
    }


def safe_objects_without_owner() -> dict[str, Any]:
    from services.iam_common import safe_collect

    return safe_collect("objects-without-owner", lambda: list_objects_without_owner(limit=500))
