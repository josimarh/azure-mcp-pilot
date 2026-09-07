from __future__ import annotations

import re
import unicodedata
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from services.entra_groups import list_groups
from services.entra_users import list_users
from services.entra_workload_identities import list_managed_identities, list_service_principals
from services.iam_common import is_mock_mode, load_mock_iam, sanitize_assignment
from services.role_risk import role_risk_score


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _identity_index() -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    for user in list_users():
        if user.get("id"):
            idx[str(user["id"])] = {
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "mail": user.get("mail") or user.get("userPrincipalName"),
                "identityType": "User",
                "accountEnabled": user.get("accountEnabled"),
                "userType": user.get("userType"),
            }
    for group in list_groups():
        if group.get("id"):
            idx[str(group["id"])] = {
                "displayName": group.get("displayName"),
                "identityType": "Group",
            }
    for sp in list_service_principals():
        if sp.get("id"):
            idx[str(sp["id"])] = {
                "displayName": sp.get("displayName"),
                "identityType": "ServicePrincipal",
            }
    for mi in list_managed_identities():
        if mi.get("id"):
            idx[str(mi["id"])] = {
                "displayName": mi.get("displayName"),
                "identityType": "ManagedIdentity",
            }
    return idx


def _load_events() -> list[dict[str, Any]]:
    if not is_mock_mode():
        raise RuntimeError(
            "Timeline de mudanças de privilégio em modo live ainda não está habilitada neste projeto. "
            "É necessário integrar fontes de auditoria (Graph AuditLogs e/ou Activity Logs)."
        )
    return list(load_mock_iam().get("privilege_change_events", []))


def _event_row(event: dict[str, Any], identities: dict[str, dict[str, Any]]) -> dict[str, Any]:
    principal_id = str(event.get("principalId") or "")
    identity = identities.get(principal_id, {})
    risk = role_risk_score(
        role=str(event.get("role")),
        provider=str(event.get("provider")),
        scope=event.get("scope"),
        state=str(event.get("assignmentType") or ""),
    )
    return sanitize_assignment(
        {
            "eventId": event.get("id"),
            "timestamp": event.get("timestamp"),
            "action": event.get("action"),
            "provider": event.get("provider"),
            "name": identity.get("displayName"),
            "displayName": identity.get("displayName"),
            "userPrincipalName": identity.get("userPrincipalName"),
            "mail": identity.get("mail"),
            "objectId": principal_id or None,
            "identityType": identity.get("identityType") or event.get("principalType"),
            "role": event.get("role"),
            "scope": event.get("scope"),
            "assignmentType": event.get("assignmentType"),
            "origin": event.get("source"),
            "risk": risk["level"],
            "riskScore": risk["score"],
            "resolutionStatus": "resolved" if identity else "unresolved",
        }
    )


def list_privilege_timeline_events(
    days: int = 30,
    provider: str = "all",
    action: str = "all",
    limit: int = 200,
) -> list[dict[str, Any]]:
    identities = _identity_index()
    raw = _load_events()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max(1, int(days)))
    rows: list[dict[str, Any]] = []
    for event in raw:
        dt = _parse_dt(str(event.get("timestamp") or ""))
        if dt and dt < cutoff:
            continue
        if provider.lower() != "all" and str(event.get("provider", "")).lower() != provider.lower():
            continue
        if action.lower() != "all" and str(event.get("action", "")).lower() != action.lower():
            continue
        rows.append(_event_row(event, identities))
    rows.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return rows[: max(1, min(int(limit), 1000))]


def get_identity_privilege_timeline(identity_identifier: str, days: int = 90, limit: int = 200) -> dict[str, Any]:
    q = _normalize(identity_identifier)
    identities = _identity_index()
    match_id: str | None = None
    match_identity: dict[str, Any] | None = None
    for principal_id, item in identities.items():
        if q in {
            _normalize(principal_id),
            _normalize(str(item.get("displayName") or "")),
            _normalize(str(item.get("userPrincipalName") or "")),
            _normalize(str(item.get("mail") or "")),
        }:
            match_id = principal_id
            match_identity = item
            break
    if not match_id:
        raise RuntimeError(f"Identidade `{identity_identifier}` não encontrada no escopo atual.")

    raw = _load_events()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max(1, int(days)))
    rows: list[dict[str, Any]] = []
    for event in raw:
        if str(event.get("principalId")) != str(match_id):
            continue
        dt = _parse_dt(str(event.get("timestamp") or ""))
        if dt and dt < cutoff:
            continue
        rows.append(_event_row(event, identities))
    rows.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    rows = rows[: max(1, min(int(limit), 1000))]
    summary = Counter([str(item.get("action") or "Unknown") for item in rows])
    return {
        "identity": sanitize_assignment(
            {
                "displayName": match_identity.get("displayName"),
                "name": match_identity.get("displayName"),
                "userPrincipalName": match_identity.get("userPrincipalName"),
                "mail": match_identity.get("mail"),
                "objectId": match_id,
                "identityType": match_identity.get("identityType"),
            }
        ),
        "events_count": len(rows),
        "by_action": dict(summary),
        "events": rows,
    }


def summarize_privilege_timeline(days: int = 30) -> dict[str, Any]:
    rows = list_privilege_timeline_events(days=days, provider="all", action="all", limit=1000)
    by_action = Counter([str(item.get("action") or "Unknown") for item in rows])
    by_provider = Counter([str(item.get("provider") or "Unknown") for item in rows])
    high_risk_changes = [row for row in rows if int(row.get("riskScore") or 0) >= 90]
    unresolved = [row for row in rows if str(row.get("resolutionStatus")) == "unresolved"]
    return {
        "days": days,
        "total_events": len(rows),
        "by_action": dict(by_action),
        "by_provider": dict(by_provider),
        "critical_or_high_events": len(high_risk_changes),
        "unresolved_identity_events": len(unresolved),
    }


def build_privilege_timeline_report(days: int = 30, top: int = 10) -> dict[str, Any]:
    rows = list_privilege_timeline_events(days=days, provider="all", action="all", limit=5000)
    top_n = max(1, min(int(top), 100))

    by_identity = Counter()
    by_role = Counter()
    by_scope = Counter()
    by_action = Counter()
    for row in rows:
        identity = str(row.get("displayName") or row.get("userPrincipalName") or row.get("objectId") or "N/A")
        by_identity[identity] += 1
        role = str(row.get("role") or "N/A")
        by_role[role] += 1
        scope = str(row.get("scope") or "N/A")
        by_scope[scope] += 1
        by_action[str(row.get("action") or "Unknown")] += 1

    top_grants = [row for row in rows if str(row.get("action", "")).lower() == "grant"][:top_n]
    top_revokes = [row for row in rows if str(row.get("action", "")).lower() == "revoke"][:top_n]
    top_activations = [row for row in rows if str(row.get("action", "")).lower() == "activate"][:top_n]
    critical = [row for row in rows if int(row.get("riskScore") or 0) >= 90][:top_n]

    summary = summarize_privilege_timeline(days=days)
    return {
        "summary": summary,
        "top_by_identity": [{"identity": k, "events": v} for k, v in by_identity.most_common(top_n)],
        "top_by_role": [{"role": k, "events": v} for k, v in by_role.most_common(top_n)],
        "top_by_scope": [{"scope": k, "events": v} for k, v in by_scope.most_common(top_n)],
        "top_grants": top_grants,
        "top_revokes": top_revokes,
        "top_activations": top_activations,
        "critical_events": critical,
        "events_sample": rows[:top_n],
        "by_action": dict(by_action),
    }


def _report_narrative(report: dict[str, Any], top: int) -> str:
    summary = report.get("summary", {})
    lines = [
        f"Relatório de timeline de privilégios ({summary.get('days', 30)} dias):",
        f"- Eventos totais: **{summary.get('total_events', 0)}**",
        f"- Eventos críticos/altos: **{summary.get('critical_or_high_events', 0)}**",
        f"- Identidades não resolvidas: **{summary.get('unresolved_identity_events', 0)}**",
        "",
        f"Top {top} identidades por volume de mudanças:",
    ]
    for item in report.get("top_by_identity", [])[:top]:
        lines.append(f"- {item['identity']}: {item['events']} evento(s)")
    lines.append("")
    lines.append(f"Top {top} roles por mudanças:")
    for item in report.get("top_by_role", [])[:top]:
        lines.append(f"- {item['role']}: {item['events']} evento(s)")
    lines.append("")
    lines.append(f"Top {top} escopos por mudanças:")
    for item in report.get("top_by_scope", [])[:top]:
        lines.append(f"- {item['scope']}: {item['events']} evento(s)")
    return "\n".join(lines)


def _format_timeline(rows: list[dict[str, Any]], limit: int = 20) -> str:
    lines: list[str] = []
    for item in rows[: max(1, limit)]:
        lines.append(
            "- "
            f"{item.get('timestamp')} | "
            f"{item.get('action')} | "
            f"{item.get('provider')} | "
            f"{item.get('displayName') or item.get('objectId') or 'N/A'} | "
            f"Tipo: {item.get('identityType') or 'N/A'} | "
            f"Role/Permissão: {item.get('role') or 'N/A'} | "
            f"Escopo: {item.get('scope') or 'N/A'} | "
            f"Origem: {item.get('origin') or 'N/A'} | "
            f"Risco: {item.get('risk') or 'N/A'} ({item.get('riskScore') or 0}/100)"
        )
    return "\n".join(lines) if lines else "- Nenhum evento encontrado."


def answer_timeline_question(question: str, limit: int = 20) -> dict[str, Any]:
    q = _normalize(question)
    days = 30
    if "90" in q:
        days = 90
    elif "180" in q:
        days = 180

    if "relatorio" in q or "report" in q:
        report = build_privilege_timeline_report(days=days, top=max(1, min(limit, 20)))
        return {
            "intent": "timeline_report",
            "narrative": _report_narrative(report, top=max(1, min(limit, 20))),
            "data": report,
        }

    if "resumo" in q or "visao geral" in q or "sumario" in q:
        summary = summarize_privilege_timeline(days=days)
        narrative = (
            f"Resumo da timeline de privilégios ({days} dias):\n"
            f"- Total de eventos: **{summary.get('total_events', 0)}**\n"
            f"- Eventos críticos/altos: **{summary.get('critical_or_high_events', 0)}**\n"
            f"- Eventos com identidade não resolvida: **{summary.get('unresolved_identity_events', 0)}**"
        )
        return {"intent": "timeline_summary", "narrative": narrative, "data": summary}

    email_match = re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", q)
    if email_match:
        upn = email_match.group(0)
        result = get_identity_privilege_timeline(identity_identifier=upn, days=days, limit=limit)
        narrative = [
            f"Timeline de privilégios da identidade {result.get('identity', {}).get('userPrincipalName') or upn}:",
            f"- Eventos encontrados: **{result.get('events_count', 0)}**",
            "",
            _format_timeline(result.get("events", []), limit=limit),
        ]
        return {"intent": "timeline_identity", "narrative": "\n".join(narrative), "data": result}

    action = "all"
    if "recebeu" in q or "ganhou" in q or "grant" in q:
        action = "grant"
    elif "removeu" in q or "perdeu" in q or "revoke" in q:
        action = "revoke"
    elif "ativ" in q:
        action = "activate"
    provider = "all"
    if "entra" in q:
        provider = "entra"
    elif "azure" in q or "rbac" in q:
        provider = "azure"

    rows = list_privilege_timeline_events(days=days, provider=provider, action=action, limit=limit)
    narrative = [
        f"Timeline de mudanças de privilégios ({days} dias): **{len(rows)}** evento(s)",
        "",
        _format_timeline(rows, limit=limit),
    ]
    return {"intent": "timeline_events", "narrative": "\n".join(narrative), "data": {"count": len(rows), "rows": rows}}
