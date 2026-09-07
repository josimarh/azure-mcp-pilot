from __future__ import annotations

import unicodedata
from typing import Any

from services.azure_rbac import list_role_assignments
from services.blast_radius import compute_identity_blast_radius
from services.entra_authentication import get_user_authentication_methods
from services.entra_groups import list_group_owner_ids, list_groups, list_user_group_ids
from services.entra_pim import list_pim_assignments, list_permanent_privileged_assignments
from services.entra_roles import list_directory_role_members, PRIVILEGED_ENTRA_ROLES
from services.entra_users import list_users
from services.iam_common import sanitize_assignment, sanitize_identity
from services.ownership import get_owned_objects
from services.role_risk import role_risk_score

AZURE_HIGH_ROLES = {"Owner", "User Access Administrator"}
ENTRA_ADMIN_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "User Administrator",
}


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


def _scope_level(scope: str | None) -> str:
    if not scope or scope == "/":
        return "Tenant"
    low = scope.lower()
    if "/providers/microsoft.management/managementgroups/" in low:
        return "Management Group"
    if "/resourcegroups/" in low:
        return "Resource Group"
    if "/providers/" in low:
        return "Resource"
    if "/subscriptions/" in low:
        return "Subscription"
    return "Unknown"


def build_identity_360(user_identifier: str) -> dict[str, Any]:
    user = _resolve_user(user_identifier)
    user_id = str(user.get("id"))
    group_ids = set(list_user_group_ids(user_id))
    groups = {str(g.get("id")): g for g in list_groups()}

    # 1. WHO IS IT
    identity = sanitize_identity(
        {
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
            "mail": user.get("mail") or user.get("userPrincipalName"),
            "id": user_id,
            "userType": user.get("userType"),
            "accountEnabled": user.get("accountEnabled"),
            "identityOrigin": "Cloud-only" if user.get("onPremisesSyncEnabled") in (None, False) else "Hybrid",
        }
    )

    # Authentication
    try:
        auth = get_user_authentication_methods(user_id)
        authentication = {
            "isMfaRegistered": auth.get("isMfaRegistered"),
            "isPasswordlessCapable": auth.get("isPasswordlessCapable"),
            "methods": auth.get("methods", []),
            "status": "PASS" if auth.get("isMfaRegistered") else "FAIL",
        }
    except Exception as exc:
        authentication = {
            "status": "NOT_EVALUATED",
            "note": "Métodos de autenticação não puderam ser avaliados com os dados atuais.",
            "error": str(exc),
        }

    # 2/3. ENTRA privileges (direct + group + PIM eligible/active/permanent)
    entra_direct: list[dict[str, Any]] = []
    for member in list_directory_role_members():
        principal_id = str(member.get("principalId") or "")
        role = member.get("role")
        via = None
        if principal_id == user_id:
            via = "Direct"
        elif principal_id in group_ids:
            via = f"Group ({groups.get(principal_id, {}).get('displayName') or principal_id})"
        if via:
            risk = role_risk_score(str(role), "Entra")
            entra_direct.append(
                sanitize_assignment(
                    {
                        "role": role,
                        "scope": "/",
                        "via": via,
                        "assignmentType": "Direct" if via == "Direct" else "InheritedFromGroup",
                        "privileged": role in PRIVILEGED_ENTRA_ROLES,
                        "riskScore": risk["score"],
                        "risk": risk["level"],
                    }
                )
            )

    # 4. AZURE privileges (direct + group inherited)
    azure_assignments: list[dict[str, Any]] = []
    for item in list_role_assignments():
        principal_id = str(item.get("principalId") or "")
        principal_type = str(item.get("principalType") or "").lower()
        via = None
        if principal_id == user_id and principal_type == "user":
            via = "Direct"
        elif principal_type == "group" and principal_id in group_ids:
            via = f"Group ({groups.get(principal_id, {}).get('displayName') or principal_id})"
        if via:
            risk = role_risk_score(str(item.get("role")), "Azure", scope=item.get("scope"))
            azure_assignments.append(
                sanitize_assignment(
                    {
                        "role": item.get("role"),
                        "scope": item.get("scope"),
                        "scopeLevel": _scope_level(item.get("scope")),
                        "via": via,
                        "assignmentType": "Direct" if via == "Direct" else "InheritedFromGroup",
                        "riskScore": risk["score"],
                        "risk": risk["level"],
                    }
                )
            )

    # PIM (Eligible / Active / Permanent) for this identity
    pim_eligible: list[dict[str, Any]] = []
    pim_active: list[dict[str, Any]] = []
    pim_permanent: list[dict[str, Any]] = []
    for item in list_pim_assignments() + list_permanent_privileged_assignments():
        if str(item.get("principalId")) != user_id:
            continue
        risk = role_risk_score(
            str(item.get("role")),
            str(item.get("provider")),
            scope=item.get("scope"),
            state=str(item.get("state") or ""),
        )
        row = sanitize_assignment(
            {
                "provider": item.get("provider"),
                "role": item.get("role"),
                "scope": item.get("scope"),
                "state": item.get("state"),
                "origin": item.get("origin"),
                "riskScore": risk["score"],
                "risk": risk["level"],
            }
        )
        state = str(item.get("state"))
        if state == "Eligible":
            pim_eligible.append(row)
        elif state == "Active":
            pim_active.append(row)
        elif state == "Permanent":
            pim_permanent.append(row)

    # Group membership (with privileged flag + owners)
    membership: list[dict[str, Any]] = []
    for gid in group_ids:
        group = groups.get(gid, {})
        owner_ids = list_group_owner_ids(gid)
        membership.append(
            sanitize_assignment(
                {
                    "groupId": gid,
                    "displayName": group.get("displayName"),
                    "roleAssignable": bool(group.get("isAssignableToRole")),
                    "hasOwner": bool(owner_ids),
                }
            )
        )

    # Ownership
    try:
        ownership = get_owned_objects(user_id, limit=200)
    except Exception as exc:
        ownership = {"count": 0, "ownedObjects": [], "note": str(exc)}

    # Risk: blast radius + toxic + findings
    try:
        blast = compute_identity_blast_radius(user_id)
    except Exception:
        blast = {"blastRadiusScore": 0, "blastRadiusLevel": "Low", "subscriptionsAffected": [], "managementGroupsAffected": []}

    entra_role_names = {str(r.get("role")) for r in entra_direct if r.get("privileged")}
    azure_role_names = {str(a.get("role")) for a in azure_assignments}
    findings: list[dict[str, Any]] = []
    if entra_role_names & ENTRA_ADMIN_ROLES and azure_role_names & AZURE_HIGH_ROLES:
        findings.append(
            {
                "id": "TOXIC-ENTRA-AZURE",
                "title": "Privilégio administrativo simultâneo Entra + Azure",
                "severity": "High",
                "evidence": f"Entra: {sorted(entra_role_names)}; Azure: {sorted(azure_role_names)}",
            }
        )
    if user.get("accountEnabled") is False and (entra_role_names or azure_role_names):
        findings.append(
            {
                "id": "DISABLED-WITH-PRIV",
                "title": "Conta desabilitada com privilégios ativos",
                "severity": "High",
                "evidence": "Usuário desabilitado ainda possui roles privilegiadas.",
            }
        )
    if str(user.get("userType", "")).lower() == "guest" and (entra_role_names or azure_role_names):
        findings.append(
            {
                "id": "GUEST-WITH-PRIV",
                "title": "Usuário convidado com privilégios",
                "severity": "High",
                "evidence": "Guest com roles privilegiadas.",
            }
        )
    if authentication.get("status") == "FAIL" and (entra_role_names or azure_role_names):
        findings.append(
            {
                "id": "PRIV-NO-MFA",
                "title": "Usuário privilegiado sem MFA registrado",
                "severity": "Critical",
                "evidence": "MFA não registrado para identidade privilegiada.",
            }
        )
    if pim_permanent and (entra_role_names or azure_role_names):
        findings.append(
            {
                "id": "PERMANENT-PRIV",
                "title": "Privilégios permanentes em vez de elegíveis via PIM",
                "severity": "Medium",
                "evidence": f"{len(pim_permanent)} atribuição(ões) permanente(s).",
            }
        )

    overall_score = max(
        [int(blast.get("blastRadiusScore") or 0)]
        + [int(r.get("riskScore") or 0) for r in entra_direct]
        + [int(a.get("riskScore") or 0) for a in azure_assignments]
        + [0]
    )
    if findings:
        overall_score = min(100, overall_score + 3 * len(findings))
    overall_level = (
        "Critical" if overall_score >= 90 else "High" if overall_score >= 75 else "Medium" if overall_score >= 50 else "Low"
    )

    return {
        "identity": identity,
        "authentication": authentication,
        "entraPrivileges": {
            "assignments": entra_direct,
            "count": len(entra_direct),
        },
        "azurePrivileges": {
            "assignments": azure_assignments,
            "count": len(azure_assignments),
        },
        "pim": {
            "eligible": pim_eligible,
            "active": pim_active,
            "permanent": pim_permanent,
        },
        "groupMembership": membership,
        "ownership": ownership,
        "risk": {
            "overallScore": overall_score,
            "overallLevel": overall_level,
            "blastRadiusScore": blast.get("blastRadiusScore"),
            "blastRadiusLevel": blast.get("blastRadiusLevel"),
            "subscriptionsAffected": blast.get("subscriptionsAffected", []),
            "managementGroupsAffected": blast.get("managementGroupsAffected", []),
            "canGrantAccess": blast.get("canGrantAccess", False),
            "findings": findings,
        },
    }


def _format_identity_360(data: dict[str, Any]) -> str:
    identity = data.get("identity", {})
    auth = data.get("authentication", {})
    entra = data.get("entraPrivileges", {})
    azure = data.get("azurePrivileges", {})
    pim = data.get("pim", {})
    ownership = data.get("ownership", {})
    risk = data.get("risk", {})

    lines = [
        f"Identity 360 — {identity.get('displayName') or identity.get('userPrincipalName') or 'N/A'}",
        "",
        "QUEM É:",
        f"- UPN: {identity.get('userPrincipalName') or 'N/A'}",
        f"- Object ID: {identity.get('id') or 'N/A'}",
        f"- Tipo: {identity.get('userType') or 'N/A'} | Habilitado: {identity.get('accountEnabled')}",
        f"- Origem: {identity.get('identityOrigin') or 'N/A'}",
        "",
        "AUTENTICAÇÃO:",
    ]
    if auth.get("status") == "NOT_EVALUATED":
        lines.append(f"- NOT EVALUATED: {auth.get('note')}")
    else:
        lines.append(
            f"- MFA registrado: {auth.get('isMfaRegistered')} | Passwordless: {auth.get('isPasswordlessCapable')} "
            f"| Métodos: {', '.join(auth.get('methods', [])) or 'N/A'}"
        )

    lines.append("")
    lines.append("A QUE POSSUI ACESSO (Entra ID):")
    if entra.get("assignments"):
        for a in entra["assignments"]:
            lines.append(
                f"- {a.get('role')} | Via: {a.get('via')} | Risco: {a.get('risk')} ({a.get('riskScore')}/100)"
            )
    else:
        lines.append("- Nenhuma role Entra atribuída.")

    lines.append("")
    lines.append("A QUE POSSUI ACESSO (Azure RBAC):")
    if azure.get("assignments"):
        for a in azure["assignments"]:
            lines.append(
                f"- {a.get('role')} | Escopo: {a.get('scope')} ({a.get('scopeLevel')}) | Via: {a.get('via')} "
                f"| Risco: {a.get('risk')} ({a.get('riskScore')}/100)"
            )
    else:
        lines.append("- Nenhuma role Azure atribuída (direta ou por grupo).")

    lines.append("")
    lines.append("COMO RECEBEU (PIM):")
    lines.append(
        f"- Eligible: {len(pim.get('eligible', []))} | Active: {len(pim.get('active', []))} "
        f"| Permanent: {len(pim.get('permanent', []))}"
    )

    lines.append("")
    lines.append("QUEM É RESPONSÁVEL / OWNERSHIP:")
    owned = ownership.get("ownedObjects", [])
    if owned:
        for o in owned[:10]:
            lines.append(f"- {o.get('objectType')}: {o.get('objectName')} (privilegiado: {'Sim' if o.get('privileged') else 'Não'})")
    else:
        lines.append("- Não é owner de objetos identificados.")

    lines.append("")
    lines.append("QUAL O RISCO:")
    lines.append(f"- Score geral: {risk.get('overallLevel')} ({risk.get('overallScore')}/100)")
    lines.append(
        f"- Blast radius: {risk.get('blastRadiusLevel')} ({risk.get('blastRadiusScore')}/100) "
        f"| Subscriptions: {len(risk.get('subscriptionsAffected', []))} "
        f"| Management Groups: {len(risk.get('managementGroupsAffected', []))} "
        f"| Pode conceder acesso: {'Sim' if risk.get('canGrantAccess') else 'Não'}"
    )
    findings = risk.get("findings", [])
    if findings:
        lines.append("- Findings:")
        for f in findings:
            lines.append(f"  * [{f.get('severity')}] {f.get('title')} — {f.get('evidence')}")
    else:
        lines.append("- Nenhum finding crítico correlacionado.")

    lines.append("")
    lines.append(
        "Observação: OWNERSHIP, PERMISSION e EFFECTIVE ACCESS são apresentados separadamente; "
        "ser owner de um objeto não concede automaticamente as permissões desse objeto."
    )
    return "\n".join(lines)


def answer_identity_360(user_identifier: str) -> dict[str, Any]:
    data = build_identity_360(user_identifier)
    return {
        "intent": "identity_360",
        "narrative": _format_identity_360(data),
        "data": data,
    }
