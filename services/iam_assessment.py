from __future__ import annotations

import re
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from services.azure_management_groups import list_management_groups
from services.azure_rbac import list_deny_assignments, list_privileged_role_assignments, list_role_assignments
from services.azure_resources import summarize_resource_groups, summarize_resources, summarize_subscriptions
from services.azure_roles import list_dangerous_custom_roles
from services.entra_apps import (
    list_applications_without_owners,
    list_secrets_expiring,
    list_service_principals_with_graph_critical_permissions,
)
from services.entra_conditional_access import safe_conditional_access_policies
from services.entra_pim import answer_pim_question, safe_list_pim_assignments
from services.entra_roles import list_privileged_directory_role_members
from services.entra_users import list_disabled_users, list_guest_users, list_users, present_users
from services.entra_workload_identities import list_managed_identities, list_service_principals
from services.agent_identities import answer_agent_question
from services.effective_access import get_user_effective_azure_access, list_orphan_role_assignments
from services.iam_common import safe_collect, sanitize_assignment
from services.identity_risk import correlate_privileged_identities
from services.privilege_timeline import answer_timeline_question, summarize_privilege_timeline
from services.identity_360 import answer_identity_360
from services.entra_authentication import (
    assess_privileged_mfa,
    get_authentication_strength_summary,
    list_users_without_mfa,
    list_users_with_passkey,
    list_users_with_weak_authentication,
    safe_authentication_methods_summary,
    safe_privileged_mfa,
)
from services.ownership import answer_ownership_question, safe_objects_without_owner
from services.toxic_combinations import answer_toxic_question, safe_toxic_combinations
from services.blast_radius import answer_blast_radius_question

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SUBSCRIPTION_PRIVILEGED_ROLES = {"Owner", "User Access Administrator", "Contributor"}


def _normalize(text: str) -> str:
    norm = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in norm if not unicodedata.combining(ch)).lower()


def _identity_name(row: dict[str, Any]) -> str:
    return str(row.get("name") or row.get("displayName") or "N/A")


def _format_identity_list(rows: list[dict[str, Any]], limit: int = 20) -> str:
    lines: list[str] = []
    for item in rows[: max(1, limit)]:
        name = _identity_name(item)
        upn = item.get("userPrincipalName")
        mail = item.get("mail")
        role = item.get("role") or item.get("permission") or "N/A"
        risk = item.get("risk") or "N/A"
        risk_score = item.get("riskScore")
        risk_text = f"{risk} ({risk_score}/100)" if risk_score is not None else str(risk)
        lines.append(f"- **{name}**")
        lines.append(f"  - Tipo: {item.get('identityType') or 'N/A'}")
        if upn:
            lines.append(f"  - UPN: {upn}")
        if mail and str(mail) != str(upn):
            lines.append(f"  - E-mail: {mail}")
        lines.append(f"  - Objeto: {item.get('objectId') or item.get('id') or 'N/A'}")
        lines.append(f"  - Role/Permissão: {role}")
        lines.append(f"  - Escopo: {item.get('scope') or 'N/A'}")
        lines.append(f"  - Tipo de atribuição: {item.get('assignmentType') or 'N/A'}")
        lines.append(f"  - Origem: {item.get('origin') or 'N/A'}")
        lines.append(f"  - Risco: {risk_text}")
        lines.append("")
    return "\n".join(lines) if lines else "- Nenhum resultado."


def _build_privileged_users_view(limit: int) -> dict[str, Any]:
    entra_rows = [r for r in list_privileged_directory_role_members() if r.get("identityType") == "User"]
    azure_rows = [
        r
        for r in list_privileged_role_assignments()
        if str(r.get("principalType", "")).lower() == "user"
    ]
    counter = Counter([r.get("role") for r in entra_rows + azure_rows if r.get("role")])
    identities = correlate_privileged_identities()
    users = [r for r in identities if str(r.get("identityType", "")).lower() == "user"]
    return {
        "summary": {
            "total_privileged_users": len(users),
            "by_role": dict(counter),
        },
        "rows": users[: max(1, limit)],
    }


def _users_with_role(role_name: str, limit: int) -> list[dict[str, Any]]:
    rows = []
    for item in list_privileged_directory_role_members():
        if str(item.get("role", "")).lower() == role_name.lower():
            rows.append(item)
    for item in list_privileged_role_assignments():
        if str(item.get("role", "")).lower() == role_name.lower():
            rows.append(item)
    return rows[: max(1, limit)]


def _users_with_global_admin_and_owner(limit: int) -> list[dict[str, Any]]:
    ga = {str(r.get("principalId")) for r in list_privileged_directory_role_members() if r.get("role") == "Global Administrator"}
    owner = {
        str(r.get("principalId"))
        for r in list_privileged_role_assignments()
        if str(r.get("role")) == "Owner"
    }
    both = ga.intersection(owner)
    users_map = {str(u.get("id")): u for u in list_users() if u.get("id")}
    rows: list[dict[str, Any]] = []
    for principal_id in both:
        user = users_map.get(principal_id, {})
        rows.append(
            sanitize_assignment(
                {
                    "name": user.get("displayName"),
                    "displayName": user.get("displayName"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "mail": user.get("mail") or user.get("userPrincipalName"),
                    "objectId": principal_id,
                    "identityType": "User",
                    "role": "Global Administrator + Owner",
                    "scope": "Entra + Azure",
                    "assignmentType": "Direct",
                    "inherited": False,
                    "origin": "Correlation",
                    "risk": "High",
                }
            )
        )
    return rows[: max(1, limit)]


def _workload_with_roles(role_names: set[str], managed_identity: bool, limit: int) -> list[dict[str, Any]]:
    identities = list_managed_identities() if managed_identity else list_service_principals()
    identity_map = {str(i.get("id")): i for i in identities if i.get("id")}
    ids = set(identity_map.keys())
    rows = []
    for item in list_role_assignments():
        if str(item.get("principalId")) not in ids:
            continue
        if str(item.get("role")) not in role_names:
            continue
        identity = identity_map.get(str(item.get("principalId")), {})
        row = {
            "name": identity.get("displayName"),
            "displayName": identity.get("displayName"),
            "objectId": item.get("principalId"),
            "identityType": "ManagedIdentity" if managed_identity else "ServicePrincipal",
            "userPrincipalName": identity.get("servicePrincipalNames", [None])[0]
            if isinstance(identity.get("servicePrincipalNames"), list)
            else None,
            "mail": None,
            "role": item.get("role"),
            "scope": item.get("scope"),
            "assignmentType": item.get("assignmentType"),
            "origin": "Azure RBAC",
            "risk": "High" if item.get("role") == "Owner" else "Medium",
        }
        rows.append(row)
    return rows[: max(1, limit)]


def _coverage_status(flags: list[bool]) -> str:
    if not flags:
        return "NOT_EVALUATED"
    if all(flags):
        return "EVALUATED"
    if any(flags):
        return "PARTIAL"
    return "NOT_EVALUATED"


def _is_subscription_scope(scope: str | None) -> bool:
    if not scope:
        return False
    normalized = str(scope).strip().rstrip("/")
    return bool(re.match(r"^/subscriptions/[^/]+$", normalized, flags=re.IGNORECASE))


def get_management_group_inventory(limit: int = 50) -> dict[str, Any]:
    rows = list_management_groups()
    limited = rows[: max(1, min(int(limit), 500))]
    return {
        "count": len(rows),
        "managementGroups": limited,
    }


def get_subscription_direct_access_summary(limit: int = 20) -> dict[str, Any]:
    assignments = [
        item
        for item in list_role_assignments()
        if _is_subscription_scope(item.get("scope"))
    ]
    privileged = [item for item in assignments if str(item.get("role") or "") in SUBSCRIPTION_PRIVILEGED_ROLES]
    subscriptions = sorted({str(item.get("subscription") or "") for item in assignments if item.get("subscription")})
    identities = {str(item.get("principalId") or "") for item in assignments if item.get("principalId")}
    privileged_identities = {str(item.get("principalId") or "") for item in privileged if item.get("principalId")}
    per_subscription: dict[str, dict[str, Any]] = {}
    for item in assignments:
        sub = str(item.get("subscription") or "unknown")
        bucket = per_subscription.setdefault(sub, {"subscriptionId": sub, "assignments": 0, "privilegedAssignments": 0})
        bucket["assignments"] += 1
        if str(item.get("role") or "") in SUBSCRIPTION_PRIVILEGED_ROLES:
            bucket["privilegedAssignments"] += 1
    top_subscriptions = sorted(
        per_subscription.values(),
        key=lambda row: (
            -int(row.get("privilegedAssignments") or 0),
            -int(row.get("assignments") or 0),
            str(row.get("subscriptionId")),
        ),
    )[: max(1, min(int(limit), 100))]
    return {
        "subscriptionsWithDirectAssignments": len(subscriptions),
        "directSubscriptionAssignments": len(assignments),
        "privilegedDirectSubscriptionAssignments": len(privileged),
        "identitiesWithDirectSubscriptionAssignments": len(identities),
        "identitiesWithPrivilegedDirectSubscriptionAssignments": len(privileged_identities),
        "topSubscriptions": top_subscriptions,
    }


def _metric_text(value: Any) -> str:
    if isinstance(value, int):
        return str(value)
    return "NOT_EVALUATED"


def _domain_from_control(control: str) -> str:
    mapping = {
        "privileged-users": "Privileged Access",
        "disabled-users": "Identity Lifecycle",
        "guest-users": "External Identities",
        "applications-without-owner": "Applications",
        "secrets-expired-or-expiring": "Credentials",
        "applications-graph-critical-permissions": "Microsoft Graph/API",
        "dangerous-custom-roles": "Custom Roles",
        "deny-assignments": "Azure RBAC",
        "pim": "PIM",
        "conditional-access-policies": "Conditional Access",
        "correlated-privileges": "Identity Risk",
        "orphan-role-assignments": "Azure RBAC",
        "privilege-change-timeline": "Sign-in / Activity",
        "privileged-mfa": "Authentication",
        "toxic-combinations": "Toxic Combinations",
        "objects-without-owner": "Ownership",
        "subscriptions-inventory": "Azure Subscriptions",
        "management-groups": "Azure Management Groups",
        "subscription-direct-access": "Azure Subscription Governance",
    }
    return mapping.get(control, "General IAM")


def _recommendation_for_control(control: str) -> str:
    mapping = {
        "privileged-users": "Reduzir contas com privilégios administrativos ao mínimo necessário.",
        "disabled-users": "Remover privilégios de contas desabilitadas imediatamente.",
        "guest-users": "Revisar e restringir privilégios de identidades convidadas.",
        "applications-without-owner": "Definir owners responsáveis para todas as aplicações críticas.",
        "secrets-expired-or-expiring": "Rotacionar segredos expirados e próximos da expiração.",
        "applications-graph-critical-permissions": "Revisar e aprovar somente permissões Graph estritamente necessárias.",
        "dangerous-custom-roles": "Eliminar wildcards e reduzir escopo em custom roles.",
        "orphan-role-assignments": "Remediar role assignments órfãos e validar principalId alvo.",
        "privileged-mfa": "Exigir MFA forte para todas as identidades privilegiadas.",
        "toxic-combinations": "Corrigir segregação de função removendo combinações tóxicas.",
        "objects-without-owner": "Garantir owner ativo para objetos com impacto de segurança.",
        "subscription-direct-access": "Revisar e reduzir role assignments diretos em subscription, priorizando grupos e PIM.",
        "subscriptions-inventory": "Validar o inventário de subscriptions e padronizar baseline de governança por assinatura.",
        "management-groups": "Revisar hierarquia de Management Groups e herança de políticas/RBAC.",
    }
    return mapping.get(control, "Investigar evidência e aplicar remediação baseada em least privilege.")


def run_iam_assessment(limit_risks: int = 10) -> dict[str, Any]:
    controls: list[dict[str, Any]] = []

    privileged = safe_collect("privileged-users", lambda: _build_privileged_users_view(100))
    controls.append(privileged)

    disabled_users = safe_collect("disabled-users", list_disabled_users)
    controls.append(disabled_users)

    guests = safe_collect("guest-users", list_guest_users)
    controls.append(guests)

    app_without_owner = safe_collect("applications-without-owner", list_applications_without_owners)
    controls.append(app_without_owner)

    expired_secrets = safe_collect("secrets-expired-or-expiring", lambda: list_secrets_expiring(days=30))
    controls.append(expired_secrets)

    graph_perm = safe_collect(
        "applications-graph-critical-permissions",
        list_service_principals_with_graph_critical_permissions,
    )
    controls.append(graph_perm)

    custom_roles = safe_collect("dangerous-custom-roles", list_dangerous_custom_roles)
    controls.append(custom_roles)

    deny_assignments = safe_collect("deny-assignments", list_deny_assignments)
    controls.append(deny_assignments)

    pim = safe_list_pim_assignments()
    controls.append(pim)

    ca = safe_conditional_access_policies()
    controls.append(ca)
    subscriptions_inventory = safe_collect("subscriptions-inventory", summarize_subscriptions)
    controls.append(subscriptions_inventory)
    management_groups = safe_collect("management-groups", list_management_groups)
    controls.append(management_groups)
    subscription_direct_access = safe_collect("subscription-direct-access", get_subscription_direct_access_summary)
    controls.append(subscription_direct_access)

    identities = safe_collect("correlated-privileges", correlate_privileged_identities)
    controls.append(identities)
    orphan_assignments = safe_collect("orphan-role-assignments", list_orphan_role_assignments)
    controls.append(orphan_assignments)
    privilege_timeline = safe_collect("privilege-change-timeline", lambda: summarize_privilege_timeline(days=30))
    controls.append(privilege_timeline)
    privileged_mfa = safe_privileged_mfa()
    controls.append(privileged_mfa)
    toxic = safe_toxic_combinations()
    controls.append(toxic)
    objects_no_owner = safe_objects_without_owner()
    controls.append(objects_no_owner)

    risks: list[dict[str, Any]] = []
    not_assessed: list[dict[str, Any]] = []

    for control in controls:
        if not control.get("ok"):
            not_assessed.append({"control": control.get("control"), "note": control.get("note"), "error": control.get("error")})

    if privileged.get("ok"):
        summary = privileged["data"]["summary"]
        if summary.get("by_role", {}).get("Global Administrator", 0) > 2:
            risks.append({"risk": "Excesso de Global Administrators", "severity": "High", "control": "privileged-users"})
        if summary.get("by_role", {}).get("Owner", 0) > 5:
            risks.append({"risk": "Excesso de Owners em Azure", "severity": "High", "control": "privileged-users"})

    if disabled_users.get("ok") and identities.get("ok"):
        disabled_ids = {str(u.get("id")) for u in disabled_users["data"]}
        for row in identities["data"]:
            if str(row.get("objectId")) in disabled_ids:
                risks.append({"risk": "Conta desabilitada com privilégios ativos", "severity": "High", "control": "disabled-users"})
                break

    if guests.get("ok") and identities.get("ok"):
        guest_ids = {str(u.get("id")) for u in guests["data"]}
        for row in identities["data"]:
            if str(row.get("objectId")) in guest_ids:
                risks.append({"risk": "Usuário convidado com privilégios", "severity": "High", "control": "guest-users"})
                break

    if app_without_owner.get("ok") and app_without_owner["data"]:
        risks.append({"risk": "Aplicações sem owner", "severity": "High", "control": "applications-without-owner"})

    if expired_secrets.get("ok"):
        has_expired = any("T" in str(item.get("expiresAt", "")) and item.get("risk") == "High" for item in expired_secrets["data"])
        if has_expired:
            risks.append({"risk": "Secrets expirados em aplicações", "severity": "High", "control": "secrets-expired-or-expiring"})
        elif expired_secrets["data"]:
            risks.append({"risk": "Secrets próximos da expiração (30 dias)", "severity": "Medium", "control": "secrets-expired-or-expiring"})

    if graph_perm.get("ok") and graph_perm["data"]:
        risks.append({"risk": "Permissões críticas de Microsoft Graph em aplicações", "severity": "High", "control": "applications-graph-critical-permissions"})

    if custom_roles.get("ok") and custom_roles["data"]:
        risks.append({"risk": "Custom Roles perigosas com wildcard", "severity": "High", "control": "dangerous-custom-roles"})

    if identities.get("ok"):
        both = [r for r in identities["data"] if str(r.get("scope")) == "Entra + Azure"]
        if both:
            risks.append({"risk": "Identidades com privilégio simultâneo Entra + Azure", "severity": "High", "control": "correlated-privileges"})
        critical = [r for r in identities["data"] if int(r.get("riskScore") or 0) >= 90]
        if critical:
            risks.append(
                {
                    "risk": "Concentração de identidades com score crítico de privilégio (>=90)",
                    "severity": "High",
                    "control": "correlated-privileges",
                }
            )
        highly_concentrated = [r for r in identities["data"] if int(r.get("privilegedRolesCount") or 0) >= 3]
        if highly_concentrated:
            risks.append(
                {
                    "risk": "Possível violação de Least Privilege por concentração de roles privilegiadas",
                    "severity": "High",
                    "control": "correlated-privileges",
                }
            )

    if subscription_direct_access.get("ok"):
        sub_data = subscription_direct_access.get("data", {})
        if int(sub_data.get("privilegedDirectSubscriptionAssignments", 0)) > 0:
            risks.append(
                {
                    "risk": "Existem role assignments diretos privilegiados no escopo de subscription",
                    "severity": "High",
                    "control": "subscription-direct-access",
                }
            )
        elif int(sub_data.get("directSubscriptionAssignments", 0)) > 0:
            risks.append(
                {
                    "risk": "Existem role assignments diretos no escopo de subscription (revisar least privilege)",
                    "severity": "Medium",
                    "control": "subscription-direct-access",
                }
            )

    if orphan_assignments.get("ok") and orphan_assignments["data"]:
        risks.append(
            {
                "risk": "Role assignments órfãos em Azure RBAC (principal não resolvido)",
                "severity": "High",
                "control": "orphan-role-assignments",
            }
        )
    if privilege_timeline.get("ok"):
        timeline = privilege_timeline["data"]
        if int(timeline.get("critical_or_high_events", 0)) >= 2:
            risks.append(
                {
                    "risk": "Múltiplas mudanças críticas de privilégio no período recente",
                    "severity": "High",
                    "control": "privilege-change-timeline",
                }
            )
        if int(timeline.get("unresolved_identity_events", 0)) >= 1:
            risks.append(
                {
                    "risk": "Eventos de privilégio com identidade não resolvida",
                    "severity": "High",
                    "control": "privilege-change-timeline",
                }
            )

    if privileged_mfa.get("ok"):
        mfa_data = privileged_mfa["data"]
        if mfa_data.get("privileged_without_mfa"):
            risks.append(
                {
                    "risk": "Usuários privilegiados sem MFA registrado",
                    "severity": "Critical",
                    "control": "privileged-mfa",
                }
            )
        if mfa_data.get("privileged_weak_methods"):
            risks.append(
                {
                    "risk": "Usuários privilegiados usando apenas métodos de autenticação fracos",
                    "severity": "High",
                    "control": "privileged-mfa",
                }
            )

    if toxic.get("ok") and toxic["data"]:
        risks.append(
            {
                "risk": "Toxic combinations / possíveis violações de Separation of Duties",
                "severity": "High",
                "control": "toxic-combinations",
            }
        )

    if objects_no_owner.get("ok"):
        privileged_no_owner = [o for o in objects_no_owner["data"] if o.get("privileged")]
        if privileged_no_owner:
            risks.append(
                {
                    "risk": "Objetos privilegiados sem owner definido",
                    "severity": "High",
                    "control": "objects-without-owner",
                }
            )

    all_risks_sorted = sorted(
        risks,
        key=lambda r: (
            SEVERITY_ORDER.get(str(r.get("severity")), 99),
            str(r.get("risk") or ""),
        ),
    )
    risks_sorted = all_risks_sorted[: max(1, int(limit_risks))]

    controls_map = {str(c.get("control")): c for c in controls}
    coverage = {
        "Microsoft Entra Users": _coverage_status(
            [
                bool(controls_map.get("privileged-users", {}).get("ok")),
                bool(controls_map.get("disabled-users", {}).get("ok")),
                bool(controls_map.get("guest-users", {}).get("ok")),
            ]
        ),
        "Entra Roles": _coverage_status([bool(controls_map.get("privileged-users", {}).get("ok"))]),
        "PIM": _coverage_status([bool(controls_map.get("pim", {}).get("ok"))]),
        "Azure RBAC": _coverage_status(
            [
                bool(controls_map.get("correlated-privileges", {}).get("ok")),
                bool(controls_map.get("orphan-role-assignments", {}).get("ok")),
                bool(controls_map.get("dangerous-custom-roles", {}).get("ok")),
            ]
        ),
        "Applications": _coverage_status(
            [
                bool(controls_map.get("applications-without-owner", {}).get("ok")),
                bool(controls_map.get("secrets-expired-or-expiring", {}).get("ok")),
            ]
        ),
        "Service Principals": _coverage_status(
            [
                bool(controls_map.get("applications-graph-critical-permissions", {}).get("ok")),
                bool(controls_map.get("correlated-privileges", {}).get("ok")),
            ]
        ),
        "Managed Identities": _coverage_status([bool(controls_map.get("correlated-privileges", {}).get("ok"))]),
        "Agent Identities": "PARTIAL",
        "Microsoft Graph/API": _coverage_status([bool(controls_map.get("applications-graph-critical-permissions", {}).get("ok"))]),
        "Authentication": _coverage_status([bool(controls_map.get("privileged-mfa", {}).get("ok"))]),
        "Conditional Access": _coverage_status([bool(controls_map.get("conditional-access-policies", {}).get("ok"))]),
        "Subscriptions & Management Groups": _coverage_status(
            [
                bool(controls_map.get("subscriptions-inventory", {}).get("ok")),
                bool(controls_map.get("management-groups", {}).get("ok")),
                bool(controls_map.get("subscription-direct-access", {}).get("ok")),
            ]
        ),
        "Identity Governance": "NOT_EVALUATED",
        "Sign-in / Activity": _coverage_status([bool(controls_map.get("privilege-change-timeline", {}).get("ok"))]),
        "Ownership": _coverage_status(
            [
                bool(controls_map.get("applications-without-owner", {}).get("ok")),
                bool(controls_map.get("objects-without-owner", {}).get("ok")),
            ]
        ),
    }

    privileged_summary = controls_map.get("privileged-users", {}).get("data", {}).get("summary", {})
    identities_rows = controls_map.get("correlated-privileges", {}).get("data", []) if controls_map.get("correlated-privileges", {}).get("ok") else []
    app_graph_rows = controls_map.get("applications-graph-critical-permissions", {}).get("data", []) if controls_map.get("applications-graph-critical-permissions", {}).get("ok") else []
    pim_rows = controls_map.get("pim", {}).get("data", []) if controls_map.get("pim", {}).get("ok") else []
    guest_rows = controls_map.get("guest-users", {}).get("data", []) if controls_map.get("guest-users", {}).get("ok") else []
    mfa_data = controls_map.get("privileged-mfa", {}).get("data", {}) if controls_map.get("privileged-mfa", {}).get("ok") else {}
    subscriptions_data = controls_map.get("subscriptions-inventory", {}).get("data", {}) if controls_map.get("subscriptions-inventory", {}).get("ok") else {}
    management_groups_data = controls_map.get("management-groups", {}).get("data", []) if controls_map.get("management-groups", {}).get("ok") else []
    subscription_direct_data = controls_map.get("subscription-direct-access", {}).get("data", {}) if controls_map.get("subscription-direct-access", {}).get("ok") else {}

    metrics = {
        "privilegedHumanIdentities": privileged_summary.get("total_privileged_users")
        if controls_map.get("privileged-users", {}).get("ok")
        else "NOT_EVALUATED",
        "privilegedWorkloadIdentities": (
            sum(1 for row in identities_rows if str(row.get("identityType", "")).lower() in {"serviceprincipal", "managedidentity"})
            if controls_map.get("correlated-privileges", {}).get("ok")
            else "NOT_EVALUATED"
        ),
        "pimEligibleAssignments": (
            sum(1 for row in pim_rows if str(row.get("state")) == "Eligible")
            if controls_map.get("pim", {}).get("ok")
            else "NOT_EVALUATED"
        ),
        "pimActiveAssignments": (
            sum(1 for row in pim_rows if str(row.get("state")) == "Active")
            if controls_map.get("pim", {}).get("ok")
            else "NOT_EVALUATED"
        ),
        "permanentPrivilegedAssignments": (
            sum(1 for row in pim_rows if str(row.get("state")) == "Permanent")
            if controls_map.get("pim", {}).get("ok")
            else "NOT_EVALUATED"
        ),
        "guestIdentitiesWithPrivilege": (
            sum(1 for row in identities_rows if str(row.get("objectId")) in {str(g.get("id")) for g in guest_rows})
            if controls_map.get("guest-users", {}).get("ok") and controls_map.get("correlated-privileges", {}).get("ok")
            else "NOT_EVALUATED"
        ),
        "applicationsWithCriticalGraphPermissions": (
            len(app_graph_rows) if controls_map.get("applications-graph-critical-permissions", {}).get("ok") else "NOT_EVALUATED"
        ),
        "usersWithoutMfaInPrivilegedSet": (
            len(mfa_data.get("privileged_without_mfa", [])) if controls_map.get("privileged-mfa", {}).get("ok") else "NOT_EVALUATED"
        ),
        "visibleSubscriptions": (
            subscriptions_data.get("subscriptions_count", "NOT_EVALUATED")
            if controls_map.get("subscriptions-inventory", {}).get("ok")
            else "NOT_EVALUATED"
        ),
        "visibleManagementGroups": (
            len(management_groups_data) if controls_map.get("management-groups", {}).get("ok") else "NOT_EVALUATED"
        ),
        "directSubscriptionRoleAssignments": (
            subscription_direct_data.get("directSubscriptionAssignments", 0)
            if controls_map.get("subscription-direct-access", {}).get("ok")
            else "NOT_EVALUATED"
        ),
        "privilegedDirectSubscriptionRoleAssignments": (
            subscription_direct_data.get("privilegedDirectSubscriptionAssignments", 0)
            if controls_map.get("subscription-direct-access", {}).get("ok")
            else "NOT_EVALUATED"
        ),
        "identitiesWithDirectSubscriptionAssignments": (
            subscription_direct_data.get("identitiesWithDirectSubscriptionAssignments", 0)
            if controls_map.get("subscription-direct-access", {}).get("ok")
            else "NOT_EVALUATED"
        ),
    }

    findings = []
    for idx, risk in enumerate(all_risks_sorted, start=1):
        control = str(risk.get("control") or "unknown")
        finding = {
            "findingId": f"iam-finding-{idx:03d}",
            "domain": _domain_from_control(control),
            "title": str(risk.get("risk") or "IAM Risk"),
            "severity": str(risk.get("severity") or "Medium").upper(),
            "status": "OPEN",
            "identity": {},
            "object": {},
            "role": {},
            "assignment": {},
            "scope": {"assessmentScope": "tenant-visible"},
            "relationships": [],
            "effectiveAccess": {},
            "privilegePaths": [],
            "blastRadius": {},
            "evidence": [f"Control evaluated: {control}"],
            "riskFactors": [str(risk.get("risk") or "")],
            "mitigatingFactors": [],
            "recommendation": {"action": _recommendation_for_control(control)},
            "confidence": "Medium",
            "coverage": {
                "control": control,
                "status": "EVALUATED" if controls_map.get(control, {}).get("ok") else "NOT_EVALUATED",
            },
        }
        findings.append(finding)

    critical_count = sum(1 for r in all_risks_sorted if str(r.get("severity")) == "Critical")
    high_count = sum(1 for r in all_risks_sorted if str(r.get("severity")) == "High")
    medium_count = sum(1 for r in all_risks_sorted if str(r.get("severity")) == "Medium")
    posture_level = "LOW"
    if critical_count > 0:
        posture_level = "CRITICAL"
    elif high_count >= 3:
        posture_level = "HIGH"
    elif high_count > 0 or medium_count >= 3:
        posture_level = "MODERATE"

    limitations = [
        {
            "domain": _domain_from_control(str(item.get("control") or "")),
            "control": item.get("control"),
            "status": "NOT_EVALUATED",
            "reason": item.get("note"),
            "error": item.get("error"),
        }
        for item in not_assessed
    ]

    top_subscriptions = subscription_direct_data.get("topSubscriptions", []) if isinstance(subscription_direct_data, dict) else []
    checklist = [
        {
            "domain": "Identity Core",
            "status": coverage.get("Microsoft Entra Users", "NOT_EVALUATED"),
            "detail": (
                f"Privileged human identities: {_metric_text(metrics.get('privilegedHumanIdentities'))}; "
                f"Privileged workload identities: {_metric_text(metrics.get('privilegedWorkloadIdentities'))}"
            ),
        },
        {
            "domain": "Subscription Governance",
            "status": coverage.get("Subscriptions & Management Groups", "NOT_EVALUATED"),
            "detail": (
                f"Visible subscriptions: {_metric_text(metrics.get('visibleSubscriptions'))}; "
                f"Direct subscription assignments: {_metric_text(metrics.get('directSubscriptionRoleAssignments'))}; "
                f"Privileged direct assignments: {_metric_text(metrics.get('privilegedDirectSubscriptionRoleAssignments'))}"
            ),
        },
        {
            "domain": "Privileged Access Model",
            "status": coverage.get("PIM", "NOT_EVALUATED"),
            "detail": (
                f"PIM active: {_metric_text(metrics.get('pimActiveAssignments'))}; "
                f"PIM eligible: {_metric_text(metrics.get('pimEligibleAssignments'))}; "
                f"Permanent assignments: {_metric_text(metrics.get('permanentPrivilegedAssignments'))}"
            ),
        },
        {
            "domain": "Authentication Strength",
            "status": coverage.get("Authentication", "NOT_EVALUATED"),
            "detail": (
                f"Privileged users without MFA: {_metric_text(metrics.get('usersWithoutMfaInPrivilegedSet'))}"
            ),
        },
        {
            "domain": "Workload Permissions",
            "status": coverage.get("Microsoft Graph/API", "NOT_EVALUATED"),
            "detail": (
                "Graph critical permissions in applications: "
                f"{_metric_text(metrics.get('applicationsWithCriticalGraphPermissions'))}"
            ),
        },
        {
            "domain": "Ownership & SoD",
            "status": (
                "EVALUATED"
                if coverage.get("Ownership") == "EVALUATED" and any(r.get("control") == "toxic-combinations" and r.get("ok") for r in controls)
                else "PARTIAL"
                if coverage.get("Ownership") in {"EVALUATED", "PARTIAL"} or any(r.get("control") == "toxic-combinations" and r.get("ok") for r in controls)
                else "NOT_EVALUATED"
            ),
            "detail": "Ownership e toxic combinations avaliados conforme cobertura disponível.",
        },
    ]

    narrative_lines = [
        "MICROSOFT IDENTITY SECURITY ASSESSMENT",
        "",
        "AUDIT MODE: ENTERPRISE",
        "",
        "EXECUTIVE SUMMARY",
        f"- Identity Security Posture: **{posture_level}**",
        f"- Top risks priorizados: **{len(risks_sorted)}**",
        f"- Controles não avaliados: **{len(not_assessed)}**",
        f"- Subscriptions visíveis: **{_metric_text(metrics.get('visibleSubscriptions'))}**",
        f"- Management Groups visíveis: **{_metric_text(metrics.get('visibleManagementGroups'))}**",
        f"- Role assignments diretos em subscription: **{_metric_text(metrics.get('directSubscriptionRoleAssignments'))}**",
        f"- Identidades com assignment direto em subscription: **{_metric_text(metrics.get('identitiesWithDirectSubscriptionAssignments'))}**",
        "",
        "AUDIT CHECKLIST",
        *[
            f"- {item['domain']}: **{item['status']}** | {item['detail']}"
            for item in checklist
        ],
        "",
        "ASSESSMENT COVERAGE",
        *[f"- {name}: **{status}**" for name, status in coverage.items()],
    ]
    if top_subscriptions:
        narrative_lines.append("")
        narrative_lines.append("SUBSCRIPTION HIGHLIGHTS")
        for row in top_subscriptions[:5]:
            narrative_lines.append(
                f"- {row.get('subscriptionId') or 'unknown'} | "
                f"Assignments diretos: {row.get('assignments', 0)} | "
                f"Privilegiados: {row.get('privilegedAssignments', 0)}"
            )
    if risks_sorted:
        narrative_lines.append("")
        narrative_lines.append("TOP RISKS")
        for idx, risk in enumerate(risks_sorted, start=1):
            narrative_lines.append(f"{idx}. {risk['risk']} (Severidade: {risk['severity']})")

    if not_assessed:
        narrative_lines.append("")
        narrative_lines.append("COVERAGE GAPS")
        for item in not_assessed:
            narrative_lines.append(
                f"- {item['control']}: {item['note']}"
            )

    remediation = [
        "REMEDIATION ROADMAP",
        "1. Reduzir Global Administrators e Owners ao mínimo operacional.",
        "2. Remover privilégios de contas desabilitadas e convidados privilegiados.",
        "3. Corrigir aplicações sem owner e rotacionar secrets expirados/próximos da expiração.",
        "4. Revisar permissões críticas de Microsoft Graph e custom roles com wildcard.",
        "5. Priorizar revisão de identidades com privilégio simultâneo Entra + Azure.",
        "6. Remediar role assignments órfãos e validar ciclo de vida das identidades.",
        "7. Priorizar remoção/downgrade de privilégios com baixa necessidade operacional (least privilege).",
        "8. Auditar periodicamente a timeline de ganho/perda de privilégios e validar aprovações.",
    ]

    return {
        "summary": {"total_risks": len(risks_sorted), "not_assessed_controls": len(not_assessed)},
        "risks": risks_sorted,
        "not_assessed": not_assessed,
        "remediation_plan": remediation,
        "assessmentId": f"iam-assessment-{uuid4()}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scope": {"type": "TenantVisibleScope", "description": "Escopo visível para a identidade autenticada"},
        "coverage": coverage,
        "auditChecklist": checklist,
        "inventory": {
            "privilegedIdentities": len(identities_rows) if controls_map.get("correlated-privileges", {}).get("ok") else "NOT_EVALUATED",
            "guestIdentities": len(guest_rows) if controls_map.get("guest-users", {}).get("ok") else "NOT_EVALUATED",
        },
        "metrics": metrics,
        "posture": {
            "identitySecurityPosture": posture_level,
            "criticalFindings": critical_count,
            "highFindings": high_count,
            "mediumFindings": medium_count,
        },
        "findings": findings,
        "topRisks": findings[: max(1, int(limit_risks))],
        "recommendations": [{"priority": idx + 1, "action": item} for idx, item in enumerate(remediation)],
        "roadmap": {
            "phases": [
                {"phase": "Immediate", "focus": "Critical and high privilege exposure"},
                {"phase": "ShortTerm", "focus": "Ownership, credential hygiene, and RBAC scope reduction"},
                {"phase": "Continuous", "focus": "Periodic timeline, SoD, and governance controls"},
            ]
        },
        "limitations": limitations,
        "technicalAppendix": {
            "evaluatedControls": [
                {"control": c.get("control"), "ok": bool(c.get("ok")), "note": c.get("note"), "error": c.get("error")}
                for c in controls
            ]
        },
        "narrative": "\n".join(narrative_lines + [""] + remediation),
    }


def answer_iam_question(question: str, limit: int = 20) -> dict[str, Any]:
    q = _normalize(question)
    has_email = bool(re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", q))

    identity_360_phrases = [
        "identity 360",
        "analise o usuario",
        "analise a usuaria",
        "mostre tudo sobre",
        "tudo sobre",
        "assessment desse usuario",
        "assessment do usuario",
        "visao completa",
    ]
    if has_email and (
        any(p in q for p in identity_360_phrases)
        or ("analise" in q and "usuario" in q)
        or ("analise" in q)
        or ("qual o acesso de" in q)
    ):
        upn = re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", q).group(0)
        return answer_identity_360(user_identifier=upn)

    mfa_triggers = [
        "mfa",
        "metodo de autenticacao",
        "metodos de autenticacao",
        "autenticacao",
        "passwordless",
        "fido",
        "authenticator",
        "hello for business",
        "temporary access pass",
    ]
    if any(term in q for term in mfa_triggers):
        if has_email:
            from services.entra_authentication import get_user_authentication_methods

            upn = re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", q).group(0)
            auth = get_user_authentication_methods(upn)
            narrative = (
                f"Métodos de autenticação de {auth.get('userPrincipalName') or upn}:\n"
                f"- MFA registrado: {auth.get('isMfaRegistered')}\n"
                f"- Passwordless: {auth.get('isPasswordlessCapable')}\n"
                f"- Métodos: {', '.join(auth.get('methods', [])) or 'N/A'}"
            )
            return {"intent": "user_authentication_methods", "narrative": narrative, "data": auth}
        if "passkey" in q or "fido2" in q:
            rows = list_users_with_passkey()
            lines = [f"Usuários com passkey/FIDO2 registrado: **{len(rows)}**", ""]
            for u in rows[: max(1, limit)]:
                lines.append(f"- {u.get('displayName')} | UPN: {u.get('userPrincipalName')}")
            return {"intent": "users_with_passkey", "narrative": "\n".join(lines), "data": {"count": len(rows), "rows": rows}}
        if any(term in q for term in ["fraco", "fracos", "weak", "sms", "voice", "email"]):
            rows = list_users_with_weak_authentication(include_mfa_registered=True)
            lines = [f"Usuários com métodos fracos registrados: **{len(rows)}**", ""]
            for u in rows[: max(1, limit)]:
                weak = ", ".join(u.get("weakMethods", [])) or "N/A"
                lines.append(f"- {u.get('displayName')} | UPN: {u.get('userPrincipalName')} | Métodos fracos: {weak}")
            return {"intent": "users_with_weak_authentication", "narrative": "\n".join(lines), "data": {"count": len(rows), "rows": rows}}
        if any(term in q for term in ["forca", "força", "strength", "maturidade", "resumo"]):
            summary = get_authentication_strength_summary()
            breakdown = summary.get("auth_strength_breakdown", {})
            lines = [
                "Resumo de força de autenticação:",
                f"- Usuários avaliados: **{summary.get('users_evaluated', 0)}**",
                f"- MFA registrado: **{summary.get('mfa_registered', 0)}**",
                f"- Passwordless capable: **{summary.get('passwordless_capable', 0)}**",
                f"- Passkey/FIDO2 registrado: **{summary.get('users_with_passkey_or_fido2', 0)}**",
                f"- Métodos fracos registrados: **{summary.get('users_with_weak_methods_registered', 0)}**",
                "",
                "Distribuição de força:",
                f"- STRONG: **{breakdown.get('STRONG', 0)}**",
                f"- MIXED: **{breakdown.get('MIXED', 0)}**",
                f"- WEAK_ONLY: **{breakdown.get('WEAK_ONLY', 0)}**",
                f"- NO_METHODS: **{breakdown.get('NO_METHODS', 0)}**",
                f"- UNKNOWN: **{breakdown.get('UNKNOWN', 0)}**",
            ]
            return {"intent": "authentication_strength_summary", "narrative": "\n".join(lines), "data": summary}
        if "privilegiad" in q or "administrador" in q or "admin" in q:
            result = assess_privileged_mfa()
            without = result.get("privileged_without_mfa", [])
            weak = result.get("privileged_weak_methods", [])
            lines = [
                f"Assessment de MFA de usuários privilegiados:",
                f"- Privilegiados avaliados: **{result.get('privileged_users_evaluated', 0)}**",
                f"- Sem MFA: **{len(without)}**",
                f"- Apenas métodos fracos: **{len(weak)}**",
            ]
            for u in without[: max(1, limit)]:
                lines.append(f"  * Sem MFA: {u.get('displayName')} ({u.get('userPrincipalName')})")
            return {"intent": "privileged_mfa_assessment", "narrative": "\n".join(lines), "data": result}
        rows = list_users_without_mfa()
        lines = [f"Usuários sem MFA registrado: **{len(rows)}**", ""]
        for u in rows[: max(1, limit)]:
            lines.append(f"- {u.get('displayName')} | UPN: {u.get('userPrincipalName')}")
        return {"intent": "users_without_mfa", "narrative": "\n".join(lines), "data": {"count": len(rows), "rows": rows}}

    if "toxic" in q or "separation of duties" in q or " sod" in q or "combinac" in q:
        return answer_toxic_question(question=question, limit=limit)

    if "blast radius" in q or "maior alcance" in q or ("alcance" in q and "identidade" in q):
        return answer_blast_radius_question(question=question, limit=limit)

    ownership_triggers = [
        "responsavel",
        "owner de",
        "e owner",
        "objetos que",
        "pelo que",
        "objetos sem owner",
        "dono direto",
        "owner direto",
        "ownership direto",
    ]
    if any(term in q for term in ownership_triggers) and "agent" not in q and "blueprint" not in q:
        return answer_ownership_question(question=question, limit=limit)

    agent_triggers = [
        "agent",
        "agente",
        "egente",
        "agnt",
        "agnte",
        "agenteses",
        "agentess",
        "blueprint",
        "ownership",
        "responsavel",
        "responsável",
    ]
    if any(term in q for term in agent_triggers):
        return answer_agent_question(question=question, limit=limit)

    timeline_triggers = [
        "timeline",
        "historico",
        "histórico",
        "quando",
        "recebeu",
        "ganhou",
        "ganhou acesso",
        "perdeu acesso",
        "recebeu role",
        "revog",
        "mudanca de privilegio",
        "mudança de privilégio",
    ]
    if any(term in q for term in timeline_triggers):
        return answer_timeline_question(question=question, limit=limit)

    pim_triggers = [
        "pim",
        "eligible",
        "elegivel",
        "elegive",
        "ativo",
        "ativa",
        "ativas",
        "ativos",
        "permanente",
        "permanent",
    ]
    if any(term in q for term in pim_triggers):
        return answer_pim_question(question=question, limit=limit)

    audit_triggers = [
        "auditoria",
        "audit",
        "assessment",
        "assessment completo",
        "10 principais riscos",
        "least privilege",
        "remediacao",
        "remediação",
        "enterprise",
        "completo",
    ]
    if any(term in q for term in audit_triggers):
        result = run_iam_assessment(limit_risks=10)
        return {"intent": "iam_assessment", "narrative": result["narrative"], "data": result}

    if "management group" in q or "management groups" in q:
        mg = get_management_group_inventory(limit=limit)
        lines = [
            f"Management Groups identificados: **{mg.get('count', 0)}**",
            "",
        ]
        for item in mg.get("managementGroups", [])[: max(1, limit)]:
            lines.append(f"- {item.get('name') or 'N/A'}")
        return {"intent": "management_groups_inventory", "narrative": "\n".join(lines), "data": mg}

    if "subscription" in q and ("permiss" in q or "rbac" in q or "diret" in q):
        sub = get_subscription_direct_access_summary(limit=limit)
        lines = [
            "Acesso direto em subscriptions:",
            f"- Subscriptions com assignments diretos: **{sub.get('subscriptionsWithDirectAssignments', 0)}**",
            f"- Assignments diretos em subscription: **{sub.get('directSubscriptionAssignments', 0)}**",
            f"- Assignments diretos privilegiados (Owner/UAA/Contributor): **{sub.get('privilegedDirectSubscriptionAssignments', 0)}**",
            f"- Identidades com assignment direto em subscription: **{sub.get('identitiesWithDirectSubscriptionAssignments', 0)}**",
            "",
            "Top subscriptions por concentração:",
        ]
        for row in sub.get("topSubscriptions", [])[: max(1, limit)]:
            lines.append(
                f"- {row.get('subscriptionId') or 'unknown'} | "
                f"Assignments: {row.get('assignments', 0)} | "
                f"Privilegiados: {row.get('privilegedAssignments', 0)}"
            )
        return {"intent": "subscription_direct_access_summary", "narrative": "\n".join(lines), "data": sub}

    if "orfa" in q and ("role assignment" in q or "rbac" in q or "permiss" in q):
        rows = list_orphan_role_assignments(limit=limit)
        return {
            "intent": "orphan_role_assignments",
            "narrative": f"Role assignments órfãos encontrados: **{len(rows)}**\n\n{_format_identity_list(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    effective_terms = ["acesso efetivo", "efetivo", "herdad", "via grupo", "transitive", "transitivo"]
    email_match = re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", q)
    if email_match and any(term in q for term in effective_terms):
        upn = email_match.group(0)
        result = get_user_effective_azure_access(user_identifier=upn, limit=limit)
        rows = result.get("assignments", [])
        narrative = [
            f"Acesso efetivo Azure RBAC de {result.get('user', {}).get('userPrincipalName') or upn}:",
            f"- Assignments diretos: **{result.get('directAssignmentsCount', 0)}**",
            f"- Assignments herdados via grupo: **{result.get('inheritedAssignmentsCount', 0)}**",
            f"- Total: **{result.get('totalAssignmentsCount', 0)}**",
            "",
            _format_identity_list(rows, limit),
        ]
        return {
            "intent": "effective_user_access",
            "narrative": "\n".join(narrative),
            "data": result,
        }

    if "global administrator e owner" in q:
        rows = _users_with_global_admin_and_owner(limit)
        narrative = (
            f"Identidades com Global Administrator e Owner encontradas: **{len(rows)}**\n\n"
            f"{_format_identity_list(rows, limit)}"
        )
        return {"intent": "global_admin_and_owner", "narrative": narrative, "data": {"count": len(rows), "rows": rows}}

    if "global administrator" in q:
        rows = _users_with_role("Global Administrator", limit)
        return {
            "intent": "global_admin_holders",
            "narrative": f"Identidades com Global Administrator: **{len(rows)}**\n\n{_format_identity_list(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    if "owner" in q and ("azure" in q or "rbac" in q or "subscription" in q):
        rows = _users_with_role("Owner", limit)
        return {
            "intent": "azure_owner_holders",
            "narrative": f"Identidades com Owner em Azure: **{len(rows)}**\n\n{_format_identity_list(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    if "service principal" in q and ("privile" in q or "owner" in q or "contributor" in q):
        rows = _workload_with_roles({"Owner", "Contributor", "User Access Administrator"}, managed_identity=False, limit=limit)
        return {
            "intent": "privileged_service_principals",
            "narrative": f"Service Principals com permissões privilegiadas: **{len(rows)}**\n\n{_format_identity_list(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    if "managed identit" in q and ("owner" in q or "contributor" in q):
        rows = _workload_with_roles({"Owner", "Contributor"}, managed_identity=True, limit=limit)
        return {
            "intent": "privileged_managed_identities",
            "narrative": f"Managed Identities com Owner/Contributor: **{len(rows)}**\n\n{_format_identity_list(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    if "aplic" in q and "sem owner" in q:
        rows = list_applications_without_owners()
        formatted = [
            {
                "name": item.get("displayName"),
                "displayName": item.get("displayName"),
                "objectId": item.get("id"),
                "identityType": "Application",
                "risk": "High",
                "origin": "Application ownership",
            }
            for item in rows
        ]
        return {
            "intent": "apps_without_owner",
            "narrative": f"Aplicações sem owner: **{len(formatted)}**\n\n{_format_identity_list(formatted, limit)}",
            "data": {"count": len(formatted), "rows": formatted},
        }

    if "secret" in q and ("expirad" in q or "expira" in q):
        days = 30 if "30" in q else 90
        rows = list_secrets_expiring(days=days)
        return {
            "intent": "application_secrets_expiring",
            "narrative": f"Secrets expirados/próximos ({days} dias): **{len(rows)}**\n\n{_format_identity_list(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    if "graph application permission" in q or "microsoft graph application permission" in q:
        rows = list_service_principals_with_graph_critical_permissions()
        return {
            "intent": "graph_critical_permissions",
            "narrative": f"Aplicações com Graph Application Permissions críticas: **{len(rows)}**\n\n{_format_identity_list(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    if "convidad" in q and ("privile" in q or "permiss" in q):
        guests = {str(u.get("id")) for u in list_guest_users()}
        correlated = [r for r in correlate_privileged_identities() if str(r.get("objectId")) in guests]
        return {
            "intent": "privileged_guests",
            "narrative": f"Usuários convidados com privilégios: **{len(correlated)}**\n\n{_format_identity_list(correlated, limit)}",
            "data": {"count": len(correlated), "rows": correlated},
        }

    if "desabilitad" in q and ("privile" in q or "permiss" in q):
        disabled = {str(u.get("id")) for u in list_disabled_users()}
        correlated = [r for r in correlate_privileged_identities() if str(r.get("objectId")) in disabled]
        return {
            "intent": "disabled_with_privileges",
            "narrative": f"Usuários desabilitados com privilégios: **{len(correlated)}**\n\n{_format_identity_list(correlated, limit)}",
            "data": {"count": len(correlated), "rows": correlated},
        }

    if "mais privilegiad" in q or "blast radius" in q or "entra e azure simult" in q:
        rows = correlate_privileged_identities()[: max(1, limit)]
        return {
            "intent": "most_privileged_identities",
            "narrative": f"Identidades mais privilegiadas encontradas: **{len(rows)}**\n\n{_format_identity_list(rows, limit)}",
            "data": {"count": len(rows), "rows": rows},
        }

    if ("risk score" in q or "score de risco" in q) and ("role" in q or "roles" in q):
        rows = correlate_privileged_identities()[: max(1, limit)]
        return {
            "intent": "privileged_role_risk_score",
            "narrative": (
                f"Score de risco para identidades com roles privilegiadas: **{len(rows)}**\n\n"
                "Modelo base: IAM Scope (Tier/Risk Tier) + calibração local de escopo e correlação.\n\n"
                f"{_format_identity_list(rows, limit)}"
            ),
            "data": {"count": len(rows), "rows": rows},
        }

    if "quant" in q and "resource group" in q:
        rg = summarize_resource_groups()
        return {
            "intent": "resource_group_count",
            "narrative": f"Resource Groups visíveis: **{rg.get('resource_groups_count', 0)}**.",
            "data": rg,
        }

    if "quant" in q and ("subscription" in q or "assinatura" in q):
        subs = summarize_subscriptions()
        return {
            "intent": "subscription_count",
            "narrative": f"Subscriptions visíveis: **{subs.get('subscriptions_count', 0)}**.",
            "data": subs,
        }

    if ("subscription" in q or "assinatura" in q) and any(
        term in q for term in ["inventario", "inventário", "completo", "detalhado", "detalhe"]
    ):
        env = summarize_resources()
        coverage = env.get("coverage", {}) if isinstance(env, dict) else {}
        subs_rows = env.get("resources_by_subscription", []) if isinstance(env, dict) else []
        lines = [
            "Inventário completo por subscription:",
            f"- Subscriptions: **{env.get('subscriptions', 'NOT_EVALUATED')}**",
            f"- Recursos totais: **{env.get('total_resources', 'NOT_EVALUATED')}**",
            f"- Resource Groups: **{env.get('resource_groups', 'NOT_EVALUATED')}**",
            f"- Cobertura de subscriptions: **{coverage.get('subscriptions', 'NOT_EVALUATED')}**",
            f"- Cobertura de recursos: **{coverage.get('resources', 'NOT_EVALUATED')}**",
            "",
            "Detalhamento por subscription:",
        ]
        for row in subs_rows[: max(1, limit)]:
            lines.append(
                f"- {row.get('displayName') or row.get('subscriptionId') or 'N/A'} | "
                f"ID: {row.get('subscriptionId') or 'N/A'} | "
                f"State: {row.get('state') or 'Unknown'} | "
                f"Recursos: {row.get('resources', 'N/A')} | "
                f"RGs: {row.get('resourceGroups', 'N/A')} | "
                f"Locations: {row.get('locations', 'N/A')}"
            )
        return {
            "intent": "subscription_inventory_complete",
            "narrative": "\n".join(lines),
            "data": env,
        }

    # Default IAM answer: privileged users summary
    view = _build_privileged_users_view(limit)
    by_role = view["summary"]["by_role"]
    summary_lines = [
        f"Usuários privilegiados encontrados: **{view['summary']['total_privileged_users']}**",
        "",
        f"Global Administrator: {by_role.get('Global Administrator', 0)}",
        f"Privileged Role Administrator: {by_role.get('Privileged Role Administrator', 0)}",
        f"Owner Azure: {by_role.get('Owner', 0)}",
        f"User Access Administrator: {by_role.get('User Access Administrator', 0)}",
        "",
        "Detalhes:",
        _format_identity_list(view["rows"], limit),
    ]
    return {
        "intent": "default_iam_privileged_summary",
        "narrative": "\n".join(summary_lines),
        "data": view,
    }
