from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from services.azure_graph import (
    get_environment_summary as azure_get_environment_summary,
    list_public_ip_resources as azure_list_public_ip_resources,
    list_resources as azure_list_resources,
)
from services.azure_graph import get_subscriptions_count as azure_get_subscriptions_count
from services.azure_rbac import list_deny_assignments as azure_list_deny_assignments
from services.azure_rbac import list_privileged_role_assignments as azure_list_privileged_role_assignments
from services.azure_rbac import list_role_assignments as azure_list_role_assignments
from services.docs import search_official_guidance as docs_search_official_guidance
from services.app_provenance import (
    list_application_provenance as provenance_list_application_provenance,
)
from services.app_provenance import (
    summarize_application_provenance as provenance_summarize_application_provenance,
)
from services.capability_service import (
    capability_answer_question,
    capability_assessment,
    capability_directory_objects,
    capability_domain_coverage,
    capability_domains,
    capability_execute,
    capability_explain_routing,
    capability_list,
    capability_required_permissions,
    capability_role_assignments,
)
from services.entra_apps import list_applications_without_owners as entra_list_applications_without_owners
from services.entra_apps import list_secrets_expiring as entra_list_secrets_expiring
from services.entra_apps import (
    list_service_principals_with_graph_critical_permissions as entra_list_graph_critical_permissions,
)
from services.entra_pim import (
    answer_pim_question as pim_answer_question,
    get_pim_state_summary as pim_get_state_summary,
    list_pim_role_states as pim_list_role_states,
    pim_coverage,
)
from services.entra_users import list_users as entra_list_users
from services.effective_access import (
    get_user_effective_azure_access as effective_get_user_effective_azure_access,
    list_orphan_role_assignments as effective_list_orphan_role_assignments,
)
from services.privilege_timeline import (
    answer_timeline_question,
    build_privilege_timeline_report as timeline_build_privilege_timeline_report,
    get_identity_privilege_timeline as timeline_get_identity_privilege_timeline,
    list_privilege_timeline_events as timeline_list_privilege_timeline_events,
    summarize_privilege_timeline as timeline_summarize_privilege_timeline,
)
from services.agent_identities import (
    answer_agent_question,
    assess_all_agents,
    get_agent_relationships as agent_get_relationships,
    get_agents_by_owner as agent_get_by_owner,
    list_agents as agent_list_agents,
)
from services.iam_assessment import (
    answer_iam_question,
    get_management_group_inventory as iam_get_management_group_inventory,
    get_subscription_direct_access_summary as iam_get_subscription_direct_access_summary,
    run_iam_assessment as iam_run_assessment,
)
from services.role_risk import role_risk_score
from services.identity_360 import answer_identity_360 as identity_answer_identity_360
from services.entra_authentication import (
    assess_privileged_mfa as auth_assess_privileged_mfa,
    get_authentication_strength_summary as auth_get_strength_summary,
    get_authentication_methods_summary as auth_get_summary,
    get_user_authentication_methods as auth_get_user_methods,
    list_users_with_passkey as auth_list_users_with_passkey,
    list_users_with_weak_authentication as auth_list_users_with_weak_authentication,
    list_users_without_mfa as auth_list_users_without_mfa,
)
from services.ownership import (
    answer_ownership_question,
    get_owned_objects as ownership_get_owned_objects,
    list_objects_without_owner as ownership_list_objects_without_owner,
)
from services.toxic_combinations import (
    answer_toxic_question,
    detect_toxic_combinations as toxic_detect,
)
from services.blast_radius import (
    answer_blast_radius_question,
    compute_identity_blast_radius as blast_compute,
    top_blast_radius as blast_top,
)
from services.identity_access import (
    get_identity_access_summary as identity_get_identity_access_summary,
    get_resource_groups_count as identity_get_resource_groups_count,
    list_users as identity_list_users,
    list_disabled_users_with_active_roles as identity_list_disabled_users_with_active_roles,
    list_resource_groups as identity_list_resource_groups,
    list_users_with_direct_permissions as identity_list_users_with_direct_permissions,
)

mcp = MCPServer(
    "azure-environment-pilot",
    instructions=(
        "Read-only pilot for Azure environment inventory and Microsoft official guidance. "
        "Never claim a configuration exists unless a tool result proves it."
    ),
)

# Todas as tools deste servidor são somente leitura por design. A anotação
# readOnlyHint evita que o cliente MCP peça confirmação a cada chamada.
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    idempotentHint=True,
    openWorldHint=True,
)


def read_only_tool(*args, **kwargs):
    """Registra uma tool somente leitura."""
    kwargs.setdefault("annotations", _READ_ONLY)
    return mcp.tool(*args, **kwargs)


@read_only_tool()
def get_environment_summary() -> dict:
    """Get a read-only high-level snapshot of the accessible Azure environment."""
    return azure_get_environment_summary()

@read_only_tool()
def get_subscriptions_count() -> dict:
    """
    Retorna exclusivamente a quantidade de subscriptions Azure
    visíveis para a identidade autenticada.
 
    Use esta ferramenta para perguntas como:
    - Quantas subscriptions existem?
    - Quantas assinaturas Azure eu tenho?
    - Quantas subscriptions consigo visualizar?
 
    NÃO use search_official_guidance para descobrir quantidade de subscriptions.
    """
    return azure_get_subscriptions_count()


@read_only_tool()
def get_resource_groups_count() -> dict:
    """Retorna a quantidade de Resource Groups visíveis no escopo autenticado."""
    return identity_get_resource_groups_count()


@read_only_tool()
def list_resource_groups(name_contains: str = "", limit: int = 20) -> dict:
    """Lista Resource Groups com filtros read-only por nome."""
    return identity_list_resource_groups(name_contains=name_contains, limit=limit)


@read_only_tool()
def get_identity_access_summary() -> dict:
    """
    Retorna resumo de identidade e RBAC:
    - total de usuários
    - usuários habilitados/desabilitados
    - usuários com permissões diretas
    - usuários desabilitados com roles ativas
    """
    return identity_get_identity_access_summary()


@read_only_tool()
def list_users(limit: int = 20, disabled_only: bool = False, name_contains: str = "") -> dict:
    """Lista usuários do Entra ID visíveis para a identidade autenticada."""
    return identity_list_users(limit=limit, disabled_only=disabled_only, name_contains=name_contains)


@read_only_tool()
def list_users_with_direct_permissions(limit: int = 20, disabled_only: bool = False) -> dict:
    """Lista usuários com role assignments diretos no Azure RBAC."""
    return identity_list_users_with_direct_permissions(limit=limit, disabled_only=disabled_only)


@read_only_tool()
def list_disabled_users_with_active_roles(limit: int = 20) -> dict:
    """Lista usuários desabilitados no Entra ID que ainda possuem role assignments diretos ativos."""
    return identity_list_disabled_users_with_active_roles(limit=limit)


@read_only_tool()
def list_entra_users(limit: int = 20) -> dict:
    """Lista usuários do Microsoft Entra ID com nome, UPN e e-mail."""
    users = entra_list_users()
    rows = []
    for user in users[: max(1, min(int(limit), 100))]:
        rows.append(
            {
                "name": user.get("displayName"),
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "mail": user.get("mail") or user.get("userPrincipalName"),
                "objectId": user.get("id"),
                "identityType": "User",
            }
        )
    return {"count": len(rows), "users": rows}


@read_only_tool()
def list_azure_role_assignments(limit: int = 50) -> dict:
    """Lista role assignments Azure RBAC (User, Group, Service Principal e Managed Identity)."""
    rows = azure_list_role_assignments()[: max(1, min(int(limit), 200))]
    return {"count": len(rows), "assignments": rows}


@read_only_tool()
def list_privileged_azure_role_assignments(limit: int = 50) -> dict:
    """Lista role assignments privilegiados em Azure RBAC (Owner, User Access Administrator, Contributor)."""
    rows = azure_list_privileged_role_assignments()[: max(1, min(int(limit), 200))]
    return {"count": len(rows), "assignments": rows}


@read_only_tool()
def get_role_risk_score(role: str, provider: str, scope: str = "/", state: str = "") -> dict:
    """Calcula score de risco (0-100) para uma role privilegiada de Entra ID ou Azure RBAC."""
    score = role_risk_score(role=role, provider=provider, scope=scope, state=state)
    return {
        "role": role,
        "provider": provider,
        "scope": scope,
        "state": state,
        "riskScore": score["score"],
        "riskLevel": score["level"],
        "riskSource": score["source"],
    }


@read_only_tool()
def list_agent_identities(status: str = "all", limit: int = 50) -> dict:
    """Lista inventário de Agent Identities com owner, blueprint, permissões e risco."""
    try:
        rows = agent_list_agents(status=status, limit=limit)
        return {"status": "PASS", "count": len(rows), "agents": rows}
    except Exception as exc:
        return {
            "status": "NOT_EVALUATED",
            "count": 0,
            "agents": [],
            "note": (
                "Não foi possível avaliar Agent Identities porque a identidade atual não possui "
                "permissão suficiente ou a API/fonte não está disponível."
            ),
            "error": str(exc),
        }


@read_only_tool()
def get_agent_relationships(agent_identifier: str) -> dict:
    """Resolve Agent → Owners → Identity → Blueprint → Graph Permissions → Azure RBAC."""
    try:
        return agent_get_relationships(agent_identifier=agent_identifier)
    except Exception as exc:
        return {
            "agent_identifier": agent_identifier,
            "note": (
                "Não foi possível resolver os relacionamentos deste Agent com as fontes disponíveis."
            ),
            "error": str(exc),
        }


@read_only_tool()
def get_agents_by_owner(owner_identifier: str, limit: int = 50) -> dict:
    """Lista Agents sob responsabilidade de um owner (UPN, nome ou objectId)."""
    try:
        return agent_get_by_owner(owner_identifier=owner_identifier, limit=limit)
    except Exception as exc:
        return {
            "owner_identifier": owner_identifier,
            "count": 0,
            "agents": [],
            "note": (
                "Não foi possível resolver os Agents deste owner com as fontes disponíveis."
            ),
            "error": str(exc),
        }


@read_only_tool()
def get_user_effective_azure_access(user_identifier: str, limit: int = 200) -> dict:
    """Resolve acesso efetivo Azure RBAC de um usuário (direto + herdado via grupos transitive)."""
    try:
        return effective_get_user_effective_azure_access(user_identifier=user_identifier, limit=limit)
    except Exception as exc:
        return {
            "user_identifier": user_identifier,
            "note": (
                "Não foi possível avaliar acesso efetivo do usuário com as permissões/fontes atuais."
            ),
            "error": str(exc),
        }


@read_only_tool()
def list_orphan_azure_role_assignments(limit: int = 200) -> dict:
    """Lista role assignments órfãos (principal não resolvido no tenant visível)."""
    rows = effective_list_orphan_role_assignments(limit=limit)
    return {"count": len(rows), "assignments": rows}


@read_only_tool()
def list_privilege_timeline_events(days: int = 30, provider: str = "all", action: str = "all", limit: int = 200) -> dict:
    """Lista eventos de ganho/perda/ativação de privilégios no período informado."""
    try:
        rows = timeline_list_privilege_timeline_events(days=days, provider=provider, action=action, limit=limit)
        return {"count": len(rows), "events": rows}
    except Exception as exc:
        return {
            "count": 0,
            "events": [],
            "note": (
                "Não foi possível consultar timeline de privilégios com as permissões/fontes atuais."
            ),
            "error": str(exc),
        }


@read_only_tool()
def get_identity_privilege_timeline(identity_identifier: str, days: int = 90, limit: int = 200) -> dict:
    """Retorna timeline de privilégios para uma identidade específica (UPN, nome ou objectId)."""
    try:
        return timeline_get_identity_privilege_timeline(
            identity_identifier=identity_identifier,
            days=days,
            limit=limit,
        )
    except Exception as exc:
        return {
            "identity_identifier": identity_identifier,
            "events_count": 0,
            "events": [],
            "note": (
                "Não foi possível consultar timeline desta identidade com as permissões/fontes atuais."
            ),
            "error": str(exc),
        }


@read_only_tool()
def summarize_privilege_timeline(days: int = 30) -> dict:
    """Resumo da timeline de privilégios (ganhos, revogações, ativações e anomalias)."""
    try:
        return timeline_summarize_privilege_timeline(days=days)
    except Exception as exc:
        return {
            "days": days,
            "total_events": 0,
            "note": (
                "Não foi possível gerar o resumo da timeline com as permissões/fontes atuais."
            ),
            "error": str(exc),
        }


@read_only_tool()
def export_privilege_timeline_report(days: int = 30, top: int = 10) -> dict:
    """Gera relatório de timeline com top grants/revokes por identidade, role e escopo."""
    try:
        report = timeline_build_privilege_timeline_report(days=days, top=top)
        return {
            "narrative": (
                f"Relatório de timeline gerado com sucesso para {report.get('summary', {}).get('days', days)} dias. "
                f"Eventos totais: {report.get('summary', {}).get('total_events', 0)}."
            ),
            "report": report,
        }
    except Exception as exc:
        return {
            "narrative": (
                "Não foi possível gerar o relatório de timeline com as permissões/fontes atuais."
            ),
            "report": {},
            "error": str(exc),
        }


@read_only_tool()
def timeline_natural_language_query(question: str, limit: int = 20) -> dict:
    """Interpreta perguntas de auditoria temporal de privilégios em linguagem natural."""
    try:
        result = answer_timeline_question(question=question, limit=limit)
    except Exception as exc:
        return {
            "question": question,
            "intent": "timeline_query_unavailable",
            "narrative": (
                "Não foi possível avaliar esta timeline porque a identidade atual não possui "
                "permissão suficiente ou a fonte de auditoria não está disponível."
            ),
            "error": str(exc),
        }
    return {
        "question": question,
        "intent": result.get("intent"),
        "narrative": result.get("narrative"),
        "data": result.get("data"),
    }


@read_only_tool()
def agent_natural_language_query(question: str, limit: int = 20) -> dict:
    """Interpreta perguntas sobre Agent Identities em linguagem natural."""
    try:
        result = answer_agent_question(question=question, limit=limit)
    except Exception as exc:
        return {
            "question": question,
            "intent": "agent_query_unavailable",
            "narrative": (
                "Não foi possível avaliar esta consulta de Agent Identities porque a identidade atual "
                "não possui permissão suficiente ou a API/fonte necessária não está disponível."
            ),
            "error": str(exc),
        }
    return {
        "question": question,
        "intent": result.get("intent"),
        "narrative": result.get("narrative"),
        "data": result.get("data"),
    }


@read_only_tool()
def run_agent_assessment(top_risks: int = 10) -> dict:
    """Executa assessment específico de Agent Identities e retorna ranking de risco."""
    try:
        result = assess_all_agents(top=max(1, min(int(top_risks), 100)))
        result["status"] = "PASS"
        return result
    except Exception as exc:
        return {
            "status": "NOT_EVALUATED",
            "summary": {"agents_evaluated": 0},
            "findings": [],
            "top_agents": [],
            "top_owners": [],
            "narrative": (
                "Não foi possível executar o assessment de Agent Identities porque a fonte/API "
                "não está disponível para a identidade atual."
            ),
            "error": str(exc),
        }


@read_only_tool()
def list_deny_assignments(limit: int = 50) -> dict:
    """Lista deny assignments do Azure."""
    rows = azure_list_deny_assignments()[: max(1, min(int(limit), 200))]
    return {"count": len(rows), "deny_assignments": rows}


@read_only_tool()
def list_applications_without_owners(limit: int = 50) -> dict:
    """Lista aplicações sem owner definido no Entra ID."""
    rows = entra_list_applications_without_owners()[: max(1, min(int(limit), 200))]
    return {"count": len(rows), "applications": rows}


@read_only_tool()
def list_application_secrets_expiring(days: int = 30, limit: int = 100) -> dict:
    """Lista secrets expirados ou próximos da expiração em aplicações do Entra ID."""
    rows = entra_list_secrets_expiring(days=days)[: max(1, min(int(limit), 500))]
    return {"count": len(rows), "secrets": rows}


@read_only_tool()
def list_graph_critical_application_permissions(limit: int = 100) -> dict:
    """Lista aplicações/service principals com Microsoft Graph Application Permissions críticas."""
    rows = entra_list_graph_critical_permissions()[: max(1, min(int(limit), 500))]
    return {"count": len(rows), "permissions": rows}


@read_only_tool()
def list_pim_role_states(limit: int = 200, include_permanent: bool = True) -> dict:
    """
    Lista atribuições privilegiadas classificadas por estado:
    Active, Eligible e Permanent.
    """
    rows = pim_list_role_states(include_permanent=include_permanent)
    limited = rows[: max(1, min(int(limit), 500))]
    return {"count": len(limited), "rows": limited, "coverage": pim_coverage()}


@read_only_tool()
def get_pim_state_summary() -> dict:
    """Retorna comparativo de estados PIM (Active vs Eligible vs Permanent)."""
    rows = pim_list_role_states(include_permanent=True)
    summary = pim_get_state_summary(rows)
    if isinstance(summary, dict):
        summary["coverage"] = pim_coverage()
    return summary


@read_only_tool()
def pim_natural_language_query(question: str, limit: int = 20) -> dict:
    """Interpreta perguntas de PIM em linguagem natural e retorna resposta com resumo e detalhes."""
    result = pim_answer_question(question=question, limit=limit)
    return {
        "question": question,
        "intent": result.get("intent"),
        "narrative": result.get("narrative"),
        "data": result.get("data"),
    }


@read_only_tool()
def iam_natural_language_query(question: str, limit: int = 20) -> dict:
    """
    Interpreta uma pergunta de IAM em linguagem natural e responde com correlação Entra + Azure.
    Sempre retorna resumo e detalhes compreensíveis, sem depender de frase exata.
    """
    try:
        result = answer_iam_question(question=question, limit=limit)
    except Exception as exc:
        return {
            "question": question,
            "intent": "iam_query_unavailable",
            "narrative": (
                "Não foi possível avaliar esta consulta IAM porque a identidade atual "
                "não possui permissão suficiente ou a API necessária não está disponível."
            ),
            "error": str(exc),
        }
    return {
        "question": question,
        "intent": result.get("intent"),
        "narrative": result.get("narrative"),
        "data": result.get("data"),
    }


@read_only_tool()
def run_iam_assessment(top_risks: int = 10) -> dict:
    """Executa um IAM Assessment no ambiente e retorna riscos principais e plano de remediação."""
    try:
        return iam_run_assessment(limit_risks=top_risks)
    except Exception as exc:
        return {
            "summary": {"total_risks": 0, "not_assessed_controls": 1},
            "risks": [],
            "not_assessed": [
                {
                    "control": "iam_assessment",
                    "note": (
                        "Não foi possível avaliar este controle porque a identidade atual "
                        "não possui permissão suficiente."
                    ),
                    "error": str(exc),
                }
            ],
            "remediation_plan": [],
            "narrative": (
                "Não foi possível executar o IAM Assessment completo porque faltam permissões "
                "na identidade atual para consultar todas as APIs necessárias."
            ),
        }


@read_only_tool()
def run_enterprise_identity_audit(top_risks: int = 15) -> dict:
    """Executa auditoria IAM enterprise consolidada (Entra + Azure + subscriptions + management groups)."""
    try:
        return iam_run_assessment(limit_risks=top_risks)
    except Exception as exc:
        return {
            "summary": {"total_risks": 0, "not_assessed_controls": 1},
            "risks": [],
            "not_assessed": [
                {
                    "control": "enterprise_identity_audit",
                    "note": (
                        "Não foi possível executar a auditoria enterprise completa com a identidade atual."
                    ),
                    "error": str(exc),
                }
            ],
            "remediation_plan": [],
            "narrative": (
                "Não foi possível executar a auditoria IAM enterprise completa porque faltam permissões "
                "na identidade atual para consultar todas as APIs necessárias."
            ),
        }


@read_only_tool()
def get_management_group_inventory(limit: int = 50) -> dict:
    """Retorna inventário de Management Groups visíveis para auditoria de governança."""
    return iam_get_management_group_inventory(limit=limit)


@read_only_tool()
def get_subscription_direct_access_summary(limit: int = 20) -> dict:
    """Resumo de role assignments diretos em escopo de subscription (inclui privilegiados)."""
    return iam_get_subscription_direct_access_summary(limit=limit)


@read_only_tool()
def list_resources(resource_type: str = "", name_contains: str = "", limit: int = 20) -> dict:
    """List Azure resources using controlled read-only filters. Use full Azure resource type when filtering, e.g. microsoft.compute/virtualmachines."""
    return azure_list_resources(resource_type=resource_type, name_contains=name_contains, limit=limit)


@read_only_tool()
def list_public_ip_resources(limit: int = 20) -> dict:
    """List Public IP resources. This does not prove that a workload is actually internet-exposed."""
    return azure_list_public_ip_resources(limit=limit)


@read_only_tool()
def identity_360(user_identifier: str) -> dict:
    """
    Identity 360: visão completa de uma identidade — quem é, a que possui acesso
    (Entra + Azure, direto/grupo/PIM), como recebeu, ownership e risco (blast radius, findings).
    Aceita UPN, displayName ou objectId.
    """
    try:
        return identity_answer_identity_360(user_identifier=user_identifier)
    except Exception as exc:
        return {
            "intent": "identity_360_unavailable",
            "narrative": (
                "Não foi possível montar o Identity 360 desta identidade porque a identidade atual "
                "não possui permissão suficiente ou a fonte necessária não está disponível."
            ),
            "error": str(exc),
        }


@read_only_tool()
def get_user_authentication_methods(user_identifier: str) -> dict:
    """Retorna métodos de autenticação e status de MFA/passwordless de um usuário."""
    try:
        return auth_get_user_methods(user_identifier=user_identifier)
    except Exception as exc:
        return {
            "user_identifier": user_identifier,
            "note": "Métodos de autenticação não puderam ser avaliados com os dados atuais.",
            "error": str(exc),
        }


@read_only_tool()
def get_authentication_methods_summary() -> dict:
    """Resumo de registro de MFA e capacidade passwordless do tenant."""
    return auth_get_summary()


@read_only_tool()
def list_users_without_mfa(limit: int = 100) -> dict:
    """Lista usuários sem MFA registrado."""
    rows = auth_list_users_without_mfa()[: max(1, min(int(limit), 500))]
    return {"count": len(rows), "users": rows}


@read_only_tool()
def assess_privileged_mfa() -> dict:
    """Assessment de MFA para usuários privilegiados (sem MFA ou métodos fracos)."""
    return auth_assess_privileged_mfa()


@read_only_tool()
def get_authentication_strength_summary() -> dict:
    """Resumo enterprise de força de autenticação (forte/misto/fraco) e adoção de passkey/FIDO2."""
    return auth_get_strength_summary()


@read_only_tool()
def list_users_with_weak_authentication(limit: int = 100, include_mfa_registered: bool = True) -> dict:
    """Lista usuários com métodos fracos registrados (sms/voice/email/password), com evidência técnica."""
    rows = auth_list_users_with_weak_authentication(include_mfa_registered=include_mfa_registered)[
        : max(1, min(int(limit), 500))
    ]
    return {"count": len(rows), "users": rows}


@read_only_tool()
def list_users_with_passkey(limit: int = 100) -> dict:
    """Lista usuários com passkey/FIDO2 registrado."""
    rows = auth_list_users_with_passkey()[: max(1, min(int(limit), 500))]
    return {"count": len(rows), "users": rows}


@read_only_tool()
def get_owned_objects(user_identifier: str, limit: int = 100) -> dict:
    """Ownership 360: objetos (Groups, Applications, Service Principals, Agents, Blueprints) sob responsabilidade de um usuário."""
    try:
        return ownership_get_owned_objects(user_identifier=user_identifier, limit=limit)
    except Exception as exc:
        return {
            "user_identifier": user_identifier,
            "count": 0,
            "ownedObjects": [],
            "note": "Ownership não pôde ser resolvido com as fontes atuais.",
            "error": str(exc),
        }


@read_only_tool()
def list_objects_without_owner(limit: int = 200) -> dict:
    """Lista objetos sem owner (Groups, Applications, Service Principals, Agents, Blueprints)."""
    try:
        rows = ownership_list_objects_without_owner(limit=limit)
        return {"count": len(rows), "objects": rows}
    except Exception as exc:
        return {"count": 0, "objects": [], "note": "Não foi possível avaliar ownership.", "error": str(exc)}


@read_only_tool()
def detect_toxic_combinations(limit: int = 50) -> dict:
    """Detecta toxic combinations / violações de Separation of Duties com evidência."""
    try:
        rows = toxic_detect(limit=limit)
        return {"count": len(rows), "combinations": rows}
    except Exception as exc:
        return {"count": 0, "combinations": [], "note": "Não foi possível avaliar toxic combinations.", "error": str(exc)}


@read_only_tool()
def compute_identity_blast_radius(identity_identifier: str) -> dict:
    """Estima o blast radius (alcance) de uma identidade (subscriptions, management groups, capacidade de conceder acesso)."""
    try:
        return blast_compute(identity_identifier=identity_identifier)
    except Exception as exc:
        return {
            "identity_identifier": identity_identifier,
            "note": "Blast radius não pôde ser calculado com as fontes atuais.",
            "error": str(exc),
        }


@read_only_tool()
def list_top_blast_radius(limit: int = 10) -> dict:
    """Ranking de identidades por maior blast radius."""
    rows = blast_top(limit=limit)
    return {"count": len(rows), "identities": rows}


@read_only_tool()
def search_official_guidance(topic: str, limit: int = 4) -> dict:
    """Return curated official Microsoft Learn references relevant to an Azure topic or best-practice question."""
    return docs_search_official_guidance(topic=topic, limit=limit)


# ==========================================================================
# Camada genérica de capacidades de identidade (READ ONLY)
#
# Estas tools substituem a necessidade de criar uma tool nova por pergunta.
# Toda execução passa pelo capability registry, validação e normalização.
# ==========================================================================


@read_only_tool()
def graph_discover_capabilities(
    question: str = "",
    domain: str = "",
    source: str = "",
    include_gaps: bool = True,
) -> dict:
    """
    Capability discovery de identidade.

    Use ANTES de consultar quando não souber qual domínio/endpoint atende a pergunta.
    - Se 'question' for informado, retorna o roteamento sugerido (domínio, capability, fonte,
      permissões necessárias) SEM executar nada.
    - Se 'domain'/'source' forem informados, lista as capacidades catalogadas.

    Fontes possíveis: microsoft_graph (identidade/diretório),
    azure_resource_graph / azure_management / azure_authorization (recursos e Azure RBAC).
    """
    payload: dict = {"read_only_mode": True}
    if question.strip():
        payload["routing"] = capability_explain_routing(question)
    caps = [
        cap.to_dict()
        for cap in capability_list(
            domain=domain or None,
            source=source or None,
            only_available=not include_gaps,
        )
    ]
    payload["capabilities"] = caps
    payload["capability_count"] = len(caps)
    payload["domains"] = capability_domains()
    payload["coverage"] = capability_domain_coverage()
    return payload


@read_only_tool()
def graph_answer_identity_question(question: str, limit: int = 50) -> dict:
    """
    Interpreta uma pergunta de identidade em linguagem natural, escolhe a capability
    correta e executa a consulta de forma validada.

    Use para perguntas abertas como:
    - "Quais usuários possuem Global Administrator?"
    - "Quais aplicações possuem Directory.ReadWrite.All?"
    - "Quem pode ativar Owner via PIM?"

    Respeita a separação de fontes: Microsoft Graph para identidade/diretório e
    APIs Azure para Azure RBAC/recursos. Retorna erro explícito quando a capability
    não existe ou quando falta permissão. Nunca inventa chamadas Graph.
    """
    return capability_answer_question(question=question, limit=limit)


@read_only_tool()
def graph_list(capability_id: str, filter: str = "", select: str = "", limit: int = 50) -> dict:
    """
    Lista objetos de uma capability catalogada (operação 'list').

    'capability_id' precisa existir no registry (use graph_discover_capabilities).
    'filter' aceita apenas campos declarados como suportados pela capability.
    Endpoints arbitrários são rejeitados.
    """
    params: dict = {"limit": limit}
    if filter:
        params["filter"] = filter
    if select:
        params["select"] = select
    return capability_execute(capability_id, params, operation="list")


@read_only_tool()
def graph_get(capability_id: str, id: str, select: str = "") -> dict:
    """
    Obtém um objeto específico de uma capability catalogada (operação 'get').

    'id' deve ser um GUID ou identificador simples; valores fora desse padrão são rejeitados.
    """
    params: dict = {"id": id, "limit": 1}
    if select:
        params["select"] = select
    return capability_execute(capability_id, params, operation="get")


@read_only_tool()
def graph_query(capability_id: str, query: str = "", scope: str = "", limit: int = 100) -> dict:
    """
    Executa consulta parametrizada em fontes que aceitam query (ex.: Azure Resource Graph).

    Somente leitura: operadores KQL de escrita ou de acesso externo são bloqueados.
    'scope' é validado contra o formato de escopo Azure.
    """
    params: dict = {"limit": limit}
    if query:
        params["query"] = query
    if scope:
        params["scope"] = scope
    return capability_execute(capability_id, params, operation="query")


@read_only_tool()
def graph_relationship(capability_id: str, id: str, limit: int = 100) -> dict:
    """
    Consulta relacionamentos de um objeto de diretório (membros, owners, membership transitiva,
    app role assignments de um principal).

    Exemplos de capability_id:
    - graph.groups.members
    - graph.groups.transitive_membership
    - graph.applications.owners
    - graph.service_principals.owners
    - graph.app_role_assignments.assigned_to
    """
    return capability_execute(capability_id, {"id": id, "limit": limit}, operation="list")


@read_only_tool()
def graph_permissions(question: str = "", capability_id: str = "") -> dict:
    """
    Retorna as permissões Microsoft Graph / Azure necessárias para uma consulta,
    incluindo suporte a delegated e application permission e requisito de licença.

    Não executa consulta: serve para validar viabilidade antes de consultar.
    """
    return capability_required_permissions(question=question, capability_id=capability_id)


@read_only_tool()
def graph_role_assignments(
    include_directory_roles: bool = True,
    include_pim: bool = True,
    include_azure_rbac: bool = True,
    limit: int = 200,
) -> dict:
    """
    Consulta atribuições de privilégio mantendo as fontes separadas:
    - Directory roles e PIM de diretório via Microsoft Graph
    - Azure RBAC via Azure Resource Graph

    Não assume que Microsoft Graph cobre Azure RBAC.
    """
    return capability_role_assignments(
        include_directory_roles=include_directory_roles,
        include_pim=include_pim,
        include_azure_rbac=include_azure_rbac,
        limit=limit,
    )


@read_only_tool()
def graph_directory_objects(question: str = "", domains: str = "", limit: int = 100) -> dict:
    """
    Coleta objetos de diretório de um ou mais domínios e correlaciona a mesma identidade
    entre eles, preservando a fonte de cada evidência.

    'domains' aceita lista separada por vírgula (ex.: "users,service_principals,directory_roles").
    Se vazio, os domínios são inferidos da pergunta.
    """
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    return capability_directory_objects(question=question, domains=domain_list, limit=limit)


@read_only_tool()
def list_application_provenance(
    provenance: str = "all",
    include_managed_identities: bool = True,
    limit: int = 100,
) -> dict:
    """
    Diferencia app registrations criadas por usuários no seu tenant das aplicações
    nativas da Microsoft (first-party) e de apps de terceiros consentidos.

    Classificação baseada em appOwnerOrganizationId (sinal autoritativo do diretório),
    não em heurística de nome.

    'provenance' aceita: all, tenant (criadas no seu tenant), microsoft (nativas),
    thirdparty (terceiros), managedidentity.

    Use para perguntas como:
    - "Quais aplicações foram criadas pelos usuários?"
    - "Qual a diferença entre app registrations próprias e nativas?"
    - "Quantas aplicações são nativas da Microsoft?"
    """
    return provenance_list_application_provenance(
        provenance=provenance,
        include_managed_identities=include_managed_identities,
        limit=limit,
    )


@read_only_tool()
def summarize_application_provenance() -> dict:
    """
    Resumo executivo da procedência das aplicações do tenant: quantas estão sob sua
    governança (criadas no tenant) versus pré-provisionadas pela Microsoft,
    com percentuais e foco de governança.
    """
    return provenance_summarize_application_provenance()


@read_only_tool()
def graph_assessment(scope: str = "identity", limit: int = 200) -> dict:
    """
    Executa assessment de identidade baseado no capability registry, declarando
    explicitamente cobertura EVALUATED / PARTIAL / NOT_EVALUATED por domínio.

    'scope' aceita: identity, directory, privileged, workload, azure.
    Nunca reporta NOT_EVALUATED como zero.
    """
    return capability_assessment(scope=scope, limit=limit)


def main() -> None:
    """Entry point do MCP server (stdio) para uvx/console_scripts.

    Carrega variáveis de ambiente (.env, se presente) e inicia o servidor no
    transporte stdio, que é o esperado por clientes MCP como o VS Code/Copilot.
    """
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except Exception:
        pass
    mcp.run()


if __name__ == "__main__":
    main()
