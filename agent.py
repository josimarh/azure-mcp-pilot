from __future__ import annotations

import asyncio
import json
import os
import unicodedata
from typing import Any

import httpx
from mcp import Client

from mcp_server import mcp

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

SYSTEM_PROMPT = """
Você é um assistente especializado em analisar um ambiente Microsoft Azure.
 
Você deve responder perguntas usando dados REAIS obtidos pelas ferramentas MCP.
 
REGRAS OBRIGATÓRIAS:
 
1. Nunca invente dados do ambiente Azure.
 
2. Para visão geral do ambiente:
   use get_environment_summary.
   Para inventário completo por subscription, também use get_environment_summary.
 
3. Para perguntas sobre quantidade de subscriptions:
   use get_subscriptions_count.

3.1 Para perguntas sobre quantidade de Resource Groups:
   use get_resource_groups_count.
 
4. Para listar ou contar recursos Azure:
   use list_resources.

4.1 Para listar Resource Groups:
   use list_resource_groups.

4.2 Para perguntas de identidade e RBAC (usuários, permissões diretas, contas desabilitadas):
   use iam_natural_language_query por padrão.
   - Essa tool deve interpretar a intenção e correlacionar Entra ID + Azure RBAC.
   - Use tools específicas apenas quando a pergunta for explicitamente técnica para um domínio único.

4.3 Para pedido de avaliação de risco IAM, least privilege ou plano de remediação:
   use run_iam_assessment.
   Para auditoria enterprise completa, use run_enterprise_identity_audit.

4.4 Para perguntas de PIM (Active, Eligible, Permanent):
   use pim_natural_language_query.
   Para comparativo de estado, use get_pim_state_summary quando necessário.

4.5 Para perguntas sobre Agent Identities (Agent, Owner, Blueprint, permissões do Agent):
   use agent_natural_language_query.
   Para assessment específico de Agents, use run_agent_assessment.

4.6 Para perguntas de acesso efetivo (direto + herdado via grupo) e órfãos RBAC:
   use get_user_effective_azure_access e list_orphan_azure_role_assignments.

4.7 Para perguntas de auditoria temporal (quem ganhou/perdeu acesso e quando):
   use timeline_natural_language_query.
   Para resumo, use summarize_privilege_timeline.
   Para relatório consolidado (tops por identidade/role/escopo), use export_privilege_timeline_report.

4.8 Para análise completa de uma identidade ("Analise joao@contoso.com", "Mostre tudo sobre", "Qual o acesso de"):
   use identity_360.

4.9 Para MFA / métodos de autenticação:
   use get_user_authentication_methods, assess_privileged_mfa, list_users_without_mfa,
   get_authentication_strength_summary, list_users_with_weak_authentication ou list_users_with_passkey.

4.10 Para ownership de objetos (grupos, apps, service principals, agents):
   use get_owned_objects e list_objects_without_owner.

4.11 Para toxic combinations / Separation of Duties:
   use detect_toxic_combinations.

4.12 Para blast radius / alcance de identidade:
   use compute_identity_blast_radius ou list_top_blast_radius.

4.13 Para governança de subscriptions e management groups:
   use get_subscription_direct_access_summary e get_management_group_inventory.
 
5. Para perguntas sobre IP público:
   use list_public_ip_resources.
 
6. search_official_guidance deve ser usada SOMENTE quando o usuário perguntar:
   - qual é a recomendação da Microsoft
   - boas práticas
   - documentação oficial
   - como deveria configurar algo
   - Microsoft Learn
   - Well-Architected Framework
 
7. NUNCA use search_official_guidance para descobrir:
   - quantidade de recursos
   - quantidade de subscriptions
   - quantidade de resource groups
   - quantidade de VMs
   - quantidade de IPs
   - usuários com permissões
   - usuários desabilitados com roles
   - estado atual do ambiente
 
8. Não chame ferramentas sem relação com a pergunta.
 
9. Se uma única ferramenta responder à pergunta, não chame outras ferramentas.
 
10. Diferencie:
    DADO DO AMBIENTE -> Azure Resource Graph
    DOCUMENTAÇÃO -> Microsoft Learn / search_official_guidance

11. Nunca responda ao usuário final com JSON bruto.
    Responda em linguagem natural e, quando útil, com resumo e lista legível.
 
Responda sempre em português do Brasil.
"""


def _configured_models() -> list[str]:
    raw = os.getenv(
        "OPENROUTER_MODELS",
        "liquid/lfm-2.5-2.6b:free,openrouter/free",
    )
    models = [m.strip() for m in raw.split(",") if m.strip()]
    return models or ["liquid/lfm-2.5-2.6b:free"]


def _headers() -> dict[str, str]:
    key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY não configurada. Copie .env.example para .env e informe a chave.")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "X-OpenRouter-Title": os.getenv("OPENROUTER_APP_TITLE", "Azure Environment Copilot Pilot"),
    }
    referer = os.getenv("OPENROUTER_HTTP_REFERER", "").strip()
    if referer:
        headers["HTTP-Referer"] = referer
    return headers


def _tool_schema(tool: Any) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or tool.name,
            "parameters": tool.input_schema,
        },
    }


def _tool_payload(result: Any) -> Any:
    if result.structured_content is not None:
        return result.structured_content
    chunks: list[str] = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text:
            chunks.append(text)
    return {"is_error": result.is_error, "content": "\n".join(chunks)}


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower()


def _parse_tool_result(result: Any) -> Any:
    if result.structured_content is not None:
        return result.structured_content
    chunks: list[str] = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text:
            chunks.append(text)
    joined = "\n".join(chunks).strip()
    if not joined:
        return {}
    try:
        return json.loads(joined)
    except json.JSONDecodeError:
        return {"raw": joined}


def _fallback_tool_for_question(question: str) -> tuple[str, dict[str, Any]] | None:
    q = _normalize(question)
    agent_terms = [
        "agent",
        "agents",
        "agente",
        "agentes",
        "egente",
        "egentes",
        "agnt",
        "agnts",
        "agnte",
        "agenteses",
        "agentees",
        "agentess",
        "blueprint",
        "owner de agent",
        "responsavel pelo agent",
        "responsavel por agent",
        "identidade do agent",
    ]
    iam_terms = [
        "usuario",
        "group",
        "grupo",
        "role",
        "owner",
        "administrator",
        "privilegi",
        "pim",
        "eligible",
        "elegivel",
        "elegive",
        "active",
        "ativo",
        "ativa",
        "permanent",
        "permanente",
        "rbac",
        "entra",
        "permission",
        "permiss",
        "service principal",
        "managed identit",
        "application",
        "secret",
        "least privilege",
        "assessment",
        "risco",
        "mfa",
        "autenticacao",
        "passwordless",
        "fido",
        "authenticator",
        "toxic",
        "separation of duties",
        "blast radius",
        "alcance",
        "identity 360",
        "analise",
        "responsavel",
        "tudo sobre",
    ]
    is_count = any(token in q for token in ["quantos", "quantas", "qtd", "quantidade"])
    is_list = any(token in q for token in ["listar", "liste", "lista", "mostre"])

    if any(term in q for term in agent_terms):
        if "assessment" in q or "risco" in q or "top 10" in q:
            return "run_agent_assessment", {"top_risks": 10}
        return "agent_natural_language_query", {"question": question, "limit": 20}

    audit_terms = ["auditoria", "audit", "assessment completo", "enterprise"]
    if any(term in q for term in audit_terms):
        return "run_enterprise_identity_audit", {"top_risks": 15}

    if "management group" in q or "management groups" in q:
        return "get_management_group_inventory", {"limit": 50}

    subscription_inventory_terms = [
        "inventario por subscription",
        "inventário por subscription",
        "inventario completo por subscription",
        "inventário completo por subscription",
        "resumo completo do ambiente",
        "ambiente completo",
    ]
    if any(term in q for term in subscription_inventory_terms):
        return "get_environment_summary", {}

    if "subscription" in q and ("permiss" in q or "rbac" in q or "diret" in q):
        return "get_subscription_direct_access_summary", {"limit": 20}

    if ("orfa" in q or "orfao" in q) and ("rbac" in q or "role assignment" in q or "permiss" in q):
        return "list_orphan_azure_role_assignments", {"limit": 50}

    timeline_terms = [
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
    if any(term in q for term in timeline_terms):
        if "relatorio" in q or "report" in q:
            return "export_privilege_timeline_report", {"days": 30, "top": 10}
        if "resumo" in q or "sumario" in q:
            return "summarize_privilege_timeline", {"days": 30}
        return "timeline_natural_language_query", {"question": question, "limit": 20}

    if any(term in q for term in iam_terms):
        pim_terms = [
            "pim",
            "eligible",
            "elegivel",
            "elegive",
            "active",
            "ativo",
            "ativa",
            "permanent",
            "permanente",
        ]
        if any(term in q for term in pim_terms):
            return "pim_natural_language_query", {"question": question, "limit": 20}
        if "assessment" in q or "least privilege" in q or "risco" in q or "remediacao" in q:
            return "run_iam_assessment", {"top_risks": 10}
        return "iam_natural_language_query", {"question": question, "limit": 20}

    if "visao geral" in q or ("ambiente" in q and not is_list):
        return "get_environment_summary", {}
    if ("subscription" in q or "assinatura" in q) and any(
        term in q for term in ["inventario", "inventário", "completo", "detalhado", "detalhe"]
    ):
        return "get_environment_summary", {}
    if "subscription" in q or "assinatura" in q:
        return "get_subscriptions_count", {}
    if "resource group" in q:
        return ("get_resource_groups_count", {}) if is_count else ("list_resource_groups", {"limit": 20})
    if "public ip" in q or "ip publico" in q:
        return "list_public_ip_resources", {"limit": 20}
    if "usuario" in q and "desabilitad" in q and ("role" in q or "permiss" in q):
        return "list_disabled_users_with_active_roles", {"limit": 20}
    if "usuario" in q and "permiss" in q and "diret" in q:
        return "list_users_with_direct_permissions", {"limit": 20}
    if "usuario" in q:
        if "desabilitad" in q:
            return "list_users", {"limit": 20, "disabled_only": True}
        return "list_users", {"limit": 20}
    if "vm" in q or "virtual machine" in q:
        return "list_resources", {"resource_type": "microsoft.compute/virtualmachines", "limit": 20}
    return None


def _fallback_answer_from_tool(tool_name: str, payload: Any) -> str:
    def _friendly_owner_status(value: Any) -> str:
        mapping = {
            "OWNER_CONFIGURED": "Owner configurado",
            "NO_OWNER_CONFIGURED": "Sem owner configurado",
            "OWNER_NOT_RESOLVED": "Owner não resolvido",
            "OWNER_NOT_EVALUATED": "Owner não avaliado",
            "INSUFFICIENT_PERMISSIONS": "Permissões insuficientes",
            "UNSUPPORTED": "Não suportado",
        }
        key = str(value or "").strip()
        return mapping.get(key, key or "N/A")

    def _coverage_label(value: Any) -> str:
        mapping = {
            "PASS": "EVALUATED",
            "EVALUATED": "EVALUATED",
            "PARTIAL": "PARTIAL",
            "NOT_EVALUATED": "NOT_EVALUATED",
            "FAIL": "NOT_EVALUATED",
            "ERROR": "NOT_EVALUATED",
            "INSUFFICIENT_PERMISSIONS": "NOT_EVALUATED",
            "UNSUPPORTED": "NOT_EVALUATED",
        }
        key = str(value or "").strip().upper()
        return mapping.get(key, key or "NOT_EVALUATED")

    def _domain_status(values: list[str], evaluated_value: str = "PASS") -> str:
        normalized = [str(v or "").strip().upper() for v in values if str(v or "").strip()]
        if not normalized:
            return "NOT_EVALUATED"
        if all(v == evaluated_value for v in normalized):
            return "EVALUATED"
        if any(v == evaluated_value for v in normalized):
            return "PARTIAL"
        return "NOT_EVALUATED"

    def _ownership_coverage_status(values: list[str]) -> str:
        normalized = [str(v or "").strip().upper() for v in values if str(v or "").strip()]
        if not normalized:
            return "NOT_EVALUATED"
        evaluated = {"OWNER_CONFIGURED", "NO_OWNER_CONFIGURED", "OWNER_NOT_RESOLVED"}
        not_evaluated = {"OWNER_NOT_EVALUATED", "INSUFFICIENT_PERMISSIONS", "UNSUPPORTED", "FAIL"}
        has_eval = any(v in evaluated for v in normalized)
        has_no_eval = any(v in not_evaluated for v in normalized)
        if has_eval and not has_no_eval:
            return "EVALUATED"
        if has_eval and has_no_eval:
            return "PARTIAL"
        return "NOT_EVALUATED"

    def _is_heuristic_inventory(source_mode: str, agent_id_api_status: str) -> bool:
        return source_mode == "live_workload_heuristic" and agent_id_api_status == "NOT_INTEGRATED"

    def _inventory_sentence(total: int, heuristic: bool) -> str:
        if heuristic:
            if total == 1:
                return "1 objeto candidato relacionado a Agent Identities foi identificado pelo inventário heurístico."
            return f"{total} objetos candidatos relacionados a Agent Identities foram identificados pelo inventário heurístico."
        if total == 1:
            return "1 identidade de Agent foi identificada."
        return f"{total} identidades de Agent foram identificadas."

    def _summary_overall_assessment(azure: str, graph: str, ownership: str) -> str:
        return "COMPLETE" if azure == "EVALUATED" and graph == "EVALUATED" and ownership == "EVALUATED" else "PARTIAL"

    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    if isinstance(payload, dict) and isinstance(payload.get("content"), str):
        content = str(payload.get("content") or "").strip()
        if content.startswith("{") or content.startswith("["):
            try:
                payload = json.loads(content)
            except json.JSONDecodeError:
                pass

    if not isinstance(payload, dict):
        return f"Resultado da consulta:\n\n{json.dumps(payload, ensure_ascii=False, indent=2, default=str)}"
    if payload.get("narrative"):
        return str(payload.get("narrative"))

    if tool_name == "iam_natural_language_query":
        narrative = payload.get("narrative")
        if narrative:
            return str(narrative)
        data = payload.get("data")
        return f"Resultado IAM:\n\n{json.dumps(data, ensure_ascii=False, indent=2, default=str)}"
    if tool_name == "run_iam_assessment":
        narrative = payload.get("narrative")
        if narrative:
            return str(narrative)
        return f"IAM Assessment:\n\n{json.dumps(payload, ensure_ascii=False, indent=2, default=str)}"
    if tool_name == "run_enterprise_identity_audit":
        narrative = payload.get("narrative")
        if narrative:
            return str(narrative)
        return "Auditoria enterprise concluída, mas sem narrativa formatada no retorno."
    if tool_name == "pim_natural_language_query":
        narrative = payload.get("narrative")
        if narrative:
            return str(narrative)
        return "Consulta PIM concluída, mas sem narrativa formatada no retorno."
    if tool_name == "agent_natural_language_query":
        narrative = payload.get("narrative")
        if narrative:
            return str(narrative)
        return "Consulta de Agent Identities concluída, mas sem narrativa formatada no retorno."
    if tool_name == "run_agent_assessment":
        if payload.get("status") == "NOT_EVALUATED":
            note = payload.get("note") or payload.get("narrative")
            error = payload.get("error")
            if note and error:
                return f"{note}\n\nDetalhe técnico: {error}"
            if note:
                return str(note)
        narrative = payload.get("narrative")
        if narrative:
            source_mode = payload.get("sourceMode")
            source_note = payload.get("sourceNote")
            extra = []
            if source_mode:
                extra.append(f"Fonte: {source_mode}.")
            if source_note:
                extra.append(str(source_note))
            if extra:
                return f"{narrative}\n\n" + "\n".join(extra)
            return str(narrative)
        return "Assessment de Agent Identities concluído, mas sem narrativa formatada no retorno."

    if tool_name == "get_subscriptions_count":
        return f"Você tem **{payload.get('subscriptions_count', 0)}** subscriptions visíveis."
    if tool_name == "get_resource_groups_count":
        return f"Existem **{payload.get('resource_groups_count', 0)}** resource groups visíveis."
    if tool_name == "get_environment_summary":
        coverage = payload.get("coverage", {}) or {}
        subscriptions_inventory = payload.get("subscriptions_inventory", []) or []
        top_types = payload.get("top_resource_types", []) or []
        top_locations = payload.get("top_locations", []) or []
        lines = [
            "Resumo do ambiente:",
            f"- Recursos totais: **{payload.get('total_resources', 'NOT_EVALUATED')}**",
            f"- Subscriptions: **{payload.get('subscriptions', 'NOT_EVALUATED')}**",
            f"- Resource Groups: **{payload.get('resource_groups', 'NOT_EVALUATED')}**",
            f"- Localizações: **{payload.get('locations', 'NOT_EVALUATED')}**",
            "",
            "Cobertura da consulta:",
            f"- Subscriptions: **{coverage.get('subscriptions', 'NOT_EVALUATED')}**",
            f"- Recursos: **{coverage.get('resources', 'NOT_EVALUATED')}**",
            f"- Resource Groups: **{coverage.get('resource_groups', 'NOT_EVALUATED')}**",
        ]
        if payload.get("total_resources") == 0 and str(payload.get("subscriptions")) not in {"0", "NOT_EVALUATED"}:
            lines.extend(
                [
                    "",
                    "Observação:",
                    "- Há subscriptions visíveis, mas nenhum recurso foi identificado dentro da cobertura desta consulta.",
                ]
            )
        if subscriptions_inventory:
            lines.extend(["", "Subscriptions (detalhe):"])
            for row in subscriptions_inventory[:20]:
                lines.append(
                    "- "
                    f"{row.get('displayName') or row.get('subscriptionId') or 'N/A'} | "
                    f"ID: {row.get('subscriptionId') or 'N/A'} | "
                    f"State: {row.get('state') or 'Unknown'} | "
                    f"Recursos: {row.get('resources', 'N/A')} | "
                    f"RGs: {row.get('resourceGroups', 'N/A')}"
                )
        if top_types:
            lines.extend(["", "Top tipos de recurso:"])
            for row in top_types[:10]:
                lines.append(f"- {row.get('type') or 'N/A'}: {row.get('count', 0)}")
        if top_locations:
            lines.extend(["", "Top localizações:"])
            for row in top_locations[:10]:
                lines.append(f"- {row.get('location') or 'unknown'}: {row.get('count', 0)}")
        return "\n".join(lines)
    if tool_name == "list_resources":
        rows = payload.get("resources", [])
        lines = [f"Recursos encontrados: **{payload.get('count', len(rows))}**", ""]
        for row in rows[:20]:
            lines.append(
                "- "
                f"{row.get('name') or 'N/A'} | "
                f"Tipo: {row.get('type') or 'N/A'} | "
                f"RG: {row.get('resourceGroup') or 'N/A'} | "
                f"Subscription: {row.get('subscriptionId') or 'N/A'}"
            )
        return "\n".join(lines)
    if tool_name == "list_resource_groups":
        rows = payload.get("resource_groups", [])
        lines = [f"Resource Groups encontrados: **{payload.get('count', len(rows))}**", ""]
        for row in rows[:20]:
            lines.append(
                "- "
                f"{row.get('name') or 'N/A'} | "
                f"Subscription: {row.get('subscriptionId') or 'N/A'} | "
                f"Location: {row.get('location') or 'N/A'}"
            )
        return "\n".join(lines)
    if tool_name == "list_public_ip_resources":
        rows = payload.get("resources", [])
        lines = [f"Recursos com IP público encontrados: **{payload.get('count', len(rows))}**", ""]
        for row in rows[:20]:
            lines.append(
                "- "
                f"{row.get('name') or 'N/A'} | "
                f"Tipo: {row.get('type') or 'N/A'} | "
                f"RG: {row.get('resourceGroup') or 'N/A'}"
            )
        return "\n".join(lines)
    if tool_name == "list_users":
        users = payload.get("users", [])
        lines = [f"Usuários encontrados: **{payload.get('count', len(users))}**", ""]
        for user in users[:20]:
            lines.append(
                "- "
                f"{user.get('displayName') or 'N/A'} | "
                f"UPN: {user.get('userPrincipalName') or 'N/A'} | "
                f"Status: {'Habilitado' if user.get('accountEnabled') else 'Desabilitado'}"
            )
        return "\n".join(lines)
    if tool_name in {"list_users_with_direct_permissions", "list_disabled_users_with_active_roles"}:
        users = payload.get("users", [])
        lines = [
            f"Usuários encontrados: **{payload.get('count', len(users))}**",
            "",
        ]
        for user in users:
            lines.append(
                "- "
                f"Nome: **{user.get('displayName') or 'N/A'}** | "
                f"UPN: `{user.get('userPrincipalName') or 'N/A'}` | "
                f"E-mail: `{user.get('mail') or user.get('userPrincipalName') or 'N/A'}`"
            )
        return "\n".join(lines)
    if tool_name == "get_identity_access_summary":
        return (
            "Resumo de identidade e RBAC:\n"
            f"- Usuários totais: **{payload.get('total_users', 0)}**\n"
            f"- Usuários com permissões diretas: **{payload.get('users_with_direct_role_assignments', 0)}**\n"
            f"- Usuários desabilitados com roles atribuídas: **{payload.get('disabled_users_with_active_roles', 0)}**"
        )
    if tool_name == "get_user_effective_azure_access":
        user = payload.get("user", {})
        return (
            f"Acesso efetivo Azure RBAC de {user.get('userPrincipalName') or user.get('displayName') or 'N/A'}:\n"
            f"- Direto: **{payload.get('directAssignmentsCount', 0)}**\n"
            f"- Herdado via grupo: **{payload.get('inheritedAssignmentsCount', 0)}**\n"
            f"- Total: **{payload.get('totalAssignmentsCount', 0)}**"
        )
    if tool_name == "list_orphan_azure_role_assignments":
        return f"Role assignments órfãos encontrados: **{payload.get('count', 0)}**."
    if tool_name == "get_management_group_inventory":
        rows = payload.get("managementGroups", [])
        lines = [f"Management Groups identificados: **{payload.get('count', len(rows))}**", ""]
        for row in rows[:20]:
            lines.append(f"- {row.get('name') or 'N/A'}")
        return "\n".join(lines)
    if tool_name == "get_subscription_direct_access_summary":
        rows = payload.get("topSubscriptions", [])
        lines = [
            "Resumo de acesso direto em subscriptions:",
            f"- Subscriptions com assignments diretos: **{payload.get('subscriptionsWithDirectAssignments', 0)}**",
            f"- Assignments diretos em subscription: **{payload.get('directSubscriptionAssignments', 0)}**",
            f"- Assignments diretos privilegiados (Owner/UAA/Contributor): **{payload.get('privilegedDirectSubscriptionAssignments', 0)}**",
            f"- Identidades com assignment direto em subscription: **{payload.get('identitiesWithDirectSubscriptionAssignments', 0)}**",
            "",
            "Top subscriptions por concentração:",
        ]
        for row in rows[:20]:
            lines.append(
                f"- {row.get('subscriptionId') or 'unknown'} | "
                f"Assignments: {row.get('assignments', 0)} | "
                f"Privilegiados: {row.get('privilegedAssignments', 0)}"
            )
        return "\n".join(lines)
    if tool_name == "get_user_authentication_methods":
        methods = payload.get("methods", []) or []
        return (
            f"Métodos de autenticação de {payload.get('userPrincipalName') or payload.get('displayName') or 'N/A'}:\n"
            f"- MFA registrado: **{'Sim' if payload.get('isMfaRegistered') else 'Não'}**\n"
            f"- Passwordless: **{'Sim' if payload.get('isPasswordlessCapable') else 'Não'}**\n"
            f"- Métodos: {', '.join(methods) if methods else 'Nenhum identificado'}"
        )
    if tool_name == "get_authentication_methods_summary":
        return (
            "Resumo de autenticação:\n"
            f"- Usuários avaliados: **{payload.get('registered_users', 0)}**\n"
            f"- Com MFA: **{payload.get('users_capable_mfa', 0)}**\n"
            f"- Sem MFA: **{payload.get('users_without_mfa', 0)}**\n"
            f"- Passwordless: **{payload.get('users_capable_passwordless', 0)}**"
        )
    if tool_name == "list_users_without_mfa":
        users = payload.get("users", [])
        lines = [f"Usuários sem MFA: **{payload.get('count', len(users))}**", ""]
        for user in users[:20]:
            lines.append(f"- {user.get('displayName') or 'N/A'} | UPN: {user.get('userPrincipalName') or 'N/A'}")
        return "\n".join(lines)
    if tool_name == "assess_privileged_mfa":
        without = payload.get("privileged_without_mfa", []) or []
        weak = payload.get("privileged_weak_methods", []) or []
        lines = [
            "Assessment MFA de usuários privilegiados:",
            f"- Privilegiados avaliados: **{payload.get('privileged_users_evaluated', 0)}**",
            f"- Sem MFA: **{len(without)}**",
            f"- Com métodos fracos: **{len(weak)}**",
        ]
        return "\n".join(lines)
    if tool_name == "get_authentication_strength_summary":
        breakdown = payload.get("auth_strength_breakdown", {}) or {}
        return (
            "Resumo de força de autenticação:\n"
            f"- Usuários avaliados: **{payload.get('users_evaluated', 0)}**\n"
            f"- MFA registrado: **{payload.get('mfa_registered', 0)}**\n"
            f"- Passwordless capable: **{payload.get('passwordless_capable', 0)}**\n"
            f"- Passkey/FIDO2 registrado: **{payload.get('users_with_passkey_or_fido2', 0)}**\n"
            f"- Métodos fracos registrados: **{payload.get('users_with_weak_methods_registered', 0)}**\n"
            f"- STRONG: **{breakdown.get('STRONG', 0)}** | MIXED: **{breakdown.get('MIXED', 0)}** | "
            f"WEAK_ONLY: **{breakdown.get('WEAK_ONLY', 0)}**"
        )
    if tool_name == "list_users_with_weak_authentication":
        rows = payload.get("users", [])
        lines = [f"Usuários com métodos fracos registrados: **{payload.get('count', len(rows))}**", ""]
        for row in rows[:20]:
            weak = ", ".join(row.get("weakMethods", []) or []) or "N/A"
            lines.append(f"- {row.get('displayName') or 'N/A'} | UPN: {row.get('userPrincipalName') or 'N/A'} | Métodos fracos: {weak}")
        return "\n".join(lines)
    if tool_name == "list_users_with_passkey":
        rows = payload.get("users", [])
        lines = [f"Usuários com passkey/FIDO2: **{payload.get('count', len(rows))}**", ""]
        for row in rows[:20]:
            lines.append(f"- {row.get('displayName') or 'N/A'} | UPN: {row.get('userPrincipalName') or 'N/A'}")
        return "\n".join(lines)
    if tool_name == "get_owned_objects":
        owner = payload.get("owner", {})
        rows = payload.get("ownedObjects", [])
        lines = [
            f"Objetos sob responsabilidade de {owner.get('userPrincipalName') or owner.get('displayName') or 'N/A'}:",
            f"- Total: **{payload.get('count', len(rows))}**",
            "",
        ]
        for row in rows[:20]:
            lines.append(
                "- "
                f"{row.get('objectName') or 'N/A'} | "
                f"Tipo: {row.get('objectType') or 'N/A'} | "
                f"Privilegiado: {'Sim' if row.get('privileged') else 'Não'}"
            )
        return "\n".join(lines)
    if tool_name == "list_objects_without_owner":
        rows = payload.get("objects", [])
        lines = [f"Objetos sem owner: **{payload.get('count', len(rows))}**", ""]
        for row in rows[:20]:
            lines.append(
                "- "
                f"{row.get('objectName') or 'N/A'} | "
                f"Tipo: {row.get('objectType') or 'N/A'} | "
                f"Privilegiado: {'Sim' if row.get('privileged') else 'Não'}"
            )
        return "\n".join(lines)
    if tool_name == "detect_toxic_combinations":
        rows = payload.get("combinations", [])
        lines = [f"Toxic combinations encontradas: **{payload.get('count', len(rows))}**", ""]
        for row in rows[:20]:
            lines.append(
                "- "
                f"{row.get('displayName') or row.get('name') or row.get('objectId') or 'N/A'} | "
                f"Risco: {row.get('risk') or 'N/A'} ({row.get('riskScore') or 0}/100)"
            )
        return "\n".join(lines)
    if tool_name == "compute_identity_blast_radius":
        identity = payload.get("identity", {})
        return (
            f"Blast radius de {identity.get('userPrincipalName') or identity.get('displayName') or identity.get('objectId') or 'N/A'}:\n"
            f"- Score: **{payload.get('blastRadiusScore', 0)}/100** ({payload.get('blastRadiusLevel', 'N/A')})\n"
            f"- Subscriptions afetadas: **{len(payload.get('subscriptionsAffected', []))}**\n"
            f"- Management Groups afetados: **{len(payload.get('managementGroupsAffected', []))}**\n"
            f"- Pode conceder acesso: **{'Sim' if payload.get('canGrantAccess') else 'Não'}**"
        )
    if tool_name == "list_top_blast_radius":
        rows = payload.get("identities", [])
        lines = [f"Top identidades por blast radius: **{payload.get('count', len(rows))}**", ""]
        for row in rows[:20]:
            identity = row.get("identity", {})
            lines.append(
                "- "
                f"{identity.get('userPrincipalName') or identity.get('displayName') or identity.get('objectId') or 'N/A'} | "
                f"Score: {row.get('blastRadiusScore', 0)}/100 ({row.get('blastRadiusLevel', 'N/A')})"
            )
        return "\n".join(lines)
    if tool_name == "timeline_natural_language_query":
        narrative = payload.get("narrative")
        if narrative:
            return str(narrative)
        return "Consulta de timeline concluída, mas sem narrativa formatada no retorno."
    if tool_name == "summarize_privilege_timeline":
        return (
            f"Resumo da timeline ({payload.get('days', 30)} dias):\n"
            f"- Eventos: **{payload.get('total_events', 0)}**\n"
            f"- Críticos/altos: **{payload.get('critical_or_high_events', 0)}**\n"
            f"- Identidades não resolvidas: **{payload.get('unresolved_identity_events', 0)}**"
        )
    if tool_name == "list_privilege_timeline_events":
        return f"Eventos de timeline encontrados: **{payload.get('count', 0)}**."
    if tool_name == "get_identity_privilege_timeline":
        identity = payload.get("identity", {})
        return (
            f"Timeline da identidade {identity.get('userPrincipalName') or identity.get('displayName') or 'N/A'}:\n"
            f"- Eventos: **{payload.get('events_count', 0)}**"
        )
    if tool_name == "export_privilege_timeline_report":
        report = payload.get("report", {})
        summary = report.get("summary", {})
        return (
            f"Relatório de timeline ({summary.get('days', 30)} dias):\n"
            f"- Eventos totais: **{summary.get('total_events', 0)}**\n"
            f"- Críticos/altos: **{summary.get('critical_or_high_events', 0)}**\n"
            f"- Identidades não resolvidas: **{summary.get('unresolved_identity_events', 0)}**"
        )
    if tool_name == "list_agent_identities":
        if payload.get("status") == "NOT_EVALUATED":
            note = payload.get("note") or "Não foi possível avaliar Agent Identities com as fontes/permissões atuais."
            error = payload.get("error")
            if error:
                return f"{note}\n\nDetalhe técnico: {error}"
            return note
        agents = payload.get("agents", [])
        total = _safe_int(payload.get("count"), len(agents))
        source_mode = str(payload.get("sourceMode") or (agents[0].get("sourceMode") if agents else "") or "").strip()
        agent_id_api_status = str(
            payload.get("agentIdApiStatus") or (agents[0].get("agentIdApiStatus") if agents else "") or "NOT_INTEGRATED"
        ).strip()
        heuristic = _is_heuristic_inventory(source_mode, agent_id_api_status)
        inventory_mode_label = "HEURISTIC" if heuristic else ("INTEGRATED" if source_mode and source_mode != "mock" else "MOCK")

        class_counter: dict[str, int] = {}
        for item in agents:
            key = str(item.get("objectClassification") or "Unknown")
            class_counter[key] = class_counter.get(key, 0) + 1

        confirmed = sum(
            1
            for item in agents
            if str(item.get("objectClassification") or "") == "Agent Identity"
            and str(item.get("identification") or "") != "Heuristic Candidate"
        )
        blueprints = class_counter.get("Agent Identity Blueprint", 0)
        managed = class_counter.get("Managed Identity", 0)
        first_party = class_counter.get("Microsoft-managed / First-party identity", 0) + class_counter.get(
            "Microsoft-managed Agent", 0
        )
        heuristic_candidates = class_counter.get("Heuristic Candidate", 0)
        unknown = class_counter.get("Unknown", 0)

        azure_status = _domain_status([str(a.get("azureRbacStatus") or "") for a in agents])
        graph_status = _domain_status([str(a.get("graphPermissionsStatus") or "") for a in agents])
        ownership_status = _ownership_coverage_status([str(a.get("ownerStatus") or "") for a in agents])
        with_azure = [a for a in agents if a.get("azureRoleAssignments")]
        with_azure_count = len(with_azure)
        without_azure_count = max(0, total - with_azure_count)
        overall = _summary_overall_assessment(azure_status, graph_status, ownership_status)

        lines = [
            "AGENT INVENTORY",
            "",
            _inventory_sentence(total, heuristic),
            f"Inventory Mode: {inventory_mode_label}",
            f"Agent ID API: {'NOT INTEGRATED' if agent_id_api_status == 'NOT_INTEGRATED' else agent_id_api_status}",
            "",
            "CLASSIFICATION",
            f"- Confirmed Agent Identities: {confirmed}",
            f"- Agent Identity Blueprints: {blueprints}",
            f"- Managed Identities: {managed}",
            f"- Microsoft/First-party identities: {first_party}",
            f"- Unclassified heuristic candidates: {heuristic_candidates}",
            f"- Unknown: {unknown}",
            "",
            "PERMISSION COVERAGE",
            f"- Azure RBAC: {_coverage_label(azure_status)}",
            f"- Microsoft Graph/API: {_coverage_label(graph_status)}",
            f"- Ownership: {_coverage_label(ownership_status)}",
            "",
            "AZURE RBAC RESULT",
            f"- Objetos com Azure RBAC identificado: {with_azure_count}",
            (
                f"- Para os outros {without_azure_count} candidatos, não foi identificado Azure RBAC dentro da cobertura da consulta executada."
                if without_azure_count > 0
                else "- Todos os candidatos avaliados possuem Azure RBAC identificado."
            ),
        ]
        if with_azure:
            lines.extend(["", "OBJECT WITH ACCESS"])
            for item in with_azure[:3]:
                identity = item.get("identity") or {}
                first = (item.get("azureRoleAssignments") or [{}])[0]
                scope_name = first.get("resource") or first.get("scopeName") or first.get("scope")
                scope_type = first.get("resourceType") or first.get("scopeType") or "Scope"
                scope_desc = f"{scope_type} {scope_name}" if scope_name else str(scope_type)
                lines.extend(
                    [
                        "",
                        f"Name: {item.get('name') or 'N/A'}",
                        f"Identity Category: {identity.get('identityCategory') or item.get('objectClassification') or 'Unknown'}",
                        f"Directory Object Type: {identity.get('directoryObjectType') or 'ServicePrincipal'}",
                        f"Role: {first.get('role') or 'N/A'}",
                        f"Capability: {first.get('effectiveCapability') or first.get('dataCapability') or 'N/A'}",
                        f"Scope: {scope_desc}",
                        f"Assignment: {first.get('accessPath') or first.get('assignmentType') or 'Direct'}",
                        f"Azure RBAC Risk: {item.get('azureRbacRisk') or item.get('riskLevel') or item.get('risk') or 'N/A'}",
                    ]
                )
        lines.extend(
            [
                "",
                "OVERALL ASSESSMENT",
                overall,
                "",
                "Reason:",
                (
                    "Azure RBAC foi avaliado. Microsoft Graph/API permissions e ownership não foram avaliados."
                    if azure_status == "EVALUATED" and graph_status == "NOT_EVALUATED" and ownership_status == "NOT_EVALUATED"
                    else "A avaliação consolidada considera apenas os domínios efetivamente avaliados."
                ),
            ]
        )
        return "\n".join(lines)
    if tool_name == "get_agents_by_owner":
        owner = payload.get("owner", {})
        agents = payload.get("agents", [])
        lines = [
            f"Owner: {owner.get('displayName') or owner.get('userPrincipalName') or 'N/A'}",
            f"Agents encontrados: **{payload.get('count', len(agents))}**",
            "",
        ]
        for agent in agents[:20]:
            lines.append(f"- **{agent.get('name') or 'N/A'}**")
            lines.append(f"  - Risco: {agent.get('risk') or 'N/A'} ({agent.get('riskScore') or 0}/100)")
            lines.append("")
        return "\n".join(lines)
    if tool_name == "get_agent_relationships":
        identity = payload.get("identity") or {}
        azure_status = _coverage_label(payload.get("azureRbacStatus"))
        graph_status = _coverage_label(payload.get("graphPermissionsStatus"))
        ownership_status = _coverage_label(
            "EVALUATED"
            if str(payload.get("ownerStatus") or "").strip().upper() in {"OWNER_CONFIGURED", "NO_OWNER_CONFIGURED", "OWNER_NOT_RESOLVED"}
            else str(payload.get("ownerStatus") or "NOT_EVALUATED")
        )
        overall = _summary_overall_assessment(azure_status, graph_status, ownership_status)
        return (
            f"Agent: {payload.get('name') or 'N/A'}\n"
            f"- Categoria: {identity.get('identityCategory') or payload.get('objectClassification') or 'Unknown'}\n"
            f"- Tipo de objeto no diretório: {identity.get('directoryObjectType') or 'ServicePrincipal'}\n"
            f"- Owners identificados: {payload.get('ownerCount', 0)}\n"
            f"- Blueprint: {(payload.get('blueprint') or {}).get('name') or 'N/A'}\n"
            f"- Azure RBAC Risk: {payload.get('azureRbacRisk') or payload.get('riskLevel') or payload.get('risk') or 'N/A'}\n"
            f"- Overall Assessment: {overall}\n"
            f"- Coverage: Azure RBAC={azure_status}, Graph/API={graph_status}, Ownership={ownership_status}"
        )
    if tool_name == "get_role_risk_score":
        return (
            f"Score da role **{payload.get('role', 'N/A')}** ({payload.get('provider', 'N/A')}): "
            f"**{payload.get('riskScore', 0)}/100**\n"
            f"- Nível: {payload.get('riskLevel', 'N/A')}\n"
            f"- Escopo: {payload.get('scope', 'N/A')}\n"
            f"- Estado: {payload.get('state', 'N/A')}\n"
            f"- Referência: {payload.get('riskSource', 'N/A')}"
        )
    if tool_name == "list_privileged_azure_role_assignments":
        assignments = payload.get("assignments", [])
        if not assignments:
            return (
                "Não encontrei atribuições privilegiadas diretas no Azure RBAC neste retorno. "
                "Se você quis cruzar Entra ID + Azure (ex.: Global Administrator + Owner), "
                "use a consulta IAM correlacionada."
            )
        lines = [f"Atribuições privilegiadas Azure RBAC: **{payload.get('count', len(assignments))}**", ""]
        for item in assignments[:20]:
            lines.append(
                "- "
                f"{item.get('displayName') or item.get('name') or item.get('principalId') or 'N/A'} | "
                f"Tipo: {item.get('identityType') or item.get('principalType') or 'N/A'} | "
                f"Role: {item.get('role') or 'N/A'} | "
                f"Escopo: {item.get('scope') or 'N/A'}"
            )
        return "\n".join(lines)
    if isinstance(payload.get("count"), int):
        return f"Consulta concluída com sucesso. Registros encontrados: **{payload.get('count', 0)}**."
    return "Consulta concluída com sucesso, mas não há um formatador específico para este tipo de retorno."


async def _openrouter_call(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    preferred_model: str | None = None,
) -> tuple[dict[str, Any], str]:
    models = _configured_models()
    if preferred_model and preferred_model in models:
        models = [preferred_model] + [m for m in models if m != preferred_model]

    errors: list[str] = []
    async with httpx.AsyncClient(timeout=60.0) as client:
        for model in models:
            try:
                response = await client.post(
                    OPENROUTER_URL,
                    headers=_headers(),
                    json={
                        "model": model,
                        "messages": messages,
                        "tools": tools,
                        "tool_choice": "auto",
                        "temperature": 0.1,
                        "max_tokens": 1200,
                    },
                )
                response.raise_for_status()
                payload = response.json()
                raw_message = payload["choices"][0]["message"]
                message = {
                    "role": "assistant",
                    "content": raw_message.get("content"),
                }
                if raw_message.get("tool_calls"):
                    message["tool_calls"] = raw_message["tool_calls"]
                return message, payload.get("model", model)
            except Exception as exc:
                errors.append(f"{model}: {exc}")
    raise RuntimeError("Falha ao chamar os modelos OpenRouter: " + " | ".join(errors))


async def ask(question: str, history: list[dict[str, str]] | None = None) -> dict[str, Any]:
    history = history or []
    messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    for item in history[-8:]:
        if item.get("role") in {"user", "assistant"} and item.get("content"):
            messages.append({"role": item["role"], "content": item["content"]})
    messages.append({"role": "user", "content": question})

    async with Client(mcp) as mcp_client:
        listed = await mcp_client.list_tools()
        openrouter_tools = [_tool_schema(tool) for tool in listed.tools]

        active_model: str | None = None
        tool_trace: list[dict[str, Any]] = []
        tool_outputs: list[dict[str, Any]] = []
        repeated_call_count: dict[str, int] = {}
        last_call_signature: str | None = None

        for _ in range(5):
            try:
                assistant_message, active_model = await _openrouter_call(
                    messages,
                    openrouter_tools,
                    preferred_model=active_model,
                )
            except Exception as exc:
                if tool_outputs:
                    latest = tool_outputs[-1]
                    fallback = _fallback_tool_for_question(question)
                    if fallback and fallback[0] != latest["tool"]:
                        fallback_tool, fallback_args = fallback
                        try:
                            fallback_result = await mcp_client.call_tool(fallback_tool, fallback_args)
                            fallback_payload = _parse_tool_result(fallback_result)
                            tool_trace.append(
                                {
                                    "tool": fallback_tool,
                                    "arguments": fallback_args,
                                    "is_error": fallback_result.is_error,
                                    "fallback_without_llm": True,
                                    "triggered_after_openrouter_failure": True,
                                }
                            )
                            if not fallback_result.is_error:
                                return {
                                    "answer": _fallback_answer_from_tool(fallback_tool, fallback_payload),
                                    "model": active_model,
                                    "tool_trace": tool_trace,
                                }
                        except Exception as tool_exc:
                            tool_trace.append(
                                {
                                    "tool": fallback_tool,
                                    "arguments": fallback_args,
                                    "is_error": True,
                                    "fallback_without_llm": True,
                                    "triggered_after_openrouter_failure": True,
                                    "error": str(tool_exc),
                                }
                            )
                    return {
                        "answer": (
                            "Não foi possível gerar a resposta final no OpenRouter neste momento, "
                            "mas a consulta no Azure foi concluída com sucesso.\n\n"
                            f"{_fallback_answer_from_tool(latest['tool'], latest['payload'])}"
                        ),
                        "model": active_model,
                        "tool_trace": tool_trace,
                    }
                fallback = _fallback_tool_for_question(question)
                if fallback:
                    fallback_tool, fallback_args = fallback
                    try:
                        fallback_result = await mcp_client.call_tool(fallback_tool, fallback_args)
                        fallback_payload = _parse_tool_result(fallback_result)
                        tool_trace.append(
                            {
                                "tool": fallback_tool,
                                "arguments": fallback_args,
                                "is_error": fallback_result.is_error,
                                "fallback_without_llm": True,
                            }
                        )
                        if not fallback_result.is_error:
                            return {
                                "answer": _fallback_answer_from_tool(fallback_tool, fallback_payload),
                                "model": active_model,
                                "tool_trace": tool_trace,
                            }
                    except Exception as tool_exc:
                        tool_trace.append(
                            {
                                "tool": fallback_tool,
                                "arguments": fallback_args,
                                "is_error": True,
                                "fallback_without_llm": True,
                                "error": str(tool_exc),
                            }
                        )
                return {
                    "answer": (
                        "Falha ao consultar o modelo OpenRouter no momento. "
                        f"Detalhe: {exc}"
                    ),
                    "model": active_model,
                    "tool_trace": tool_trace,
                }
            messages.append(assistant_message)
            calls = assistant_message.get("tool_calls") or []
            if not calls:
                fallback = _fallback_tool_for_question(question)
                if fallback:
                    fallback_tool, fallback_args = fallback
                    try:
                        fallback_result = await mcp_client.call_tool(fallback_tool, fallback_args)
                        fallback_payload = _parse_tool_result(fallback_result)
                        tool_trace.append(
                            {
                                "tool": fallback_tool,
                                "arguments": fallback_args,
                                "is_error": fallback_result.is_error,
                                "fallback_without_llm": True,
                                "triggered_after_no_tool_call": True,
                            }
                        )
                        if not fallback_result.is_error:
                            return {
                                "answer": _fallback_answer_from_tool(fallback_tool, fallback_payload),
                                "model": active_model,
                                "tool_trace": tool_trace,
                            }
                    except Exception as tool_exc:
                        tool_trace.append(
                            {
                                "tool": fallback_tool,
                                "arguments": fallback_args,
                                "is_error": True,
                                "fallback_without_llm": True,
                                "triggered_after_no_tool_call": True,
                                "error": str(tool_exc),
                            }
                        )
                return {
                    "answer": assistant_message.get("content") or "Não foi possível gerar uma resposta textual.",
                    "model": active_model,
                    "tool_trace": tool_trace,
                }

            signature_parts: list[str] = []
            for call in calls:
                name = call["function"]["name"]
                raw_args = call["function"].get("arguments") or "{}"
                signature_parts.append(f"{name}:{raw_args}")
            call_signature = "||".join(signature_parts)
            repeated_call_count[call_signature] = repeated_call_count.get(call_signature, 0) + 1
            if last_call_signature == call_signature and repeated_call_count[call_signature] >= 2:
                if tool_outputs:
                    latest = tool_outputs[-1]
                    return {
                        "answer": (
                            "Interrompi um ciclo repetitivo de chamadas no chat para evitar loop. "
                            "Aqui está o último resultado consolidado:\n\n"
                            f"{_fallback_answer_from_tool(latest['tool'], latest['payload'])}"
                        ),
                        "model": active_model,
                        "tool_trace": tool_trace,
                    }
                return {
                    "answer": "Interrompi um ciclo repetitivo de chamadas no chat para evitar loop. Tente refinar a pergunta.",
                    "model": active_model,
                    "tool_trace": tool_trace,
                }
            last_call_signature = call_signature

            for call in calls:
                name = call["function"]["name"]
                raw_args = call["function"].get("arguments") or "{}"
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except json.JSONDecodeError:
                    args = {}
                try:
                    tool_timeout = 45
                    if name in {"list_agent_identities", "agent_natural_language_query", "run_agent_assessment"}:
                        tool_timeout = 90
                    result = await asyncio.wait_for(mcp_client.call_tool(name, args), timeout=tool_timeout)
                except TimeoutError:
                    tool_trace.append(
                        {
                            "tool": name,
                            "arguments": args,
                            "is_error": True,
                            "error": f"Timeout ao executar tool ({tool_timeout}s).",
                        }
                    )
                    if tool_outputs:
                        latest = tool_outputs[-1]
                        return {
                            "answer": (
                                f"A consulta excedeu o tempo limite ({tool_timeout}s) e foi interrompida para evitar travamento.\n\n"
                                f"{_fallback_answer_from_tool(latest['tool'], latest['payload'])}"
                            ),
                            "model": active_model,
                            "tool_trace": tool_trace,
                        }
                    return {
                        "answer": (
                            f"A consulta excedeu o tempo limite ({tool_timeout}s) e foi interrompida."
                        ),
                        "model": active_model,
                        "tool_trace": tool_trace,
                    }
                except Exception as exc:
                    tool_trace.append(
                        {
                            "tool": name,
                            "arguments": args,
                            "is_error": True,
                            "error": str(exc),
                        }
                    )
                    return {
                        "answer": (
                            "Falha ao executar uma consulta interna necessária para responder com dados do ambiente. "
                            f"Detalhe: {exc}"
                        ),
                        "model": active_model,
                        "tool_trace": tool_trace,
                    }
                payload = _tool_payload(result)
                tool_trace.append({"tool": name, "arguments": args, "is_error": result.is_error})
                tool_outputs.append({"tool": name, "payload": payload})
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "name": name,
                        "content": json.dumps(payload, ensure_ascii=False, default=str),
                    }
                )

    return {
        "answer": "Limite de chamadas de ferramentas atingido neste turno.",
        "model": active_model,
        "tool_trace": tool_trace,
    }
