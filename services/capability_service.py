"""Orquestração das capacidades de identidade expostas pelo MCP.

Une roteamento de intenção, execução segura, normalização e correlação em
operações reutilizáveis, evitando uma tool nova por pergunta.
"""

from __future__ import annotations

from typing import Any

from services.capability_executor import safe_execute_capability
from services.capability_normalizer import correlate_identities, summarize_result
from services.capability_router import explain_routing, route_question
from services.graph_capabilities import (
    AZURE_SOURCES,
    SOURCE_GRAPH,
    STATUS_NOT_INTEGRATED,
    domain_coverage,
    get_capability,
    list_capabilities,
    list_domains,
    required_permissions,
)

# Consultas KQL padrão usadas para capacidades Azure que exigem 'query'.
DEFAULT_KQL: dict[str, str] = {
    "azure.rbac.role_assignments": (
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/roleassignments' "
        "| extend principalId=tostring(properties.principalId), "
        "principalType=tostring(properties.principalType), "
        "roleDefinitionId=tostring(properties.roleDefinitionId), "
        "scope=tostring(properties.scope) "
        "| project principalId, principalType, roleDefinitionId, scope"
    ),
    "azure.rbac.deny_assignments": (
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/denyassignments' "
        "| extend principalId=tostring(properties.principalId), "
        "scope=tostring(properties.scope), "
        "denyAssignmentName=tostring(properties.denyAssignmentName) "
        "| project principalId, scope, denyAssignmentName"
    ),
    "azure.resources.inventory": (
        "Resources | project id, name, type, location, resourceGroup, subscriptionId"
    ),
}


def _params_for(capability_id: str, limit: int, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"limit": limit}
    if capability_id in DEFAULT_KQL:
        params["query"] = DEFAULT_KQL[capability_id]
    if extra:
        params.update(extra)
    return params


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

capability_explain_routing = explain_routing
capability_list = list_capabilities
capability_domains = list_domains
capability_domain_coverage = domain_coverage


def capability_execute(
    capability_id: str,
    params: dict[str, Any] | None = None,
    operation: str = "list",
) -> dict[str, Any]:
    """Executa uma capability aplicando defaults seguros quando aplicável."""
    merged = dict(params or {})

    handler = COMPOSITE_CAPABILITIES.get(capability_id)
    if handler is not None:
        return handler(merged, operation)

    if capability_id in DEFAULT_KQL and not merged.get("query"):
        merged["query"] = DEFAULT_KQL[capability_id]
    result = safe_execute_capability(capability_id, merged, operation=operation)
    if result.get("ok"):
        result["summary"] = summarize_result(result)
    return result


def _execute_application_provenance(params: dict[str, Any], operation: str) -> dict[str, Any]:
    """Capability composta: cruza /servicePrincipals com /applications."""
    from services.graph_capabilities import is_write_operation

    if is_write_operation(operation):
        return {
            "ok": False,
            "error_kind": "write_blocked",
            "error": f"Operação '{operation.upper()}' bloqueada: o MCP está em modo READ ONLY.",
        }

    from services.app_provenance import list_application_provenance

    limit = int(params.get("limit") or 200)
    result = list_application_provenance(
        provenance=str(params.get("provenance") or "all"),
        include_managed_identities=bool(params.get("include_managed_identities", True)),
        limit=limit,
    )
    if result.get("ok"):
        result.setdefault("capability_id", "graph.applications.provenance")
        result.setdefault("domain", "application_provenance")
        result.setdefault("source", SOURCE_GRAPH)
    return result


COMPOSITE_CAPABILITIES: dict[str, Any] = {
    "graph.applications.provenance": _execute_application_provenance,
}


def capability_required_permissions(question: str = "", capability_id: str = "") -> dict[str, Any]:
    """Permissões necessárias para uma pergunta ou capability específica."""
    if capability_id:
        cap = get_capability(capability_id)
        if cap is None:
            return {
                "ok": False,
                "error_kind": "unknown_capability",
                "error": f"Capability '{capability_id}' não existe no registry.",
            }
        return {
            "ok": True,
            "capability_id": cap.id,
            "domain": cap.domain,
            "source": cap.source,
            "support_status": cap.support_status,
            "requires_license": cap.requires_license,
            "supports_delegated_permission": cap.supports_delegated,
            "supports_application_permission": cap.supports_application,
            "required_permissions": {
                "delegated": list(cap.delegated_permissions),
                "application": list(cap.application_permissions),
            },
        }

    if not question.strip():
        return {
            "ok": False,
            "error_kind": "invalid_input",
            "error": "Informe 'question' ou 'capability_id'.",
        }

    plan = route_question(question)
    if plan.blocked:
        return {"ok": False, "error_kind": "write_blocked", "error": plan.blocked_reason}

    selected_ids = [item.capability.id for item in plan.selected]
    return {
        "ok": True,
        "question": question,
        "capabilities": selected_ids,
        "sources": plan.sources,
        "required_permissions": required_permissions(selected_ids),
        "licenses": sorted(
            {
                item.capability.requires_license
                for item in plan.selected
                if item.capability.requires_license
            }
        ),
        "notes": plan.notes,
    }


# --------------------------------------------------------------------------
# Pergunta em linguagem natural
# --------------------------------------------------------------------------


def capability_answer_question(question: str, limit: int = 50) -> dict[str, Any]:
    """Fluxo completo: NL -> intenção -> capability -> execução -> normalização."""
    plan = route_question(question)

    if plan.blocked:
        return {
            "ok": False,
            "error_kind": "write_blocked",
            "error": plan.blocked_reason,
            "read_only_mode": True,
            "allowed_operations": ["get", "list", "query", "assess", "correlate"],
        }

    if not plan.has_capability:
        gaps = sorted({item.capability.domain for item in plan.unavailable})
        message = (
            "Essa consulta exige uma API/capability ainda não integrada ao MCP."
            if gaps
            else "Não identifiquei um domínio de identidade suportado nessa pergunta."
        )
        return {
            "ok": False,
            "error_kind": "no_capability",
            "error": message,
            "question": question,
            "recognized_gap_domains": gaps,
            "missing_capabilities": [item.capability.to_dict() for item in plan.unavailable],
            "available_domains": list_domains(),
            "notes": plan.notes,
        }

    results: list[dict[str, Any]] = []
    for item in plan.selected:
        cap = item.capability
        params = _params_for(cap.id, limit)
        if "{id}" in cap.endpoint or "{scope}" in cap.endpoint:
            # Capacidades que exigem um alvo específico não são executadas em
            # resposta aberta; são reportadas como próximo passo.
            continue
        results.append(capability_execute(cap.id, params, operation="list"))

    executed = [r for r in results if r.get("ok")]
    failed = [r for r in results if not r.get("ok")]

    needs_target = [
        item.capability.to_dict()
        for item in plan.selected
        if "{id}" in item.capability.endpoint or "{scope}" in item.capability.endpoint
    ]

    payload: dict[str, Any] = {
        "ok": bool(executed),
        "question": question,
        "interpreted_operation": plan.operation,
        "routing": plan.to_dict(),
        "sources_used": sorted({r.get("source") for r in executed if r.get("source")}),
        "results": executed,
        "summaries": [summarize_result(r) for r in executed],
        "failures": failed,
        "requires_target_input": needs_target,
        "notes": list(plan.notes),
        "read_only_mode": True,
    }

    if len(executed) > 1:
        payload["correlation"] = correlate_identities(*executed)

    if not executed and failed:
        payload["error_kind"] = failed[0].get("error_kind", "provider_error")
        payload["error"] = failed[0].get("error")

    if plan.is_multi_source:
        payload.setdefault("notes", []).append(
            "Resultados de Microsoft Graph e de APIs Azure foram mantidos separados."
        )

    return payload


# --------------------------------------------------------------------------
# Atribuições de privilégio (fontes separadas)
# --------------------------------------------------------------------------


def capability_role_assignments(
    include_directory_roles: bool = True,
    include_pim: bool = True,
    include_azure_rbac: bool = True,
    limit: int = 200,
) -> dict[str, Any]:
    """Consulta privilégios mantendo Graph (diretório) e Azure RBAC separados."""
    graph_results: list[dict[str, Any]] = []
    azure_results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    def _run(capability_id: str, bucket: list[dict[str, Any]]) -> None:
        result = capability_execute(capability_id, _params_for(capability_id, limit))
        (bucket if result.get("ok") else failures).append(result)

    if include_directory_roles:
        _run("graph.directory_roles.list", graph_results)

    if include_pim:
        _run("graph.pim.eligible_directory_roles", graph_results)
        _run("graph.pim.active_directory_roles", graph_results)

    if include_azure_rbac:
        _run("azure.rbac.role_assignments", azure_results)
        _run("azure.rbac.deny_assignments", azure_results)

    coverage = {
        "directory_roles": _coverage_state(include_directory_roles, graph_results, "directory_roles"),
        "pim_directory": _coverage_state(include_pim, graph_results, "pim"),
        "azure_rbac": _coverage_state(include_azure_rbac, azure_results, "azure_rbac"),
        "azure_pim_resource": "NOT_EVALUATED",
    }

    return {
        "ok": bool(graph_results or azure_results),
        "read_only_mode": True,
        "microsoft_graph": {
            "scope": "Identidade e funções de diretório (Entra ID)",
            "results": graph_results,
            "summaries": [summarize_result(r) for r in graph_results],
        },
        "azure": {
            "scope": "Azure RBAC em subscriptions/resource groups/recursos",
            "results": azure_results,
            "summaries": [summarize_result(r) for r in azure_results],
        },
        "coverage": coverage,
        "failures": failures,
        "notes": [
            "Microsoft Graph não cobre Azure RBAC; as fontes são consultadas separadamente.",
            "PIM de recursos Azure exige escopo explícito e é reportado como NOT_EVALUATED aqui.",
            "NOT_EVALUATED não significa zero.",
        ],
    }


def _coverage_state(requested: bool, results: list[dict[str, Any]], domain: str) -> str:
    if not requested:
        return "NOT_EVALUATED"
    matching = [r for r in results if r.get("domain") == domain]
    if not matching:
        return "NOT_EVALUATED"
    if any(r.get("truncated") for r in matching):
        return "PARTIAL"
    return "EVALUATED"


# --------------------------------------------------------------------------
# Objetos de diretório + correlação
# --------------------------------------------------------------------------

_DEFAULT_OBJECT_DOMAINS = ("users", "groups", "service_principals", "applications")


def capability_directory_objects(
    question: str = "",
    domains: list[str] | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Coleta objetos de diretório e correlaciona a mesma identidade entre domínios."""
    target_domains = list(domains or [])

    if not target_domains and question.strip():
        plan = route_question(question)
        if plan.blocked:
            return {"ok": False, "error_kind": "write_blocked", "error": plan.blocked_reason}
        target_domains = list(dict.fromkeys(item.capability.domain for item in plan.selected))

    if not target_domains:
        target_domains = list(_DEFAULT_OBJECT_DOMAINS)

    known = set(list_domains())
    unknown = [d for d in target_domains if d not in known]
    target_domains = [d for d in target_domains if d in known]

    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    gaps: list[str] = []

    for domain in target_domains:
        caps = [c for c in list_capabilities(domain=domain, only_available=True) if "{id}" not in c.endpoint]
        if not caps:
            gaps.append(domain)
            continue
        cap = caps[0]
        result = capability_execute(cap.id, _params_for(cap.id, limit))
        (results if result.get("ok") else failures).append(result)

    payload: dict[str, Any] = {
        "ok": bool(results),
        "read_only_mode": True,
        "requested_domains": target_domains,
        "unknown_domains": unknown,
        "domains_without_capability": gaps,
        "results": results,
        "summaries": [summarize_result(r) for r in results],
        "failures": failures,
    }
    if results:
        payload["correlation"] = correlate_identities(*results)
    return payload


# --------------------------------------------------------------------------
# Assessment orientado a capability
# --------------------------------------------------------------------------

ASSESSMENT_SCOPES: dict[str, tuple[str, ...]] = {
    "identity": (
        "users",
        "external_identities",
        "groups",
        "directory_roles",
        "pim",
        "applications",
        "application_provenance",
        "service_principals",
        "workload_identities",
        "app_role_assignments",
        "authentication",
        "conditional_access",
    ),
    "directory": ("users", "groups", "directory_roles", "administrative_units"),
    "privileged": ("directory_roles", "pim", "azure_rbac", "azure_pim", "app_role_assignments"),
    "workload": (
        "service_principals",
        "workload_identities",
        "application_provenance",
        "app_role_assignments",
    ),
    "azure": ("azure_subscriptions", "azure_rbac", "azure_resources", "azure_management_groups"),
}


def capability_assessment(scope: str = "identity", limit: int = 200) -> dict[str, Any]:
    """Assessment com cobertura explícita por domínio (nunca trata gap como zero)."""
    scope_key = (scope or "identity").strip().lower()
    domains = ASSESSMENT_SCOPES.get(scope_key)
    if domains is None:
        return {
            "ok": False,
            "error_kind": "invalid_input",
            "error": f"Escopo '{scope}' inválido. Use: {', '.join(sorted(ASSESSMENT_SCOPES))}.",
        }

    coverage_rows: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for domain in domains:
        caps = list_capabilities(domain=domain)
        available = [c for c in caps if c.is_available and "{id}" not in c.endpoint and "{scope}" not in c.endpoint]
        gap_caps = [c for c in caps if c.support_status == STATUS_NOT_INTEGRATED]

        if not available:
            needs_target = [c for c in caps if c.is_available]
            if needs_target:
                reason = (
                    "Capability integrada, porém exige um alvo específico "
                    f"({', '.join(c.resource for c in needs_target)}). "
                    "Consulte com graph_relationship informando o objeto."
                )
            else:
                reason = "Nenhuma capability integrada para este domínio."
            coverage_rows.append(
                {
                    "domain": domain,
                    "status": "NOT_EVALUATED",
                    "reason": reason,
                    "requires_target": [c.id for c in needs_target],
                    "missing_capabilities": [c.resource for c in gap_caps],
                    "source": caps[0].source if caps else "unknown",
                }
            )
            continue

        cap = available[0]
        result = capability_execute(cap.id, _params_for(cap.id, limit), operation="list")
        if result.get("ok"):
            results.append(result)
            status = "PARTIAL" if (result.get("truncated") or gap_caps) else "EVALUATED"
            coverage_rows.append(
                {
                    "domain": domain,
                    "status": status,
                    "source": cap.source,
                    "capability_id": cap.id,
                    "observed_count": result.get("count"),
                    "missing_capabilities": [c.resource for c in gap_caps],
                }
            )
        else:
            failures.append(result)
            coverage_rows.append(
                {
                    "domain": domain,
                    "status": "NOT_EVALUATED",
                    "source": cap.source,
                    "capability_id": cap.id,
                    "reason": result.get("error"),
                    "error_kind": result.get("error_kind"),
                }
            )

    evaluated = sum(1 for row in coverage_rows if row["status"] == "EVALUATED")
    partial = sum(1 for row in coverage_rows if row["status"] == "PARTIAL")
    not_evaluated = sum(1 for row in coverage_rows if row["status"] == "NOT_EVALUATED")

    if not_evaluated == len(coverage_rows):
        overall = "NOT_EVALUATED"
    elif not_evaluated or partial:
        overall = "PARTIAL"
    else:
        overall = "EVALUATED"

    graph_results = [r for r in results if r.get("source") == SOURCE_GRAPH]
    azure_results = [r for r in results if r.get("source") in AZURE_SOURCES]

    return {
        "ok": bool(results),
        "read_only_mode": True,
        "scope": scope_key,
        "overall_coverage": overall,
        "coverage": coverage_rows,
        "coverage_totals": {
            "evaluated": evaluated,
            "partial": partial,
            "not_evaluated": not_evaluated,
            "domains": len(coverage_rows),
        },
        "microsoft_graph_results": [summarize_result(r) for r in graph_results],
        "azure_results": [summarize_result(r) for r in azure_results],
        "failures": failures,
        "notes": [
            "NOT_EVALUATED não equivale a zero.",
            "Cobertura PARCIAL indica que domínios relevantes não foram totalmente avaliados.",
            "Microsoft Graph e Azure RBAC são avaliados como fontes distintas.",
        ],
    }
