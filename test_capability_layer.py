"""Suíte dedicada à capability layer (registry + router + executor).

Diferente de test_smoke.py (que cobre as tools MCP "clássicas" ponta a
ponta), este arquivo testa especificamente a camada nova introduzida por
services/graph_capabilities.py, services/capability_router.py e
services/capability_executor.py, que é onde bugs de MOCK_MODE, escopo de
subscription, permission footprint e roteamento já foram encontrados.

Cobre:
- execução em modo mock (sem autenticação real)
- expectativas de roteamento do capability_router
- validação de parâmetros/filtros não declarados
- comportamento GET vs LIST vs bloqueio de escrita
- metadados de permissão retornados
- sanitização de identidades/scopes quando SANITIZE_FOR_LLM=true
- escopo de subscriptions no Resource Graph mock
"""

import os

os.environ["MOCK_MODE"] = "true"
os.environ["SANITIZE_FOR_LLM"] = "true"

import json

from services.capability_executor import (
    CapabilityError,
    execute_capability,
    safe_execute_capability,
)
from services.capability_router import route_question
from services.capability_service import capability_execute
from services.graph_capabilities import get_capability, is_write_operation


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# --------------------------------------------------------------------------
# 1. Execução em modo mock (sem autenticação real)
# --------------------------------------------------------------------------


def test_mock_execution_graph_list() -> None:
    result = execute_capability("graph.users.list", {"limit": 10}, operation="list")
    _assert(result["ok"], "graph.users.list deveria retornar ok=True em mock")
    _assert(result["execution_mode"] == "mock", "execution_mode deveria ser 'mock'")
    _assert(result["count"] >= 1, "graph.users.list deveria retornar ao menos 1 item em mock")


def test_mock_execution_resource_graph() -> None:
    result = execute_capability(
        "azure.resources.inventory",
        {"query": "Resources | project id, name, type", "limit": 10},
        operation="query",
    )
    _assert(result["ok"], "azure.resources.inventory deveria retornar ok=True em mock")
    _assert(result["execution_mode"] == "mock", "execution_mode deveria ser 'mock'")


def test_mock_not_supported_returns_explicit_error() -> None:
    """Capabilities sem fixture devem falhar de forma explícita, nunca autenticar de verdade."""
    cap = get_capability("graph.signins.list")
    if cap is None or cap.is_available:
        return  # capability não existe mais ou passou a ser suportada; nada a validar aqui
    result = safe_execute_capability("graph.signins.list", {"limit": 5}, operation="list")
    _assert(not result["ok"], "capability não integrada não deveria retornar ok=True")


# --------------------------------------------------------------------------
# 2. Expectativas de roteamento (capability_router)
# --------------------------------------------------------------------------


def test_router_service_principal_without_owner() -> None:
    plan = route_question("quais service principals estão sem owner?")
    _assert(plan.has_capability, "deveria haver ao menos uma capability roteada")
    _assert(
        plan.primary.capability.id == "graph.service_principals.owners",
        f"esperado graph.service_principals.owners, obtido {plan.primary.capability.id}",
    )


def test_router_application_provenance_alias() -> None:
    plan = route_question("quais aplicações foram criadas no meu tenant?")
    _assert(plan.has_capability, "deveria haver ao menos uma capability roteada")
    _assert(
        plan.primary.capability.id == "graph.applications.provenance",
        f"esperado graph.applications.provenance, obtido {plan.primary.capability.id}",
    )


def test_router_azure_owner_goes_to_rbac() -> None:
    plan = route_question("quem é Owner no Azure?")
    _assert(plan.has_capability, "deveria haver ao menos uma capability roteada")
    _assert(
        plan.primary.capability.id == "azure.rbac.role_assignments",
        f"esperado azure.rbac.role_assignments, obtido {plan.primary.capability.id}",
    )


def test_router_bare_owner_does_not_force_azure_rbac() -> None:
    """'owner' isolado não deve ser tratado como sinal forte de Azure RBAC."""
    plan = route_question("quem é o owner deste grupo?")
    if plan.has_capability:
        _assert(
            plan.primary.capability.id != "azure.rbac.role_assignments",
            "pergunta sobre owner de grupo não deveria rotear para Azure RBAC",
        )


# --------------------------------------------------------------------------
# 3. Validação de parâmetros/filtros não declarados
# --------------------------------------------------------------------------


def test_unsupported_param_is_rejected() -> None:
    try:
        execute_capability(
            "graph.users.list",
            {"limit": 5, "$search": '"displayName:ana"'},
            operation="list",
        )
    except CapabilityError as exc:
        _assert(exc.kind == "invalid_input", f"esperado invalid_input, obtido {exc.kind}")
    else:
        raise AssertionError("$search não implementado deveria ser rejeitado")


def test_unknown_capability_is_rejected() -> None:
    try:
        execute_capability("graph.does.not.exist", {"limit": 5}, operation="list")
    except CapabilityError as exc:
        _assert(exc.kind == "unknown_capability", f"esperado unknown_capability, obtido {exc.kind}")
    else:
        raise AssertionError("capability inexistente deveria ser rejeitada")


def test_select_rejects_undeclared_property() -> None:
    try:
        execute_capability(
            "graph.users.list",
            {"limit": 5, "select": "passwordHash"},
            operation="list",
        )
    except CapabilityError as exc:
        _assert(exc.kind == "invalid_input", f"esperado invalid_input, obtido {exc.kind}")
    else:
        raise AssertionError("propriedade não declarada em $select deveria ser rejeitada")


# --------------------------------------------------------------------------
# 4. Comportamento GET vs LIST vs bloqueio de escrita
# --------------------------------------------------------------------------


def test_write_operation_is_blocked() -> None:
    _assert(is_write_operation("create"), "'create' deveria ser tratado como escrita")
    try:
        execute_capability("graph.users.list", {"limit": 5}, operation="create")
    except CapabilityError as exc:
        _assert(exc.kind == "write_blocked", f"esperado write_blocked, obtido {exc.kind}")
    else:
        raise AssertionError("operação de escrita deveria ser bloqueada")


def test_get_on_collection_endpoint_without_id_is_rejected() -> None:
    """Capability de coleção (sem {id} no endpoint) não deve aceitar operation='get'."""
    cap = get_capability("graph.users.list")
    _assert(cap is not None and "{id}" not in cap.endpoint, "fixture do teste mudou de forma inesperada")
    try:
        execute_capability("graph.users.list", {"id": "whatever", "limit": 1}, operation="get")
    except CapabilityError as exc:
        _assert(exc.kind == "unsupported_operation", f"esperado unsupported_operation, obtido {exc.kind}")
    else:
        raise AssertionError("get em endpoint de coleção sem {id} deveria ser rejeitado")


def test_get_on_capability_with_id_placeholder_works() -> None:
    result = execute_capability(
        "graph.groups.members",
        {"id": "g-001", "limit": 1},
        operation="get",
    )
    _assert(result["ok"], "get em capability com {id} no endpoint deveria funcionar")


# --------------------------------------------------------------------------
# 5. Metadados de permissão retornados
# --------------------------------------------------------------------------


def test_required_permissions_are_returned() -> None:
    result = execute_capability("graph.users.list", {"limit": 5}, operation="list")
    perms = result.get("required_permissions") or {}
    _assert("delegated" in perms and "application" in perms, "required_permissions deveria ter delegated/application")
    _assert(len(perms["delegated"]) > 0, "graph.users.list deveria declarar permissões delegated")


def test_registration_details_permission_footprint_is_minimal() -> None:
    cap = get_capability("graph.authentication.registration_details")
    _assert(cap is not None, "capability deveria existir no registry")
    _assert(
        "Reports.Read.All" not in cap.delegated_permissions,
        "Reports.Read.All não é least-privilege para userRegistrationDetails",
    )
    _assert(
        "Reports.Read.All" not in cap.application_permissions,
        "Reports.Read.All não é least-privilege para userRegistrationDetails",
    )


def test_app_role_assignments_assigned_to_permission_footprint_is_minimal() -> None:
    cap = get_capability("graph.app_role_assignments.assigned_to")
    _assert(cap is not None, "capability deveria existir no registry")
    _assert(
        "Directory.Read.All" not in cap.delegated_permissions,
        "Directory.Read.All é privilégio adicional desnecessário para appRoleAssignedTo",
    )


# --------------------------------------------------------------------------
# 6. Sanitização quando SANITIZE_FOR_LLM=true
# --------------------------------------------------------------------------


def test_graph_list_users_sanitizes_known_mock_values() -> None:
    result = capability_execute("graph.users.list", {"limit": 20}, operation="list")
    _assert(result["ok"], "graph.users.list deveria ter sucesso")
    payload_text = json.dumps(result)
    _assert(
        "ana.silva@contoso.com" not in payload_text,
        "UPN real do fixture não deveria vazar quando SANITIZE_FOR_LLM=true",
    )


def test_azure_rbac_sanitizes_scope_and_principal() -> None:
    result = capability_execute(
        "azure.rbac.role_assignments",
        {
            "query": (
                "AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' "
                "| project principalId, principalType, roleDefinitionId, scope"
            ),
            "limit": 20,
        },
        operation="query",
    )
    _assert(result["ok"], "azure.rbac.role_assignments deveria ter sucesso em mock")
    payload_text = json.dumps(result)
    _assert(
        "/subscriptions/sub-prd" not in payload_text,
        "subscription id real não deveria vazar quando SANITIZE_FOR_LLM=true",
    )


# --------------------------------------------------------------------------
# 7. Escopo de subscriptions no Resource Graph mock
# --------------------------------------------------------------------------


def test_resource_inventory_respects_subscription_scope() -> None:
    from services.azure_graph import _load_mock

    all_rows = list(_load_mock())
    subscriptions = sorted({str(row.get("subscriptionId")) for row in all_rows if row.get("subscriptionId")})
    if len(subscriptions) < 2:
        return  # fixture não tem subscriptions suficientes para validar o filtro

    target = subscriptions[0]
    result = execute_capability(
        "azure.resources.inventory",
        {
            "query": "Resources | project id, name, type, subscriptionId",
            "subscriptions": [target],
            "limit": 100,
        },
        operation="query",
    )
    _assert(result["ok"], "azure.resources.inventory deveria ter sucesso com subscriptions explícitas")
    returned_subs = {item["raw"].get("subscriptionId") for item in result["items"]}
    _assert(
        returned_subs <= {target},
        f"esperado apenas '{target}', obtido {returned_subs}",
    )


def test_resource_inventory_without_subscriptions_preserves_previous_behavior() -> None:
    result = execute_capability(
        "azure.resources.inventory",
        {"query": "Resources | project id, name, type, subscriptionId", "limit": 100},
        operation="query",
    )
    _assert(result["ok"], "azure.resources.inventory sem subscriptions explícitas deveria continuar funcionando")


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------


def main() -> None:
    tests = [
        test_mock_execution_graph_list,
        test_mock_execution_resource_graph,
        test_mock_not_supported_returns_explicit_error,
        test_router_service_principal_without_owner,
        test_router_application_provenance_alias,
        test_router_azure_owner_goes_to_rbac,
        test_router_bare_owner_does_not_force_azure_rbac,
        test_unsupported_param_is_rejected,
        test_unknown_capability_is_rejected,
        test_select_rejects_undeclared_property,
        test_write_operation_is_blocked,
        test_get_on_collection_endpoint_without_id_is_rejected,
        test_get_on_capability_with_id_placeholder_works,
        test_required_permissions_are_returned,
        test_registration_details_permission_footprint_is_minimal,
        test_app_role_assignments_assigned_to_permission_footprint_is_minimal,
        test_graph_list_users_sanitizes_known_mock_values,
        test_azure_rbac_sanitizes_scope_and_principal,
        test_resource_inventory_respects_subscription_scope,
        test_resource_inventory_without_subscriptions_preserves_previous_behavior,
    ]
    for test in tests:
        test()
        print(f"  ok  {test.__name__}")
    print("Capability layer test suite OK")


if __name__ == "__main__":
    main()
