"""Camada de execução segura para capacidades de identidade (READ ONLY).

Toda chamada passa obrigatoriamente por:

1. capability allowlist   -- só executa IDs presentes no registry
2. permission validation  -- valida permissões declaradas e traduz 403
3. input validation       -- parâmetros e filtros precisam ser suportados
4. scope validation       -- escopos Azure e IDs de diretório validados
5. safe execution         -- URL construída pelo registry, nunca pelo chamador
6. normalized output      -- resultado padronizado com metadados de origem

Nenhuma operação de escrita é permitida nesta fase.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

import httpx

from services.azure_auth import cached_query, get_arm_token
from services.graph_capabilities import (
    SOURCE_AZURE_AUTHORIZATION,
    SOURCE_AZURE_MANAGEMENT,
    SOURCE_GRAPH,
    SOURCE_RESOURCE_GRAPH,
    Capability,
    get_capability,
    is_write_operation,
)
from services.azure_graph import is_mock_mode as _is_mock_mode

MAX_PAGE_SIZE = 999
DEFAULT_LIMIT = 100
HARD_LIMIT = 2000

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._@\-]{1,128}$")
AZURE_SCOPE_RE = re.compile(
    r"^/(subscriptions/[0-9a-fA-F-]{36}"
    r"(/resourceGroups/[A-Za-z0-9._()\-]{1,90})?"
    r"(/providers/[A-Za-z0-9./_\-]{1,300})?"
    r"|providers/Microsoft\.Management/managementGroups/[A-Za-z0-9._()\-]{1,90})$"
)

# Caracteres/termos proibidos em qualquer valor vindo do LLM ou do usuário.
FILTER_FORBIDDEN_RE = re.compile(
    r"(;|\n|\r|--|/\*|\*/|\bdelete\b|\bupdate\b|\binsert\b|\bdrop\b)", re.IGNORECASE
)
ODATA_FIELD_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_/]*)\s*(?:eq|ne|gt|ge|lt|le|in|has)\b")
ODATA_FUNC_FIELD_RE = re.compile(r"\b(?:startswith|endswith|contains)\s*\(\s*([A-Za-z_][A-Za-z0-9_/]*)")

# Operadores KQL que buscam dados fora do escopo autorizado.
KQL_FORBIDDEN_OPERATORS: tuple[str, ...] = (
    "externaldata",
    "http_request",
    "evaluate ",
    ".create",
    ".drop",
    ".set",
    ".append",
)


class CapabilityError(Exception):
    """Erro previsto de execução, com mensagem segura para o usuário final."""

    def __init__(self, message: str, *, kind: str = "error", details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.kind = kind
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error_kind": self.kind,
            "error": self.message,
            **self.details,
        }


# --------------------------------------------------------------------------
# 1. Allowlist
# --------------------------------------------------------------------------


def _resolve_capability(capability_id: str) -> Capability:
    cap = get_capability(capability_id)
    if cap is None:
        raise CapabilityError(
            f"Capability '{capability_id}' não existe no registry. "
            "O MCP não executa endpoints arbitrários.",
            kind="unknown_capability",
        )
    if not cap.is_available:
        raise CapabilityError(
            f"Essa consulta exige a capability '{cap.resource}' ({cap.domain}), "
            "que ainda não foi integrada ao MCP.",
            kind="not_integrated",
            details={
                "capability_id": cap.id,
                "domain": cap.domain,
                "source": cap.source,
                "support_status": cap.support_status,
            },
        )
    return cap


# Endpoints singleton (sem coleção) onde GET é válido mesmo sem {id} no path,
# pois o próprio endpoint já identifica um único recurso (ex.: o tenant atual).
SINGLETON_GET_CAPABILITIES = frozenset({"graph.organization.get"})


def _assert_read_only(cap: Capability, operation: str) -> None:
    if is_write_operation(operation):
        raise CapabilityError(
            f"Operação '{operation.upper()}' bloqueada: o MCP está em modo READ ONLY.",
            kind="write_blocked",
        )
    if operation not in cap.operations:
        raise CapabilityError(
            f"Operação '{operation}' não é suportada pela capability '{cap.id}'. "
            f"Suportadas: {', '.join(cap.operations)}.",
            kind="unsupported_operation",
        )
    if cap.method not in {"GET", "POST"}:
        raise CapabilityError(
            f"Método HTTP '{cap.method}' não permitido em modo READ ONLY.",
            kind="write_blocked",
        )
    if cap.method == "POST" and cap.source not in {SOURCE_RESOURCE_GRAPH, SOURCE_GRAPH}:
        raise CapabilityError(
            "POST só é permitido para consultas de leitura em lote conhecidas.",
            kind="write_blocked",
        )
    if (
        operation == "get"
        and "{id}" not in cap.endpoint
        and cap.id not in SINGLETON_GET_CAPABILITIES
    ):
        raise CapabilityError(
            f"A capability '{cap.id}' é de coleção (endpoint sem '{{id}}') e não "
            "suporta a operação 'get'. Use 'list' para consultá-la.",
            kind="unsupported_operation",
        )


# --------------------------------------------------------------------------
# 3/4. Validação de input e escopo
# --------------------------------------------------------------------------


def _validate_object_id(value: str, label: str = "id") -> str:
    candidate = (value or "").strip()
    if not candidate:
        raise CapabilityError(f"Parâmetro '{label}' é obrigatório.", kind="invalid_input")
    if GUID_RE.match(candidate) or SAFE_ID_RE.match(candidate):
        return candidate
    raise CapabilityError(
        f"Valor inválido para '{label}'. Use um GUID ou identificador simples.",
        kind="invalid_input",
    )


def _validate_scope(scope: str) -> str:
    candidate = (scope or "").strip().rstrip("/")
    if not candidate:
        raise CapabilityError("Escopo Azure é obrigatório para esta capability.", kind="invalid_input")
    if not candidate.startswith("/"):
        candidate = "/" + candidate
    if not AZURE_SCOPE_RE.match(candidate):
        raise CapabilityError(
            "Escopo Azure inválido. Use /subscriptions/<guid>[/resourceGroups/<nome>] "
            "ou /providers/Microsoft.Management/managementGroups/<id>.",
            kind="invalid_scope",
        )
    return candidate


def _validate_filter(cap: Capability, filter_expr: str) -> str:
    expr = (filter_expr or "").strip()
    if not expr:
        return ""
    if len(expr) > 512:
        raise CapabilityError("Filtro excede o tamanho máximo permitido.", kind="invalid_input")
    if FILTER_FORBIDDEN_RE.search(expr):
        raise CapabilityError("Filtro contém construções não permitidas.", kind="invalid_input")

    if not cap.supported_filters:
        raise CapabilityError(
            f"A capability '{cap.id}' não declara filtros suportados.",
            kind="invalid_input",
        )

    referenced = set(ODATA_FIELD_RE.findall(expr)) | set(ODATA_FUNC_FIELD_RE.findall(expr))
    allowed = {f.lower() for f in cap.supported_filters}
    unknown = sorted({f for f in referenced if f.lower() not in allowed})
    if unknown:
        raise CapabilityError(
            f"Campo(s) de filtro não suportado(s) por '{cap.id}': {', '.join(unknown)}. "
            f"Permitidos: {', '.join(cap.supported_filters)}.",
            kind="invalid_input",
        )
    return expr


def _validate_select(cap: Capability, select: str) -> str:
    expr = (select or "").strip()
    if not expr:
        return ""
    fields = [f.strip() for f in expr.split(",") if f.strip()]
    if not fields:
        return ""
    for field_name in fields:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_/]*$", field_name):
            raise CapabilityError(
                f"Campo inválido em $select: '{field_name}'.", kind="invalid_input"
            )
    if cap.returned_properties:
        allowed = {p.lower() for p in cap.returned_properties}
        unknown = sorted({f for f in fields if f.lower() not in allowed})
        if unknown:
            raise CapabilityError(
                f"Propriedade(s) não declarada(s) por '{cap.id}': {', '.join(unknown)}. "
                f"Disponíveis: {', '.join(cap.returned_properties)}.",
                kind="invalid_input",
            )
    return ",".join(fields)


def _validate_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    try:
        value = int(limit)
    except (TypeError, ValueError):
        raise CapabilityError("Parâmetro 'limit' deve ser numérico.", kind="invalid_input") from None
    if value <= 0:
        raise CapabilityError("Parâmetro 'limit' deve ser maior que zero.", kind="invalid_input")
    return min(value, HARD_LIMIT)


def _validate_subscriptions(value: Any) -> list[str] | None:
    if value is None or value == "":
        return None
    raw_values = value.split(",") if isinstance(value, str) else value
    if not isinstance(raw_values, (list, tuple, set)):
        raise CapabilityError(
            "Parâmetro 'subscriptions' deve ser uma lista de IDs ou uma string separada por vírgulas.",
            kind="invalid_input",
        )
    subscriptions = [str(item).strip() for item in raw_values if str(item).strip()]
    if not subscriptions:
        raise CapabilityError("Parâmetro 'subscriptions' não pode ser vazio.", kind="invalid_input")
    if not _is_mock_mode():
        invalid = [item for item in subscriptions if not GUID_RE.fullmatch(item)]
        if invalid:
            raise CapabilityError(
                "Cada subscription deve ser um GUID válido.",
                kind="invalid_input",
                details={"invalid_subscriptions": invalid},
            )
    return subscriptions


def _reject_unknown_params(cap: Capability, params: dict[str, Any]) -> None:
    control_params = {"limit", "id", "scope", "ids", "types", "query", "operation"}
    declared = {p.lstrip("$").lower() for p in cap.supported_params}
    for key in params:
        if key in control_params:
            continue
        normalized = key.lstrip("$").lower()
        if normalized not in declared:
            raise CapabilityError(
                f"Parâmetro '{key}' não é suportado por '{cap.id}'. "
                f"Suportados: {', '.join(cap.supported_params) or 'nenhum'}.",
                kind="invalid_input",
            )


# --------------------------------------------------------------------------
# 2. Tradução de erro de permissão
# --------------------------------------------------------------------------


def _permission_error(cap: Capability, status_code: int, detail: str) -> CapabilityError:
    perms = ", ".join(cap.application_permissions or cap.delegated_permissions) or "não declaradas"
    return CapabilityError(
        "A identidade utilizada pelo MCP não possui a permissão necessária para "
        f"consultar '{cap.resource}'. Permissões requeridas: {perms}.",
        kind="permission_denied",
        details={
            "capability_id": cap.id,
            "http_status": status_code,
            "required_permissions": {
                "delegated": list(cap.delegated_permissions),
                "application": list(cap.application_permissions),
            },
            "requires_license": cap.requires_license,
            "provider_detail": detail[:300],
        },
    )


def _classify_http_error(cap: Capability, status_code: int, detail: str) -> CapabilityError:
    if status_code in {401, 403}:
        return _permission_error(cap, status_code, detail)
    if status_code == 404:
        return CapabilityError(
            f"Recurso não encontrado para '{cap.resource}'.",
            kind="not_found",
            details={"capability_id": cap.id, "http_status": status_code},
        )
    if status_code == 429:
        return CapabilityError(
            "O provedor aplicou limitação de requisições (HTTP 429). Tente novamente em instantes.",
            kind="throttled",
            details={"capability_id": cap.id},
        )
    return CapabilityError(
        f"Consulta a '{cap.resource}' retornou HTTP {status_code}.",
        kind="provider_error",
        details={"capability_id": cap.id, "http_status": status_code, "provider_detail": detail[:300]},
    )


# --------------------------------------------------------------------------
# 5. Execução
# --------------------------------------------------------------------------


def _mock_graph_rows(cap: Capability, url: str, limit: int) -> list[dict[str, Any]]:
    """Executa capabilities Graph contra fixtures sem inicializar autenticação."""
    from services.iam_common import load_mock_iam

    data = load_mock_iam()
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    query = parse_qs(parsed.query)

    if cap.id == "graph.users.list":
        rows = list(data.get("users", []))
    elif cap.id == "graph.users.guests":
        rows = [row for row in data.get("users", []) if row.get("userType") == "Guest"]
    elif cap.id == "graph.groups.list":
        rows = list(data.get("groups", []))
    elif cap.id == "graph.service_principals.list":
        rows = list(data.get("service_principals", []))
    elif cap.id == "graph.service_principals.managed_identities":
        rows = [
            row
            for row in data.get("service_principals", [])
            if row.get("servicePrincipalType") == "ManagedIdentity"
        ]
    elif cap.id == "graph.applications.list":
        rows = list(data.get("applications", []))
    elif cap.id == "graph.conditional_access.policies":
        rows = list(data.get("conditional_access_policies", []))
    elif cap.id == "graph.groups.members":
        match = re.search(r"/groups/([^/]+)/members$", path)
        if not match:
            raise CapabilityError(
                "O identificador do grupo é obrigatório para consultar membros no modo mock.",
                kind="invalid_input",
            )
        group_id = unquote(match.group(1))
        users = {str(row.get("id")): row for row in data.get("users", [])}
        rows = [
            {
                "id": member.get("memberId"),
                "displayName": users.get(str(member.get("memberId")), {}).get("displayName"),
                "userPrincipalName": users.get(str(member.get("memberId")), {}).get("userPrincipalName"),
                "mail": users.get(str(member.get("memberId")), {}).get("mail"),
            }
            for member in data.get("group_memberships", [])
            if str(member.get("groupId")) == group_id
        ]
    elif cap.id == "graph.groups.transitive_membership":
        match = re.search(r"/users/([^/]+)/transitiveMemberOf$", path)
        if not match:
            raise CapabilityError(
                "O identificador do usuário é obrigatório para consultar grupos no modo mock.",
                kind="invalid_input",
            )
        user_id = unquote(match.group(1))
        group_ids = {
            str(member.get("groupId"))
            for member in data.get("group_memberships", [])
            if str(member.get("memberId")) == user_id
        }
        rows = [row for row in data.get("groups", []) if str(row.get("id")) in group_ids]
    elif cap.id == "graph.directory_roles.list":
        role_names = sorted(
            {str(row.get("roleName")) for row in data.get("directory_role_assignments", []) if row.get("roleName")}
        )
        rows = [
            {
                "id": f"mock-role-{index}",
                "displayName": role_name,
                "roleTemplateId": f"mock-template-{index}",
            }
            for index, role_name in enumerate(role_names, start=1)
        ]
    elif cap.id == "graph.directory_roles.members":
        role_match = re.search(r"/directoryRoles/([^/]+)/members$", path)
        role_index = None
        if role_match:
            role_id = unquote(role_match.group(1))
            role_id_match = re.fullmatch(r"mock-role-(\d+)", role_id)
            role_index = int(role_id_match.group(1)) if role_id_match else None
        role_names = sorted(
            {str(row.get("roleName")) for row in data.get("directory_role_assignments", []) if row.get("roleName")}
        )
        selected_role = role_names[role_index - 1] if role_index and role_index <= len(role_names) else None
        if selected_role is None:
            raise CapabilityError(
                "A role de diretório informada não existe no fixture do MOCK_MODE.",
                kind="not_found",
            )
        users = {str(row.get("id")): row for row in data.get("users", [])}
        rows = [
            {
                "id": assignment.get("principalId"),
                "displayName": users.get(str(assignment.get("principalId")), {}).get("displayName"),
                "userPrincipalName": users.get(str(assignment.get("principalId")), {}).get("userPrincipalName"),
                "mail": users.get(str(assignment.get("principalId")), {}).get("mail"),
            }
            for assignment in data.get("directory_role_assignments", [])
            if assignment.get("roleName") == selected_role
        ]
    else:
        raise CapabilityError(
            f"A capability '{cap.id}' não possui fixture Graph no MOCK_MODE. "
            "Defina MOCK_MODE=false para consultar o tenant real.",
            kind="mock_not_supported",
            details={"capability_id": cap.id, "mock_mode": True},
        )

    filter_expr = unquote((query.get("$filter") or [""])[0]).lower()
    if "serviceprincipaltype" in filter_expr and "managedidentity" in filter_expr:
        rows = [row for row in rows if row.get("servicePrincipalType") == "ManagedIdentity"]
    if "usertype" in filter_expr and "guest" in filter_expr:
        rows = [row for row in rows if row.get("userType") == "Guest"]
    equality_filters = re.findall(r"([A-Za-z][A-Za-z0-9]*)\s+eq\s+'([^']*)'", filter_expr)
    for field_name, expected in equality_filters:
        if field_name.lower() in {"serviceprincipaltype", "usertype"}:
            continue
        rows = [row for row in rows if str(row.get(field_name, "")).lower() == expected.lower()]

    return rows[:limit]


def _graph_get(cap: Capability, url: str, limit: int) -> list[dict[str, Any]]:
    if _is_mock_mode():
        return _mock_graph_rows(cap, url, limit)

    from services.iam_common import graph_list

    try:
        return graph_list(url, max_items=limit)
    except RuntimeError as exc:
        match = re.search(r"HTTP (\d{3})", str(exc))
        status = int(match.group(1)) if match else 500
        raise _classify_http_error(cap, status, str(exc)) from exc


def _mock_resource_graph_rows(
    query: str,
    subscriptions: list[str] | None,
    limit: int,
) -> list[dict[str, Any]]:
    from services.azure_graph import _load_mock

    rows = list(_load_mock())
    if subscriptions is not None:
        allowed = {str(item) for item in subscriptions}
        rows = [row for row in rows if str(row.get("subscriptionId")) in allowed]

    lowered = query.lower()
    type_match = re.search(r"type\s*(?:=~|==|=)\s*['\"]([^'\"]+)['\"]", lowered)
    if type_match:
        expected_type = type_match.group(1).lower()
        rows = [row for row in rows if str(row.get("type", "")).lower() == expected_type]
    return rows[:limit]


def _azure_management_get(cap: Capability, url: str, limit: int) -> list[dict[str, Any]]:
    def _run() -> list[dict[str, Any]]:
        token = get_arm_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        rows: list[dict[str, Any]] = []
        next_url: str | None = url
        with httpx.Client(timeout=30.0) as client:
            while next_url:
                response = client.get(next_url, headers=headers)
                if response.is_error:
                    raise _classify_http_error(cap, response.status_code, response.text)
                payload = response.json()
                value = payload.get("value", [])
                if isinstance(value, list):
                    rows.extend(value)
                if len(rows) >= limit:
                    return rows[:limit]
                next_url = payload.get("nextLink")
        return rows[:limit]

    return cached_query(f"cap::{cap.id}::{url}::{limit}", _run)


def _build_graph_url(cap: Capability, params: dict[str, Any]) -> str:
    endpoint = cap.endpoint
    if "{id}" in endpoint:
        object_id = _validate_object_id(str(params.get("id", "")), "id")
        endpoint = endpoint.replace("{id}", object_id)

    query: list[str] = []

    select = _validate_select(cap, str(params.get("select") or params.get("$select") or ""))
    if select:
        query.append("$select=" + quote(select, safe="/,"))

    filter_expr = _validate_filter(cap, str(params.get("filter") or params.get("$filter") or ""))
    if filter_expr:
        query.append("$filter=" + quote(filter_expr, safe="/'"))

    if "$top" in cap.supported_params:
        top = min(_validate_limit(params.get("limit")), MAX_PAGE_SIZE)
        query.append(f"$top={top}")

    if query:
        joiner = "&" if "?" in endpoint else "?"
        endpoint = f"{endpoint}{joiner}{'&'.join(query)}"
    return endpoint


def _execute_resource_graph(cap: Capability, params: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    from services.azure_graph import _query_resource_graph

    query = str(params.get("query") or "").strip()
    subscriptions = _validate_subscriptions(params.get("subscriptions"))
    if not query:
        raise CapabilityError(
            f"A capability '{cap.id}' exige o parâmetro 'query' (KQL do Resource Graph).",
            kind="invalid_input",
        )
    if FILTER_FORBIDDEN_RE.search(query):
        raise CapabilityError("Consulta KQL contém construções não permitidas.", kind="invalid_input")
    lowered = query.lower()
    for banned in KQL_FORBIDDEN_OPERATORS:
        if banned in lowered:
            raise CapabilityError(
                f"Operador KQL não permitido em modo read-only: '{banned}'.",
                kind="invalid_input",
            )
    try:
        if _is_mock_mode():
            rows = _mock_resource_graph_rows(query, subscriptions, limit)
        else:
            rows = _query_resource_graph(query, subscriptions=subscriptions)
    except RuntimeError as exc:
        match = re.search(r"HTTP (\d{3})", str(exc))
        status = int(match.group(1)) if match else 500
        raise _classify_http_error(cap, status, str(exc)) from exc
    return rows[:limit]


def execute_capability(
    capability_id: str,
    params: dict[str, Any] | None = None,
    operation: str = "list",
) -> dict[str, Any]:
    """Executa uma capability do registry de forma validada e read-only."""
    params = dict(params or {})
    cap = _resolve_capability(capability_id)
    _assert_read_only(cap, operation)
    _reject_unknown_params(cap, params)
    limit = _validate_limit(params.get("limit"))

    if cap.source == SOURCE_GRAPH:
        if cap.method == "POST":
            raise CapabilityError(
                f"A capability '{cap.id}' requer execução em lote ainda não habilitada.",
                kind="not_integrated",
            )
        url = _build_graph_url(cap, params)
        rows = _graph_get(cap, url, limit)
        executed = url
    elif cap.source == SOURCE_RESOURCE_GRAPH:
        rows = _execute_resource_graph(cap, params, limit)
        executed = cap.endpoint
    elif cap.source in {SOURCE_AZURE_MANAGEMENT, SOURCE_AZURE_AUTHORIZATION}:
        endpoint = cap.endpoint
        if "{scope}" in endpoint:
            endpoint = endpoint.replace("{scope}", _validate_scope(str(params.get("scope", ""))).lstrip("/"))
        joiner = "&" if "?" in endpoint else "?"
        url = f"{endpoint}{joiner}api-version={cap.api_version}"
        rows = _azure_management_get(cap, url, limit)
        executed = url
    else:
        raise CapabilityError(
            f"Fonte '{cap.source}' não possui executor habilitado.", kind="not_integrated"
        )

    from services.capability_normalizer import normalize_rows

    normalized = normalize_rows(rows, cap)
    return {
        "ok": True,
        "capability_id": cap.id,
        "domain": cap.domain,
        "source": cap.source,
        "resource": cap.resource,
        "operation": operation,
        "api_version": cap.api_version,
        "execution_mode": "mock" if _is_mock_mode() else "live",
        "executed_endpoint": executed,
        "support_status": cap.support_status,
        "requires_license": cap.requires_license,
        "count": len(normalized),
        "truncated": len(rows) >= limit,
        "required_permissions": {
            "delegated": list(cap.delegated_permissions),
            "application": list(cap.application_permissions),
        },
        "items": normalized,
    }


def safe_execute_capability(
    capability_id: str,
    params: dict[str, Any] | None = None,
    operation: str = "list",
) -> dict[str, Any]:
    """Versão que converte erros previstos em payload estruturado."""
    try:
        return execute_capability(capability_id, params=params, operation=operation)
    except CapabilityError as exc:
        return exc.to_dict()
    except Exception as exc:  # pragma: no cover - salvaguarda
        return {
            "ok": False,
            "error_kind": "unexpected_error",
            "error": f"Falha inesperada ao executar '{capability_id}': {exc}",
        }
