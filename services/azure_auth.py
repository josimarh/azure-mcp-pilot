"""Autenticação Azure/Graph centralizada com credencial única e cache de token.

Sem este módulo, cada chamada criava uma nova ``DefaultAzureCredential``,
refazendo toda a cadeia de autenticação (incluindo sondagem IMDS de Managed
Identity) e reautenticando no tenant a cada requisição.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import threading
import time
from typing import Any, Callable, TypeVar

from azure.identity import DefaultAzureCredential

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

_TOKEN_EXPIRY_SKEW_SECONDS = 300
_QUERY_CACHE_MAX_ENTRIES = 128

_lock = threading.RLock()
_credential: DefaultAzureCredential | None = None
_token_cache: dict[str, tuple[str, float]] = {}
_query_cache: dict[str, tuple[float, Any]] = {}

T = TypeVar("T")


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _running_on_azure() -> bool:
    return any(
        os.getenv(name)
        for name in ("IDENTITY_ENDPOINT", "MSI_ENDPOINT", "WEBSITE_INSTANCE_ID", "AZURE_CONTAINER_APP_NAME")
    )


def get_credential() -> DefaultAzureCredential:
    """Retorna a credencial compartilhada do processo (criada uma única vez)."""
    global _credential
    if _credential is not None:
        return _credential
    with _lock:
        if _credential is None:
            kwargs: dict[str, Any] = {"exclude_interactive_browser_credential": False}
            exclude_mi = _bool_env("AZURE_EXCLUDE_MANAGED_IDENTITY", not _running_on_azure())
            if exclude_mi:
                kwargs["exclude_managed_identity_credential"] = True
            _credential = DefaultAzureCredential(**kwargs)
    return _credential


def get_token(scope: str) -> str:
    """Retorna um access token válido para o escopo, reaproveitando o cache."""
    now = time.time()
    cached = _token_cache.get(scope)
    if cached and cached[1] - _TOKEN_EXPIRY_SKEW_SECONDS > now:
        return cached[0]

    with _lock:
        cached = _token_cache.get(scope)
        if cached and cached[1] - _TOKEN_EXPIRY_SKEW_SECONDS > now:
            return cached[0]
        access_token = get_credential().get_token(scope)
        _token_cache[scope] = (access_token.token, float(access_token.expires_on))
        return access_token.token


def get_arm_token() -> str:
    return get_token(ARM_SCOPE)


def get_graph_token() -> str:
    return get_token(GRAPH_SCOPE)


def get_home_tenant_id() -> str | None:
    """Tenant do token atual, lido da claim ``tid`` (não exige permissão extra)."""
    override = os.getenv("AZURE_TENANT_ID", "").strip()
    if override:
        return override
    try:
        payload = get_graph_token().split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        tid = claims.get("tid")
        return str(tid) if tid else None
    except Exception:
        return None


def reset_credential() -> None:
    """Descarta credencial e tokens em cache (usar após trocar de conta/tenant)."""
    global _credential
    with _lock:
        _credential = None
        _token_cache.clear()


def query_cache_ttl() -> int:
    """TTL em segundos do cache de consultas. ``0`` desativa o cache."""
    raw = os.getenv("AZURE_QUERY_CACHE_TTL", "120").strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return 120


def cached_query(key: str, producer: Callable[[], T]) -> T:
    """Reaproveita o resultado de consultas idênticas dentro da janela de TTL.

    Evita que o agente refaça as mesmas chamadas a Graph/Resource Graph a cada
    iteração de raciocínio.
    """
    ttl = query_cache_ttl()
    if ttl <= 0:
        return producer()

    now = time.time()
    with _lock:
        hit = _query_cache.get(key)
        if hit is not None and hit[0] > now:
            return copy.deepcopy(hit[1])

    value = producer()

    with _lock:
        if len(_query_cache) >= _QUERY_CACHE_MAX_ENTRIES:
            _query_cache.clear()
        _query_cache[key] = (now + ttl, copy.deepcopy(value))
    return value


def clear_query_cache() -> None:
    with _lock:
        _query_cache.clear()
