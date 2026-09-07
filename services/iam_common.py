from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx
from azure.identity import DefaultAzureCredential

from services.azure_auth import cached_query, get_credential, get_graph_token
from services.azure_graph import is_mock_mode, sanitize_enabled

ROOT = Path(__file__).resolve().parents[1]
MOCK_IAM_FILE = Path(__file__).resolve().parent / "data" / "mock_iam.json"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def mask(value: str | None, prefix: str) -> str | None:
    if not value:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{digest}"


def sanitize_identity(row: dict[str, Any]) -> dict[str, Any]:
    if not sanitize_enabled():
        return row
    out = dict(row)
    if "id" in out:
        out["id"] = mask(str(out["id"]), "obj")
    if "objectId" in out:
        out["objectId"] = mask(str(out["objectId"]), "obj")
    if "userPrincipalName" in out and out["userPrincipalName"]:
        out["userPrincipalName"] = mask(str(out["userPrincipalName"]), "upn")
    if "mail" in out and out["mail"]:
        out["mail"] = mask(str(out["mail"]), "mail")
    if "principalId" in out and out["principalId"]:
        out["principalId"] = mask(str(out["principalId"]), "obj")
    return out


def sanitize_scope(scope: str | None) -> str | None:
    if not sanitize_enabled() or not scope:
        return scope
    parts = scope.split("/")
    out: list[str] = []
    skip = False
    for idx, part in enumerate(parts):
        if skip:
            skip = False
            continue
        if part == "subscriptions" and idx + 1 < len(parts):
            out.extend(["subscriptions", mask(parts[idx + 1], "sub") or "sub-unknown"])
            skip = True
            continue
        if part == "resourceGroups" and idx + 1 < len(parts):
            out.extend(["resourceGroups", mask(parts[idx + 1], "rg") or "rg-unknown"])
            skip = True
            continue
        out.append(part)
    return "/".join(out)


def sanitize_assignment(row: dict[str, Any]) -> dict[str, Any]:
    if not sanitize_enabled():
        return row
    out = sanitize_identity(row)
    if "scope" in out:
        out["scope"] = sanitize_scope(str(out["scope"]) if out["scope"] else None)
    return out


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_mock_iam() -> dict[str, Any]:
    if not MOCK_IAM_FILE.exists():
        raise RuntimeError(
            f"MOCK_MODE está ativo, mas os dados mock não foram encontrados em {MOCK_IAM_FILE}. "
            "Defina MOCK_MODE=false para consultar o tenant real."
        )
    return json.loads(MOCK_IAM_FILE.read_text(encoding="utf-8"))


def credential() -> DefaultAzureCredential:
    return get_credential()


def graph_list(url: str, token: str | None = None, max_items: int | None = None) -> list[dict[str, Any]]:
    return cached_query(
        f"graph_list::{url}::{max_items}",
        lambda: _graph_list_uncached(url, token, max_items),
    )


def _graph_list_uncached(
    url: str, token: str | None = None, max_items: int | None = None
) -> list[dict[str, Any]]:
    graph_token = token or get_graph_token()
    headers = {"Authorization": f"Bearer {graph_token}"}
    rows: list[dict[str, Any]] = []
    next_url: str | None = url
    with httpx.Client(timeout=30.0) as client:
        while next_url:
            response = client.get(next_url, headers=headers)
            if response.is_error:
                detail = response.text[:400]
                raise RuntimeError(
                    f"Microsoft Graph retornou HTTP {response.status_code}. Detalhe: {detail}"
                )
            payload = response.json()
            value = payload.get("value", [])
            if isinstance(value, list):
                rows.extend(value)
                if max_items is not None and max_items > 0 and len(rows) >= max_items:
                    return rows[:max_items]
            next_url = payload.get("@odata.nextLink")
    return rows


def resource_graph_query(query: str) -> list[dict[str, Any]]:
    from services.azure_graph import _query_resource_graph as query_fn

    return query_fn(query)


def safe_collect(control: str, collector: Callable[[], Any]) -> dict[str, Any]:
    try:
        return {"control": control, "ok": True, "data": collector()}
    except Exception as exc:
        return {
            "control": control,
            "ok": False,
            "error": str(exc),
            "note": (
                "Não foi possível avaliar este controle porque a identidade atual "
                "não possui permissão suficiente ou a API não está disponível."
            ),
        }
