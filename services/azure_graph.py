from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

from services.azure_auth import cached_query, get_arm_token

ROOT = Path(__file__).resolve().parents[1]
MOCK_FILE = ROOT / "data" / "mock_resources.json"
ARG_ENDPOINT = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01"


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def is_mock_mode() -> bool:
    return _bool_env("MOCK_MODE", True)


def sanitize_enabled() -> bool:
    return _bool_env("SANITIZE_FOR_LLM", True)


def _mask(value: str | None, prefix: str) -> str | None:
    if not value:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{digest}"


def _sanitize_row(row: dict[str, Any]) -> dict[str, Any]:
    if not sanitize_enabled():
        return row
    out = dict(row)
    if "name" in out:
        out["name"] = _mask(str(out["name"]), "resource")
    if "resourceGroup" in out:
        out["resourceGroup"] = _mask(str(out["resourceGroup"]), "rg")
    if "subscriptionId" in out:
        out["subscriptionId"] = _mask(str(out["subscriptionId"]), "sub")
    if "id" in out:
        out["id"] = _mask(str(out["id"]), "resource-id")
    if "ipAddress" in out and out["ipAddress"]:
        out["ipAddress"] = "REDACTED"
    return out


def _load_mock() -> list[dict[str, Any]]:
    return json.loads(MOCK_FILE.read_text(encoding="utf-8"))


def _subscriptions() -> list[str] | None:
    raw = os.getenv("AZURE_SUBSCRIPTIONS", "").strip()
    if not raw:
        return None
    return [item.strip() for item in raw.split(",") if item.strip()]


def _discover_subscriptions(token: str) -> list[str]:
    return cached_query("arm::subscriptions", lambda: _discover_subscriptions_uncached(token))


def _discover_subscriptions_uncached(token: str) -> list[str]:
    subscriptions: list[str] = []
    next_url: str | None = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    with httpx.Client(timeout=30.0) as client:
        while next_url:
            response = client.get(next_url, headers=headers)
            if response.is_error:
                detail = response.text[:500]
                raise RuntimeError(
                    f"Azure Management API retornou HTTP {response.status_code}. Detalhe: {detail}"
                )
            payload = response.json()
            for item in payload.get("value", []):
                if item.get("state") != "Enabled":
                    continue
                sub_id = item.get("subscriptionId")
                if isinstance(sub_id, str) and sub_id:
                    subscriptions.append(sub_id)
            next_url = payload.get("nextLink")
    return subscriptions


def _query_resource_graph(query: str) -> list[dict[str, Any]]:
    return cached_query(f"arg::{query}", lambda: _query_resource_graph_uncached(query))


def _query_resource_graph_uncached(query: str) -> list[dict[str, Any]]:
    token = get_arm_token()
    body: dict[str, Any] = {"query": query}
    subscriptions = _subscriptions()
    if subscriptions is None:
        subscriptions = _discover_subscriptions(token)
    if subscriptions:
        body["subscriptions"] = subscriptions

    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            ARG_ENDPOINT,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=body,
        )
        if response.is_error:
            detail = response.text[:500]
            raise RuntimeError(
                f"Azure Resource Graph retornou HTTP {response.status_code}. Detalhe: {detail}"
            )
        payload = response.json()
        data = payload.get("data", [])
        if isinstance(data, list):
            return data
        # Resource Graph can also return table-shaped results in some configurations.
        if isinstance(data, dict) and "rows" in data and "columns" in data:
            columns = [c["name"] if isinstance(c, dict) else str(c) for c in data["columns"]]
            return [dict(zip(columns, row)) for row in data["rows"]]
        return []

def get_subscriptions_count() -> dict:
    if is_mock_mode():
        resources = _load_mock()
        return {
            "mode": "mock",
            "source": "Azure Resource Graph",
            "subscriptions_count": len({r["subscriptionId"] for r in resources}),
        }

    totals = _query_resource_graph(
        "ResourceContainers "
        "| where type =~ 'microsoft.resources/subscriptions' "
        "| summarize subscriptions_count=count()"
    )
    total = totals[0] if totals else {}
    return {
        "mode": "azure-live",
        "source": "Azure Resource Graph",
        "subscriptions_count": total.get("subscriptions_count", 0),
    }

def get_environment_summary() -> dict[str, Any]:
    if is_mock_mode():
        resources = _load_mock()
        by_type = Counter(r["type"] for r in resources)
        by_location = Counter(r.get("location") or "unknown" for r in resources)
        by_subscription: dict[str, dict[str, Any]] = {}
        for item in resources:
            sub = str(item.get("subscriptionId") or "unknown")
            bucket = by_subscription.setdefault(
                sub,
                {
                    "subscriptionId": sub,
                    "displayName": sub,
                    "state": "Enabled",
                    "resources": 0,
                    "resourceGroups": set(),
                    "locations": set(),
                },
            )
            bucket["resources"] += 1
            if item.get("resourceGroup"):
                bucket["resourceGroups"].add(str(item.get("resourceGroup")))
            if item.get("location"):
                bucket["locations"].add(str(item.get("location")))

        subscriptions_inventory: list[dict[str, Any]] = []
        for row in by_subscription.values():
            subscriptions_inventory.append(
                {
                    "subscriptionId": row["subscriptionId"],
                    "displayName": row["displayName"],
                    "state": row["state"],
                    "resources": row["resources"],
                    "resourceGroups": len(row["resourceGroups"]),
                    "locations": len(row["locations"]),
                }
            )
        subscriptions_inventory.sort(key=lambda r: (-int(r.get("resources") or 0), str(r.get("subscriptionId") or "")))
        return {
            "mode": "mock",
            "total_resources": len(resources),
            "subscriptions": len({r["subscriptionId"] for r in resources}),
            "resource_groups": len({r["resourceGroup"] for r in resources}),
            "locations": len({r.get("location") for r in resources}),
            "subscriptions_inventory": subscriptions_inventory[:100],
            "resources_by_subscription": subscriptions_inventory[:100],
            "coverage": {"subscriptions": "EVALUATED", "resources": "EVALUATED"},
            "top_resource_types": [
                {"type": key, "count": value} for key, value in by_type.most_common(12)
            ],
            "top_locations": [
                {"location": key, "count": value} for key, value in by_location.most_common(12)
            ],
        }

    def _safe_query(query: str) -> tuple[bool, list[dict[str, Any]]]:
        try:
            return True, _query_resource_graph(query)
        except Exception:
            return False, []

    ok_totals, totals = _safe_query(
        "Resources | summarize total_resources=count(), "
        "locations=dcount(location)"
    )
    ok_subscriptions_count, subscriptions = _safe_query(
        "ResourceContainers "
        "| where type =~ 'microsoft.resources/subscriptions' "
        "| summarize subscriptions=count()"
    )
    ok_resource_groups, resource_groups = _safe_query(
        "ResourceContainers "
        "| where type =~ 'microsoft.resources/resourcegroups' "
        "| summarize resource_groups=count()"
    )
    ok_types, types = _safe_query(
        "Resources | summarize count_=count() by type | top 12 by count_ desc | project type, count=count_"
    )
    ok_locations, locations = _safe_query(
        "Resources | summarize count_=count() by location | top 12 by count_ desc | project location, count=count_"
    )
    ok_subscriptions_inventory, subscriptions_inventory = _safe_query(
        "ResourceContainers "
        "| where type =~ 'microsoft.resources/subscriptions' "
        "| project subscriptionId, displayName=name, state=tostring(properties.state)"
    )
    ok_resources_by_sub, resources_by_sub = _safe_query(
        "Resources "
        "| summarize resources=count(), resourceGroups=dcount(resourceGroup), locations=dcount(location) by subscriptionId "
        "| order by resources desc"
    )
    total = totals[0] if totals else {}
    total_subscriptions = subscriptions[0] if subscriptions else {}
    total_resource_groups = resource_groups[0] if resource_groups else {}
    sub_detail_map: dict[str, dict[str, Any]] = {}
    for row in subscriptions_inventory:
        sub_id = str(row.get("subscriptionId") or "")
        if not sub_id:
            continue
        sub_detail_map[sub_id] = {
            "subscriptionId": sub_id,
            "displayName": row.get("displayName") or sub_id,
            "state": row.get("state") or "Unknown",
            "resources": 0,
            "resourceGroups": 0,
            "locations": 0,
        }
    for row in resources_by_sub:
        sub_id = str(row.get("subscriptionId") or "")
        if not sub_id:
            continue
        base = sub_detail_map.setdefault(
            sub_id,
            {
                "subscriptionId": sub_id,
                "displayName": sub_id,
                "state": "Unknown",
                "resources": 0,
                "resourceGroups": 0,
                "locations": 0,
            },
        )
        base["resources"] = int(row.get("resources") or 0)
        base["resourceGroups"] = int(row.get("resourceGroups") or 0)
        base["locations"] = int(row.get("locations") or 0)
    subscriptions_inventory_out = sorted(
        list(sub_detail_map.values()),
        key=lambda r: (-int(r.get("resources") or 0), str(r.get("subscriptionId") or "")),
    )

    resources_coverage = (
        "EVALUATED"
        if ok_totals and ok_types and ok_locations
        else "PARTIAL"
        if any([ok_totals, ok_types, ok_locations])
        else "NOT_EVALUATED"
    )
    subscriptions_coverage = (
        "EVALUATED"
        if ok_subscriptions_count and ok_subscriptions_inventory
        else "PARTIAL"
        if any([ok_subscriptions_count, ok_subscriptions_inventory])
        else "NOT_EVALUATED"
    )
    return {
        "mode": "azure-live",
        **({"total_resources": total.get("total_resources", 0), "locations": total.get("locations", 0)} if ok_totals else {}),
        "total_resources": total.get("total_resources", 0) if ok_totals else "NOT_EVALUATED",
        "subscriptions": total_subscriptions.get("subscriptions", 0) if ok_subscriptions_count else "NOT_EVALUATED",
        "resource_groups": total_resource_groups.get("resource_groups", 0) if ok_resource_groups else "NOT_EVALUATED",
        "top_resource_types": types if ok_types else [],
        "top_locations": locations if ok_locations else [],
        "subscriptions_inventory": subscriptions_inventory_out[:200] if ok_subscriptions_inventory else [],
        "resources_by_subscription": subscriptions_inventory_out[:200] if (ok_subscriptions_inventory or ok_resources_by_sub) else [],
        "coverage": {
            "subscriptions": subscriptions_coverage,
            "resources": resources_coverage,
            "resource_groups": "EVALUATED" if ok_resource_groups else "NOT_EVALUATED",
        },
    }


def list_resources(resource_type: str = "", name_contains: str = "", limit: int = 20) -> dict[str, Any]:
    limit = max(1, min(int(limit), 50))
    rt = resource_type.strip().lower()
    name = name_contains.strip().lower()

    if is_mock_mode():
        resources = _load_mock()
        if rt:
            resources = [r for r in resources if r["type"].lower() == rt]
        if name:
            resources = [r for r in resources if name in r["name"].lower()]
        rows = [_sanitize_row(r) for r in resources[:limit]]
        return {"mode": "mock", "count": len(rows), "resources": rows}

    safe_rt = rt.replace("'", "''")
    safe_name = name.replace("'", "''")
    query = "Resources"
    if safe_rt:
        query += f" | where type =~ '{safe_rt}'"
    if safe_name:
        query += f" | where tolower(name) contains '{safe_name}'"
    query += (
        " | project id, name, type, resourceGroup, subscriptionId, location"
        f" | take {limit}"
    )
    rows = [_sanitize_row(r) for r in _query_resource_graph(query)]
    return {"mode": "azure-live", "count": len(rows), "resources": rows}


def list_public_ip_resources(limit: int = 20) -> dict[str, Any]:
    limit = max(1, min(int(limit), 50))
    if is_mock_mode():
        resources = [
            r for r in _load_mock() if r["type"] == "microsoft.network/publicipaddresses"
        ][:limit]
        rows = [_sanitize_row(r) for r in resources]
        return {
            "mode": "mock",
            "count": len(rows),
            "warning": "Public IP resource is not, by itself, proof that a workload is internet-exposed.",
            "resources": rows,
        }

    query = (
        "Resources "
        "| where type =~ 'microsoft.network/publicipaddresses' "
        "| project id, name, type, resourceGroup, subscriptionId, location, "
        "ipAddress=tostring(properties.ipAddress), "
        "allocationMethod=tostring(properties.publicIPAllocationMethod), "
        "ipVersion=tostring(properties.publicIPAddressVersion) "
        f"| take {limit}"
    )
    rows = [_sanitize_row(r) for r in _query_resource_graph(query)]
    return {
        "mode": "azure-live",
        "count": len(rows),
        "warning": "Public IP resource is not, by itself, proof that a workload is internet-exposed.",
        "resources": rows,
    }
