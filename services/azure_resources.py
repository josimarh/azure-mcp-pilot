from __future__ import annotations

from typing import Any

from services.azure_graph import get_environment_summary, get_subscriptions_count, list_resources
from services.identity_access import get_resource_groups_count, list_resource_groups


def summarize_resources() -> dict[str, Any]:
    return get_environment_summary()


def summarize_subscriptions() -> dict[str, Any]:
    return get_subscriptions_count()


def summarize_resource_groups() -> dict[str, Any]:
    return get_resource_groups_count()


def list_resource_groups_inventory(limit: int = 20) -> dict[str, Any]:
    return list_resource_groups(limit=limit)


def list_resources_inventory(resource_type: str = "", limit: int = 20) -> dict[str, Any]:
    return list_resources(resource_type=resource_type, limit=limit)
