from __future__ import annotations

import os
from typing import Any

from services.iam_common import graph_list, is_mock_mode, load_mock_iam, sanitize_identity

SPS_URL = (
    "https://graph.microsoft.com/v1.0/servicePrincipals"
    "?$select=id,displayName,appId,servicePrincipalType,accountEnabled&$top=999"
)
MAX_WORKLOAD_ITEMS = max(100, int(os.getenv("GRAPH_WORKLOAD_MAX_ITEMS", "2000")))


def list_service_principals() -> list[dict[str, Any]]:
    if is_mock_mode():
        return [
            sp
            for sp in load_mock_iam().get("service_principals", [])
            if sp.get("servicePrincipalType") != "ManagedIdentity"
        ]
    return [
        sp
        for sp in graph_list(SPS_URL, max_items=MAX_WORKLOAD_ITEMS)
        if sp.get("servicePrincipalType") != "ManagedIdentity"
    ]


def list_managed_identities() -> list[dict[str, Any]]:
    if is_mock_mode():
        return [
            sp
            for sp in load_mock_iam().get("service_principals", [])
            if sp.get("servicePrincipalType") == "ManagedIdentity"
        ]
    return [
        sp
        for sp in graph_list(SPS_URL, max_items=MAX_WORKLOAD_ITEMS)
        if sp.get("servicePrincipalType") == "ManagedIdentity"
    ]


def present_workload_identities(items: list[dict[str, Any]], identity_type: str, limit: int = 20) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in items[: max(1, limit)]:
        rows.append(
            sanitize_identity(
                {
                    "name": item.get("displayName"),
                    "displayName": item.get("displayName"),
                    "objectId": item.get("id"),
                    "identityType": identity_type,
                    "appId": item.get("appId"),
                }
            )
        )
    return rows
