from __future__ import annotations

from typing import Any

from services.iam_common import is_mock_mode, load_mock_iam, resource_graph_query


def list_management_groups() -> list[dict[str, Any]]:
    if is_mock_mode():
        return list(load_mock_iam().get("management_groups", []))
    return resource_graph_query(
        "ResourceContainers "
        "| where type =~ 'microsoft.management/managementgroups' "
        "| project id, name"
    )
