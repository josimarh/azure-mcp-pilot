from __future__ import annotations

from typing import Any

from services.iam_common import graph_list, is_mock_mode, load_mock_iam, safe_collect


def list_conditional_access_policies() -> list[dict[str, Any]]:
    if is_mock_mode():
        return list(load_mock_iam().get("conditional_access_policies", []))
    return graph_list("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999")


def safe_conditional_access_policies() -> dict[str, Any]:
    return safe_collect("conditional-access-policies", list_conditional_access_policies)
