from __future__ import annotations

from typing import Any


ENTRA_ROLE_BASE_SCORE = {
    "Global Administrator": 100,
    "Privileged Role Administrator": 96,
    "Conditional Access Administrator": 90,
    "Security Administrator": 88,
    "Authentication Administrator": 86,
    "User Administrator": 78,
    "Application Administrator": 74,
    "Cloud Application Administrator": 74,
}

AZURE_ROLE_BASE_SCORE = {
    "Owner": 98,
    "User Access Administrator": 95,
    "Contributor": 78,
}


def _scope_level(scope: str | None) -> str:
    if not scope or scope == "/":
        return "Tenant"
    scope_l = scope.lower()
    if "/providers/microsoft.management/managementgroups/" in scope_l:
        return "ManagementGroup"
    if "/resourcegroups/" in scope_l:
        return "ResourceGroup"
    if "/providers/" in scope_l:
        return "Resource"
    if "/subscriptions/" in scope_l:
        return "Subscription"
    return "Unknown"


def _risk_level(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 75:
        return "High"
    if score >= 55:
        return "Medium"
    return "Low"


def _azure_scope_boost(scope: str | None) -> int:
    level = _scope_level(scope)
    if level == "ManagementGroup":
        return 8
    if level == "Subscription":
        return 6
    if level == "ResourceGroup":
        return 3
    if level == "Resource":
        return 1
    return 0


def _state_boost(state: str | None) -> int:
    state_l = str(state or "").lower()
    if state_l == "active":
        return 4
    if state_l == "permanent":
        return 6
    return 0


def role_risk_score(
    role: str | None,
    provider: str | None,
    *,
    scope: str | None = None,
    state: str | None = None,
) -> dict[str, Any]:
    role_name = str(role or "").strip()
    provider_name = str(provider or "").strip().lower()

    if provider_name == "entra":
        base = ENTRA_ROLE_BASE_SCORE.get(role_name, 65 if role_name else 0)
    else:
        base = AZURE_ROLE_BASE_SCORE.get(role_name, 60 if role_name else 0)
        base += _azure_scope_boost(scope)

    score = max(0, min(100, base + _state_boost(state)))
    return {
        "score": score,
        "level": _risk_level(score),
        "source": "IAM Scope (Tier/Risk Tier) + baseline calibration",
    }

