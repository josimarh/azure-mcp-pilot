"""Licencas do tenant e disponibilidade real de capacidades.

Sem conhecer as licencas, um resultado vazio e ambiguo. "Nenhuma politica de
acesso condicional" pode significar que nada foi configurado ou que o recurso
sequer esta disponivel no tenant - e as duas respostas levam a acoes opostas.

Este modulo consulta os SKUs assinados e traduz o requisito textual de licenca
declarado no registry de capacidades em um veredito verificado: LICENSED,
NOT_LICENSED ou UNKNOWN.
"""

from __future__ import annotations

from typing import Any

from services.azure_auth import cached_query
from services.iam_common import graph_list
from services.azure_graph import is_mock_mode

SUBSCRIBED_SKUS_URL = "https://graph.microsoft.com/v1.0/subscribedSkus"

LICENSED = "LICENSED"
NOT_LICENSED = "NOT_LICENSED"
UNKNOWN = "UNKNOWN"

# Planos que habilitam cada familia de recurso. P2 e superset de P1, entao um
# requisito de P1 tambem e satisfeito por P2.
PLAN_P1 = ("AAD_PREMIUM", "AAD_PREMIUM_P2")
PLAN_P2 = ("AAD_PREMIUM_P2",)
PLAN_GOVERNANCE = ("Entra_Identity_Governance", "AAD_GOVERNANCE", "AAD_PREMIUM_P2")
PLAN_WORKLOAD_ID = ("WORKLOAD_IDENTITIES_P1", "WORKLOAD_IDENTITIES_P2")

# Traduz o texto livre de `requires_license` do registry para planos concretos.
# A ordem importa: as chaves mais especificas sao avaliadas primeiro.
_REQUIREMENT_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("workload identities", PLAN_WORKLOAD_ID),
    ("governance", PLAN_GOVERNANCE),
    ("p2", PLAN_P2),
    ("p1", PLAN_P1),
)


def _normalize(text: str) -> str:
    return " ".join(str(text or "").strip().lower().split())


def _fetch_skus() -> list[dict[str, Any]]:
    return graph_list(SUBSCRIBED_SKUS_URL)


def subscribed_skus() -> list[dict[str, Any]]:
    """SKUs assinados pelo tenant. Lista vazia quando nao foi possivel avaliar."""
    if is_mock_mode():
        return []
    try:
        return cached_query("entra::subscribed_skus", _fetch_skus)
    except Exception:
        return []


def license_inventory() -> dict[str, Any]:
    """Inventario de licencas com cobertura declarada.

    `evaluated=False` significa que a leitura falhou, e nao que o tenant nao
    possui licencas.
    """
    if is_mock_mode():
        return {"evaluated": False, "reason": "MOCK_MODE", "skus": [], "servicePlans": []}

    try:
        skus = cached_query("entra::subscribed_skus", _fetch_skus)
    except Exception as exc:
        return {
            "evaluated": False,
            "reason": f"Falha ao ler licencas: {exc}"[:300],
            "skus": [],
            "servicePlans": [],
        }

    inventory: list[dict[str, Any]] = []
    plans: set[str] = set()
    for sku in skus:
        prepaid = sku.get("prepaidUnits") or {}
        enabled = prepaid.get("enabled") or 0
        consumed = sku.get("consumedUnits") or 0
        sku_plans = [
            str(plan.get("servicePlanName"))
            for plan in sku.get("servicePlans", []) or []
            if plan.get("servicePlanName")
            and str(plan.get("provisioningStatus", "")).lower() == "success"
        ]
        plans.update(sku_plans)
        inventory.append(
            {
                "skuPartNumber": sku.get("skuPartNumber"),
                "skuId": sku.get("skuId"),
                "enabledUnits": enabled,
                "consumedUnits": consumed,
                "unusedUnits": max(0, int(enabled) - int(consumed)),
                "servicePlans": sorted(sku_plans),
            }
        )

    return {
        "evaluated": True,
        "reason": None,
        "skus": inventory,
        "servicePlans": sorted(plans),
    }


def enabled_service_plans() -> set[str]:
    inventory = license_inventory()
    if not inventory["evaluated"]:
        return set()
    return {str(plan).upper() for plan in inventory["servicePlans"]}


def _plans_for_requirement(requirement: str) -> tuple[str, ...] | None:
    normalized = _normalize(requirement)
    if not normalized:
        return None
    # Requisitos que descrevem permissao de RBAC, nao licenca, nao sao avaliaveis aqui.
    if "rbac" in normalized and "licen" not in normalized:
        return None
    for marker, plans in _REQUIREMENT_RULES:
        if marker in normalized:
            return plans
    return None


def evaluate_requirement(requirement: str | None) -> dict[str, Any]:
    """Verifica se o requisito de licenca de uma capability esta satisfeito."""
    if not requirement:
        return {"status": LICENSED, "requirement": None, "matchedPlan": None, "detail": "Nao requer licenca adicional."}

    plans = _plans_for_requirement(requirement)
    if plans is None:
        return {
            "status": UNKNOWN,
            "requirement": requirement,
            "matchedPlan": None,
            "detail": "Requisito nao mapeavel para um plano de servico verificavel.",
        }

    inventory = license_inventory()
    if not inventory["evaluated"]:
        return {
            "status": UNKNOWN,
            "requirement": requirement,
            "matchedPlan": None,
            "detail": inventory["reason"],
        }

    available = enabled_service_plans()
    for plan in plans:
        if plan.upper() in available:
            return {
                "status": LICENSED,
                "requirement": requirement,
                "matchedPlan": plan,
                "detail": None,
            }

    return {
        "status": NOT_LICENSED,
        "requirement": requirement,
        "matchedPlan": None,
        "detail": f"Nenhum plano habilitado entre: {', '.join(plans)}",
    }


def has_entra_id_p2() -> bool:
    return any(plan.upper() in enabled_service_plans() for plan in PLAN_P2)
