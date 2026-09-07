"""Azure PIM (role eligibility / assignment schedules) por fonte autoritativa.

O Azure Resource Graph nem sempre indexa os tipos de PIM de recurso. Quando
isso acontece, a consulta retorna zero linhas sem sinalizar erro, e um zero
silencioso e indistinguivel de "nao existe PIM configurado".

Este modulo confirma o vazio contra a Azure Management API antes de afirmar
ausencia. Se a API indicar falta de permissao, o resultado e NOT_EVALUATED em
vez de zero.
"""

from __future__ import annotations

from typing import Any

import httpx

from services.azure_auth import cached_query, get_arm_token
from services.iam_common import resource_graph_query

PIM_API_VERSION = "2020-10-01"

ELIGIBLE = "Eligible"
ACTIVE = "Active"

_ARM_KIND = {
    ELIGIBLE: "roleEligibilityScheduleInstances",
    ACTIVE: "roleAssignmentScheduleInstances",
}

_ARG_TYPE = {
    ELIGIBLE: "microsoft.authorization/roleeligibilityscheduleinstances",
    ACTIVE: "microsoft.authorization/roleassignmentscheduleinstances",
}

STATUS_EVALUATED = "EVALUATED"
STATUS_NOT_EVALUATED = "NOT_EVALUATED"


def _subscription_ids() -> list[str]:
    try:
        rows = resource_graph_query(
            "ResourceContainers "
            "| where type =~ 'microsoft.resources/subscriptions' "
            "| project subscriptionId"
        )
    except Exception:
        return []
    return [str(r.get("subscriptionId")) for r in rows if r.get("subscriptionId")]


def _from_resource_graph(state: str) -> list[dict[str, Any]]:
    return resource_graph_query(
        "AuthorizationResources "
        f"| where type =~ '{_ARG_TYPE[state]}' "
        "| extend principalId=tostring(properties.principalId), "
        "principalType=tostring(properties.principalType), "
        "roleDefinitionId=tolower(tostring(properties.roleDefinitionId)), "
        "scope=tostring(properties.scope) "
        "| project id, principalId, principalType, roleDefinitionId, scope"
    )


def _from_management_api(state: str) -> dict[str, Any]:
    """Consulta o ARM e devolve linhas e cobertura observada por subscription."""
    subscription_ids = _subscription_ids()
    if not subscription_ids:
        return {
            "rows": [],
            "status": STATUS_NOT_EVALUATED,
            "detail": "Nenhuma subscription visivel para consultar PIM de recurso.",
        }

    try:
        token = get_arm_token()
    except Exception as exc:
        return {"rows": [], "status": STATUS_NOT_EVALUATED, "detail": str(exc)[:300]}

    rows: list[dict[str, Any]] = []
    evaluated: list[str] = []
    denied: list[str] = []
    detail: str | None = None
    headers = {"Authorization": f"Bearer {token}"}
    kind = _ARM_KIND[state]

    with httpx.Client(timeout=60.0) as client:
        for subscription_id in subscription_ids:
            url = (
                f"https://management.azure.com/subscriptions/{subscription_id}"
                f"/providers/Microsoft.Authorization/{kind}"
                f"?api-version={PIM_API_VERSION}"
            )
            try:
                response = client.get(url, headers=headers)
            except Exception as exc:
                denied.append(subscription_id)
                detail = detail or str(exc)[:300]
                continue

            if response.status_code == 200:
                evaluated.append(subscription_id)
                for item in response.json().get("value", []) or []:
                    properties = item.get("properties") or {}
                    rows.append(
                        {
                            "id": item.get("id"),
                            "principalId": properties.get("principalId"),
                            "principalType": properties.get("principalType"),
                            "roleDefinitionId": properties.get("roleDefinitionId"),
                            "scope": properties.get("scope") or f"/subscriptions/{subscription_id}",
                        }
                    )
            else:
                # InsufficientPermissions chega como 400 nesta API, nao 403.
                denied.append(subscription_id)
                detail = detail or f"HTTP {response.status_code}: {response.text[:200]}"

    if not evaluated:
        return {"rows": [], "status": STATUS_NOT_EVALUATED, "detail": detail}

    return {
        "rows": rows,
        "status": STATUS_EVALUATED,
        "evaluatedSubscriptions": len(evaluated),
        "notEvaluatedSubscriptions": len(denied),
        "detail": detail if denied else None,
    }


def azure_pim_instances(state: str) -> dict[str, Any]:
    """Instancias de PIM de recurso com cobertura declarada.

    Um retorno vazio do Resource Graph nunca e tratado como ausencia: ele e
    confirmado contra o ARM, que distingue "avaliado e vazio" de "sem
    permissao para avaliar".
    """
    return cached_query(f"azure_pim::{state}", lambda: _azure_pim_instances(state))


def _azure_pim_instances(state: str) -> dict[str, Any]:
    try:
        rows = _from_resource_graph(state)
    except Exception as exc:
        rows = []
        arg_error: str | None = str(exc)[:300]
    else:
        arg_error = None

    if rows:
        return {
            "rows": rows,
            "status": STATUS_EVALUATED,
            "source": "AzureResourceGraph",
            "detail": None,
        }

    confirmation = _from_management_api(state)
    return {
        "rows": confirmation["rows"],
        "status": confirmation["status"],
        "source": "AzureManagementAPI",
        "detail": confirmation.get("detail") or arg_error,
        "evaluatedSubscriptions": confirmation.get("evaluatedSubscriptions"),
        "notEvaluatedSubscriptions": confirmation.get("notEvaluatedSubscriptions"),
    }
