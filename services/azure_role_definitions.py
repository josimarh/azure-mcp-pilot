"""Resolução autoritativa de Azure RBAC role definitions.

O Azure Resource Graph nem sempre expõe `microsoft.authorization/roledefinitions`.
Quando isso acontece, o join entre role assignment e nome da role falha e o
resultado vira um falso zero (ex.: "nenhum Owner"), o que é pior do que declarar
que a informação não foi avaliada.

Este módulo resolve o nome da role em camadas, sempre preservando a origem da
evidência:

1. Azure Resource Graph (rápido, quando disponível).
2. Azure Management API (autoritativa por subscription).
3. Mapa estático de GUIDs built-in bem conhecidos.
4. UNRESOLVED — nunca inventa nome nem assume ausência.
"""

from __future__ import annotations

from typing import Any

import httpx

from services.azure_auth import cached_query, get_arm_token
from services.iam_common import resource_graph_query
from services.azure_graph import is_mock_mode

ARM_API_VERSION = "2022-04-01"

RESOLUTION_RESOURCE_GRAPH = "AzureResourceGraph"
RESOLUTION_MANAGEMENT_API = "AzureManagementAPI"
RESOLUTION_KNOWN_GUID = "KnownBuiltInGuid"
RESOLUTION_UNRESOLVED = "UNRESOLVED"

# Fallback mínimo e verificado de roles built-in do Azure RBAC.
KNOWN_AZURE_ROLE_GUIDS: dict[str, str] = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "Storage Blob Data Owner",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7": "Key Vault Secrets Officer",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
}


def role_guid(role_definition_id: str | None) -> str | None:
    """Extrai o GUID final de um roleDefinitionId em qualquer formato de escopo."""
    if not role_definition_id:
        return None
    value = str(role_definition_id).strip().lower().rstrip("/")
    if not value:
        return None
    return value.rsplit("/", 1)[-1] or None


def _from_resource_graph() -> dict[str, dict[str, Any]]:
    try:
        rows = resource_graph_query(
            "AuthorizationResources "
            "| where type =~ 'microsoft.authorization/roledefinitions' "
            "| extend roleType=tostring(properties.roleType) "
            "| project id, roleName=tostring(properties.roleName), roleType"
        )
    except Exception:
        return {}

    mapping: dict[str, dict[str, Any]] = {}
    for item in rows:
        guid = role_guid(item.get("id"))
        name = str(item.get("roleName") or "").strip()
        if not guid or not name:
            continue
        mapping[guid] = {
            "roleName": name,
            "roleType": str(item.get("roleType") or "") or None,
            "resolution": RESOLUTION_RESOURCE_GRAPH,
        }
    return mapping


def _visible_subscription_ids() -> list[str]:
    try:
        rows = resource_graph_query(
            "ResourceContainers "
            "| where type =~ 'microsoft.resources/subscriptions' "
            "| project subscriptionId"
        )
    except Exception:
        return []
    return [str(r.get("subscriptionId")) for r in rows if r.get("subscriptionId")]


def _from_management_api() -> dict[str, dict[str, Any]]:
    subscription_ids = _visible_subscription_ids()
    if not subscription_ids:
        return {}

    try:
        token = get_arm_token()
    except Exception:
        return {}

    mapping: dict[str, dict[str, Any]] = {}
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=60.0) as client:
        for subscription_id in subscription_ids:
            url: str | None = (
                f"https://management.azure.com/subscriptions/{subscription_id}"
                "/providers/Microsoft.Authorization/roleDefinitions"
                f"?api-version={ARM_API_VERSION}"
            )
            while url:
                try:
                    response = client.get(url, headers=headers)
                except Exception:
                    break
                if response.is_error:
                    # Falta de permissão em uma subscription não invalida as demais.
                    break
                payload = response.json()
                for item in payload.get("value", []) or []:
                    properties = item.get("properties") or {}
                    guid = role_guid(item.get("name") or item.get("id"))
                    name = str(properties.get("roleName") or "").strip()
                    if not guid or not name or guid in mapping:
                        continue
                    mapping[guid] = {
                        "roleName": name,
                        "roleType": str(properties.get("type") or "") or None,
                        "resolution": RESOLUTION_MANAGEMENT_API,
                    }
                url = payload.get("nextLink")
    return mapping


def _build_role_definitions_map() -> dict[str, dict[str, Any]]:
    mapping = _from_resource_graph()
    if not mapping:
        mapping = _from_management_api()
    else:
        for guid, data in _from_management_api().items():
            mapping.setdefault(guid, data)
    return mapping


def role_definitions_map() -> dict[str, dict[str, Any]]:
    """Mapa GUID -> metadados da role, com cache e origem preservada."""
    if is_mock_mode():
        return {}
    try:
        return cached_query("azure_role_definitions_map", _build_role_definitions_map)
    except Exception:
        return {}


def resolve_role(role_definition_id: str | None) -> dict[str, Any]:
    """Resolve o nome de uma role a partir do roleDefinitionId.

    Retorna sempre `roleName` (None quando não resolvido) e `resolution`,
    permitindo distinguir "não é privilegiada" de "não foi possível avaliar".
    """
    guid = role_guid(role_definition_id)
    if not guid:
        return {
            "roleGuid": None,
            "roleName": None,
            "roleType": None,
            "resolution": RESOLUTION_UNRESOLVED,
        }

    entry = role_definitions_map().get(guid)
    if entry:
        return {
            "roleGuid": guid,
            "roleName": entry.get("roleName"),
            "roleType": entry.get("roleType"),
            "resolution": entry.get("resolution"),
        }

    known = KNOWN_AZURE_ROLE_GUIDS.get(guid)
    if known:
        return {
            "roleGuid": guid,
            "roleName": known,
            "roleType": "BuiltInRole",
            "resolution": RESOLUTION_KNOWN_GUID,
        }

    return {
        "roleGuid": guid,
        "roleName": None,
        "roleType": None,
        "resolution": RESOLUTION_UNRESOLVED,
    }
