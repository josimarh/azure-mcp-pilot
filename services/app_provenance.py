"""Procedência de aplicações: criadas no tenant vs nativas da Microsoft.

Distingue, com base em sinais autoritativos do diretório, quem é dono de cada
aplicação/service principal:

- ``TenantOwned``          registro de aplicação criado dentro do seu tenant
- ``MicrosoftFirstParty``  aplicação nativa da Microsoft (pré-provisionada)
- ``ThirdPartyMultiTenant`` app de outro tenant, consentida no seu diretório
- ``ManagedIdentity``      identidade gerenciada do Azure
- ``ServiceIdentity``      identidade interna de serviço da plataforma
- ``Unknown``              sem sinal suficiente

Sinal principal: ``appOwnerOrganizationId``. Diferente de heurística por nome,
esse campo é atribuído pelo próprio diretório.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any

from services.azure_auth import get_home_tenant_id
from services.iam_common import graph_list, is_mock_mode, load_mock_iam

# Tenants first-party da Microsoft que aparecem como donos de apps nativas.
MICROSOFT_TENANT_IDS: dict[str, str] = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a": "Microsoft Services",
    "72f988bf-86f1-41af-91ab-2d7cd011db47": "Microsoft Corporation",
    "cdc5aeea-15c5-4db6-b079-fcadd2505dc2": "Microsoft Services (secundário)",
    "975f013f-7f24-47e8-a7d3-abc4752bf346": "Microsoft Services (legado)",
}

PROVENANCE_TENANT_OWNED = "TenantOwned"
PROVENANCE_MICROSOFT = "MicrosoftFirstParty"
PROVENANCE_THIRD_PARTY = "ThirdPartyMultiTenant"
PROVENANCE_MANAGED_IDENTITY = "ManagedIdentity"
PROVENANCE_SERVICE_IDENTITY = "ServiceIdentity"
PROVENANCE_UNKNOWN = "Unknown"

PROVENANCE_LABELS: dict[str, str] = {
    PROVENANCE_TENANT_OWNED: "Criada no seu tenant (app registration)",
    PROVENANCE_MICROSOFT: "Aplicação nativa da Microsoft (first-party)",
    PROVENANCE_THIRD_PARTY: "Aplicação de terceiro consentida no tenant",
    PROVENANCE_MANAGED_IDENTITY: "Managed Identity do Azure",
    PROVENANCE_SERVICE_IDENTITY: "Identidade interna de serviço da plataforma",
    PROVENANCE_UNKNOWN: "Procedência não determinada",
}

SP_URL = (
    "https://graph.microsoft.com/v1.0/servicePrincipals"
    "?$select=id,displayName,appId,servicePrincipalType,appOwnerOrganizationId,"
    "accountEnabled,tags,signInAudience,createdDateTime"
    "&$top=999"
)
APPS_URL = (
    "https://graph.microsoft.com/v1.0/applications"
    "?$select=id,displayName,appId,signInAudience,createdDateTime,publisherDomain"
    "&$top=999"
)

MAX_ITEMS = max(100, int(os.getenv("GRAPH_WORKLOAD_MAX_ITEMS", "2000")))

GALLERY_TAG = "WindowsAzureActiveDirectoryIntegratedApp"


def _is_microsoft_tenant(owner_id: str | None) -> bool:
    return bool(owner_id) and str(owner_id).lower() in MICROSOFT_TENANT_IDS


def classify_service_principal(
    sp: dict[str, Any],
    home_tenant_id: str | None,
    local_app_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Classifica um service principal quanto à sua procedência."""
    local_app_ids = local_app_ids or set()
    sp_type = str(sp.get("servicePrincipalType") or "").strip()
    owner_id = sp.get("appOwnerOrganizationId")
    owner_str = str(owner_id).lower() if owner_id else None
    app_id = str(sp.get("appId") or "")
    has_local_registration = app_id in local_app_ids

    signals: list[str] = []
    if owner_id:
        signals.append(f"appOwnerOrganizationId={owner_id}")
    else:
        signals.append("appOwnerOrganizationId ausente")
    signals.append(f"servicePrincipalType={sp_type or 'desconhecido'}")
    if has_local_registration:
        signals.append("possui objeto /applications no tenant")

    if sp_type.lower() == "managedidentity":
        provenance = PROVENANCE_MANAGED_IDENTITY
        confidence = "High"
        basis = "Confirmed"
    elif home_tenant_id and owner_str == str(home_tenant_id).lower():
        provenance = PROVENANCE_TENANT_OWNED
        confidence = "High" if has_local_registration else "Medium"
        basis = "Confirmed" if has_local_registration else "Directory-signal"
    elif _is_microsoft_tenant(owner_str):
        provenance = PROVENANCE_MICROSOFT
        confidence = "High"
        basis = "Confirmed"
    elif owner_str:
        provenance = PROVENANCE_THIRD_PARTY
        confidence = "High"
        basis = "Confirmed"
    elif sp_type.lower() in {"serviceidentity", "socialidp", "legacy"}:
        provenance = PROVENANCE_SERVICE_IDENTITY
        confidence = "Medium"
        basis = "Directory-signal"
    else:
        provenance = PROVENANCE_UNKNOWN
        confidence = "Low"
        basis = "Insufficient-signal"

    tags = sp.get("tags") or []
    is_gallery = isinstance(tags, list) and GALLERY_TAG in tags

    return {
        "objectId": sp.get("id"),
        "displayName": sp.get("displayName"),
        "appId": sp.get("appId"),
        "servicePrincipalType": sp_type or None,
        "accountEnabled": sp.get("accountEnabled"),
        "appOwnerOrganizationId": owner_id,
        "appOwnerName": MICROSOFT_TENANT_IDS.get(owner_str or "", None)
        or ("Seu tenant" if home_tenant_id and owner_str == str(home_tenant_id).lower() else None),
        "provenance": provenance,
        "provenanceLabel": PROVENANCE_LABELS[provenance],
        "isCustomerCreated": provenance == PROVENANCE_TENANT_OWNED,
        "isMicrosoftNative": provenance == PROVENANCE_MICROSOFT,
        "hasLocalAppRegistration": has_local_registration,
        "isGalleryApp": is_gallery,
        "signInAudience": sp.get("signInAudience"),
        "createdDateTime": sp.get("createdDateTime"),
        "classificationBasis": basis,
        "confidence": confidence,
        "signals": signals,
    }


def _load_service_principals() -> list[dict[str, Any]]:
    if is_mock_mode():
        return list(load_mock_iam().get("service_principals", []))
    return graph_list(SP_URL, max_items=MAX_ITEMS)


def _load_applications() -> list[dict[str, Any]]:
    if is_mock_mode():
        return list(load_mock_iam().get("applications", []))
    return graph_list(APPS_URL, max_items=MAX_ITEMS)


def list_application_provenance(
    provenance: str = "all",
    include_managed_identities: bool = True,
    limit: int = 200,
) -> dict[str, Any]:
    """Inventário de aplicações classificadas por procedência."""
    home_tenant_id = get_home_tenant_id()
    try:
        sps = _load_service_principals()
        apps = _load_applications()
    except Exception as exc:
        return {
            "ok": False,
            "error_kind": "provider_error",
            "error": f"Não foi possível coletar aplicações do diretório: {exc}",
            "coverage": "NOT_EVALUATED",
        }

    local_app_ids = {str(a.get("appId")) for a in apps if a.get("appId")}
    app_by_id = {str(a.get("appId")): a for a in apps if a.get("appId")}

    classified = [classify_service_principal(sp, home_tenant_id, local_app_ids) for sp in sps]

    for row in classified:
        registration = app_by_id.get(str(row.get("appId") or ""))
        if registration:
            row["applicationObjectId"] = registration.get("id")
            row["publisherDomain"] = registration.get("publisherDomain")
            if not row.get("createdDateTime"):
                row["createdDateTime"] = registration.get("createdDateTime")

    if not include_managed_identities:
        classified = [r for r in classified if r["provenance"] != PROVENANCE_MANAGED_IDENTITY]

    wanted = (provenance or "all").strip().lower()
    alias = {
        "all": None,
        "tenant": PROVENANCE_TENANT_OWNED,
        "tenantowned": PROVENANCE_TENANT_OWNED,
        "customer": PROVENANCE_TENANT_OWNED,
        "custom": PROVENANCE_TENANT_OWNED,
        "criadas": PROVENANCE_TENANT_OWNED,
        "microsoft": PROVENANCE_MICROSOFT,
        "firstparty": PROVENANCE_MICROSOFT,
        "native": PROVENANCE_MICROSOFT,
        "nativas": PROVENANCE_MICROSOFT,
        "thirdparty": PROVENANCE_THIRD_PARTY,
        "terceiro": PROVENANCE_THIRD_PARTY,
        "managedidentity": PROVENANCE_MANAGED_IDENTITY,
    }
    if wanted not in alias:
        return {
            "ok": False,
            "error_kind": "invalid_input",
            "error": f"Filtro de procedência inválido: '{provenance}'. Use: {', '.join(sorted(alias))}.",
        }
    target = alias[wanted]
    filtered = [r for r in classified if target is None or r["provenance"] == target]

    filtered.sort(key=lambda r: (str(r.get("provenance")), str(r.get("displayName") or "").lower()))

    counts = Counter(r["provenance"] for r in classified)
    orphan_registrations = [
        {"displayName": a.get("displayName"), "appId": a.get("appId"), "objectId": a.get("id")}
        for a in apps
        if str(a.get("appId")) not in {str(s.get("appId")) for s in sps if s.get("appId")}
    ]

    return {
        "ok": True,
        "mode": "mock" if is_mock_mode() else "azure-live",
        "home_tenant_id": home_tenant_id,
        "coverage": "EVALUATED" if home_tenant_id else "PARTIAL",
        "coverage_note": (
            "Classificação baseada em appOwnerOrganizationId (sinal do diretório), "
            "não em heurística de nome."
            if home_tenant_id
            else "Tenant de origem não determinado; classificação TenantOwned pode ficar incompleta."
        ),
        "totals": {
            "service_principals": len(classified),
            "application_registrations": len(apps),
            "tenant_owned": counts.get(PROVENANCE_TENANT_OWNED, 0),
            "microsoft_first_party": counts.get(PROVENANCE_MICROSOFT, 0),
            "third_party_multi_tenant": counts.get(PROVENANCE_THIRD_PARTY, 0),
            "managed_identities": counts.get(PROVENANCE_MANAGED_IDENTITY, 0),
            "service_identities": counts.get(PROVENANCE_SERVICE_IDENTITY, 0),
            "unknown": counts.get(PROVENANCE_UNKNOWN, 0),
        },
        "application_registrations_without_service_principal": orphan_registrations[:50],
        "filter": wanted,
        "count": len(filtered),
        "truncated": len(filtered) > limit,
        "items": filtered[: max(1, limit)],
    }


def summarize_application_provenance() -> dict[str, Any]:
    """Resumo executivo: quanto do diretório é seu e quanto é nativo da Microsoft."""
    data = list_application_provenance(limit=1)
    if not data.get("ok"):
        return data

    totals = data["totals"]
    total_sps = int(totals["service_principals"]) or 1
    tenant_owned = int(totals["tenant_owned"])
    microsoft = int(totals["microsoft_first_party"])
    third_party = int(totals["third_party_multi_tenant"])

    return {
        "ok": True,
        "home_tenant_id": data.get("home_tenant_id"),
        "coverage": data.get("coverage"),
        "totals": totals,
        "percentages": {
            "tenant_owned": round(tenant_owned * 100 / total_sps, 1),
            "microsoft_first_party": round(microsoft * 100 / total_sps, 1),
            "third_party_multi_tenant": round(third_party * 100 / total_sps, 1),
        },
        "attack_surface_note": (
            f"{tenant_owned} aplicação(ões) criada(s) no seu tenant estão sob sua responsabilidade "
            f"de governança (credenciais, owners, permissões). As {microsoft} aplicações "
            "first-party da Microsoft são pré-provisionadas e não são registros criados por usuários."
        ),
        "governance_focus": (
            "Priorize revisão de credenciais, owners e permissões nas aplicações TenantOwned "
            "e ThirdPartyMultiTenant. Aplicações MicrosoftFirstParty devem ser avaliadas pelo "
            "consentimento concedido, não pelo registro."
        ),
    }
