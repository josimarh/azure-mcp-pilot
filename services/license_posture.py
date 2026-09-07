"""Postura de licenciamento: o que o tenant paga versus o que realmente usa.

Uma auditoria de identidade fica incompleta quando ignora licenca. Recursos de
seguranca pagos e nunca ativados representam risco aceito sem necessidade, e
licencas atribuidas a ninguem representam custo sem retorno.

Todo veredito aqui distingue tres situacoes que um numero sozinho confunde:
nao licenciado, licenciado e ocioso, e nao avaliado.
"""

from __future__ import annotations

from typing import Any

from services.entra_licenses import (
    LICENSED,
    NOT_LICENSED,
    evaluate_requirement,
    license_inventory,
)

VERDICT_NOT_LICENSED = "NOT_LICENSED"
VERDICT_NOT_CONFIGURED = "LICENSED_NOT_CONFIGURED"
VERDICT_NOT_EVALUATED = "LICENSED_NOT_EVALUATED"
VERDICT_IN_USE = "IN_USE"
VERDICT_UNKNOWN = "LICENSE_UNKNOWN"


def _capability_usage(name: str, requirement: str, probe) -> dict[str, Any]:
    """Avalia uma capacidade licenciavel sem transformar falha em ausencia."""
    licensing = evaluate_requirement(requirement)

    if licensing["status"] == NOT_LICENSED:
        return {
            "feature": name,
            "requirement": requirement,
            "verdict": VERDICT_NOT_LICENSED,
            "licenseStatus": licensing["status"],
            "count": None,
            "detail": "Recurso indisponivel: licenca ausente. A ausencia de dados e esperada.",
        }

    if licensing["status"] != LICENSED:
        return {
            "feature": name,
            "requirement": requirement,
            "verdict": VERDICT_UNKNOWN,
            "licenseStatus": licensing["status"],
            "count": None,
            "detail": licensing.get("detail"),
        }

    try:
        count = probe()
    except Exception as exc:
        return {
            "feature": name,
            "requirement": requirement,
            "verdict": VERDICT_NOT_EVALUATED,
            "licenseStatus": licensing["status"],
            "matchedPlan": licensing.get("matchedPlan"),
            "count": None,
            "detail": f"Licenciado, mas nao foi possivel avaliar: {exc}"[:300],
        }

    if count is None:
        return {
            "feature": name,
            "requirement": requirement,
            "verdict": VERDICT_NOT_EVALUATED,
            "licenseStatus": licensing["status"],
            "matchedPlan": licensing.get("matchedPlan"),
            "count": None,
            "detail": "Licenciado, mas a fonte nao pode ser avaliada.",
        }

    return {
        "feature": name,
        "requirement": requirement,
        "verdict": VERDICT_IN_USE if count > 0 else VERDICT_NOT_CONFIGURED,
        "licenseStatus": licensing["status"],
        "matchedPlan": licensing.get("matchedPlan"),
        "count": count,
        "detail": None
        if count > 0
        else "Recurso licenciado, avaliado e sem configuracao encontrada.",
    }


def _probe_pim() -> int | None:
    from services.entra_pim import list_pim_assignments_with_coverage

    result = list_pim_assignments_with_coverage()
    evaluated = [c for c in result["coverage"] if c.get("status") == "EVALUATED"]
    if not evaluated:
        return None
    return sum(int(c.get("count") or 0) for c in result["coverage"])


def _probe_conditional_access() -> int | None:
    from services.entra_conditional_access import list_conditional_access_policies

    return len(list_conditional_access_policies())


def get_license_posture() -> dict[str, Any]:
    """Cruza licencas assinadas com uso observado de recursos de seguranca."""
    inventory = license_inventory()

    if not inventory["evaluated"]:
        return {
            "evaluated": False,
            "reason": inventory["reason"],
            "skus": [],
            "features": [],
            "findings": [],
        }

    features = [
        _capability_usage("Privileged Identity Management (PIM)", "Microsoft Entra ID P2", _probe_pim),
        _capability_usage("Acesso Condicional", "Microsoft Entra ID P1", _probe_conditional_access),
    ]

    findings: list[dict[str, Any]] = []

    for feature in features:
        if feature["verdict"] == VERDICT_NOT_CONFIGURED:
            findings.append(
                {
                    "type": "LICENSED_FEATURE_UNUSED",
                    "severity": "Medium",
                    "feature": feature["feature"],
                    "message": (
                        f"{feature['feature']} esta licenciado ({feature.get('matchedPlan')}) "
                        "mas nao ha configuracao em uso."
                    ),
                }
            )
        elif feature["verdict"] == VERDICT_NOT_EVALUATED:
            findings.append(
                {
                    "type": "LICENSED_FEATURE_NOT_EVALUATED",
                    "severity": "Info",
                    "feature": feature["feature"],
                    "message": (
                        f"{feature['feature']} esta licenciado, mas nao foi possivel avaliar o uso. "
                        "Nao e possivel afirmar que esta sem configuracao."
                    ),
                }
            )

    for sku in inventory["skus"]:
        unused = int(sku.get("unusedUnits") or 0)
        enabled = int(sku.get("enabledUnits") or 0)
        if enabled > 0 and unused > 0:
            findings.append(
                {
                    "type": "UNUSED_LICENSE_UNITS",
                    "severity": "Low",
                    "feature": sku.get("skuPartNumber"),
                    "message": (
                        f"{sku.get('skuPartNumber')}: {unused} de {enabled} licencas "
                        "habilitadas nao estao atribuidas."
                    ),
                }
            )

    return {
        "evaluated": True,
        "reason": None,
        "skus": inventory["skus"],
        "servicePlans": inventory["servicePlans"],
        "features": features,
        "findings": findings,
    }
