from __future__ import annotations

import unicodedata
from typing import Any

from services.entra_roles import list_privileged_directory_role_members
from services.entra_users import list_users
from services.iam_common import graph_list, is_mock_mode, load_mock_iam, safe_collect

WEAK_METHODS = {"sms", "voice", "password", "email"}
STRONG_METHODS = {"fido2", "windowsHelloForBusiness", "microsoftAuthenticator", "passkey"}


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower()


def _normalized_methods(row: dict[str, Any]) -> set[str]:
    return {str(method).strip().lower() for method in (row.get("methods") or []) if str(method).strip()}


def _auth_strength(row: dict[str, Any]) -> str:
    methods = _normalized_methods(row)
    weak = {m.lower() for m in WEAK_METHODS}
    strong = {m.lower() for m in STRONG_METHODS}
    has_weak = bool(methods.intersection(weak))
    has_strong = bool(methods.intersection(strong))
    if not methods:
        return "NO_METHODS"
    if has_strong and has_weak:
        return "MIXED"
    if has_strong:
        return "STRONG"
    if has_weak:
        return "WEAK_ONLY"
    return "UNKNOWN"


def list_user_authentication_details() -> list[dict[str, Any]]:
    """Retorna detalhes de registro de métodos de autenticação por usuário."""
    users = {str(u.get("id")): u for u in list_users() if u.get("id")}
    if is_mock_mode():
        rows: list[dict[str, Any]] = []
        for item in load_mock_iam().get("authentication_methods", []):
            user = users.get(str(item.get("userId")), {})
            rows.append(
                {
                    "objectId": item.get("userId"),
                    "displayName": user.get("displayName"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "mail": user.get("mail") or user.get("userPrincipalName"),
                    "isMfaRegistered": bool(item.get("isMfaRegistered")),
                    "isPasswordlessCapable": bool(item.get("isPasswordlessCapable")),
                    "methods": item.get("methods", []),
                }
            )
        return rows

    rows = graph_list(
        "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
        "?$select=id,userPrincipalName,isMfaRegistered,isPasswordlessCapable,methodsRegistered"
    )
    output: list[dict[str, Any]] = []
    for item in rows:
        user = users.get(str(item.get("id")), {})
        output.append(
            {
                "objectId": item.get("id"),
                "displayName": user.get("displayName") or item.get("userPrincipalName"),
                "userPrincipalName": item.get("userPrincipalName"),
                "mail": user.get("mail") or item.get("userPrincipalName"),
                "isMfaRegistered": bool(item.get("isMfaRegistered")),
                "isPasswordlessCapable": bool(item.get("isPasswordlessCapable")),
                "methods": item.get("methodsRegistered", []) or [],
            }
        )
    return output


def get_user_authentication_methods(user_identifier: str) -> dict[str, Any]:
    q = _normalize(user_identifier)
    for row in list_user_authentication_details():
        if q in {
            _normalize(str(row.get("objectId") or "")),
            _normalize(str(row.get("displayName") or "")),
            _normalize(str(row.get("userPrincipalName") or "")),
            _normalize(str(row.get("mail") or "")),
        }:
            return row
    raise RuntimeError(
        f"Não foi possível resolver métodos de autenticação para `{user_identifier}` com os dados disponíveis."
    )


def get_authentication_methods_summary() -> dict[str, Any]:
    rows = list_user_authentication_details()
    return {
        "registered_users": len(rows),
        "users_capable_passwordless": sum(1 for r in rows if r.get("isPasswordlessCapable")),
        "users_capable_mfa": sum(1 for r in rows if r.get("isMfaRegistered")),
        "users_without_mfa": sum(1 for r in rows if not r.get("isMfaRegistered")),
    }


def list_users_without_mfa() -> list[dict[str, Any]]:
    return [r for r in list_user_authentication_details() if not r.get("isMfaRegistered")]


def list_users_with_weak_authentication(include_mfa_registered: bool = True) -> list[dict[str, Any]]:
    rows = list_user_authentication_details()
    out: list[dict[str, Any]] = []
    weak_methods = {m.lower() for m in WEAK_METHODS}
    for row in rows:
        methods = _normalized_methods(row)
        has_strong = bool(methods.intersection({m.lower() for m in STRONG_METHODS}))
        weak_present = sorted([m for m in methods if m in weak_methods])
        if not weak_present:
            continue
        if not include_mfa_registered and row.get("isMfaRegistered"):
            continue
        item = dict(row)
        item["authStrength"] = _auth_strength(row)
        item["weakMethods"] = weak_present
        item["hasStrongMethod"] = has_strong
        out.append(item)
    return out


def list_users_with_passkey() -> list[dict[str, Any]]:
    rows = list_user_authentication_details()
    out: list[dict[str, Any]] = []
    for row in rows:
        methods = _normalized_methods(row)
        if "passkey" in methods or "fido2" in methods:
            item = dict(row)
            item["authStrength"] = _auth_strength(row)
            out.append(item)
    return out


def get_authentication_strength_summary() -> dict[str, Any]:
    rows = list_user_authentication_details()
    weak_rows = list_users_with_weak_authentication(include_mfa_registered=True)
    passkey_rows = list_users_with_passkey()
    breakdown = {"STRONG": 0, "MIXED": 0, "WEAK_ONLY": 0, "NO_METHODS": 0, "UNKNOWN": 0}
    for row in rows:
        strength = _auth_strength(row)
        breakdown[strength] = breakdown.get(strength, 0) + 1
    return {
        "users_evaluated": len(rows),
        "mfa_registered": sum(1 for r in rows if r.get("isMfaRegistered")),
        "passwordless_capable": sum(1 for r in rows if r.get("isPasswordlessCapable")),
        "users_with_passkey_or_fido2": len(passkey_rows),
        "users_with_weak_methods_registered": len(weak_rows),
        "auth_strength_breakdown": breakdown,
    }


def assess_privileged_mfa() -> dict[str, Any]:
    """Assessment de MFA focado em usuários privilegiados (Entra roles privilegiadas)."""
    auth_by_id = {str(r.get("objectId")): r for r in list_user_authentication_details()}
    privileged_ids = {
        str(m.get("principalId"))
        for m in list_privileged_directory_role_members()
        if str(m.get("identityType", "")).lower() == "user"
    }
    privileged_without_mfa: list[dict[str, Any]] = []
    privileged_weak_methods: list[dict[str, Any]] = []
    for pid in privileged_ids:
        auth = auth_by_id.get(pid)
        if not auth:
            continue
        if not auth.get("isMfaRegistered"):
            privileged_without_mfa.append(auth)
            continue
        methods = {str(m).lower() for m in auth.get("methods", [])}
        if methods and methods.issubset({m.lower() for m in WEAK_METHODS}):
            privileged_weak_methods.append(auth)
    return {
        "privileged_users_evaluated": len(privileged_ids),
        "privileged_without_mfa": privileged_without_mfa,
        "privileged_weak_methods": privileged_weak_methods,
    }


def safe_authentication_methods_summary() -> dict[str, Any]:
    return safe_collect("authentication-methods-summary", get_authentication_methods_summary)


def safe_authentication_strength_summary() -> dict[str, Any]:
    return safe_collect("authentication-strength-summary", get_authentication_strength_summary)


def safe_privileged_mfa() -> dict[str, Any]:
    return safe_collect("privileged-mfa", assess_privileged_mfa)
