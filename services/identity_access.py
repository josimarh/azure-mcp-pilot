from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import httpx
from azure.identity import DefaultAzureCredential

from services.azure_auth import get_credential, get_graph_token

from services.azure_graph import is_mock_mode, sanitize_enabled

ROOT = Path(__file__).resolve().parents[1]
MOCK_FILE = ROOT / "data" / "mock_identity.json"
GRAPH_USERS_URL = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,accountEnabled&$top=999"


def _mask(value: str | None, prefix: str) -> str | None:
    if not value:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{digest}"


def _sanitize_scope(scope: str | None) -> str | None:
    if not scope:
        return scope
    parts = scope.split("/")
    output: list[str] = []
    skip_next = False
    for idx, part in enumerate(parts):
        if skip_next:
            skip_next = False
            continue
        if part == "subscriptions" and idx + 1 < len(parts):
            output.extend(["subscriptions", _mask(parts[idx + 1], "sub") or "sub-unknown"])
            skip_next = True
            continue
        if part == "resourceGroups" and idx + 1 < len(parts):
            output.extend(["resourceGroups", _mask(parts[idx + 1], "rg") or "rg-unknown"])
            skip_next = True
            continue
        output.append(part)
    return "/".join(output)


def _sanitize_user_row(row: dict[str, Any]) -> dict[str, Any]:
    if not sanitize_enabled():
        return row
    out = dict(row)
    if "id" in out:
        out["id"] = _mask(str(out["id"]), "user-id")
    if "userPrincipalName" in out:
        out["userPrincipalName"] = _mask(str(out["userPrincipalName"]), "upn")
    if "mail" in out and out["mail"]:
        out["mail"] = _mask(str(out["mail"]), "mail")
    return out


def _sanitize_resource_group_row(row: dict[str, Any]) -> dict[str, Any]:
    if not sanitize_enabled():
        return row
    out = dict(row)
    if "name" in out:
        out["name"] = _mask(str(out["name"]), "rg")
    if "subscriptionId" in out:
        out["subscriptionId"] = _mask(str(out["subscriptionId"]), "sub")
    return out


def _sanitize_assignment_row(row: dict[str, Any]) -> dict[str, Any]:
    if not sanitize_enabled():
        return row
    out = dict(row)
    out["scope"] = _sanitize_scope(out.get("scope"))
    if "principalId" in out:
        out["principalId"] = _mask(str(out["principalId"]), "user-id")
    return out


def _load_mock() -> dict[str, Any]:
    return json.loads(MOCK_FILE.read_text(encoding="utf-8"))


def _query_resource_graph(query: str) -> list[dict[str, Any]]:
    from services.azure_graph import _query_resource_graph as graph_query

    return graph_query(query)


def _credential() -> DefaultAzureCredential:
    return get_credential()


def _list_graph_users() -> list[dict[str, Any]]:
    token = get_graph_token()
    headers = {"Authorization": f"Bearer {token}"}
    users: list[dict[str, Any]] = []
    next_url: str | None = GRAPH_USERS_URL
    with httpx.Client(timeout=30.0) as client:
        while next_url:
            response = client.get(next_url, headers=headers)
            if response.is_error:
                detail = response.text[:500]
                raise RuntimeError(
                    "Microsoft Graph retornou erro ao listar usuários. "
                    f"HTTP {response.status_code}. Detalhe: {detail}"
                )
            payload = response.json()
            value = payload.get("value", [])
            if isinstance(value, list):
                users.extend(value)
            next_url = payload.get("@odata.nextLink")
    return users


def _list_user_role_assignments() -> list[dict[str, Any]]:
    from services.azure_role_definitions import resolve_role

    assignments = _query_resource_graph(
        "AuthorizationResources "
        "| where type =~ 'microsoft.authorization/roleassignments' "
        "| extend principalId=tostring(properties.principalId), "
        "principalType=tostring(properties.principalType), "
        "roleDefinitionId=tostring(properties.roleDefinitionId), "
        "scope=tostring(properties.scope) "
        "| where principalType =~ 'User' "
        "| project principalId, roleDefinitionId, scope"
    )
    enriched: list[dict[str, Any]] = []
    for item in assignments:
        role_id = str(item.get("roleDefinitionId", ""))
        resolved = resolve_role(role_id)
        row = {
            "principalId": item.get("principalId"),
            "roleDefinitionId": role_id,
            "scope": item.get("scope"),
            "roleName": resolved.get("roleName"),
            "roleResolution": resolved.get("resolution"),
        }
        enriched.append(row)
    return enriched


def get_resource_groups_count() -> dict[str, Any]:
    if is_mock_mode():
        from services.azure_graph import _load_mock as load_mock_resources

        resources = load_mock_resources()
        return {
            "mode": "mock",
            "source": "Azure Resource Graph",
            "resource_groups_count": len({r["resourceGroup"] for r in resources}),
        }

    totals = _query_resource_graph(
        "ResourceContainers "
        "| where type =~ 'microsoft.resources/resourcegroups' "
        "| summarize resource_groups_count=count()"
    )
    total = totals[0] if totals else {}
    return {
        "mode": "azure-live",
        "source": "Azure Resource Graph",
        "resource_groups_count": total.get("resource_groups_count", 0),
    }


def list_resource_groups(name_contains: str = "", limit: int = 20) -> dict[str, Any]:
    limit = max(1, min(int(limit), 100))
    needle = name_contains.strip().lower()

    if is_mock_mode():
        from services.azure_graph import _load_mock as load_mock_resources

        resources = load_mock_resources()
        grouped: dict[str, dict[str, Any]] = {}
        for item in resources:
            rg = item.get("resourceGroup")
            if not rg:
                continue
            if needle and needle not in str(rg).lower():
                continue
            grouped[str(rg)] = {
                "name": rg,
                "subscriptionId": item.get("subscriptionId"),
                "location": item.get("location"),
            }
        rows = [_sanitize_resource_group_row(row) for row in list(grouped.values())[:limit]]
        return {"mode": "mock", "count": len(rows), "resource_groups": rows}

    safe_needle = needle.replace("'", "''")
    query = (
        "ResourceContainers "
        "| where type =~ 'microsoft.resources/resourcegroups' "
        "| project name, subscriptionId, location "
    )
    if safe_needle:
        query += f"| where tolower(name) contains '{safe_needle}' "
    query += f"| take {limit}"
    rows = [_sanitize_resource_group_row(row) for row in _query_resource_graph(query)]
    return {"mode": "azure-live", "count": len(rows), "resource_groups": rows}


def get_identity_access_summary() -> dict[str, Any]:
    if is_mock_mode():
        data = _load_mock()
        users = data.get("users", [])
        assignments = data.get("role_assignments", [])
    else:
        users = _list_graph_users()
        assignments = _list_user_role_assignments()

    users_by_id = {str(item.get("id")): item for item in users if item.get("id")}
    user_ids_with_roles = {str(a.get("principalId")) for a in assignments if a.get("principalId")}
    disabled_ids = {
        uid
        for uid, user in users_by_id.items()
        if user.get("accountEnabled") is False
    }

    disabled_with_roles = sorted(disabled_ids.intersection(user_ids_with_roles))
    unresolved_user_ids = sorted(uid for uid in user_ids_with_roles if uid not in users_by_id)

    return {
        "mode": "mock" if is_mock_mode() else "azure-live",
        "source": "Microsoft Graph + Azure RBAC",
        "total_users": len(users_by_id),
        "enabled_users": sum(1 for u in users_by_id.values() if u.get("accountEnabled") is True),
        "disabled_users": sum(1 for u in users_by_id.values() if u.get("accountEnabled") is False),
        "users_with_direct_role_assignments": len(user_ids_with_roles),
        "disabled_users_with_active_roles": len(disabled_with_roles),
        "unresolved_principal_ids_with_roles": len(unresolved_user_ids),
    }


def list_users(limit: int = 20, disabled_only: bool = False, name_contains: str = "") -> dict[str, Any]:
    limit = max(1, min(int(limit), 100))
    needle = name_contains.strip().lower()
    if is_mock_mode():
        data = _load_mock()
        users = data.get("users", [])
    else:
        users = _list_graph_users()

    filtered: list[dict[str, Any]] = []
    for user in users:
        if disabled_only and user.get("accountEnabled") is not False:
            continue
        if needle:
            display = str(user.get("displayName") or "").lower()
            upn = str(user.get("userPrincipalName") or "").lower()
            if needle not in display and needle not in upn:
                continue
        filtered.append(
            {
                "id": user.get("id"),
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "mail": user.get("mail") or user.get("userPrincipalName"),
                "accountEnabled": user.get("accountEnabled"),
            }
        )

    filtered.sort(key=lambda x: str(x.get("displayName") or x.get("userPrincipalName") or ""))
    rows = [_sanitize_user_row(item) for item in filtered[:limit]]
    return {
        "mode": "mock" if is_mock_mode() else "azure-live",
        "count": len(rows),
        "users": rows,
    }


def list_users_with_direct_permissions(limit: int = 20, disabled_only: bool = False) -> dict[str, Any]:
    limit = max(1, min(int(limit), 100))
    if is_mock_mode():
        data = _load_mock()
        users = data.get("users", [])
        assignments = data.get("role_assignments", [])
    else:
        users = _list_graph_users()
        assignments = _list_user_role_assignments()

    users_by_id = {str(item.get("id")): item for item in users if item.get("id")}
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in assignments:
        principal_id = item.get("principalId")
        if principal_id:
            by_user[str(principal_id)].append(item)

    rows: list[dict[str, Any]] = []
    for principal_id, user_assignments in by_user.items():
        user = users_by_id.get(principal_id, {})
        account_enabled = user.get("accountEnabled")
        if disabled_only and account_enabled is not False:
            continue
        roles = sorted(
            {
                a.get("roleName") or a.get("roleDefinitionId")
                for a in user_assignments
                if a.get("roleName") or a.get("roleDefinitionId")
            }
        )
        scopes = sorted({a.get("scope") for a in user_assignments if a.get("scope")})
        row = {
            "id": principal_id,
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
            "mail": user.get("mail") or user.get("userPrincipalName"),
            "accountEnabled": account_enabled,
            "assignments_count": len(user_assignments),
            "roles": roles[:20],
            "scopes_sample": scopes[:20],
        }
        rows.append(row)

    rows.sort(
        key=lambda x: (
            -(x.get("assignments_count") or 0),
            str(x.get("displayName") or x.get("userPrincipalName") or x.get("id") or ""),
        )
    )
    output = []
    for item in rows[:limit]:
        sanitized = _sanitize_user_row(item)
        sanitized["scopes_sample"] = [
            _sanitize_assignment_row({"scope": scope}).get("scope")
            for scope in item.get("scopes_sample", [])
        ]
        output.append(sanitized)
    return {
        "mode": "mock" if is_mock_mode() else "azure-live",
        "count": len(output),
        "users": output,
    }


def list_disabled_users_with_active_roles(limit: int = 20) -> dict[str, Any]:
    return list_users_with_direct_permissions(limit=limit, disabled_only=True)
