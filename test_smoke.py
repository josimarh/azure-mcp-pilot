import asyncio
import json
import os

os.environ["MOCK_MODE"] = "true"
os.environ["SANITIZE_FOR_LLM"] = "true"

from mcp import Client
from mcp_server import mcp


def _content_to_dict(result: object) -> dict:
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        return structured

    chunks: list[str] = []
    for block in getattr(result, "content", []):
        text = getattr(block, "text", None)
        if text:
            chunks.append(text)

    if not chunks:
        return {}
    return json.loads("\n".join(chunks))


async def main() -> None:
    async with Client(mcp) as client:
        tools = await client.list_tools()
        names = {tool.name for tool in tools.tools}
        assert "get_environment_summary" in names
        assert "get_resource_groups_count" in names
        assert "get_identity_access_summary" in names
        assert "list_users" in names
        assert "list_disabled_users_with_active_roles" in names
        assert "iam_natural_language_query" in names
        assert "run_iam_assessment" in names
        assert "pim_natural_language_query" in names
        assert "get_pim_state_summary" in names
        assert "get_role_risk_score" in names
        assert "list_agent_identities" in names
        assert "agent_natural_language_query" in names
        assert "run_agent_assessment" in names
        assert "get_user_effective_azure_access" in names
        assert "list_orphan_azure_role_assignments" in names
        assert "timeline_natural_language_query" in names
        assert "summarize_privilege_timeline" in names
        assert "list_privilege_timeline_events" in names
        assert "export_privilege_timeline_report" in names
        assert "identity_360" in names
        assert "get_user_authentication_methods" in names
        assert "assess_privileged_mfa" in names
        assert "get_owned_objects" in names
        assert "detect_toxic_combinations" in names
        assert "compute_identity_blast_radius" in names
        result = await client.call_tool("get_environment_summary", {})
        assert not result.is_error
        summary = _content_to_dict(result)
        assert summary["total_resources"] == 6
        rg_count = await client.call_tool("get_resource_groups_count", {})
        rg_summary = _content_to_dict(rg_count)
        assert rg_summary["resource_groups_count"] == 6
        resources = await client.call_tool(
            "list_resources",
            {"resource_type": "microsoft.compute/virtualmachines", "limit": 10},
        )
        listed = _content_to_dict(resources)
        assert listed["count"] == 2
        assert listed["resources"][0]["name"].startswith("resource-")
        identity = await client.call_tool("get_identity_access_summary", {})
        identity_summary = _content_to_dict(identity)
        assert identity_summary["total_users"] == 4
        assert identity_summary["disabled_users_with_active_roles"] == 1
        direct_users = await client.call_tool(
            "list_users_with_direct_permissions",
            {"limit": 10},
        )
        direct_users_payload = _content_to_dict(direct_users)
        assert direct_users_payload["count"] == 3
        assert "mail" in direct_users_payload["users"][0]
        privileged_azure = await client.call_tool("list_privileged_azure_role_assignments", {"limit": 10})
        privileged_azure_payload = _content_to_dict(privileged_azure)
        assert "riskScore" in privileged_azure_payload["assignments"][0]
        users = await client.call_tool("list_users", {"limit": 10})
        users_list = _content_to_dict(users)
        assert users_list["count"] == 4
        assert "mail" in users_list["users"][0]
        iam_query = await client.call_tool(
            "iam_natural_language_query",
            {"question": "Quem possui Global Administrator?", "limit": 10},
        )
        iam_payload = _content_to_dict(iam_query)
        assert "narrative" in iam_payload
        assessment = await client.call_tool("run_iam_assessment", {"top_risks": 5})
        assessment_payload = _content_to_dict(assessment)
        assert "summary" in assessment_payload
        assert "risks" in assessment_payload
        pim_summary = await client.call_tool("get_pim_state_summary", {})
        pim_summary_payload = _content_to_dict(pim_summary)
        assert "states" in pim_summary_payload
        pim_query = await client.call_tool(
            "pim_natural_language_query",
            {"question": "Quem possui role elegível via PIM?", "limit": 10},
        )
        pim_query_payload = _content_to_dict(pim_query)
        assert "narrative" in pim_query_payload
        narrative = str(pim_query_payload.get("narrative", ""))
        assert "Entra ID PIM" in narrative
        assert "Azure PIM RBAC" in narrative
        role_score = await client.call_tool(
            "get_role_risk_score",
            {"role": "Global Administrator", "provider": "Entra", "scope": "/", "state": "Active"},
        )
        role_score_payload = _content_to_dict(role_score)
        assert role_score_payload["riskScore"] >= 90
        agents = await client.call_tool("list_agent_identities", {"status": "all", "limit": 10})
        agents_payload = _content_to_dict(agents)
        assert agents_payload["count"] >= 1
        assert "riskScore" in agents_payload["agents"][0]
        agent_query = await client.call_tool(
            "agent_natural_language_query",
            {"question": "Quais agents não possuem owner?", "limit": 10},
        )
        agent_query_payload = _content_to_dict(agent_query)
        assert "narrative" in agent_query_payload
        assert "sem owner" in str(agent_query_payload.get("narrative", "")).lower()
        agent_assessment = await client.call_tool("run_agent_assessment", {"top_risks": 5})
        agent_assessment_payload = _content_to_dict(agent_assessment)
        assert "top_agents" in agent_assessment_payload
        effective_access = await client.call_tool(
            "get_user_effective_azure_access",
            {"user_identifier": "ana.silva@contoso.com", "limit": 20},
        )
        effective_access_payload = _content_to_dict(effective_access)
        assert effective_access_payload["totalAssignmentsCount"] >= 1
        assert effective_access_payload["inheritedAssignmentsCount"] >= 1
        orphan_assignments = await client.call_tool("list_orphan_azure_role_assignments", {"limit": 20})
        orphan_assignments_payload = _content_to_dict(orphan_assignments)
        assert orphan_assignments_payload["count"] >= 1
        timeline_summary = await client.call_tool("summarize_privilege_timeline", {"days": 90})
        timeline_summary_payload = _content_to_dict(timeline_summary)
        assert timeline_summary_payload["total_events"] >= 1
        timeline_query = await client.call_tool(
            "timeline_natural_language_query",
            {"question": "Quem recebeu privilégios nos últimos 90 dias?", "limit": 10},
        )
        timeline_query_payload = _content_to_dict(timeline_query)
        assert "narrative" in timeline_query_payload
        timeline_report = await client.call_tool("export_privilege_timeline_report", {"days": 90, "top": 5})
        timeline_report_payload = _content_to_dict(timeline_report)
        assert "report" in timeline_report_payload
        assert "top_by_identity" in timeline_report_payload["report"]
        identity360 = await client.call_tool("identity_360", {"user_identifier": "ana.silva@contoso.com"})
        identity360_payload = _content_to_dict(identity360)
        assert "narrative" in identity360_payload
        assert identity360_payload["data"]["azurePrivileges"]["count"] >= 1
        assert "risk" in identity360_payload["data"]
        user_auth = await client.call_tool(
            "get_user_authentication_methods", {"user_identifier": "bruno.lima@contoso.com"}
        )
        user_auth_payload = _content_to_dict(user_auth)
        assert user_auth_payload["isMfaRegistered"] is False
        priv_mfa = await client.call_tool("assess_privileged_mfa", {})
        priv_mfa_payload = _content_to_dict(priv_mfa)
        assert "privileged_without_mfa" in priv_mfa_payload
        owned = await client.call_tool("get_owned_objects", {"user_identifier": "ana.silva@contoso.com", "limit": 20})
        owned_payload = _content_to_dict(owned)
        assert owned_payload["count"] >= 1
        toxic = await client.call_tool("detect_toxic_combinations", {"limit": 20})
        toxic_payload = _content_to_dict(toxic)
        assert "combinations" in toxic_payload
        blast = await client.call_tool(
            "compute_identity_blast_radius", {"identity_identifier": "ana.silva@contoso.com"}
        )
        blast_payload = _content_to_dict(blast)
        assert "blastRadiusScore" in blast_payload
        print("Smoke test OK")


if __name__ == "__main__":
    asyncio.run(main())
