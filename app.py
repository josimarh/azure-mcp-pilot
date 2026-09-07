from __future__ import annotations

import asyncio
import base64
import mimetypes
import os
from pathlib import Path
import re

import streamlit as st
from dotenv import load_dotenv

from agent import ask
from services.azure_graph import is_mock_mode, sanitize_enabled

load_dotenv()


def _is_openrouter_rate_limited(message: str) -> bool:
    text = message.lower()
    return (
        "429 too many requests" in text
        or "too many requests" in text
        or "rate limit" in text
    )


def _is_section_title(line: str) -> bool:
    text = line.strip()
    if not text or text.startswith("- "):
        return False
    if text.endswith(":"):
        return False
    alpha = [ch for ch in text if ch.isalpha()]
    if not alpha:
        return False
    upper_ratio = sum(1 for ch in alpha if ch.isupper()) / len(alpha)
    return upper_ratio >= 0.7 and len(text) <= 80


def _split_sections(answer: str) -> list[tuple[str | None, list[str]]]:
    sections: list[tuple[str | None, list[str]]] = []
    current_title: str | None = None
    current_lines: list[str] = []
    for raw in answer.splitlines():
        line = raw.strip()
        if not line:
            current_lines.append("")
            continue
        if _is_section_title(line):
            if current_title is not None or current_lines:
                sections.append((current_title, current_lines))
            current_title = line
            current_lines = []
            continue
        current_lines.append(line)
    if current_title is not None or current_lines:
        sections.append((current_title, current_lines))
    return sections


def _render_section_lines(lines: list[str]) -> None:
    for line in lines:
        if not line:
            st.write("")
            continue
        if line.startswith("- "):
            st.markdown(line)
            continue
        if " | " in line and not line.lower().startswith("http"):
            st.markdown("- " + line.replace(" | ", " • "))
            continue
        st.markdown(line)


def _render_assistant_answer(answer: str) -> None:
    sections = _split_sections(answer)
    if len(sections) <= 1:
        _render_section_lines([ln.strip() for ln in answer.splitlines()])
        return
    for title, lines in sections:
        if title:
            with st.container(border=True):
                st.subheader(title)
                _render_section_lines(lines)
        else:
            _render_section_lines(lines)


def _find_mvp_logo_path() -> Path | None:
    env_path = os.getenv("MVP_LOGO_PATH", "").strip()
    if env_path:
        logo_path = Path(env_path)
    else:
        candidates = [
            Path("assets/microsoft-mvp-logo.png"),
            Path("assets/microsoft-mvp-logo.jpg"),
            Path("assets/microsoft-mvp-logo.jpeg"),
            Path("assets/microsoft-mvp-logo.jpe"),
            Path("assets/microsoft-mvp-logo.webp"),
        ]
        logo_path = next((p for p in candidates if p.exists()), None)
    if logo_path is None or not logo_path.exists():
        return None
    return logo_path


def _render_mvp_logo_discreet() -> None:
    logo_path = _find_mvp_logo_path()
    if logo_path is None:
        return
    raw = logo_path.read_bytes()
    mime, _ = mimetypes.guess_type(str(logo_path))
    data_uri = f"data:{mime or 'image/png'};base64,{base64.b64encode(raw).decode('ascii')}"
    max_width = os.getenv("MVP_LOGO_MAX_WIDTH", "120px").strip() or "120px"
    st.markdown(
        f'<img src="{data_uri}" alt="Microsoft MVP" style="width:{max_width};height:auto;opacity:0.85;" />',
        unsafe_allow_html=True,
    )


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _is_assessment_text(text: str) -> bool:
    up = text.upper()
    return "ASSESSMENT" in up or "AUDIT MODE" in up


def _extract_severity_counts(text: str) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for hit in re.findall(r"Severidade:\s*([A-Za-z]+)", text, flags=re.IGNORECASE):
        key = hit.strip().capitalize()
        if key in counts:
            counts[key] += 1
    return counts


@st.cache_data(ttl=180, show_spinner=False)
def _portal_snapshot_cached(_refresh_nonce: int) -> dict[str, object]:
    from services.agent_identities import list_agents
    from services.azure_graph import get_environment_summary
    from services.azure_rbac import list_role_assignments
    from services.entra_apps import list_applications
    from services.entra_users import list_guest_users, list_users
    from services.entra_workload_identities import list_managed_identities, list_service_principals
    from services.identity_risk import correlate_privileged_identities

    snapshot: dict[str, object] = {
        "tenant": os.getenv("AZURE_TENANT_ID", "Tenant visível"),
        "subscriptions": "NOT_EVALUATED",
        "identity_objects": "NOT_EVALUATED",
        "connection_status": "Disconnected",
        "data_mode": "LIVE" if not is_mock_mode() else "MOCK",
        "assessment_status": "Not Started",
        "total_identities": "NOT_EVALUATED",
        "privileged_identities": "NOT_EVALUATED",
        "azure_rbac_assignments": "NOT_EVALUATED",
        "applications": "NOT_EVALUATED",
        "workload_identities": "NOT_EVALUATED",
        "agent_identities": "NOT_EVALUATED",
        "guests": "NOT_EVALUATED",
        "critical_findings": "NOT_EVALUATED",
    }
    try:
        env = get_environment_summary()
        snapshot["subscriptions"] = env.get("subscriptions", "NOT_EVALUATED")
        snapshot["connection_status"] = "Connected"
    except Exception:
        pass

    try:
        users = list_users()
        guests = list_guest_users()
        sps = list_service_principals()
        mis = list_managed_identities()
        apps = list_applications()
        agents = list_agents(limit=500)
        privileged = correlate_privileged_identities()
        rbac = list_role_assignments()

        total_identities = len(users) + len(sps) + len(mis)
        snapshot["identity_objects"] = total_identities
        snapshot["total_identities"] = total_identities
        snapshot["privileged_identities"] = len(privileged)
        snapshot["azure_rbac_assignments"] = len(rbac)
        snapshot["applications"] = len(apps)
        snapshot["workload_identities"] = len(sps) + len(mis)
        snapshot["agent_identities"] = len(agents)
        snapshot["guests"] = len(guests)
        snapshot["critical_findings"] = sum(1 for row in privileged if str(row.get("risk")) == "Critical")
    except Exception:
        pass

    return snapshot


def _portal_snapshot() -> dict[str, object]:
    refresh_nonce = int(st.session_state.get("snapshot_refresh_nonce", 0))
    return _portal_snapshot_cached(refresh_nonce)


def _empty_snapshot() -> dict[str, object]:
    return {
        "tenant": os.getenv("AZURE_TENANT_ID", "Tenant visível"),
        "subscriptions": "NOT_EVALUATED",
        "identity_objects": "NOT_EVALUATED",
        "connection_status": "Disconnected",
        "data_mode": "LIVE" if not is_mock_mode() else "MOCK",
        "total_identities": "NOT_EVALUATED",
        "privileged_identities": "NOT_EVALUATED",
        "azure_rbac_assignments": "NOT_EVALUATED",
        "applications": "NOT_EVALUATED",
        "workload_identities": "NOT_EVALUATED",
        "agent_identities": "NOT_EVALUATED",
        "guests": "NOT_EVALUATED",
        "critical_findings": "NOT_EVALUATED",
    }


def _render_coverage_summary(answer: str) -> None:
    expected = [
        "Entra ID",
        "Azure RBAC",
        "Graph",
        "PIM",
        "Applications",
        "Managed Identities",
        "Agent Identities",
        "Conditional Access",
        "Governance",
    ]
    upper = answer.upper()
    status_map: dict[str, str] = {}
    for domain in expected:
        d = domain.upper()
        if d in upper and "NOT_EVALUATED" in upper:
            status = "Not Evaluated"
        else:
            status = "Evaluated"
        if d in upper and "PARTIAL" in upper:
            status = "Partial"
        status_map[domain] = status
    st.caption("Assessment coverage")
    for domain, status in status_map.items():
        st.markdown(f"- **{domain}**: {status}")


def _render_assessment_tabs() -> None:
    text = str(st.session_state.get("latest_assessment_text") or "").strip()
    if not text:
        return
    severity = _extract_severity_counts(text)
    cols = st.columns(5)
    cols[0].metric("Critical", severity["Critical"])
    cols[1].metric("High", severity["High"])
    cols[2].metric("Medium", severity["Medium"])
    cols[3].metric("Low", severity["Low"])
    cols[4].metric("Informational", severity["Informational"])

    sections = _split_sections(text)
    by_title = {str(title or "").strip().upper(): lines for title, lines in sections if title}
    executive = by_title.get("EXECUTIVE SUMMARY") or by_title.get("AUDIT MODE: ENTERPRISE") or [text]
    findings = by_title.get("TOP RISKS") or [line for line in text.splitlines() if "Severidade:" in line or "RISK" in line.upper()]
    evidence = (
        by_title.get("ASSESSMENT COVERAGE")
        or by_title.get("SUBSCRIPTION HIGHLIGHTS")
        or by_title.get("COVERAGE GAPS")
        or ["Sem evidências adicionais neste retorno."]
    )

    tabs = st.tabs(["Executive Summary", "Findings", "Evidence", "Technical Details"])
    with tabs[0]:
        _render_section_lines(executive)
    with tabs[1]:
        _render_section_lines(findings)
    with tabs[2]:
        _render_section_lines(evidence)
        _render_coverage_summary(text)
    with tabs[3]:
        st.text(text)
        trace = st.session_state.get("latest_assessment_trace", [])
        if trace:
            st.json(trace)


st.set_page_config(page_title="IdenGraph", page_icon=":material/security:", layout="wide")

st.title("IdenGraph", anchor=False)
st.caption("Microsoft Entra ID + Azure RBAC + Workload & Agent Identity")
st.caption(":material/shield_lock: Security/Data Privacy: revise a política de dados antes de enviar contexto para modelos externos.")
if is_mock_mode():
    st.warning("Modo de dados atual: MOCK. Para dados reais do tenant, defina MOCK_MODE=false no ambiente do app.")

if "messages" not in st.session_state:
    st.session_state.messages = []
if "chat_processing" not in st.session_state:
    st.session_state.chat_processing = False
if "last_question_hash" not in st.session_state:
    st.session_state.last_question_hash = ""
if "processed_hashes" not in st.session_state:
    st.session_state.processed_hashes = set()
if "snapshot_refresh_nonce" not in st.session_state:
    st.session_state.snapshot_refresh_nonce = 0
if "portal_snapshot" not in st.session_state:
    st.session_state.portal_snapshot = _empty_snapshot()

snapshot = st.session_state.portal_snapshot

with st.sidebar:
    st.subheader("Navegação")
    portal_sections = [
        "Overview",
        "Identity 360",
        "Privileged Access",
        "Azure RBAC",
        "Applications",
        "Workload Identities",
        "Agent Identities",
        "External Identities",
        "Authentication",
        "Conditional Access",
        "Governance",
        "Assessments",
        "Reports",
    ]
    st.radio("Seções do portal", portal_sections, label_visibility="collapsed")
    action_cols = st.columns(2)
    with action_cols[0]:
        if st.button("Atualizar página", icon=":material/refresh:"):
            from services.azure_auth import clear_query_cache

            clear_query_cache()
            st.session_state.snapshot_refresh_nonce = int(st.session_state.snapshot_refresh_nonce) + 1
            st.session_state.portal_snapshot = _portal_snapshot()
            snapshot = st.session_state.portal_snapshot
    with action_cols[1]:
        if st.button("Limpar chat", icon=":material/delete:"):
            st.session_state.messages = []
            st.session_state.processed_hashes = set()
            st.session_state.last_question_hash = ""
            st.rerun()

    with st.expander("Settings"):
        st.write(f"Modo Azure: **{'MOCK' if is_mock_mode() else 'LIVE'}**")
        st.write(f"Sanitização para LLM: **{'ON' if sanitize_enabled() else 'OFF'}**")
    with st.expander("Debug"):
        st.write("Use esta seção apenas para troubleshooting.")
        st.write("Último status de assessment:", st.session_state.get("assessment_status", "Not Started"))
    with st.expander("About"):
        st.caption("Microsoft MVP")
        _render_mvp_logo_discreet()
    st.caption("Microsoft MVP")
    _render_mvp_logo_discreet()

header_cols = st.columns(5)
header_cols[0].metric("Tenant", str(snapshot.get("tenant")))
header_cols[1].metric("Subscriptions", str(snapshot.get("subscriptions")))
header_cols[2].metric("Identity Objects", str(snapshot.get("identity_objects")))
header_cols[3].metric("Assessment Status", str(st.session_state.get("assessment_status", "Not Started")))
header_cols[4].metric("Connection Status", f"{snapshot.get('connection_status')} ({snapshot.get('data_mode')})")

st.write("")
dashboard_cols = st.columns(4)
dashboard_cols[0].metric("Total Identities", str(snapshot.get("total_identities")))
dashboard_cols[1].metric("Privileged Identities", str(snapshot.get("privileged_identities")))
dashboard_cols[2].metric("Azure RBAC Assignments", str(snapshot.get("azure_rbac_assignments")))
dashboard_cols[3].metric("Applications", str(snapshot.get("applications")))
dashboard_cols2 = st.columns(4)
dashboard_cols2[0].metric("Workload Identities", str(snapshot.get("workload_identities")))
dashboard_cols2[1].metric("Agent Identities", str(snapshot.get("agent_identities")))
dashboard_cols2[2].metric("Guests", str(snapshot.get("guests")))
dashboard_cols2[3].metric("Critical Findings", str(snapshot.get("critical_findings")))

if hasattr(st, "segmented_control"):
    mode = st.segmented_control("Portal mode", ["CHAT MODE", "ASSESSMENT MODE", "REPORT MODE"]) or "CHAT MODE"
else:
    mode = st.radio("Portal mode", ["CHAT MODE", "ASSESSMENT MODE", "REPORT MODE"], horizontal=True)

suggested_queries = [
    "Quem possui Owner no Azure?",
    "Quais usuários possuem privilégio permanente?",
    "Quais aplicações possuem Graph permissions críticas?",
    "Analise as Managed Identities",
    "Faça um assessment de Agent Identities",
]
with st.container(border=True):
    st.subheader("Suggested Queries")
    query_cols = st.columns(2)
    for idx, query_text in enumerate(suggested_queries):
        with query_cols[idx % 2]:
            if st.button(query_text, key=f"suggested-query-{idx}"):
                st.session_state.pending_question = query_text

if mode == "ASSESSMENT MODE":
    with st.container(border=True):
        st.subheader("Assessment actions")
        assessment_cols = st.columns(2)
        with assessment_cols[0]:
            if st.button("Run enterprise identity audit", icon=":material/analytics:"):
                st.session_state.pending_question = "Execute auditoria enterprise completa de identidade"
        with assessment_cols[1]:
            if st.button("Run agent assessment", icon=":material/smart_toy:"):
                st.session_state.pending_question = "Faça um assessment de Agent Identities"

if mode == "REPORT MODE":
    _render_assessment_tabs()

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        if message["role"] == "assistant":
            _render_assistant_answer(message["content"])
        else:
            st.markdown(message["content"])

question = st.chat_input("Pergunte sobre o ambiente Azure...")
if not question and st.session_state.get("pending_question"):
    question = str(st.session_state.pop("pending_question"))
if question:
    q_hash = question.strip().lower()
    if st.session_state.chat_processing:
        st.warning("Já existe uma consulta em execução. Aguarde finalizar.")
        question = ""
    elif q_hash in st.session_state.processed_hashes:
        question = ""

if question:
    st.session_state.chat_processing = True
    st.session_state.last_question_hash = q_hash
    st.session_state.processed_hashes.add(q_hash)
    if len(st.session_state.processed_hashes) > 500:
        st.session_state.processed_hashes = set()
    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        with st.spinner("Consultando MCP e modelo..."):
            try:
                result = asyncio.run(asyncio.wait_for(ask(question, st.session_state.messages[:-1]), timeout=90))
                answer = result["answer"]
                _render_assistant_answer(answer)
                if _is_assessment_text(answer):
                    st.session_state.latest_assessment_text = answer
                    st.session_state.latest_assessment_trace = result.get("tool_trace", [])
                    st.session_state.assessment_status = "Completed"
                else:
                    st.session_state.assessment_status = st.session_state.get("assessment_status", "Not Started")
                if _is_openrouter_rate_limited(answer):
                    st.warning(
                        "OpenRouter está com limite de requisições no momento (HTTP 429). "
                        "Aguarde alguns segundos e tente novamente."
                    )
                with st.expander("Debug"):
                    st.write("Modelo usado:", result.get("model"))
                    st.json(result.get("tool_trace", []))
            except TimeoutError:
                answer = (
                    "A consulta excedeu o tempo limite (90s). "
                    "Isso pode ocorrer quando o tenant tem muitas identidades/permissões. "
                    "Tente uma pergunta mais específica."
                )
                st.session_state.assessment_status = "Timeout"
                st.warning(answer)
            except Exception as exc:
                answer = f"Erro: `{exc}`"
                st.session_state.assessment_status = "Error"
                st.error(answer)
            finally:
                st.session_state.chat_processing = False

    st.session_state.messages.append({"role": "assistant", "content": answer})
