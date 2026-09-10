# IdenGraph

**Identity & Access intelligence powered by Microsoft Graph and MCP.**

Ask in natural language inside Copilot Chat and get answers backed by real data from your **Microsoft Entra ID** and **Azure RBAC** — without leaving VS Code.

> **It never writes.** Every create, update, delete, grant, or privilege-activation operation is blocked before routing.

## What you can ask

- Who has **Owner** on Azure? And who holds **Global Administrator** in Entra?
- Which applications were **created in my tenant**, and which are Microsoft first-party?
- Which users have **no MFA**, or rely on weak methods?
- Which **application secrets** expire in the next 30 days?
- Which objects have **no owner** assigned?
- What is the **blast radius** of a given identity?
- Are we **paying for security features we don't use**?

**66 tools** across users, groups, applications, service principals, managed identities, PIM, RBAC, authentication, conditional access, ownership, privilege timeline, licensing posture, and toxic combinations (SoD).

## Prerequisites

- **[uv](https://docs.astral.sh/uv/getting-started/installation/)** — runs the MCP server
- **[Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli)** with an active session:

```bash
az login
```

The extension checks both on startup and guides you if anything is missing.

There is no API key to manage. Authentication reuses your Azure CLI session, and the model is **your own Copilot** — no additional LLM cost.

## Getting started

1. Install the extension.
2. Run `az login` in a terminal.
3. If VS Code was already open when you installed IdenGraph, run **Developer: Reload Window** from the Command Palette (`Ctrl+Shift+P`).
4. Open a **new** GitHub Copilot Chat in **Agent** mode.
5. Type `/mcp` and confirm that **IdenGraph** appears in the server list.
6. Ask your question in natural language.

IdenGraph tools are invoked automatically based on your question. You do not need to create an `mcp.json` file or run `uvx idengraph` yourself.

### Check readiness

Run **IdenGraph: Show readiness status** from the Command Palette (`Ctrl+Shift+P`) at any time. It shows whether the extension is active, the MCP definition is registered, `uvx` is available, and Azure CLI is authenticated. VS Code starts the MCP process only when Copilot needs a tool, so `/mcp` in a new Agent chat is the authoritative connection check.

## Settings

| Setting | Default | Description |
|---|---|---|
| `idengraph.useMockData` | `false` | Query fictional data instead of your real tenant |
| `idengraph.sanitizeOutput` | `true` | Mask names, subscription IDs and IPs before they reach the model |
| `idengraph.subscriptions` | `""` | Restrict queries to specific subscriptions |

## Design principles

**Source separation.** Microsoft Graph answers for identity and directory. Azure APIs answer for RBAC and resources. Graph is never treated as a source of truth for Azure RBAC.

**No false zero.** If a permission is missing, the answer is `PERMISSION_DENIED` with `NOT_EVALUATED` coverage — never `0`. "I could not evaluate this" and "this does not exist" are different answers, and conflating them in an audit is worse than not answering, because a false zero looks like a clean result.

**Read-only by construction.** Only `GET`, `LIST`, `QUERY`, `ASSESS`, and `CORRELATE`. The `graph_query` tool can receive read-only KQL generated from a user request, but it does not accept arbitrary endpoints: the capability registry selects the data source, and the executor blocks mutation operators and external-access constructs before sending the query.

## Permissions

On Azure: `Reader` on the subscriptions you want to audit.

On Microsoft Graph, delegated permissions vary by question:

| Area | Permission |
|---|---|
| Users, groups, applications, service principals | `Directory.Read.All` |
| Directory roles and directory PIM | `RoleManagement.Read.All` |
| Authentication methods and MFA | `UserAuthenticationMethod.Read.All` |
| Conditional access | `Policy.Read.All` |
| License posture | `Organization.Read.All` |

Missing a permission only marks the matching area as not evaluated — and that area reports *why*. Everything else keeps working.

## Privacy

Queried data belongs to **your** tenant and travels between your machine, Microsoft APIs, and the Copilot model you already use. The extension sends nothing to third-party servers and collects no telemetry.

## License

MIT. Source code at [github.com/josimarh/idengraph](https://github.com/josimarh/idengraph).
