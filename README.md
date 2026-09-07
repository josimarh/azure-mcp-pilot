# Azure Environment Copilot — piloto MCP

Piloto mínimo para validar o fluxo:

`Usuário -> Streamlit -> OpenRouter -> MCP -> Azure Resource Graph / Docs Microsoft -> resposta`

## O que já faz

- Chat em linguagem natural.
- Usa `liquid/lfm-2.5-2.6b:free` como modelo primário.
- Usa `openrouter/free` como fallback gratuito.
- Converte automaticamente tools MCP para tool calling do OpenRouter.
- MCP real usando o SDK Python v2 (`MCPServer` + `Client`).
- Snapshot lógico do ambiente via Azure Resource Graph.
- Ferramentas read-only e controladas, sem KQL arbitrário gerado pelo LLM.
- Catálogo inicial de referências oficiais Microsoft Learn.
- Modo mock para demonstrar sem acesso ao Azure.
- Sanitização opcional de nomes, IDs, resource groups e IPs antes de chegar ao LLM.

## Estrutura

```text
app.py                 UI Streamlit
agent.py               loop LLM + tool calling
mcp_server.py          servidor MCP
services/azure_graph.py             Azure Resource Graph + mock + sanitização
services/entra_users.py             usuários Entra ID
services/entra_groups.py            grupos Entra ID
services/entra_roles.py             roles Entra ID
services/entra_pim.py               PIM Entra ID
services/entra_apps.py              aplicações, owners e secrets
services/entra_workload_identities.py service principals e managed identities
services/entra_authentication.py    métodos de autenticação
services/entra_conditional_access.py políticas de acesso condicional
services/azure_rbac.py              role assignments e deny assignments
services/azure_roles.py             role definitions e custom roles perigosas
services/azure_management_groups.py management groups
services/identity_risk.py           correlação de privilégios Entra + Azure
services/iam_assessment.py          motor de consulta IAM e assessment
services/docs.py                    referências oficiais Microsoft
```

## Rodar em 5 minutos

Requer Python 3.10+.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env       # Windows
# cp .env.example .env       # Linux/macOS
```

Edite `.env` e preencha:

```env
OPENROUTER_API_KEY=sk-or-v1-...
MOCK_MODE=true
SANITIZE_FOR_LLM=true
```

Teste o MCP sem chamar IA:

```bash
python test_smoke.py
```

Suba a interface:

```bash
streamlit run app.py
```

## Usar Azure real

Primeiro use um tenant/subscription de laboratório ou desenvolvimento aprovado.

```bash
az login
```

Depois no `.env`:

```env
MOCK_MODE=false
SANITIZE_FOR_LLM=true

# Opcional: limite o escopo. Separar múltiplas subscriptions por vírgula.
AZURE_SUBSCRIPTIONS=00000000-0000-0000-0000-000000000000
```

A identidade usada precisa ter leitura nos recursos Azure e permissão para leitura de diretório (Microsoft Graph) quando usar ferramentas de usuários/RBAC. O código usa `DefaultAzureCredential` e solicita token para `management.azure.com` e `graph.microsoft.com`.

Se `AZURE_SUBSCRIPTIONS` ficar vazio, o código tenta descobrir automaticamente as subscriptions habilitadas da identidade autenticada e usa essa lista nas consultas do Resource Graph.

## Ferramentas MCP do piloto

### `get_environment_summary`
Retorna contagem de recursos, subscriptions, resource groups, regiões e principais tipos.

### `get_resource_groups_count`
Retorna exclusivamente a quantidade de Resource Groups.

### `list_resource_groups`
Lista Resource Groups com filtro read-only por nome.

### `list_resources`
Lista recursos com filtros read-only controlados por tipo e nome.

### `list_public_ip_resources`
Lista recursos do tipo Public IP. O próprio tool avisa que Public IP não é prova suficiente de exposição de workload.

### `get_identity_access_summary`
Retorna resumo de identidade e RBAC com:
- total de usuários
- usuários habilitados/desabilitados
- usuários com permissões diretas
- usuários desabilitados com roles ativas

### `list_users`
Lista usuários do Entra ID, com filtros por nome e opção de trazer apenas desabilitados.

### `list_users_with_direct_permissions`
Lista usuários com role assignments diretos no RBAC (nome, UPN, e-mail, contagem de assignments, roles e escopos de exemplo).

### `list_disabled_users_with_active_roles`
Lista usuários desabilitados no Entra ID que ainda possuem role assignments diretos.

### `iam_natural_language_query`
Interpreta perguntas IAM em linguagem natural e escolhe a correlação adequada entre Entra ID e Azure. Também roteia para Identity 360, MFA, ownership, toxic combinations, blast radius e timeline.

### `identity_360`
Visão completa de uma identidade respondendo às 5 perguntas fundamentais: quem é, a que possui acesso (Entra + Azure, direto/grupo/PIM), como recebeu, quem é responsável (ownership) e qual o risco (blast radius + findings).

### `get_user_authentication_methods` / `get_authentication_methods_summary` / `list_users_without_mfa` / `assess_privileged_mfa`
Consultam métodos de autenticação, status de MFA/passwordless e fazem assessment de MFA focado em usuários privilegiados.

### `get_owned_objects` / `list_objects_without_owner`
Ownership 360 transversal: objetos (Groups, Applications, Service Principals, Agents, Blueprints) sob responsabilidade de um usuário, e objetos sem owner.

### `detect_toxic_combinations`
Detecta toxic combinations / violações potenciais de Separation of Duties com evidência e contexto.

### `compute_identity_blast_radius` / `list_top_blast_radius`
Estima o alcance (blast radius) de uma identidade — subscriptions/management groups afetados e capacidade de conceder acesso — e ranqueia as identidades de maior alcance.

### `pim_natural_language_query`
Interpreta perguntas de PIM em linguagem natural e classifica privilégios como Active, Eligible e Permanent.

### `get_pim_state_summary`
Compara Active vs Eligible vs Permanent com totais de atribuições, usuários e roles.

### `list_pim_role_states`
Lista atribuições privilegiadas com estado (Active/Eligible/Permanent), role e escopo.

### `get_role_risk_score`
Calcula score de risco (0-100) para roles de Entra ID e Azure RBAC, usando modelo baseado no IAM Scope (Tier/Risk Tier) com calibração por escopo e estado (Active/Permanent).

### `list_agent_identities`
Lista inventário de Agent Identities com owners, blueprint, permissões Graph, Azure RBAC e score de risco.
Em `LIVE`, quando a API específica de Agents não estiver integrada, usa fallback heurístico com Service Principals/Managed Identities + Graph/Azure RBAC (com indicação de fonte).
Inclui status de ownership (`OWNER_CONFIGURED`, `NO_OWNER_CONFIGURED`, `OWNER_NOT_RESOLVED`, `OWNER_NOT_EVALUATED`, `INSUFFICIENT_PERMISSIONS`) e detalhamento técnico de RBAC (role, roleDefinitionId, role type, scope e access path).
Inclui classificação do objeto (`Agent Identity`, `Agent Identity Blueprint`, `Microsoft-managed Agent`, `Heuristic Agent Candidate`, `Service Principal`, `Managed Identity`, `Unknown`) com confiança e identificação heurística.

### `get_agent_relationships`
Resolve a cadeia Agent → Owner → Identity → Blueprint → Permissions (Graph + Azure).

### `get_agents_by_owner`
Lista todos os Agents sob responsabilidade de um usuário (UPN, nome ou objectId).

### `agent_natural_language_query`
Interpreta perguntas em linguagem natural sobre Agent Identities e ownership.
Para perguntas de contagem de acesso, separa explicitamente Azure RBAC vs Graph/API e evita conclusão total quando um domínio estiver `NOT_EVALUATED`.
Não converte `NOT_EVALUATED` em “none”; apresenta `Evaluation Completeness` (`COMPLETE`, `PARTIAL`, `NOT_EVALUATED`) e riscos por domínio (Azure RBAC, Graph/API e Ownership).

### `run_agent_assessment`
Executa assessment de Agent Identities com top riscos, findings e ranking.
Se nem o fallback heurístico puder ser avaliado por falta de permissão/fonte, retorna `status: NOT_EVALUATED` com mensagem explícita.

### `get_user_effective_azure_access`
Calcula acesso efetivo de um usuário no Azure RBAC separando atribuições diretas e herdadas via grupos.

### `list_orphan_azure_role_assignments`
Lista role assignments órfãos (principal não resolvido no tenant visível).

### `list_privilege_timeline_events`
Lista eventos de mudanças de privilégio (grant/revoke/activate) com data, identidade, role e escopo.

### `get_identity_privilege_timeline`
Mostra histórico de mudanças de privilégio para uma identidade específica.

### `summarize_privilege_timeline`
Resumo da timeline recente com volume de eventos, criticidade e identidades não resolvidas.

### `timeline_natural_language_query`
Interpreta perguntas em linguagem natural sobre auditoria temporal de privilégios.

### `export_privilege_timeline_report`
Gera relatório consolidado da timeline com top grants/revokes/activations por identidade, role e escopo.

### `run_iam_assessment`
Executa avaliação IAM com riscos priorizados, controles não avaliados (quando faltar permissão/API) e plano de remediação.

### `search_official_guidance`
Retorna fontes oficiais Microsoft Learn relacionadas ao assunto.

## Segurança / dados

**Não use este piloto com dados sensíveis de produção sem aprovação da empresa.**

O modelo gratuito LFM2.5-2.6B informa no OpenRouter que prompts e outputs podem ser retidos e usados para treinamento pelo provedor. Por isso:

1. o projeto inicia em `MOCK_MODE=true`;
2. `SANITIZE_FOR_LLM=true` vem habilitado;
3. o MCP não expõe execução arbitrária de KQL;
4. segredos e valores de propriedades não são retornados;
5. recomenda-se validar DLP, classificação de dados, contratos e requisitos de residência antes de um uso real.

Para um piloto corporativo sério, a evolução natural é manter o MCP e trocar apenas o endpoint/modelo por um provedor aprovado internamente.

## Próximos incrementos

1. Autenticação do usuário via Entra ID no front-end.
2. Azure Policy compliance.
3. Correlação de permissões herdadas por grupo com transitive membership.
4. Defender for Cloud recommendations.
5. Azure Monitor / Log Analytics.
6. RAG real da documentação oficial Microsoft com atualização e versionamento.
7. Snapshot persistente + comparação temporal.
8. Grafo de relacionamentos entre recursos.

## Referências técnicas

- OpenRouter chat completions: https://openrouter.ai/docs/quickstart
- OpenRouter tool calling: https://openrouter.ai/docs/guides/features/tool-calling
- Free router: https://openrouter.ai/docs/guides/routing/routers/free-router
- LFM2.5-2.6B free: https://openrouter.ai/liquid/lfm-2.5-2.6b:free
- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
- Azure Resource Graph REST query: https://learn.microsoft.com/azure/governance/resource-graph/first-query-rest-api
- Azure MCP Server: https://learn.microsoft.com/azure/developer/azure-mcp-server/
