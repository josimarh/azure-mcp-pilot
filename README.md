# Azure MCP Pilot

Servidor **MCP read-only** para auditoria de identidade em **Microsoft Entra ID + Azure RBAC**.

Você pergunta em linguagem natural no Copilot Chat do VS Code e recebe a resposta com dados reais do seu tenant, sem sair do editor.

> **Nunca escreve.** Toda operação de criação, alteração, remoção, concessão ou ativação de privilégio é bloqueada antes do roteamento.

## O que ele responde

Perguntas do dia a dia de quem cuida de identidade:

- Quem tem **Owner** no Azure? E quem tem **Global Administrator** no Entra?
- Quais aplicações foram **criadas no meu tenant**, e quais são nativas da Microsoft?
- Quais usuários estão **sem MFA** ou usando métodos fracos (SMS, voz, e-mail)?
- Quais **secrets de aplicação** vão expirar nos próximos 30 dias?
- Quais objetos estão **sem owner** definido?
- Quem ganhou ou perdeu privilégio nos últimos 30 dias?
- Qual o **blast radius** de uma identidade específica?

São 64 ferramentas cobrindo usuários, grupos, aplicações, service principals, managed identities, PIM, RBAC, autenticação, acesso condicional, ownership, timeline de privilégios e combinações tóxicas (SoD).

## Princípios

Estes três pontos definem o comportamento e valem mais que a lista de funcionalidades:

**Separação de fontes.** Microsoft Graph responde por identidade e diretório; as APIs do Azure respondem por RBAC e recursos. O Graph nunca é tratado como fonte de Azure RBAC.

**Sem falso zero.** Se faltar permissão, a resposta é `PERMISSION_DENIED` com cobertura `NOT_EVALUATED` — nunca `0`. "Não consegui avaliar" e "não existe" são respostas diferentes, e confundir as duas em auditoria é pior do que não responder.

**Somente leitura.** Apenas `GET`, `LIST`, `QUERY`, `ASSESS` e `CORRELATE`. Não há KQL arbitrário gerado por LLM nem endpoint livre: toda consulta passa por um registry de capacidades com allowlist e validação de filtros e escopos.

## Pré-requisitos

- **Python 3.10+**
- **[uv](https://docs.astral.sh/uv/)** (recomendado) ou `pip`
- **[Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli)** com sessão iniciada:

```bash
az login
```

A autenticação usa `DefaultAzureCredential`, que aproveita a sessão do Azure CLI. Não há chave de API para gerenciar e nenhuma credencial é armazenada pelo projeto.

## Usar no VS Code

Crie `.vscode/mcp.json` no seu projeto:

```json
{
  "servers": {
    "azure-identity-security": {
      "type": "stdio",
      "command": "uvx",
      "args": ["azure-mcp-pilot"],
      "env": {
        "MOCK_MODE": "false"
      }
    }
  }
}
```

Recarregue a janela (`Developer: Reload Window`) e pergunte no Copilot Chat. O modelo usado é o **seu próprio Copilot** — o projeto não chama nenhum LLM e não tem custo de inferência.

Para rodar a partir do código-fonte em vez do pacote publicado, troque por `"command": "python"` e `"args": ["caminho/para/mcp_server.py"]`.

## Dados reais vs mock

O modo padrão é **mock** (`MOCK_MODE=true`), para que ninguém toque no tenant sem intenção explícita. Para auditar de verdade, defina `MOCK_MODE=false` como no exemplo acima.

Opcionalmente, limite o escopo das consultas:

```env
AZURE_SUBSCRIPTIONS=00000000-0000-0000-0000-000000000000,11111111-1111-1111-1111-111111111111
```

Se ficar vazio, o projeto descobre automaticamente as subscriptions habilitadas para a identidade autenticada.

## Permissões

No Azure, `Reader` nas subscriptions que quiser auditar.

No Microsoft Graph, as permissões delegadas variam conforme a pergunta:

| Área | Permissão |
|---|---|
| Usuários, grupos, aplicações, service principals | `Directory.Read.All` |
| Directory roles e PIM de diretório | `RoleManagement.Read.All` |
| Métodos de autenticação e MFA | `UserAuthenticationMethod.Read.All` |
| Acesso condicional | `Policy.Read.All` |

Faltando alguma, apenas a área correspondente fica marcada como não avaliada. O restante continua funcionando normalmente.

## Privacidade

Os dados consultados são do **seu** tenant e trafegam entre a sua máquina, as APIs da Microsoft e o modelo do Copilot que **você** já usa. O projeto não envia nada para servidores de terceiros e não coleta telemetria.

Por padrão, `SANITIZE_FOR_LLM=true` mascara nomes de recursos, resource groups, IDs de subscription e IPs antes que o conteúdo chegue ao modelo. Desative apenas conscientemente:

```env
SANITIZE_FOR_LLM=false
```

## Desenvolvimento

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
cp .env.example .env
python test_smoke.py
```

O smoke test roda em modo mock e não toca no tenant.

### Organização

```text
mcp_server.py                       servidor MCP e registro das tools
services/azure_auth.py              credencial, tokens e cache
services/graph_capabilities.py      registry de capacidades
services/capability_router.py       linguagem natural -> capacidade
services/capability_executor.py     execução read-only validada
services/azure_role_definitions.py  resolução de nomes de role Azure
services/data/                      dados mock usados quando MOCK_MODE=true
```

O repositório também traz um portal Streamlit (`app.py` + `agent.py`) usado para
desenvolvimento e demonstração. Ele não faz parte do pacote publicado, cuja
superfície é apenas o servidor MCP. Para rodá-lo localmente:

```bash
streamlit run app.py
```

## Limitações conhecidas

- A detecção de Agent Identities é **heurística** onde o diretório não expõe um tipo próprio; o resultado é marcado como tal, não como fato.
- `Public IP` indica endereço público, o que **não prova** exposição de workload.
- Sem `RoleManagement.Read.All`, o PIM de diretório aparece como não avaliado.

## Licença

MIT. Veja [LICENSE](LICENSE).
