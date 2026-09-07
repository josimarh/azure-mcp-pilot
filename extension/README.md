# IdenGraph

**Identity & Access intelligence powered by Microsoft Graph and MCP.**

Pergunte em linguagem natural no Copilot Chat e receba respostas com dados reais do seu tenant Microsoft Entra ID e Azure RBAC — sem sair do VS Code.

> **Nunca escreve.** Toda operação de criação, alteração, remoção, concessão ou ativação de privilégio é bloqueada antes do roteamento.

## O que você pode perguntar

- Quem tem **Owner** no Azure? E quem tem **Global Administrator** no Entra?
- Quais aplicações foram **criadas no meu tenant**, e quais são nativas da Microsoft?
- Quais usuários estão **sem MFA** ou usando métodos fracos?
- Quais **secrets de aplicação** vão expirar nos próximos 30 dias?
- Quais objetos estão **sem owner** definido?
- Qual o **blast radius** de uma identidade específica?

São 64 ferramentas cobrindo usuários, grupos, aplicações, service principals, managed identities, PIM, RBAC, autenticação, acesso condicional, ownership, timeline de privilégios e combinações tóxicas (SoD).

## Pré-requisitos

- **[uv](https://docs.astral.sh/uv/getting-started/installation/)** — usado para executar o servidor MCP
- **[Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli)** com sessão iniciada:

```bash
az login
```

A extensão verifica os dois na inicialização e orienta caso algo esteja faltando.

Não há chave de API para gerenciar. A autenticação aproveita sua sessão do Azure CLI, e o modelo usado é o **seu próprio Copilot** — sem custo adicional de LLM.

## Como usar

1. Instale a extensão
2. Execute `az login` em um terminal
3. Abra o Copilot Chat em **modo agente** e pergunte

As ferramentas do IdenGraph aparecem no seletor de tools e são invocadas automaticamente conforme a pergunta.

## Configurações

| Configuração | Padrão | Descrição |
|---|---|---|
| `idengraph.useMockData` | `false` | Usa dados fictícios em vez do tenant real |
| `idengraph.sanitizeOutput` | `true` | Mascara nomes, IDs de subscription e IPs antes de chegar ao modelo |
| `idengraph.subscriptions` | `""` | Limita a consulta a subscriptions específicas |

## Princípios

**Separação de fontes.** Microsoft Graph responde por identidade e diretório; as APIs do Azure respondem por RBAC e recursos. O Graph nunca é tratado como fonte de Azure RBAC.

**Sem falso zero.** Se faltar permissão, a resposta é `PERMISSION_DENIED` com cobertura `NOT_EVALUATED` — nunca `0`. "Não consegui avaliar" e "não existe" são respostas diferentes, e confundir as duas em auditoria é pior do que não responder.

**Somente leitura.** Apenas `GET`, `LIST`, `QUERY`, `ASSESS` e `CORRELATE`. Não há KQL arbitrário gerado por LLM nem endpoint livre: toda consulta passa por um registry de capacidades com allowlist e validação.

## Permissões

No Azure, `Reader` nas subscriptions que quiser auditar.

No Microsoft Graph, as permissões delegadas variam conforme a pergunta:

| Área | Permissão |
|---|---|
| Usuários, grupos, aplicações, service principals | `Directory.Read.All` |
| Directory roles e PIM de diretório | `RoleManagement.Read.All` |
| Métodos de autenticação e MFA | `UserAuthenticationMethod.Read.All` |
| Acesso condicional | `Policy.Read.All` |

Faltando alguma, apenas a área correspondente fica marcada como não avaliada. O restante continua funcionando.

## Privacidade

Os dados consultados são do **seu** tenant e trafegam entre a sua máquina, as APIs da Microsoft e o modelo do Copilot que você já usa. A extensão não envia nada para servidores de terceiros e não coleta telemetria.

## Licença

MIT. Código-fonte em [github.com/josimarh/azure-mcp-pilot](https://github.com/josimarh/azure-mcp-pilot).
