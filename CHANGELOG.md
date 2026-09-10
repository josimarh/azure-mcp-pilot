# Changelog

## 0.1.5

Hardening da capability layer (`graph_get`/`graph_list`/`graph_query`) após revisão completa de arquitetura.

### Corrigido

- **MOCK_MODE ignorado pela capability layer**: `graph_get`/`graph_list` chamavam o Graph real mesmo com
  `MOCK_MODE=true`. Agora respeitam o modo mock via fixtures dedicadas, com erro explícito quando não há
  fixture para a capability.
- **Sanitização incompleta**: `list_entra_users`, `list_azure_role_assignments` e
  `list_privileged_azure_role_assignments` retornavam UPN/objectId/scope sem máscara. A capability layer
  nova (`graph_list`/`graph_get`/`graph_query`) também nunca sanitizava `raw` nem os campos de topo do
  objeto normalizado. Ambos os caminhos agora aplicam `sanitize_identity`/`sanitize_assignment` de forma
  consistente quando `SANITIZE_FOR_LLM=true`.
- **`reset_credential()` não limpava o cache de consultas**: como a chave do cache não inclui
  tenant/conta, uma troca de tenant podia reaproveitar resultados do tenant anterior durante o TTL. Agora
  `reset_credential()` também limpa o cache de consultas.
- **`subscriptions` declarado mas ignorado no Resource Graph**: `azure.rbac.role_assignments` e
  `azure.resources.inventory` aceitavam o parâmetro no registry, mas a execução real dependia apenas de
  `AZURE_SUBSCRIPTIONS`. A execução (mock e real) agora respeita `subscriptions` quando informado.
- **Falso roteamento no capability router**: o termo isolado "owner" não força mais Azure RBAC sem
  contexto Azure explícito; adicionados aliases para variações de "aplicações criadas no meu tenant".
- **Parâmetros Graph não implementados**: `$search`, `$count` e `$orderby` foram removidos do registry de
  `graph.users.list`, `graph.groups.list`, `graph.applications.list` e `graph.service_principals.list`
  (não eram usados por `_build_graph_url()` e eram silenciosamente ignorados).
- **`$select` sem URL-encoding**: agora é codificado da mesma forma que `$filter`.
- **`capability_assessment()` escolhia a primeira capability do domínio arbitrariamente**: novo campo
  `is_primary_for_assessment` no registry permite marcar explicitamente a fonte preferida quando um
  domínio tem múltiplas capabilities (PIM, Azure RBAC).
- **Permission footprint excessivo**: `graph.authentication.registration_details` não precisa de
  `Reports.Read.All`; `graph.app_role_assignments.assigned_to` não precisa de `Directory.Read.All`. Ambos
  reduzidos ao mínimo necessário (least privilege).
- **`graph_get` aceitava `operation=get` em endpoints de coleção sem `{id}`**: agora exige `{id}` no
  endpoint, salvo whitelist explícita de singletons (`graph.organization.get`).
- **Documentação sobre KQL**: README esclarece que `graph_query` pode receber KQL read-only derivado da
  pergunta do usuário, mas não aceita endpoints arbitrários e bloqueia operadores de mutação/acesso
  externo.

### Adicionado

- Suíte de testes dedicada à capability layer (`test_capability_layer.py`, 19 testes): mock execution,
  expectativas de roteamento, validação de parâmetros, comportamento GET/POST, metadados de permissão,
  sanitização e escopo de subscriptions.
