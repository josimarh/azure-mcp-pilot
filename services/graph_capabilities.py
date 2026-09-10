"""Capability registry normalizado para consultas de identidade.

Este módulo descreve *o que* o MCP sabe consultar, separando explicitamente
Microsoft Graph (identidade/diretório) de APIs Azure (recursos e Azure RBAC).

Princípios:
- Nada é executado a partir daqui; este módulo é apenas o catálogo.
- Capacidades ausentes são declaradas com ``support_status='not_integrated'``
  para que o MCP possa responder honestamente em vez de inventar uma chamada.
- Somente operações de leitura são catalogadas nesta fase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


# --------------------------------------------------------------------------
# Fontes de dados
# --------------------------------------------------------------------------

SOURCE_GRAPH = "microsoft_graph"
SOURCE_RESOURCE_GRAPH = "azure_resource_graph"
SOURCE_AZURE_MANAGEMENT = "azure_management"
SOURCE_AZURE_AUTHORIZATION = "azure_authorization"

IDENTITY_SOURCES = {SOURCE_GRAPH}
AZURE_SOURCES = {SOURCE_RESOURCE_GRAPH, SOURCE_AZURE_MANAGEMENT, SOURCE_AZURE_AUTHORIZATION}

# --------------------------------------------------------------------------
# Operações (READ ONLY nesta fase)
# --------------------------------------------------------------------------

OP_LIST = "list"
OP_GET = "get"
OP_FILTER = "filter"
OP_QUERY = "query"
OP_CORRELATE = "correlate"
OP_ASSESS = "assess"

READ_OPERATIONS = frozenset({OP_LIST, OP_GET, OP_FILTER, OP_QUERY, OP_CORRELATE, OP_ASSESS})

WRITE_OPERATIONS = frozenset(
    {
        "create",
        "update",
        "patch",
        "delete",
        "assign",
        "remove",
        "grant",
        "consent",
        "activate",
        "revoke",
        "add",
        "set",
    }
)

# --------------------------------------------------------------------------
# Status de suporte
# --------------------------------------------------------------------------

STATUS_SUPPORTED = "supported"
STATUS_PARTIAL = "partial"
STATUS_NOT_INTEGRATED = "not_integrated"


@dataclass(frozen=True)
class Capability:
    """Descreve uma capacidade de consulta read-only."""

    id: str
    domain: str
    resource: str
    source: str
    description: str
    operations: tuple[str, ...] = (OP_LIST,)
    method: str = "GET"
    endpoint: str = ""
    api_version: str = "v1.0"
    supported_params: tuple[str, ...] = ()
    supported_filters: tuple[str, ...] = ()
    returned_properties: tuple[str, ...] = ()
    delegated_permissions: tuple[str, ...] = ()
    application_permissions: tuple[str, ...] = ()
    requires_license: str | None = None
    support_status: str = STATUS_SUPPORTED
    confidence: str = "high"
    keywords: tuple[str, ...] = ()
    notes: str = ""
    service_hint: str = ""
    is_primary_for_assessment: bool = False

    @property
    def supports_delegated(self) -> bool:
        return bool(self.delegated_permissions)

    @property
    def supports_application(self) -> bool:
        return bool(self.application_permissions)

    @property
    def is_available(self) -> bool:
        return self.support_status in {STATUS_SUPPORTED, STATUS_PARTIAL}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "domain": self.domain,
            "resource": self.resource,
            "source": self.source,
            "description": self.description,
            "operations": list(self.operations),
            "method": self.method,
            "endpoint": self.endpoint,
            "api_version": self.api_version,
            "supported_params": list(self.supported_params),
            "supported_filters": list(self.supported_filters),
            "returned_properties": list(self.returned_properties),
            "permissions": {
                "delegated": list(self.delegated_permissions),
                "application": list(self.application_permissions),
            },
            "supports_delegated_permission": self.supports_delegated,
            "supports_application_permission": self.supports_application,
            "requires_license": self.requires_license,
            "support_status": self.support_status,
            "confidence": self.confidence,
            "keywords": list(self.keywords),
            "notes": self.notes,
            "service_hint": self.service_hint,
            "is_primary_for_assessment": self.is_primary_for_assessment,
        }


GRAPH_BASE_V1 = "https://graph.microsoft.com/v1.0"
GRAPH_BASE_BETA = "https://graph.microsoft.com/beta"

_DIRECTORY_READ = ("Directory.Read.All",)


def _cap(**kwargs: Any) -> Capability:
    return Capability(**kwargs)


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_CAPABILITIES: tuple[Capability, ...] = (
    # ---------------------------------------------------------------- users
    _cap(
        id="graph.users.list",
        domain="users",
        resource="/users",
        source=SOURCE_GRAPH,
        description="Lista usuários do diretório (membros e convidados).",
        operations=(OP_LIST, OP_FILTER, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/users",
        # $search/$count/$orderby ainda não são implementados em
        # _build_graph_url(); mantidos fora até haver suporte a
        # ConsistencyLevel: eventual e ao parâmetro correspondente.
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("userType", "accountEnabled", "displayName", "userPrincipalName", "mail"),
        returned_properties=(
            "id",
            "displayName",
            "userPrincipalName",
            "mail",
            "userType",
            "accountEnabled",
        ),
        delegated_permissions=("User.Read.All", "User.ReadBasic.All", "Directory.Read.All"),
        application_permissions=("User.Read.All", "Directory.Read.All"),
        keywords=("usuario", "usuarios", "user", "users", "conta", "contas", "pessoa", "membro"),
        service_hint="entra_users.list_users",
    ),
    _cap(
        id="graph.users.guests",
        domain="external_identities",
        resource="/users?$filter=userType eq 'Guest'",
        source=SOURCE_GRAPH,
        description="Lista identidades externas (convidados B2B) presentes no diretório.",
        operations=(OP_LIST, OP_FILTER),
        endpoint=f"{GRAPH_BASE_V1}/users",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("userType", "accountEnabled", "creationType"),
        returned_properties=("id", "displayName", "userPrincipalName", "mail", "userType"),
        delegated_permissions=("User.Read.All", "Directory.Read.All"),
        application_permissions=("User.Read.All", "Directory.Read.All"),
        keywords=("guest", "guests", "convidado", "convidados", "externo", "externa", "b2b", "external"),
        service_hint="entra_users.list_guest_users",
    ),
    # --------------------------------------------------------------- groups
    _cap(
        id="graph.groups.list",
        domain="groups",
        resource="/groups",
        source=SOURCE_GRAPH,
        description="Lista grupos do diretório, incluindo grupos de segurança e M365.",
        operations=(OP_LIST, OP_FILTER, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/groups",
        # $count/$orderby ainda não são implementados em _build_graph_url().
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("displayName", "securityEnabled", "mailEnabled", "groupTypes"),
        returned_properties=("id", "displayName", "securityEnabled", "groupTypes"),
        delegated_permissions=("Group.Read.All", "Directory.Read.All"),
        application_permissions=("Group.Read.All", "Directory.Read.All"),
        keywords=("grupo", "grupos", "group", "groups"),
        service_hint="entra_groups.list_groups",
    ),
    _cap(
        id="graph.groups.members",
        domain="groups",
        resource="/groups/{id}/members",
        source=SOURCE_GRAPH,
        description="Lista membros diretos de um grupo.",
        operations=(OP_LIST, OP_GET, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/groups/{{id}}/members",
        supported_params=("$select", "$top"),
        returned_properties=("id", "displayName", "userPrincipalName", "mail"),
        delegated_permissions=("GroupMember.Read.All", "Group.Read.All", "Directory.Read.All"),
        application_permissions=("GroupMember.Read.All", "Group.Read.All", "Directory.Read.All"),
        keywords=("membro", "membros", "member", "members", "quem esta no grupo"),
        service_hint="entra_groups.list_group_members",
    ),
    _cap(
        id="graph.groups.transitive_membership",
        domain="groups",
        resource="/users/{id}/transitiveMemberOf",
        source=SOURCE_GRAPH,
        description="Resolve associação transitiva de grupos de um usuário (grupos aninhados).",
        operations=(OP_LIST, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/users/{{id}}/transitiveMemberOf",
        supported_params=("$select", "$top"),
        returned_properties=("id", "displayName"),
        delegated_permissions=("User.Read.All", "Directory.Read.All"),
        application_permissions=("User.Read.All", "Directory.Read.All"),
        keywords=("aninhado", "transitivo", "heranca", "nested", "transitive"),
        service_hint="entra_groups.list_user_transitive_groups",
    ),
    # ------------------------------------------------------- directory roles
    _cap(
        id="graph.directory_roles.list",
        domain="directory_roles",
        resource="/directoryRoles",
        source=SOURCE_GRAPH,
        description="Lista funções de diretório ativadas no tenant (ex.: Global Administrator).",
        operations=(OP_LIST, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/directoryRoles",
        supported_params=("$select", "$filter"),
        supported_filters=("displayName", "roleTemplateId"),
        returned_properties=("id", "displayName", "roleTemplateId"),
        delegated_permissions=("RoleManagement.Read.Directory", "Directory.Read.All"),
        application_permissions=("RoleManagement.Read.Directory", "Directory.Read.All"),
        keywords=("directory role", "funcao de diretorio", "papel de diretorio", "role do entra"),
        service_hint="entra_roles.list_directory_roles",
    ),
    _cap(
        id="graph.directory_roles.members",
        domain="directory_roles",
        resource="/directoryRoles/{id}/members",
        source=SOURCE_GRAPH,
        description=(
            "Lista membros de uma função de diretório. Use para responder "
            "'quem possui Global Administrator'."
        ),
        operations=(OP_LIST, OP_FILTER, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/directoryRoles/{{id}}/members",
        supported_params=("$select", "$top"),
        returned_properties=("id", "displayName", "userPrincipalName", "mail"),
        delegated_permissions=("RoleManagement.Read.Directory", "Directory.Read.All"),
        application_permissions=("RoleManagement.Read.Directory", "Directory.Read.All"),
        keywords=(
            "global administrator",
            "global admin",
            "administrador global",
            "quem possui a role",
            "quem tem a role",
            "membros da role",
            "privileged role administrator",
        ),
        service_hint="entra_roles.list_directory_role_members",
    ),
    _cap(
        id="graph.role_management.definitions",
        domain="role_management",
        resource="/roleManagement/directory/roleDefinitions",
        source=SOURCE_GRAPH,
        description="Lista definições de função de diretório (catálogo completo de roles Entra).",
        operations=(OP_LIST, OP_FILTER, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/roleManagement/directory/roleDefinitions",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("displayName", "isBuiltIn"),
        returned_properties=("id", "displayName", "isBuiltIn", "isEnabled"),
        delegated_permissions=("RoleManagement.Read.Directory", "Directory.Read.All"),
        application_permissions=("RoleManagement.Read.Directory", "Directory.Read.All"),
        keywords=("role definition", "definicao de role", "catalogo de roles"),
        service_hint="entra_pim.list_role_definitions",
    ),
    _cap(
        id="graph.role_management.assignments",
        domain="role_management",
        resource="/roleManagement/directory/roleAssignments",
        source=SOURCE_GRAPH,
        description=(
            "Lista atribuições permanentes de função de diretório. "
            "Não cobre Azure RBAC de recursos."
        ),
        operations=(OP_LIST, OP_FILTER, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/roleManagement/directory/roleAssignments",
        supported_params=("$select", "$filter", "$expand", "$top"),
        supported_filters=("principalId", "roleDefinitionId", "directoryScopeId"),
        returned_properties=("id", "principalId", "roleDefinitionId", "directoryScopeId"),
        delegated_permissions=("RoleManagement.Read.Directory", "Directory.Read.All"),
        application_permissions=("RoleManagement.Read.Directory", "Directory.Read.All"),
        keywords=("atribuicao de role", "role assignment entra", "permanente no entra"),
        support_status=STATUS_PARTIAL,
        notes="Requer $filter em muitas consultas; correlação de principal feita localmente.",
        is_primary_for_assessment=True,
    ),
    # ------------------------------------------------------------------ PIM
    _cap(
        id="graph.pim.eligible_directory_roles",
        domain="pim",
        resource="/roleManagement/directory/roleEligibilityScheduleInstances",
        source=SOURCE_GRAPH,
        description="Lista elegibilidades PIM para funções de diretório do Entra ID.",
        operations=(OP_LIST, OP_FILTER, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/roleManagement/directory/roleEligibilityScheduleInstances",
        supported_params=("$select", "$filter", "$expand", "$top"),
        supported_filters=("principalId", "roleDefinitionId", "directoryScopeId"),
        returned_properties=(
            "id",
            "principalId",
            "roleDefinitionId",
            "directoryScopeId",
            "startDateTime",
            "endDateTime",
        ),
        delegated_permissions=("RoleManagement.Read.Directory", "RoleEligibilitySchedule.Read.Directory"),
        application_permissions=("RoleManagement.Read.Directory",),
        requires_license="Microsoft Entra ID P2 / Governance",
        keywords=("pim", "elegivel", "elegibilidade", "eligible", "just in time", "jit", "ativar role"),
        service_hint="entra_pim.list_eligible_directory_roles",
        is_primary_for_assessment=True,
    ),
    _cap(
        id="graph.pim.active_directory_roles",
        domain="pim",
        resource="/roleManagement/directory/roleAssignmentScheduleInstances",
        source=SOURCE_GRAPH,
        description="Lista atribuições PIM ativas (incluindo ativações temporárias) no Entra ID.",
        operations=(OP_LIST, OP_FILTER, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/roleManagement/directory/roleAssignmentScheduleInstances",
        supported_params=("$select", "$filter", "$expand", "$top"),
        supported_filters=("principalId", "roleDefinitionId", "assignmentType"),
        returned_properties=(
            "id",
            "principalId",
            "roleDefinitionId",
            "assignmentType",
            "memberType",
            "startDateTime",
            "endDateTime",
        ),
        delegated_permissions=("RoleManagement.Read.Directory", "RoleAssignmentSchedule.Read.Directory"),
        application_permissions=("RoleManagement.Read.Directory",),
        requires_license="Microsoft Entra ID P2 / Governance",
        keywords=("pim ativo", "ativacao", "role ativada", "assignment schedule"),
        service_hint="entra_pim.list_active_directory_roles",
    ),
    # --------------------------------------------------------- applications
    _cap(
        id="graph.applications.list",
        domain="applications",
        resource="/applications",
        source=SOURCE_GRAPH,
        description="Lista registros de aplicação (app registrations) do tenant.",
        operations=(OP_LIST, OP_FILTER, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/applications",
        # $count ainda não é implementado em _build_graph_url().
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("displayName", "appId", "publisherDomain"),
        returned_properties=(
            "id",
            "displayName",
            "appId",
            "passwordCredentials",
            "keyCredentials",
            "requiredResourceAccess",
        ),
        delegated_permissions=("Application.Read.All", "Directory.Read.All"),
        application_permissions=("Application.Read.All", "Directory.Read.All"),
        keywords=("aplicacao", "aplicacoes", "application", "applications", "app registration", "registro de app"),
        service_hint="entra_apps.list_applications",
    ),
    _cap(
        id="graph.applications.owners",
        domain="applications",
        resource="/applications/{id}/owners",
        source=SOURCE_GRAPH,
        description="Lista proprietários de um registro de aplicação.",
        operations=(OP_LIST, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/applications/{{id}}/owners",
        supported_params=("$select", "$top"),
        returned_properties=("id", "displayName", "userPrincipalName", "mail"),
        delegated_permissions=("Application.Read.All", "Directory.Read.All"),
        application_permissions=("Application.Read.All", "Directory.Read.All"),
        keywords=("dono da aplicacao", "owner da app", "proprietario da aplicacao", "app owner"),
        service_hint="entra_apps.list_application_owners",
    ),
    _cap(
        id="graph.applications.federated_credentials",
        domain="workload_identities",
        resource="/applications/{id}/federatedIdentityCredentials",
        source=SOURCE_GRAPH,
        description="Lista credenciais federadas (workload identity federation) de uma aplicação.",
        operations=(OP_LIST, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/applications/{{id}}/federatedIdentityCredentials",
        supported_params=("$select", "$top"),
        returned_properties=("id", "name", "issuer", "subject", "audiences"),
        delegated_permissions=("Application.Read.All",),
        application_permissions=("Application.Read.All",),
        keywords=("federated credential", "workload identity federation", "credencial federada", "oidc federation"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
        notes="Endpoint catalogado, porém ainda sem coletor dedicado no MCP.",
    ),
    _cap(
        id="graph.applications.provenance",
        domain="application_provenance",
        resource="/servicePrincipals + /applications (appOwnerOrganizationId)",
        source=SOURCE_GRAPH,
        description=(
            "Classifica aplicações por procedência: criadas no seu tenant (app registration) "
            "versus nativas da Microsoft (first-party) versus terceiros consentidos. "
            "Usa appOwnerOrganizationId, não heurística de nome."
        ),
        operations=(OP_LIST, OP_FILTER, OP_ASSESS, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/servicePrincipals",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("appOwnerOrganizationId", "servicePrincipalType", "displayName"),
        returned_properties=(
            "id",
            "displayName",
            "appId",
            "servicePrincipalType",
            "appOwnerOrganizationId",
            "accountEnabled",
            "tags",
            "signInAudience",
        ),
        delegated_permissions=("Application.Read.All", "Directory.Read.All"),
        application_permissions=("Application.Read.All", "Directory.Read.All"),
        keywords=(
            "app registration",
            "app registrations",
            "criada pelo usuario",
            "criadas pelos usuarios",
            "criadas no tenant",
            "aplicacao nativa",
            "aplicacoes nativas",
            "nativa da microsoft",
            "first party",
            "first-party",
            "terceiro",
            "procedencia",
            "quem criou a aplicacao",
            "aplicacao propria",
        ),
        service_hint="app_provenance.list_application_provenance",
        notes="Distingue superfície de ataque sob sua governança da superfície pré-provisionada.",
    ),
    # ----------------------------------------------------- service principals
    _cap(
        id="graph.service_principals.list",
        domain="service_principals",
        resource="/servicePrincipals",
        source=SOURCE_GRAPH,
        description="Lista service principals (aplicações empresariais, MIs e apps first-party).",
        operations=(OP_LIST, OP_FILTER, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/servicePrincipals",
        # $count ainda não é implementado em _build_graph_url().
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("displayName", "appId", "servicePrincipalType", "accountEnabled"),
        returned_properties=(
            "id",
            "displayName",
            "appId",
            "servicePrincipalType",
            "accountEnabled",
            "appRoles",
        ),
        delegated_permissions=("Application.Read.All", "Directory.Read.All"),
        application_permissions=("Application.Read.All", "Directory.Read.All"),
        keywords=("service principal", "sp", "enterprise application", "aplicacao empresarial"),
        service_hint="entra_workload_identities.list_service_principals",
    ),
    _cap(
        id="graph.service_principals.managed_identities",
        domain="workload_identities",
        resource="/servicePrincipals?$filter=servicePrincipalType eq 'ManagedIdentity'",
        source=SOURCE_GRAPH,
        description="Lista Managed Identities conforme representadas no diretório.",
        operations=(OP_LIST, OP_FILTER),
        endpoint=f"{GRAPH_BASE_V1}/servicePrincipals",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("servicePrincipalType", "displayName", "accountEnabled"),
        returned_properties=("id", "displayName", "appId", "servicePrincipalType"),
        delegated_permissions=("Application.Read.All", "Directory.Read.All"),
        application_permissions=("Application.Read.All", "Directory.Read.All"),
        keywords=("managed identity", "managed identities", "identidade gerenciada", "mi"),
        service_hint="entra_workload_identities.list_managed_identities",
    ),
    _cap(
        id="graph.service_principals.owners",
        domain="service_principals",
        resource="/servicePrincipals/{id}/owners",
        source=SOURCE_GRAPH,
        description="Lista proprietários de um service principal.",
        operations=(OP_LIST, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/servicePrincipals/{{id}}/owners",
        supported_params=("$select", "$top"),
        returned_properties=("id", "displayName", "userPrincipalName"),
        delegated_permissions=("Application.Read.All", "Directory.Read.All"),
        application_permissions=("Application.Read.All", "Directory.Read.All"),
        keywords=(
            "dono do service principal",
            "owner do sp",
            "proprietario do sp",
            "service principal sem owner",
            "service principals sem owner",
            "service principal esta sem owner",
            "service principals estao sem owner",
        ),
        service_hint="agent_identities._list_sp_owners",
    ),
    _cap(
        id="graph.app_role_assignments.assigned_to",
        domain="app_role_assignments",
        resource="/servicePrincipals/{id}/appRoleAssignedTo",
        source=SOURCE_GRAPH,
        description=(
            "Lista quem recebeu app roles de um recurso. Use para descobrir quais "
            "identidades possuem permissões de aplicação do Microsoft Graph."
        ),
        operations=(OP_LIST, OP_FILTER, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/servicePrincipals/{{id}}/appRoleAssignedTo",
        supported_params=("$select", "$top", "$filter"),
        supported_filters=("principalId", "appRoleId", "principalType"),
        returned_properties=(
            "id",
            "principalId",
            "principalDisplayName",
            "principalType",
            "appRoleId",
            "resourceId",
        ),
        delegated_permissions=("Application.Read.All",),
        application_permissions=("Application.Read.All",),
        keywords=(
            "app role",
            "permissao de aplicacao",
            "application permission",
            "directory.readwrite.all",
            "graph permission",
            "permissao critica",
        ),
        service_hint="entra_apps.list_graph_critical_application_permissions",
    ),
    _cap(
        id="graph.app_role_assignments.by_principal",
        domain="app_role_assignments",
        resource="/servicePrincipals/{id}/appRoleAssignments",
        source=SOURCE_GRAPH,
        description="Lista app roles concedidas a um principal específico.",
        operations=(OP_LIST, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/servicePrincipals/{{id}}/appRoleAssignments",
        supported_params=("$select", "$top"),
        returned_properties=("id", "appRoleId", "resourceId", "resourceDisplayName"),
        delegated_permissions=("Application.Read.All", "Directory.Read.All"),
        application_permissions=("Application.Read.All", "Directory.Read.All"),
        keywords=("permissoes do service principal", "app roles do sp", "o que a app pode acessar"),
        support_status=STATUS_PARTIAL,
    ),
    _cap(
        id="graph.oauth2_permission_grants.list",
        domain="oauth2_permission_grants",
        resource="/oauth2PermissionGrants",
        source=SOURCE_GRAPH,
        description=(
            "Lista consentimentos delegados (OAuth2). Complementa app roles ao "
            "avaliar superfície de permissão de aplicações."
        ),
        operations=(OP_LIST, OP_FILTER, OP_CORRELATE),
        endpoint=f"{GRAPH_BASE_V1}/oauth2PermissionGrants",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("clientId", "resourceId", "consentType", "principalId"),
        returned_properties=("id", "clientId", "consentType", "principalId", "resourceId", "scope"),
        delegated_permissions=("Directory.Read.All", "DelegatedPermissionGrant.ReadWrite.All"),
        application_permissions=("Directory.Read.All", "DelegatedPermissionGrant.ReadWrite.All"),
        keywords=("consentimento", "consent", "delegada", "delegated", "oauth2", "permissao delegada"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
        notes="Endpoint catalogado; coletor dedicado ainda não implementado no MCP.",
    ),
    # ------------------------------------------------ authentication methods
    _cap(
        id="graph.authentication.registration_details",
        domain="authentication",
        resource="/reports/authenticationMethods/userRegistrationDetails",
        source=SOURCE_GRAPH,
        description=(
            "Relatório de métodos de autenticação registrados por usuário "
            "(MFA, passkey/FIDO2, Authenticator, SMS)."
        ),
        operations=(OP_LIST, OP_FILTER, OP_ASSESS),
        endpoint=f"{GRAPH_BASE_V1}/reports/authenticationMethods/userRegistrationDetails",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("isMfaRegistered", "isPasswordlessCapable", "userType"),
        returned_properties=(
            "id",
            "userPrincipalName",
            "isMfaRegistered",
            "isPasswordlessCapable",
            "methodsRegistered",
        ),
        delegated_permissions=("AuditLog.Read.All",),
        application_permissions=("AuditLog.Read.All",),
        requires_license="Microsoft Entra ID P1 para relatórios completos",
        keywords=("mfa", "autenticacao", "passkey", "fido2", "authenticator", "sms", "metodo fraco", "passwordless"),
        service_hint="entra_authentication.get_authentication_strength_summary",
    ),
    _cap(
        id="graph.authentication.user_methods",
        domain="authentication",
        resource="/users/{id}/authentication/methods",
        source=SOURCE_GRAPH,
        description="Lista métodos de autenticação registrados de um usuário específico.",
        operations=(OP_LIST, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/users/{{id}}/authentication/methods",
        supported_params=("$select",),
        returned_properties=("id", "@odata.type"),
        delegated_permissions=("UserAuthenticationMethod.Read.All",),
        application_permissions=("UserAuthenticationMethod.Read.All",),
        keywords=("metodos do usuario", "authentication methods do usuario"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    # ---------------------------------------------------- conditional access
    _cap(
        id="graph.conditional_access.policies",
        domain="conditional_access",
        resource="/identity/conditionalAccess/policies",
        source=SOURCE_GRAPH,
        description="Lista políticas de Acesso Condicional configuradas no tenant.",
        operations=(OP_LIST, OP_FILTER, OP_ASSESS),
        endpoint=f"{GRAPH_BASE_V1}/identity/conditionalAccess/policies",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("state", "displayName"),
        returned_properties=("id", "displayName", "state", "conditions", "grantControls"),
        delegated_permissions=("Policy.Read.All",),
        application_permissions=("Policy.Read.All",),
        requires_license="Microsoft Entra ID P1",
        keywords=("acesso condicional", "conditional access", "ca policy", "politica de acesso"),
        service_hint="entra_conditional_access.list_conditional_access_policies",
    ),
    _cap(
        id="graph.conditional_access.named_locations",
        domain="conditional_access",
        resource="/identity/conditionalAccess/namedLocations",
        source=SOURCE_GRAPH,
        description="Lista localizações nomeadas usadas por políticas de Acesso Condicional.",
        operations=(OP_LIST,),
        endpoint=f"{GRAPH_BASE_V1}/identity/conditionalAccess/namedLocations",
        supported_params=("$select", "$top"),
        returned_properties=("id", "displayName"),
        delegated_permissions=("Policy.Read.All",),
        application_permissions=("Policy.Read.All",),
        requires_license="Microsoft Entra ID P1",
        keywords=("named location", "localizacao nomeada", "ip confiavel"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    # --------------------------------------------------- identity protection
    _cap(
        id="graph.identity_protection.risky_users",
        domain="identity_protection",
        resource="/identityProtection/riskyUsers",
        source=SOURCE_GRAPH,
        description="Lista usuários sinalizados com risco pelo Identity Protection.",
        operations=(OP_LIST, OP_FILTER, OP_ASSESS),
        endpoint=f"{GRAPH_BASE_V1}/identityProtection/riskyUsers",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("riskLevel", "riskState"),
        returned_properties=("id", "userPrincipalName", "riskLevel", "riskState", "riskLastUpdatedDateTime"),
        delegated_permissions=("IdentityRiskyUser.Read.All",),
        application_permissions=("IdentityRiskyUser.Read.All",),
        requires_license="Microsoft Entra ID P2",
        keywords=("risco", "risky", "identity protection", "usuario de risco", "comprometido"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    _cap(
        id="graph.identity_protection.risk_detections",
        domain="identity_protection",
        resource="/identityProtection/riskDetections",
        source=SOURCE_GRAPH,
        description="Lista detecções de risco individuais do Identity Protection.",
        operations=(OP_LIST, OP_FILTER),
        endpoint=f"{GRAPH_BASE_V1}/identityProtection/riskDetections",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("riskLevel", "riskType", "detectedDateTime"),
        returned_properties=("id", "userPrincipalName", "riskLevel", "riskType", "detectedDateTime"),
        delegated_permissions=("IdentityRiskEvent.Read.All",),
        application_permissions=("IdentityRiskEvent.Read.All",),
        requires_license="Microsoft Entra ID P2",
        keywords=("deteccao de risco", "risk detection", "evento de risco"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    _cap(
        id="graph.identity_protection.risky_service_principals",
        domain="identity_protection",
        resource="/identityProtection/riskyServicePrincipals",
        source=SOURCE_GRAPH,
        description="Lista workload identities sinalizadas com risco.",
        operations=(OP_LIST, OP_FILTER),
        endpoint=f"{GRAPH_BASE_V1}/identityProtection/riskyServicePrincipals",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("riskLevel", "riskState"),
        returned_properties=("id", "displayName", "riskLevel", "riskState"),
        delegated_permissions=("IdentityRiskyServicePrincipal.Read.All",),
        application_permissions=("IdentityRiskyServicePrincipal.Read.All",),
        requires_license="Microsoft Entra ID Workload Identities Premium",
        keywords=("workload identity de risco", "sp de risco", "risky service principal"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    # ------------------------------------------------------------- sign-ins
    _cap(
        id="graph.signins.list",
        domain="sign_ins",
        resource="/auditLogs/signIns",
        source=SOURCE_GRAPH,
        description="Lista logs de entrada (sign-ins) interativos e não interativos.",
        operations=(OP_LIST, OP_FILTER, OP_QUERY),
        endpoint=f"{GRAPH_BASE_V1}/auditLogs/signIns",
        supported_params=("$select", "$filter", "$top", "$orderby"),
        supported_filters=("userPrincipalName", "createdDateTime", "appId", "status/errorCode"),
        returned_properties=(
            "id",
            "createdDateTime",
            "userPrincipalName",
            "appDisplayName",
            "ipAddress",
            "status",
        ),
        delegated_permissions=("AuditLog.Read.All", "Directory.Read.All"),
        application_permissions=("AuditLog.Read.All", "Directory.Read.All"),
        requires_license="Microsoft Entra ID P1",
        keywords=("sign in", "signin", "login", "entrada", "acesso recente", "ultimo acesso"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    _cap(
        id="graph.audit_logs.directory_audits",
        domain="audit_logs",
        resource="/auditLogs/directoryAudits",
        source=SOURCE_GRAPH,
        description="Lista eventos de auditoria de diretório (mudanças em identidade).",
        operations=(OP_LIST, OP_FILTER, OP_QUERY),
        endpoint=f"{GRAPH_BASE_V1}/auditLogs/directoryAudits",
        supported_params=("$select", "$filter", "$top", "$orderby"),
        supported_filters=("activityDateTime", "activityDisplayName", "category", "result"),
        returned_properties=(
            "id",
            "activityDateTime",
            "activityDisplayName",
            "category",
            "initiatedBy",
            "targetResources",
        ),
        delegated_permissions=("AuditLog.Read.All", "Directory.Read.All"),
        application_permissions=("AuditLog.Read.All", "Directory.Read.All"),
        requires_license="Microsoft Entra ID P1",
        keywords=("auditoria", "audit log", "quem alterou", "historico de mudanca", "directory audit"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    # -------------------------------------------------- administrative units
    _cap(
        id="graph.administrative_units.list",
        domain="administrative_units",
        resource="/directory/administrativeUnits",
        source=SOURCE_GRAPH,
        description="Lista unidades administrativas usadas para delegação com escopo.",
        operations=(OP_LIST, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/directory/administrativeUnits",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("displayName",),
        returned_properties=("id", "displayName", "description"),
        delegated_permissions=("AdministrativeUnit.Read.All", "Directory.Read.All"),
        application_permissions=("AdministrativeUnit.Read.All", "Directory.Read.All"),
        keywords=("unidade administrativa", "administrative unit", "au", "delegacao com escopo"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    # ---------------------------------------------------- identity governance
    _cap(
        id="graph.governance.access_reviews",
        domain="access_reviews",
        resource="/identityGovernance/accessReviews/definitions",
        source=SOURCE_GRAPH,
        description="Lista definições de Access Review configuradas no tenant.",
        operations=(OP_LIST, OP_GET, OP_ASSESS),
        endpoint=f"{GRAPH_BASE_V1}/identityGovernance/accessReviews/definitions",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("status", "displayName"),
        returned_properties=("id", "displayName", "status", "createdDateTime"),
        delegated_permissions=("AccessReview.Read.All",),
        application_permissions=("AccessReview.Read.All",),
        requires_license="Microsoft Entra ID Governance / P2",
        keywords=("access review", "revisao de acesso", "recertificacao", "revisao periodica"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    _cap(
        id="graph.governance.entitlement_access_packages",
        domain="entitlement_management",
        resource="/identityGovernance/entitlementManagement/accessPackages",
        source=SOURCE_GRAPH,
        description="Lista access packages de Entitlement Management.",
        operations=(OP_LIST, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/identityGovernance/entitlementManagement/accessPackages",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("displayName", "isHidden"),
        returned_properties=("id", "displayName", "description"),
        delegated_permissions=("EntitlementManagement.Read.All",),
        application_permissions=("EntitlementManagement.Read.All",),
        requires_license="Microsoft Entra ID Governance / P2",
        keywords=("entitlement", "access package", "pacote de acesso", "catalogo de acesso"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    _cap(
        id="graph.governance.lifecycle_workflows",
        domain="lifecycle_workflows",
        resource="/identityGovernance/lifecycleWorkflows/workflows",
        source=SOURCE_GRAPH,
        description="Lista fluxos de ciclo de vida de identidade (joiner/mover/leaver).",
        operations=(OP_LIST, OP_GET),
        endpoint=f"{GRAPH_BASE_V1}/identityGovernance/lifecycleWorkflows/workflows",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("category", "displayName"),
        returned_properties=("id", "displayName", "category", "isEnabled"),
        delegated_permissions=("LifecycleWorkflows.Read.All",),
        application_permissions=("LifecycleWorkflows.Read.All",),
        requires_license="Microsoft Entra ID Governance",
        keywords=("lifecycle", "ciclo de vida", "joiner", "leaver", "mover", "onboarding", "offboarding"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    # ------------------------------------------------------------- devices
    _cap(
        id="graph.devices.list",
        domain="devices",
        resource="/devices",
        source=SOURCE_GRAPH,
        description="Lista dispositivos registrados/associados ao diretório.",
        operations=(OP_LIST, OP_FILTER),
        endpoint=f"{GRAPH_BASE_V1}/devices",
        supported_params=("$select", "$filter", "$top"),
        supported_filters=("displayName", "operatingSystem", "trustType", "accountEnabled"),
        returned_properties=("id", "displayName", "operatingSystem", "trustType", "isCompliant"),
        delegated_permissions=("Device.Read.All", "Directory.Read.All"),
        application_permissions=("Device.Read.All", "Directory.Read.All"),
        keywords=("dispositivo", "dispositivos", "device", "devices", "maquina registrada"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
        notes="Relevante para identidade apenas quando correlacionado a usuário/registro.",
    ),
    # ---------------------------------------------------- directory objects
    _cap(
        id="graph.directory_objects.get_by_ids",
        domain="directory_objects",
        resource="/directoryObjects/getByIds",
        source=SOURCE_GRAPH,
        description=(
            "Resolve objetos de diretório em lote a partir de IDs. Essencial para "
            "correlacionar principalId de atribuições com nomes legíveis."
        ),
        operations=(OP_QUERY, OP_CORRELATE),
        method="POST",
        endpoint=f"{GRAPH_BASE_V1}/directoryObjects/getByIds",
        supported_params=("ids", "types"),
        returned_properties=("id", "displayName", "userPrincipalName", "@odata.type"),
        delegated_permissions=("Directory.Read.All",),
        application_permissions=("Directory.Read.All",),
        keywords=("resolver id", "getbyids", "objeto de diretorio", "directory object"),
        support_status=STATUS_PARTIAL,
        notes="Única capacidade POST permitida: é leitura em lote, não escrita.",
    ),
    _cap(
        id="graph.organization.get",
        domain="organization",
        resource="/organization",
        source=SOURCE_GRAPH,
        description="Retorna dados do tenant (nome, domínios verificados, licenças atribuídas).",
        operations=(OP_GET, OP_LIST),
        endpoint=f"{GRAPH_BASE_V1}/organization",
        supported_params=("$select",),
        returned_properties=("id", "displayName", "verifiedDomains", "assignedPlans"),
        delegated_permissions=("Organization.Read.All", "Directory.Read.All"),
        application_permissions=("Organization.Read.All", "Directory.Read.All"),
        keywords=("tenant", "organizacao", "dominio verificado", "licenca do tenant"),
        support_status=STATUS_NOT_INTEGRATED,
        confidence="medium",
    ),
    # ================================================================
    # Fontes Azure — NÃO são Microsoft Graph
    # ================================================================
    _cap(
        id="azure.rbac.role_assignments",
        domain="azure_rbac",
        resource="AuthorizationResources | microsoft.authorization/roleassignments",
        source=SOURCE_RESOURCE_GRAPH,
        description=(
            "Lista atribuições de Azure RBAC em subscriptions/resource groups/recursos. "
            "Microsoft Graph NÃO cobre Azure RBAC."
        ),
        operations=(OP_LIST, OP_FILTER, OP_QUERY, OP_CORRELATE),
        method="POST",
        endpoint="https://management.azure.com/providers/Microsoft.ResourceGraph/resources",
        api_version="2024-04-01",
        supported_params=("query", "subscriptions"),
        supported_filters=("principalId", "principalType", "roleDefinitionId", "scope"),
        returned_properties=("principalId", "principalType", "roleDefinitionId", "scope"),
        delegated_permissions=("Azure RBAC: Reader no escopo consultado",),
        application_permissions=("Azure RBAC: Reader no escopo consultado",),
        keywords=("owner", "contributor", "azure rbac", "rbac", "role assignment azure", "permissao no azure"),
        service_hint="azure_rbac.list_role_assignments",
        notes="Fonte Azure. Não confundir com roles de diretório do Entra ID.",
        is_primary_for_assessment=True,
    ),
    _cap(
        id="azure.rbac.deny_assignments",
        domain="azure_rbac",
        resource="AuthorizationResources | microsoft.authorization/denyassignments",
        source=SOURCE_RESOURCE_GRAPH,
        description="Lista deny assignments de Azure RBAC.",
        operations=(OP_LIST, OP_FILTER),
        method="POST",
        endpoint="https://management.azure.com/providers/Microsoft.ResourceGraph/resources",
        api_version="2024-04-01",
        supported_params=("query", "subscriptions"),
        returned_properties=("principalId", "scope", "denyAssignmentName"),
        delegated_permissions=("Azure RBAC: Reader no escopo consultado",),
        application_permissions=("Azure RBAC: Reader no escopo consultado",),
        keywords=("deny assignment", "negacao", "bloqueio de permissao"),
        service_hint="azure_rbac.list_deny_assignments",
    ),
    _cap(
        id="azure.pim.resource_eligible",
        domain="azure_pim",
        resource="/providers/Microsoft.Authorization/roleEligibilityScheduleInstances",
        source=SOURCE_AZURE_AUTHORIZATION,
        description=(
            "Lista elegibilidades PIM para Azure RBAC (ex.: quem pode ativar Owner "
            "em uma subscription). Distinto do PIM de funções de diretório."
        ),
        operations=(OP_LIST, OP_FILTER, OP_CORRELATE),
        endpoint=(
            "https://management.azure.com/{scope}/providers/Microsoft.Authorization/"
            "roleEligibilityScheduleInstances"
        ),
        api_version="2020-10-01",
        supported_params=("$filter", "scope"),
        supported_filters=("principalId", "roleDefinitionId", "asTarget"),
        returned_properties=("principalId", "roleDefinitionId", "scope", "startDateTime", "endDateTime"),
        delegated_permissions=("Azure RBAC: Reader + PIM leitura no escopo",),
        application_permissions=("Azure RBAC: Reader + PIM leitura no escopo",),
        requires_license="Microsoft Entra ID P2",
        keywords=("ativar owner", "pim azure", "elegivel owner", "pim de recurso", "pim subscription"),
        support_status=STATUS_PARTIAL,
        confidence="medium",
        notes="Parte da pergunta pode exigir Graph (diretório) e parte Azure (recurso).",
    ),
    _cap(
        id="azure.management.subscriptions",
        domain="azure_subscriptions",
        resource="/subscriptions",
        source=SOURCE_AZURE_MANAGEMENT,
        description="Lista subscriptions visíveis para a identidade autenticada.",
        operations=(OP_LIST, OP_GET),
        endpoint="https://management.azure.com/subscriptions",
        api_version="2020-01-01",
        supported_params=("api-version",),
        returned_properties=("subscriptionId", "displayName", "state"),
        delegated_permissions=("Azure RBAC: Reader na subscription",),
        application_permissions=("Azure RBAC: Reader na subscription",),
        keywords=("subscription", "subscriptions", "assinatura", "assinaturas"),
        service_hint="azure_graph.get_subscriptions_count",
    ),
    _cap(
        id="azure.management.management_groups",
        domain="azure_management_groups",
        resource="/providers/Microsoft.Management/managementGroups",
        source=SOURCE_AZURE_MANAGEMENT,
        description="Lista management groups da hierarquia Azure.",
        operations=(OP_LIST, OP_GET),
        endpoint="https://management.azure.com/providers/Microsoft.Management/managementGroups",
        api_version="2021-04-01",
        supported_params=("api-version",),
        returned_properties=("id", "name", "displayName"),
        delegated_permissions=("Azure RBAC: Reader no management group",),
        application_permissions=("Azure RBAC: Reader no management group",),
        keywords=("management group", "grupo de gerenciamento", "hierarquia azure"),
        service_hint="azure_management_groups",
        support_status=STATUS_PARTIAL,
    ),
    _cap(
        id="azure.resources.inventory",
        domain="azure_resources",
        resource="Resources",
        source=SOURCE_RESOURCE_GRAPH,
        description="Inventário de recursos Azure via Resource Graph.",
        operations=(OP_LIST, OP_QUERY, OP_FILTER),
        method="POST",
        endpoint="https://management.azure.com/providers/Microsoft.ResourceGraph/resources",
        api_version="2024-04-01",
        supported_params=("query", "subscriptions"),
        supported_filters=("type", "location", "resourceGroup", "subscriptionId"),
        returned_properties=("id", "name", "type", "location", "resourceGroup", "subscriptionId"),
        delegated_permissions=("Azure RBAC: Reader no escopo consultado",),
        application_permissions=("Azure RBAC: Reader no escopo consultado",),
        keywords=("recurso", "recursos", "resource", "inventario", "vm", "storage"),
        service_hint="azure_graph.list_resources",
    ),
)


CAPABILITIES: dict[str, Capability] = {cap.id: cap for cap in _CAPABILITIES}


# --------------------------------------------------------------------------
# Consultas ao registry
# --------------------------------------------------------------------------


def get_capability(capability_id: str) -> Capability | None:
    return CAPABILITIES.get(capability_id)


def list_capabilities(
    domain: str | None = None,
    source: str | None = None,
    only_available: bool = False,
) -> list[Capability]:
    rows = list(CAPABILITIES.values())
    if domain:
        rows = [c for c in rows if c.domain == domain]
    if source:
        rows = [c for c in rows if c.source == source]
    if only_available:
        rows = [c for c in rows if c.is_available]
    return sorted(rows, key=lambda c: (c.domain, c.id))


def list_domains() -> list[str]:
    return sorted({cap.domain for cap in CAPABILITIES.values()})


def domain_coverage() -> list[dict[str, Any]]:
    """Cobertura por domínio, explicitando gaps sem inventar suporte."""
    coverage: dict[str, dict[str, Any]] = {}
    for cap in CAPABILITIES.values():
        bucket = coverage.setdefault(
            cap.domain,
            {
                "domain": cap.domain,
                "source": cap.source,
                "supported": 0,
                "partial": 0,
                "not_integrated": 0,
                "capabilities": [],
            },
        )
        bucket["capabilities"].append(cap.id)
        if cap.support_status == STATUS_SUPPORTED:
            bucket["supported"] += 1
        elif cap.support_status == STATUS_PARTIAL:
            bucket["partial"] += 1
        else:
            bucket["not_integrated"] += 1

    rows: list[dict[str, Any]] = []
    for bucket in coverage.values():
        if bucket["supported"]:
            status = "EVALUATED" if not bucket["not_integrated"] else "PARTIAL"
        elif bucket["partial"]:
            status = "PARTIAL"
        else:
            status = "NOT_EVALUATED"
        bucket["status"] = status
        rows.append(bucket)
    return sorted(rows, key=lambda r: str(r["domain"]))


def required_permissions(capability_ids: Iterable[str]) -> dict[str, list[str]]:
    delegated: set[str] = set()
    application: set[str] = set()
    for cap_id in capability_ids:
        cap = CAPABILITIES.get(cap_id)
        if cap is None:
            continue
        delegated.update(cap.delegated_permissions)
        application.update(cap.application_permissions)
    return {"delegated": sorted(delegated), "application": sorted(application)}


def is_write_operation(operation: str) -> bool:
    return operation.strip().lower() in WRITE_OPERATIONS


def is_read_operation(operation: str) -> bool:
    return operation.strip().lower() in READ_OPERATIONS
