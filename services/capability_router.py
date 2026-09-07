"""Roteamento de intenção: linguagem natural -> domínio -> capability -> fonte.

Fluxo implementado:

    Natural Language
          v
    Intent Classification      (leitura vs escrita bloqueada)
          v
    Identity Domain            (users, pim, azure_rbac, ...)
          v
    Graph Capability           (capability registry)
          v
    Required Permissions

A execução em si acontece em :mod:`services.capability_executor`.

Regra importante: Microsoft Graph cobre identidade/diretório; Azure RBAC e
recursos exigem APIs Azure. O roteador não força tudo para o Graph.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from services.graph_capabilities import (
    AZURE_SOURCES,
    OP_ASSESS,
    OP_CORRELATE,
    OP_GET,
    OP_LIST,
    OP_QUERY,
    SOURCE_GRAPH,
    STATUS_NOT_INTEGRATED,
    Capability,
    list_capabilities,
    required_permissions,
)

# --------------------------------------------------------------------------
# Normalização de texto
# --------------------------------------------------------------------------


def normalize_text(value: str) -> str:
    """Minúsculas, sem acentos e com pontuação reduzida a espaço."""
    decomposed = unicodedata.normalize("NFKD", value or "")
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    lowered = stripped.lower()
    return re.sub(r"[^a-z0-9@._/ -]+", " ", lowered)


# --------------------------------------------------------------------------
# Intenção de escrita (bloqueada nesta fase)
# --------------------------------------------------------------------------

WRITE_INTENT_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(crie|criar|cria)\b", "create"),
    (r"\b(adicione|adicionar|adiciona)\b", "add"),
    (r"\b(remova|remover|remove|exclua|excluir|delete|deletar|apague|apagar)\b", "delete"),
    (r"\b(atribua|atribuir|conceda|conceder|conceder acesso|grant)\b", "assign"),
    (r"\b(revogue|revogar|revoke)\b", "revoke"),
    (r"\b(altere|alterar|atualize|atualizar|modifique|modificar|update|patch)\b", "update"),
    (r"\b(ative|ativar) (a )?(role|funcao|owner|acesso)\b", "activate"),
    (r"\b(consinta|consentir|consent)\b", "consent"),
    (r"\b(desative|desativar|desabilite|desabilitar|disable)\b", "update"),
    (r"\b(resete|resetar|reset)\b", "update"),
)

# "quem pode ativar" é leitura (consulta de elegibilidade), não ativação.
READ_OVERRIDE_PATTERNS: tuple[str, ...] = (
    r"\bquem pode\b",
    r"\bquais .*podem\b",
    r"\bque podem\b",
    r"\bconsegue ativar\b",
    r"\bpode ativar\b",
    r"\bcapaz de ativar\b",
)

ASSESS_PATTERNS: tuple[str, ...] = (
    r"\bassessment\b",
    r"\bauditoria\b",
    r"\bavalie\b",
    r"\bavaliar\b",
    r"\banalise\b",
    r"\banalisar\b",
    r"\brelatorio\b",
    r"\bpostura\b",
    r"\briscos?\b",
)

CORRELATE_PATTERNS: tuple[str, ...] = (
    r"\bcorrelacion",
    r"\brelacion",
    r"\bimpacto\b",
    r"\bblast radius\b",
    r"\bcruzar\b",
    r"\bjunto com\b",
)

GET_PATTERNS: tuple[str, ...] = (
    r"\bdetalhe",
    r"\bmostre o\b",
    r"\bquem e\b",
    r"\binformacoes de\b",
)

# --------------------------------------------------------------------------
# Sinais de domínio (reforço além das keywords do registry)
# --------------------------------------------------------------------------

DOMAIN_SIGNALS: dict[str, tuple[str, ...]] = {
    "azure_rbac": (
        "no azure",
        "na subscription",
        "nas subscriptions",
        "resource group",
        "recurso azure",
        "escopo azure",
        "owner",
        "contributor",
        "user access administrator",
    ),
    "azure_pim": (
        "ativar owner",
        "ativar contributor",
        "pim no azure",
        "pim de recurso",
        "elegivel owner",
        "elegivel no azure",
    ),
    "pim": (
        "pim",
        "elegivel",
        "elegibilidade",
        "just in time",
        "privilegio permanente",
        "permanente",
        "eligible",
    ),
    "directory_roles": (
        "global administrator",
        "global admin",
        "administrador global",
        "role do entra",
        "funcao de diretorio",
        "papel de diretorio",
        "privileged role administrator",
        "security administrator",
    ),
    "app_role_assignments": (
        "graph permission",
        "permissao do graph",
        "permissoes do graph",
        "directory.readwrite.all",
        "directory.read.all",
        "application permission",
        "permissao de aplicacao",
        "permissao critica",
    ),
    "authentication": ("mfa", "passkey", "fido2", "authenticator", "sem mfa", "metodo fraco"),
    "external_identities": ("convidado", "convidados", "guest", "guests", "b2b", "externo"),
    "workload_identities": ("managed identity", "identidade gerenciada", "workload identity"),
    "application_provenance": (
        "criada pelo usuario",
        "criadas pelos usuarios",
        "criada no tenant",
        "criadas no tenant",
        "aplicacao nativa",
        "aplicacoes nativas",
        "nativa da microsoft",
        "nativas da microsoft",
        "first party",
        "first-party",
        "app registration",
        "app registrations",
        "diferenca entre",
        "propria vs",
        "quem criou",
        "procedencia",
    ),
    "conditional_access": ("acesso condicional", "conditional access"),
    "sign_ins": ("sign in", "signin", "login", "ultimo acesso", "nunca acessou"),
    "audit_logs": ("quem alterou", "auditoria de diretorio", "historico de alteracao"),
    "identity_protection": ("usuario de risco", "risky user", "identity protection"),
}

# Termos que indicam que a pergunta é sobre Azure e não sobre diretório.
AZURE_CONTEXT_TERMS: tuple[str, ...] = (
    "azure",
    "subscription",
    "subscriptions",
    "assinatura",
    "assinaturas",
    "resource group",
    "management group",
    "recurso",
    "recursos",
)

# Termos que indicam diretório/Entra e não Azure.
DIRECTORY_CONTEXT_TERMS: tuple[str, ...] = (
    "entra",
    "diretorio",
    "directory",
    "tenant",
    "aad",
    "azure ad",
)

MIN_SCORE = 1.0

# Termos genéricos demais para decidir domínio sozinhos.
GENERIC_TERMS: frozenset[str] = frozenset(
    {
        "usuario",
        "usuarios",
        "user",
        "users",
        "conta",
        "contas",
        "pessoa",
        "membro",
        "grupo",
        "grupos",
        "group",
        "groups",
        "app",
        "aplicacao",
        "aplicacoes",
        "recurso",
        "recursos",
        "resource",
        "sp",
        "mi",
        "rbac",
        "tenant",
    }
)


def _term_weight(term: str, base: float = 1.0) -> float:
    if term in GENERIC_TERMS:
        return 0.6
    return base + min(len(term.split()), 4) * 0.6


@dataclass
class RoutedCapability:
    capability: Capability
    score: float
    matched: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability.id,
            "domain": self.capability.domain,
            "source": self.capability.source,
            "resource": self.capability.resource,
            "support_status": self.capability.support_status,
            "score": round(self.score, 2),
            "matched_terms": self.matched,
        }


@dataclass
class RoutingPlan:
    question: str
    operation: str
    primary: RoutedCapability | None
    selected: list[RoutedCapability]
    unavailable: list[RoutedCapability]
    sources: list[str]
    permissions: dict[str, list[str]]
    blocked: bool = False
    blocked_reason: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def is_multi_source(self) -> bool:
        return len(self.sources) > 1

    @property
    def has_capability(self) -> bool:
        return self.primary is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "operation": self.operation,
            "blocked": self.blocked,
            "blocked_reason": self.blocked_reason,
            "primary_capability": self.primary.to_dict() if self.primary else None,
            "selected_capabilities": [item.to_dict() for item in self.selected],
            "unavailable_capabilities": [item.to_dict() for item in self.unavailable],
            "sources": self.sources,
            "requires_multiple_sources": self.is_multi_source,
            "required_permissions": self.permissions,
            "notes": self.notes,
        }


def _detect_write_intent(text: str) -> str | None:
    for pattern in READ_OVERRIDE_PATTERNS:
        if re.search(pattern, text):
            return None
    for pattern, verb in WRITE_INTENT_PATTERNS:
        if re.search(pattern, text):
            return verb
    return None


def _detect_operation(text: str) -> str:
    for pattern in ASSESS_PATTERNS:
        if re.search(pattern, text):
            return OP_ASSESS
    for pattern in CORRELATE_PATTERNS:
        if re.search(pattern, text):
            return OP_CORRELATE
    for pattern in GET_PATTERNS:
        if re.search(pattern, text):
            return OP_GET
    if re.search(r"\bquant[oa]s?\b", text) or re.search(r"\bkql\b", text):
        return OP_QUERY
    return OP_LIST


def _score_capability(cap: Capability, text: str) -> tuple[float, list[str]]:
    score = 0.0
    matched: list[str] = []

    for keyword in cap.keywords:
        term = normalize_text(keyword)
        if not term:
            continue
        if term in text:
            score += _term_weight(term)
            matched.append(keyword)

    for signal in DOMAIN_SIGNALS.get(cap.domain, ()):  # reforço de domínio
        term = normalize_text(signal)
        if term and term in text:
            score += _term_weight(term, base=1.2)
            if signal not in matched:
                matched.append(signal)

    domain_term = normalize_text(cap.domain.replace("_", " "))
    if domain_term and domain_term in text:
        score += 1.0
        matched.append(cap.domain)

    if score <= 0:
        return 0.0, []

    # Desambiguação Graph x Azure
    has_azure_ctx = any(normalize_text(t) in text for t in AZURE_CONTEXT_TERMS)
    has_dir_ctx = any(normalize_text(t) in text for t in DIRECTORY_CONTEXT_TERMS)

    if cap.source in AZURE_SOURCES:
        if has_azure_ctx:
            score += 1.6
        if has_dir_ctx and not has_azure_ctx:
            score -= 1.4
    elif cap.source == SOURCE_GRAPH:
        if has_dir_ctx:
            score += 1.0
        if has_azure_ctx and not has_dir_ctx and cap.domain not in {"pim", "directory_roles"}:
            score -= 0.8

    if cap.support_status == STATUS_NOT_INTEGRATED:
        score -= 0.5

    return max(score, 0.0), matched


def route_question(question: str, max_capabilities: int = 4) -> RoutingPlan:
    """Classifica a pergunta e seleciona capacidades permitidas."""
    text = normalize_text(question)

    write_verb = _detect_write_intent(text)
    if write_verb:
        return RoutingPlan(
            question=question,
            operation=write_verb,
            primary=None,
            selected=[],
            unavailable=[],
            sources=[],
            permissions={"delegated": [], "application": []},
            blocked=True,
            blocked_reason=(
                "O MCP opera em modo READ ONLY nesta fase. Operações de escrita "
                f"(detectado: {write_verb.upper()}) estão bloqueadas por política. "
                "Somente GET, LIST, QUERY, ASSESS e CORRELATE são permitidos."
            ),
            notes=["write_operations_disabled"],
        )

    operation = _detect_operation(text)

    scored: list[RoutedCapability] = []
    for cap in list_capabilities():
        score, matched = _score_capability(cap, text)
        if score >= MIN_SCORE:
            scored.append(RoutedCapability(capability=cap, score=score, matched=matched))

    scored.sort(key=lambda item: item.score, reverse=True)

    available = [item for item in scored if item.capability.is_available]
    unavailable = [item for item in scored if not item.capability.is_available]

    selected = available[:max_capabilities]
    primary = selected[0] if selected else None

    notes: list[str] = []
    sources = sorted({item.capability.source for item in selected})

    # Quando a capacidade mais aderente à pergunta não está integrada, isso
    # precisa ser dito explicitamente em vez de responder com um substituto fraco.
    best_overall = scored[0] if scored else None
    if best_overall is not None and not best_overall.capability.is_available:
        best_available_score = primary.score if primary else 0.0
        if best_overall.score > best_available_score:
            notes.append(
                "A consulta mais adequada seria "
                f"'{best_overall.capability.resource}' (domínio {best_overall.capability.domain}), "
                "mas essa capability ainda não está integrada ao MCP."
            )
            if primary is not None:
                notes.append(
                    f"Resposta parcial usando '{primary.capability.resource}'. "
                    "Trate o resultado como cobertura PARCIAL, não como conclusão completa."
                )

    if primary and len(sources) > 1:
        notes.append(
            "A pergunta cruza fontes distintas: identidade/diretório via Microsoft Graph "
            "e recursos/Azure RBAC via APIs Azure. As consultas serão mantidas separadas."
        )

    if unavailable and not selected:
        gap_domains = sorted({item.capability.domain for item in unavailable})
        notes.append(
            "Domínio reconhecido, porém sem capability integrada: " + ", ".join(gap_domains)
        )

    if not scored:
        notes.append("Nenhum domínio de identidade reconhecido com confiança suficiente.")

    return RoutingPlan(
        question=question,
        operation=operation,
        primary=primary,
        selected=selected,
        unavailable=unavailable[:max_capabilities],
        sources=sources,
        permissions=required_permissions(item.capability.id for item in selected),
        notes=notes,
    )


def explain_routing(question: str) -> dict[str, Any]:
    """Explica o roteamento sem executar nada (capability discovery)."""
    return route_question(question).to_dict()
