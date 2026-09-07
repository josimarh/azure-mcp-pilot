from __future__ import annotations

from typing import Any

DOCS: list[dict[str, Any]] = [
    {
        "topics": ["resource graph", "inventory", "ambiente", "resources", "azure"],
        "title": "Azure Resource Graph overview",
        "url": "https://learn.microsoft.com/azure/governance/resource-graph/overview",
        "summary": "Use Azure Resource Graph for read-oriented inventory and governance queries across accessible Azure resources at scale.",
    },
    {
        "topics": ["well architected", "arquitetura", "best practices", "boas práticas"],
        "title": "Azure Well-Architected Framework",
        "url": "https://learn.microsoft.com/azure/well-architected/",
        "summary": "Use the Well-Architected Framework to assess design decisions across reliability, security, cost optimization, operational excellence and performance efficiency.",
    },
    {
        "topics": ["storage", "storage account", "segurança storage"],
        "title": "Azure Storage security recommendations",
        "url": "https://learn.microsoft.com/azure/storage/blobs/security-recommendations",
        "summary": "Review identity-based access, secure transfer, network restrictions, encryption and data protection controls for Azure Storage.",
    },
    {
        "topics": ["key vault", "vault", "segredos", "secrets"],
        "title": "Azure Key Vault security overview",
        "url": "https://learn.microsoft.com/azure/key-vault/general/security-features",
        "summary": "Review authentication, authorization, network access, encryption and operational controls around secrets, keys and certificates.",
    },
    {
        "topics": ["policy", "compliance", "conformidade", "governança"],
        "title": "Azure Policy overview",
        "url": "https://learn.microsoft.com/azure/governance/policy/overview",
        "summary": "Use Azure Policy to evaluate resource compliance against organizational standards and to aggregate compliance state.",
    },
    {
        "topics": ["defender", "security", "segurança", "recommendations"],
        "title": "Defender for Cloud security recommendations",
        "url": "https://learn.microsoft.com/azure/defender-for-cloud/security-recommendations",
        "summary": "Use Defender for Cloud recommendations as one source of cloud security posture findings and remediation guidance.",
    },
]


def search_official_guidance(topic: str, limit: int = 4) -> dict[str, Any]:
    needle = topic.strip().lower()
    scored: list[tuple[int, dict[str, Any]]] = []
    for doc in DOCS:
        haystack = " ".join(doc["topics"] + [doc["title"], doc["summary"]]).lower()
        score = sum(1 for token in needle.split() if token and token in haystack)
        if score:
            scored.append((score, doc))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    results = [doc for _, doc in scored[: max(1, min(limit, 6))]]
    if not results:
        results = DOCS[:2]
    return {
        "topic": topic,
        "note": "Curated catalog of official Microsoft references. It is not a full Microsoft Learn RAG index yet.",
        "sources": results,
    }
