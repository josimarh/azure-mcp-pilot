"""Smoke/contract test parametrizado: cobre todas as tools MCP registradas
em modo mock, sem duplicar dezenas de testes manuais.

Diferente de test_smoke.py (que valida payloads específicos de um subconjunto
de tools "clássicas" com asserts detalhados) e de test_tool_annotations.py
(que valida só as ToolAnnotations), este arquivo garante que **toda** tool
pública:

1. Está registrada com um schema de parâmetros válido.
2. Pode ser chamada com argumentos mínimos derivados do próprio schema
   (usando defaults quando existem; um valor de exemplo somente para
   parâmetros obrigatórios).
3. Roda em MOCK_MODE=true sem lançar exceção não tratada e sem erro de
   protocolo MCP (result.is_error).

Isso fecha o gap de cobertura: hoje só ~30 das 66 tools tinham teste
dedicado em test_smoke.py. Este arquivo cobre as 66 automaticamente,
descobrindo o catálogo em runtime via mcp._tool_manager, então tools novas
adicionadas no futuro são cobertas sem precisar editar este arquivo.
"""

import asyncio
import json
import os

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("SANITIZE_FOR_LLM", "true")

import pytest

from mcp import Client
from mcp_server import mcp

# Valores de exemplo para parâmetros obrigatórios sem default, por tipo JSON
# Schema. Não tentam ser realistas por tool (isso é responsabilidade de
# test_smoke.py para as tools críticas); só precisam ser aceitos pela camada
# de validação de tipos e não quebrar a execução mock.
_EXAMPLE_BY_TYPE = {
    "string": "ana.silva@contoso.com",
    "integer": 5,
    "number": 5,
    "boolean": True,
}

# Algumas tools exigem um identificador de capability válido ou similar para
# não retornar erro de validação (não de execução). Overrides pontuais por
# nome de parâmetro, aplicados só quando o parâmetro é obrigatório.
_EXAMPLE_BY_PARAM_NAME = {
    "role": "Global Administrator",
    "provider": "Entra",
    "capability_id": "graph.users.list",
    "id": "obj-example",
    "identity_identifier": "ana.silva@contoso.com",
    "user_identifier": "ana.silva@contoso.com",
    "owner_identifier": "ana.silva@contoso.com",
    "agent_identifier": "agent-example",
    "question": "Quem possui Global Administrator?",
    "topic": "conditional access",
}


def _build_minimal_args(parameters_schema: dict) -> dict:
    """Deriva argumentos mínimos a partir do JSON Schema de uma tool."""
    props: dict = parameters_schema.get("properties", {})
    required: list[str] = parameters_schema.get("required", [])
    args: dict = {}
    for name in required:
        prop = props.get(name, {})
        if name in _EXAMPLE_BY_PARAM_NAME:
            args[name] = _EXAMPLE_BY_PARAM_NAME[name]
            continue
        json_type = prop.get("type", "string")
        args[name] = _EXAMPLE_BY_TYPE.get(json_type, "example")
    return args


def _all_tool_names() -> list[str]:
    return [tool.name for tool in mcp._tool_manager.list_tools()]


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


async def _call_tool_smoke(tool_name: str) -> None:
    tool = mcp._tool_manager.get_tool(tool_name)
    assert tool is not None, f"Tool '{tool_name}' desapareceu do catálogo entre a coleta e a execução."

    args = _build_minimal_args(tool.parameters)

    async with Client(mcp) as client:
        result = await client.call_tool(tool_name, args)

    assert not result.is_error, (
        f"Tool '{tool_name}' retornou erro de protocolo MCP com args mínimos {args!r}: "
        f"{getattr(result, 'content', result)!r}"
    )
    payload = _content_to_dict(result)
    assert isinstance(payload, dict), f"Tool '{tool_name}' não retornou um payload dict-like."


@pytest.mark.parametrize("tool_name", _all_tool_names())
def test_tool_smoke_in_mock_mode(tool_name: str) -> None:
    asyncio.run(_call_tool_smoke(tool_name))


def main() -> None:
    """Runner manual, consistente com o padrão dos demais test_*.py do repo."""
    names = _all_tool_names()
    failures: list[tuple[str, Exception]] = []
    for name in names:
        try:
            asyncio.run(_call_tool_smoke(name))
            print(f"  ok  smoke[{name}]")
        except Exception as exc:  # noqa: BLE001 - queremos reportar todas as falhas juntas
            failures.append((name, exc))
            print(f"FAIL  smoke[{name}]: {exc}")

    if failures:
        raise SystemExit(f"{len(failures)} de {len(names)} tools falharam no smoke test parametrizado.")
    print(f"Tool catalog smoke test OK ({len(names)} tools cobertas)")


if __name__ == "__main__":
    main()
