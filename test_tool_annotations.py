"""Contrato de trust scoring MCP: toda tool registrada deve declarar
explicitamente as quatro annotations padrão (readOnlyHint, destructiveHint,
idempotentHint, openWorldHint).

Diretórios/clients MCP usam essas annotations para decidir se uma tool exige
confirmação do usuário antes de ser chamada. Como o IdenGraph é somente
leitura por design, este teste falha se qualquer tool registrada não tiver
as quatro annotations definidas (não apenas com valor "verdadeiro"), e falha
também se algum valor divergir do esperado para um servidor read-only.

Roda sem client assíncrono: `mcp._tool_manager.list_tools()` já expõe os
objetos `Tool` com `.annotations` populado de forma síncrona.
"""

import os

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("SANITIZE_FOR_LLM", "true")

import pytest

from mcp_server import mcp

EXPECTED_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


def _all_tools():
    return mcp._tool_manager.list_tools()


def _tool_ids():
    return [tool.name for tool in _all_tools()]


def test_at_least_one_tool_is_registered() -> None:
    tools = _all_tools()
    assert len(tools) > 0, "Nenhuma tool MCP foi registrada; catálogo vazio."


@pytest.mark.parametrize("tool_name", _tool_ids())
def test_tool_declares_all_four_annotations_explicitly(tool_name: str) -> None:
    tool = mcp._tool_manager.get_tool(tool_name)
    assert tool is not None, f"Tool '{tool_name}' não encontrada no tool manager."

    annotations = tool.annotations
    assert annotations is not None, (
        f"Tool '{tool_name}' não possui ToolAnnotations definidas. "
        "Todas as tools devem ser registradas via read_only_tool()."
    )

    dumped = annotations.model_dump(by_alias=True, exclude_none=False)
    for field, expected_value in EXPECTED_ANNOTATIONS.items():
        assert field in dumped, f"Tool '{tool_name}' não declara '{field}' em ToolAnnotations."
        actual_value = dumped[field]
        assert actual_value is not None, (
            f"Tool '{tool_name}' declara '{field}' como None (implícito), "
            "mas o contrato exige um valor explícito."
        )
        assert actual_value == expected_value, (
            f"Tool '{tool_name}' declara {field}={actual_value!r}, "
            f"esperado {expected_value!r} para um servidor MCP somente leitura."
        )


def main() -> None:
    """Runner manual, consistente com o padrão dos demais test_*.py do repo."""
    tools = _all_tools()
    test_at_least_one_tool_is_registered()
    print(f"  ok  test_at_least_one_tool_is_registered ({len(tools)} tools)")
    for tool in tools:
        test_tool_declares_all_four_annotations_explicitly(tool.name)
        print(f"  ok  annotations[{tool.name}]")
    print(f"Tool annotations contract OK ({len(tools)} tools verificadas)")


if __name__ == "__main__":
    main()
