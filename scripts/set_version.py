"""Sincroniza a versao do projeto em todos os artefatos publicados.

O pacote Python e a extensao sao publicados juntos, mas moram em arquivos
diferentes. Manter as versoes em sincronia manualmente e fonte de erro: foi
assim que o pacote ficou em 0.1.0 enquanto a extensao ja estava em 0.1.2.

Uso:
    python scripts/set_version.py 0.2.0
    python scripts/set_version.py --check
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
EXTENSION_PACKAGE = ROOT / "extension" / "package.json"

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def read_versions() -> dict[str, str]:
    pyproject = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    if not match:
        raise SystemExit("Nao foi possivel ler a versao em pyproject.toml")

    package = json.loads(EXTENSION_PACKAGE.read_text(encoding="utf-8"))
    return {"python": match.group(1), "extension": package["version"]}


def write_version(version: str) -> None:
    pyproject = PYPROJECT.read_text(encoding="utf-8")
    updated, count = re.subn(
        r'^version\s*=\s*"[^"]+"',
        f'version = "{version}"',
        pyproject,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise SystemExit("Falha ao atualizar pyproject.toml")
    PYPROJECT.write_text(updated, encoding="utf-8")

    # Edicao textual preserva formatacao e ordem das chaves, que json.dump perderia.
    package_text = EXTENSION_PACKAGE.read_text(encoding="utf-8")
    updated_package, count = re.subn(
        r'("version"\s*:\s*)"[^"]+"',
        rf'\g<1>"{version}"',
        package_text,
        count=1,
    )
    if count != 1:
        raise SystemExit("Falha ao atualizar extension/package.json")
    EXTENSION_PACKAGE.write_text(updated_package, encoding="utf-8")

    # Garante que o resultado continua sendo JSON valido.
    json.loads(EXTENSION_PACKAGE.read_text(encoding="utf-8"))


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2

    if args[0] == "--check":
        versions = read_versions()
        print(f"pacote python : {versions['python']}")
        print(f"extensao      : {versions['extension']}")
        if versions["python"] != versions["extension"]:
            print("\nDESSINCRONIZADAS")
            return 1
        print("\nem sincronia")
        return 0

    version = args[0].lstrip("v")
    if not SEMVER.match(version):
        raise SystemExit(f"Versao invalida: {version!r}. Use MAJOR.MINOR.PATCH (ex.: 0.2.0)")

    write_version(version)
    print(f"versao definida como {version} em pyproject.toml e extension/package.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
