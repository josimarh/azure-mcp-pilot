"""Launcher para o portal Streamlit quando instalado como pacote.

Permite ``idengraph-ui`` iniciar o portal via ``streamlit run`` apontando
para o app.py empacotado, resolvendo o caminho de forma robusta mesmo quando
instalado em site-packages.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _app_path() -> Path:
    return Path(__file__).resolve().parent / "app.py"


def run_ui() -> None:
    """Inicia o portal Streamlit (requer o extra [ui])."""
    try:
        from streamlit.web import cli as stcli
    except ImportError:
        sys.stderr.write(
            "Streamlit não está instalado. Instale o extra de UI:\n"
            "  uvx 'idengraph[ui]' ui\n"
            "ou:\n"
            "  pip install 'idengraph[ui]'\n"
        )
        raise SystemExit(1)

    app_file = _app_path()
    if not app_file.exists():
        sys.stderr.write(f"Arquivo do portal não encontrado: {app_file}\n")
        raise SystemExit(1)

    port = os.getenv("STREAMLIT_SERVER_PORT", "8501")
    sys.argv = [
        "streamlit",
        "run",
        str(app_file),
        "--server.port",
        port,
    ]
    sys.exit(stcli.main())


if __name__ == "__main__":
    run_ui()
