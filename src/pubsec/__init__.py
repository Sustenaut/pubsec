"""pubsec: the commands and deploy need types that hold a secret value, a
write token or a private key in memory, apart from pubkit, which only reads
about secrets."""

import re as _re
from importlib import metadata as _metadata
from pathlib import Path as _Path


def _version() -> str:
    """pyproject.toml's version, the one place pubrel sets it: read from the
    file in a source checkout, else from the installed package's metadata."""
    source = _Path(__file__).resolve().parents[2] / "pyproject.toml"
    if source.is_file():
        text = source.read_text(encoding="utf-8")
        if _re.search(r'^name = "pubsec"$', text, _re.M):
            return _re.search(r'^version = "([^"]+)"$', text, _re.M)[1]
    return _metadata.version("pubsec")


__version__ = _version()
