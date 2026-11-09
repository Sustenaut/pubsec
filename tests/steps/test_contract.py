"""pubsec reaches pubdeploy's walk through the provider contract alone: the
Context names pubdeploy's README lists under "Provider contract", and no import
of pubkit or pubdeploy outside the tests. A name used here that the contract
lacks, or such an import in pubsec's code, fails this."""

from __future__ import annotations

import re
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "src" / "pubsec"
# The Context's names a provider may use, as pubdeploy's README lists them.
CONTRACT = {"root", "config", "block", "namespace", "unit", "channel", "kubectl", "server", "gh", "send",
            "bitwarden_writer", "http_get", "env", "now", "rendered", "offline", "slug", "zones", "resolve",
            "values", "types", "needs", "results", "sleep", "dispatched"}


def test_only_the_contract_is_used():
    used = {m for path in SOURCE.rglob("*.py") for m in re.findall(r"\bctx\.([a-z_]+)", path.read_text())}
    assert used <= CONTRACT, used - CONTRACT


def test_nothing_of_pubkit_is_imported():
    for path in SOURCE.rglob("*.py"):
        for line in path.read_text().splitlines():
            assert not re.match(r"\s*(from|import)\s+pub(kit|deploy)\b", line), f"{path.name}: {line}"


def test_the_contract_is_on_pubdeploys_context():
    """The pubdeploy the suite runs has every name of the contract on its Context."""
    from dataclasses import fields  # noqa: PLC0415

    from pubdeploy.model import Context  # noqa: PLC0415
    assert CONTRACT <= {f.name for f in fields(Context)}
