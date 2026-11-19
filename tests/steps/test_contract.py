"""pubsec reaches pubdeploy's walk through the provider contract alone: the
Context names pubdeploy's README lists under "Provider contract", and no import
of pubrules or pubdeploy outside the tests. A name used here that the contract
lacks, or such an import in pubsec's code, fails this."""

from __future__ import annotations

import re
from pathlib import Path
from pytest_bdd import scenarios, when

scenarios("contract.feature")

SOURCE = Path(__file__).resolve().parents[2] / "src" / "pubsec"
# The Context's names a provider may use, as pubdeploy's README lists them.
CONTRACT = {"root", "config", "block", "namespace", "unit", "channel", "kubectl", "server", "gh", "send",
            "bitwarden_writer", "http_get", "env", "now", "rendered", "offline", "slug", "zones", "resolve",
            "values", "types", "needs", "results", "sleep", "dispatched"}


@when("the names pubsec's code reads from a Context, and not in the contract, are gathered")
def outside_contract(ctx):
    def gathered() -> list[str]:
        used = {m for path in SOURCE.rglob("*.py") for m in re.findall(r"\bctx\.([a-z_]+)", path.read_text())}
        assert used, "pubsec's code reads nothing from a Context"
        return sorted(used - CONTRACT)
    ctx.attempt(gathered)


@when("pubsec's imports of pubkit or pubdeploy are gathered")
def imports(ctx):
    ctx.attempt(lambda: [f"{path.name}: {line}" for path in sorted(SOURCE.rglob("*.py"))
                         for line in path.read_text().splitlines()
                         if re.match(r"\s*(from|import)\s+pub(kit|deploy)\b", line)])


@when("the names of the contract that pubdeploy's Context lacks are gathered")
def lacking(ctx):
    """The pubdeploy the suite runs has every name of the contract on its Context."""
    from dataclasses import fields  # noqa: PLC0415

    from pubdeploy.model import Context  # noqa: PLC0415
    ctx.attempt(lambda: sorted(CONTRACT - {f.name for f in fields(Context)}))
