"""pubsec reaches pubdeploy's walk through the provider contract alone: the
Context names pubdeploy.contract holds, no import of pubkit or pubdeploy in
pubsec's code, and, in its tests, no module of pubdeploy but pubdeploy.contract
and pubdeploy.testing. A name used here that the contract lacks, or such an
import, fails this."""

from __future__ import annotations

import re
from pathlib import Path
from pubdeploy.contract import CONTEXT
from pytest_bdd import scenarios, when

scenarios("contract.feature")

SOURCE = Path(__file__).resolve().parents[2] / "src" / "pubsec"
TESTS = Path(__file__).resolve().parents[1]
# The modules of pubdeploy a provider's tests may import (pubdeploy's README, "Provider contract").
OPEN = ("pubdeploy.contract", "pubdeploy.testing")


@when("the names pubsec's code reads from a Context, and not in the contract, are gathered")
def outside_contract(ctx):
    def gathered() -> list[str]:
        used = {m for path in SOURCE.rglob("*.py") for m in re.findall(r"\bctx\.([a-z_]+)", path.read_text())}
        assert used, "pubsec's code reads nothing from a Context"
        return sorted(used - CONTEXT)
    ctx.attempt(gathered)


@when("pubsec's imports of pubkit or pubdeploy are gathered")
def imports(ctx):
    ctx.attempt(lambda: [f"{path.name}: {line}" for path in sorted(SOURCE.rglob("*.py"))
                         for line in path.read_text().splitlines()
                         if re.match(r"\s*(from|import)\s+pub(kit|deploy)\b", line)])


@when("the modules of pubdeploy pubsec's tests import, beside the contract and the harness, are gathered")
def test_imports(ctx):
    def gathered() -> list[str]:
        found = []
        for path in sorted(TESTS.rglob("*.py")):
            for line in path.read_text().splitlines():
                m = re.match(r"\s*(?:from\s+(pubdeploy[\w.]*)\s+import|import\s+(pubdeploy[\w.]*))", line)
                module = m and (m.group(1) or m.group(2))
                if module and not any(module == o or module.startswith(f"{o}.") for o in OPEN):
                    found.append(f"{path.relative_to(TESTS)}: {line.strip()}")
        return found
    ctx.attempt(gathered)
