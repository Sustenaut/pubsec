"""Steps for pubsec's own command line: the shared ones are conftest's and pubkit's plugin's."""

from __future__ import annotations

from pytest_bdd import scenarios

scenarios("cli.feature")
