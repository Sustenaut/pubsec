"""pubsec's suite. Its steps are pubtest's (files, `I run`, the result, the
output, secrets), and the deploy scenarios run pubsec's types through
pubdeploy's own walk (steps/deploy_world.py).

What more than one steps module shares lives here: the scratch repository
the commands run in, the environment they get, and running `pubsec` with no
terminal. pytest-bdd registers a step only in the module that defines it, or
in a conftest.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator, MutableMapping
from pathlib import Path

import pytest
from pubtest.core import Result
from pubtest.steps.files import scratch_directory
from pytest_bdd import parsers, then


def pytest_configure(config: pytest.Config) -> None:
    # The program under test is the pubsec installed beside the Python running this suite,
    # unless PUBSEC_BIN_DIR names another.
    os.environ.setdefault("PUBSEC_BIN_DIR", str(Path(sys.executable).parent))


@pytest.fixture
def repo(pubtest_ctx, tmp_path, monkeypatch) -> Path:
    """The repository a command runs in: the scenario's scratch directory."""
    if pubtest_ctx.directory is None:
        scratch_directory(pubtest_ctx, tmp_path, monkeypatch)
    return pubtest_ctx.directory


class Environment(MutableMapping):
    """The environment the scenario's commands get, set for the scenario alone."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.monkeypatch = monkeypatch

    def __getitem__(self, name: str) -> str:
        return os.environ[name]

    def __setitem__(self, name: str, value: str | None) -> None:
        if value is None:
            self.monkeypatch.delenv(name, raising=False)
        else:
            self.monkeypatch.setenv(name, value)

    def __delitem__(self, name: str) -> None:
        if name not in os.environ:
            raise KeyError(name)
        self.monkeypatch.delenv(name)

    def __iter__(self) -> Iterator[str]:
        return iter(os.environ)

    def __len__(self) -> int:
        return len(os.environ)


@pytest.fixture
def env(monkeypatch) -> Environment:
    return Environment(monkeypatch)


def without_terminal(pubtest_ctx, argv: list[str], lines: list[str], cwd: Path) -> Result:
    """Run `argv` as a person piping its answers in, one a line, in a session of its
    own, so no prompt reaches the terminal running the suite; what it did is the
    scenario's result, for pubtest's steps."""
    pubtest_ctx.acting()
    done = subprocess.run(argv, input="".join(f"{line}\n" for line in lines).encode(), cwd=cwd,
                          capture_output=True, timeout=60, start_new_session=True, check=False)
    return pubtest_ctx.ran(Result(code=done.returncode, stdout=done.stdout.decode("utf-8", "replace"),
                                  stderr=done.stderr.decode("utf-8", "replace"), argv=[str(a) for a in argv]))


def _sdk_reads(tmp_path) -> list[dict]:
    """What the stand-in SDK was asked to read (steps/fake_reads.py)."""
    import json  # noqa: PLC0415
    log = tmp_path / "sdk-reads.log"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@then("Bitwarden gave pubsec no secret's value")
def no_value_read(tmp_path):
    reads = _sdk_reads(tmp_path)
    assert reads and all(r["call"] == "list" for r in reads), reads


@then(parsers.parse('Bitwarden gave pubsec the value of "{secret}" alone'))
def one_value_read(tmp_path, secret):
    assert [r["ids"] for r in _sdk_reads(tmp_path) if r["call"] == "get"] == [[secret]]
