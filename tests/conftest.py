"""pubsec's suite. The steps it does not define here (`it succeeds`, `it
prints ...`) are pubkit's plugin's, and the deploy scenarios run pubsec's
types through pubkit's own walk (steps/deploy_world.py).

Steps and fixtures more than one steps module uses live here: the scratch
repository, running the `pubsec` command in it, and its files. pytest-bdd
registers a step only in the module that defines it, or in a conftest.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, then, when


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    return root


def pubsec():
    """The `pubsec` installed beside the Python running this suite."""
    found = shutil.which("pubsec", path=str(Path(sys.executable).parent))
    assert found, "pubsec is not installed in this environment; run `make venv`"
    return found


@pytest.fixture
def env():
    return {}


@given(parsers.parse('the file "{path}" reads "{text}"'))
@when(parsers.parse('the file "{path}" reads "{text}"'))
def file_reads(repo, path, text):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text + "\n")


@when(parsers.re(r'I run pubsec (?P<args>(?:"[^"]*" ?)+)'), target_fixture="result")
def run_pubsec(repo, run, env, args):
    return run(pubsec(), *args.strip().strip('"').split('" "'), cwd=repo, env=env)


@then(parsers.parse('"{path}" contains "{text}"'))
def contains(repo, path, text):
    assert text in (repo / path).read_text()


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
