"""pubsec's suite. Its steps are pubtest's (files, `I run`, the result, the
output, secrets), and the deploy scenarios run pubsec's types through
pubdeploy's own walk, in pubdeploy.testing's world (pytest.ini sets
pubdeploy_testing), which PubsecWorld extends with what pubsec's types ask
of gcloud.

What more than one steps module shares lives here: the scratch repository
the commands run in, the environment they get, and running `pubsec` with no
terminal. pytest-bdd registers a step only in the module that defines it, or
in a conftest.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from collections.abc import Iterator, MutableMapping
from pathlib import Path

import pytest
from pubdeploy.contract import Ran
from pubdeploy.testing.world import CANARY, FakeWriter, World
from pubtest.core import Result
from pubtest.steps.files import scratch_directory
from pytest_bdd import given, parsers, then


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


# --- the deploy world: pubdeploy.testing's, with gcloud as pubsec's gcp types ask it ---------------


def gcloud_flags(args: list[str]) -> dict[str, str]:
    """A gcloud call's --name=value flags, by name."""
    return dict(a.removeprefix("--").split("=", 1) for a in args if a.startswith("--") and "=" in a)


def key_value(key_id: str) -> str:
    """A key as Bitwarden keeps it: base64 of its JSON."""
    return base64.b64encode(json.dumps({"private_key_id": key_id, "private_key": CANARY}).encode()).decode()


class PubsecWorld(World):
    """pubdeploy.testing's world, as pubsec's types see it: ./with-secrets
    under its pubrules name, and gcloud, which only pubsec's gcp types run:
    its service accounts and their keys, the workload-identity policy,
    unknown accounts, and keys an organization policy or a role forbids."""

    secrets_project = "PUBRULES_SECRETS_PROJECT"

    def __init__(self, root) -> None:
        super().__init__(root)
        self.gcloud: dict = {"accounts": {"example-files@example-project.iam.gserviceaccount.com"},
                             "keys": {}, "missing": False}

    def leaked(self) -> list[str]:
        """pubdeploy's canary, and every argv gcloud was given."""
        seen = [json.dumps(c) for c in self.calls.get("gcloud", [])]
        return [*super().leaked(), *(t for t in seen for v in [CANARY, *self.values, self.token] if v in t)]

    def run_gcloud(self, args: list[str]) -> Ran:
        """gcloud, as pubsec's types run it: the call kept, then `gcloud_answer`'s answer."""
        self.calls.setdefault("gcloud", []).append(args)
        return self.gcloud_answer(args)

    def patch(self, monkeypatch) -> None:
        """pubdeploy's patching, then pubsec's own: its types, which hold a
        secret's value, and its hook that asks for the write token, with
        Bitwarden's writer, its generator and gcloud pointed at the world."""
        super().patch(monkeypatch)
        import pubsec.needs.bitwarden as bitwarden  # noqa: PLC0415
        import pubsec.walk  # noqa: PLC0415
        monkeypatch.setattr(pubsec.walk, "_writers", {})
        monkeypatch.setattr(pubsec.walk, "ask_hidden", lambda prompt: self.outputs.append(prompt) or self.token)
        monkeypatch.setattr(pubsec.walk, "BitwardenWriter", lambda token, project: FakeWriter(self, token))
        made = bitwarden.generate

        def generate(shape):
            value = made(shape)
            self.values.append(value)
            return value
        monkeypatch.setattr(bitwarden, "generate", generate)
        monkeypatch.setattr("pubsec.needs.gcp.gcloud", self.run_gcloud)

    def gcloud_answer(self, args: list[str]) -> Ran:
        if self.gcloud["missing"]:
            return self.accounts_and_keys(args)
        if args[:3] == ["iam", "service-accounts", "get-iam-policy"]:
            if args[3] not in self.gcloud["accounts"]:
                return Ran(1, "", f"ERROR: NOT_FOUND: Unknown service account {args[3]}")
            members = sorted(self.gcloud.setdefault("acting", {}).get(args[3], []))
            return Ran(0, json.dumps({"bindings": [{"role": "roles/iam.workloadIdentityUser", "members": members}]}
                                     if members else {}))
        if args[:3] == ["iam", "service-accounts", "keys"]:
            account = gcloud_flags(args).get("iam-account", "")
            if account not in self.gcloud["accounts"]:
                return Ran(1, "", f"NOT_FOUND: Unknown service account {account}")
            if args[3] == "create" and self.gcloud.get("policy_forbids"):
                return Ran(1, "", "ERROR: (gcloud.iam.service-accounts.keys.create) FAILED_PRECONDITION: Key creation "
                                  "is not allowed on this service account.")
            if args[3] == "create" and self.gcloud.get("deny_create"):
                return Ran(1, "", "ERROR: (gcloud.iam.service-accounts.keys.create) PERMISSION_DENIED: Permission "
                                  "'iam.serviceAccountKeys.create' denied on resource (or it may not exist). 403")
        return self.accounts_and_keys(args)

    def accounts_and_keys(self, args: list[str]) -> Ran:
        """gcloud's answers about service accounts and their keys; a key it
        makes holds the canary in its private key."""
        if self.gcloud["missing"]:
            return Ran(127, "", "gcloud is not installed")
        if args[:3] == ["iam", "service-accounts", "describe"]:
            there = args[3] in self.gcloud["accounts"]
            return Ran(0, args[3]) if there else Ran(1, "", f"NOT_FOUND: Unknown service account {args[3]}")
        keys = self.gcloud["keys"].setdefault(gcloud_flags(args).get("iam-account", ""), [])
        if args[3] == "list":
            return Ran(0, "\n".join(keys) + "\n")
        if args[3] == "create":
            key_id = (f"{len(keys) + 1:x}" * 40)[:40]
            keys.append(key_id)
            return Ran(0, json.dumps({"type": "service_account", "private_key_id": key_id,
                                      "private_key": f"-----BEGIN PRIVATE KEY-----\n{CANARY}\n-----END PRIVATE KEY-----"}))
        if args[3] == "delete":
            keys.remove(args[4])
            return Ran(0, "")
        raise AssertionError(args)


@pytest.fixture
def deploy_world_class() -> type[World]:
    return PubsecWorld


@then("gcloud was called once")
def gcloud_called_once(world):
    assert len(world.calls.get("gcloud", [])) == 1, world.calls.get("gcloud")


@given("gcloud may not make keys")
def gcloud_denies(world):
    world.gcloud["deny_create"] = True


@given(parsers.parse('"{workload}" may act as "{account}" through the pool "{pool}"'))
def may_act(world, workload, account, pool):
    namespace, name = workload.split("/")
    world.gcloud.setdefault("acting", {}).setdefault(account, []).append(
        f"principal://iam.googleapis.com/{pool}/subject/system:serviceaccount:{namespace}:{name}")


@given("an organization policy forbids service account keys")
def policy_forbids(world):
    world.gcloud["policy_forbids"] = True


@given(parsers.parse('PUBSEC_GCP_KEYS_GRANTED_IN is "{where}"'))
def granted_in(world, where):
    world.env["PUBSEC_GCP_KEYS_GRANTED_IN"] = where


@given(parsers.parse('Bitwarden holds "{name}" as the live key "{key_id}" of "{account}"'))
def live_key(world, name, key_id, account):
    world.env[env_name(name)] = key_value(key_id)
    world.values.append(world.env[env_name(name)])
    world.gcloud["keys"][account] = [key_id]


@given(parsers.parse('Bitwarden holds "{name}" as a key "{key_id}" the account does not have'))
def dead_key(world, name, key_id):
    world.env[env_name(name)] = key_value(key_id)
    world.values.append(world.env[env_name(name)])


@given("gcloud is not installed")
def no_gcloud(world):
    world.gcloud["missing"] = True


@then(parsers.parse('Bitwarden was given "{name}" as a key of "{account}"'))
def given_key(world, name, account):
    key = json.loads(base64.b64decode(world.written[name]))
    assert key["private_key_id"] in world.gcloud["keys"][account] and CANARY in key["private_key"]


@then(parsers.parse('"{account}" has no key'))
def no_key(world, account):
    assert world.gcloud["keys"].get(account) == [], world.gcloud["keys"]


def env_name(name: str) -> str:
    """The name ./with-secrets exports a secret under."""
    return name.upper().replace("-", "_")
