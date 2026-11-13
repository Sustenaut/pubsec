"""The canary: no secret value ever reaches what `pubdeploy` prints
when it walks pubsec's types, nor what pubsec's write-token hook says.

Every fake Secret value, every fake Bitwarden value, the write token, every
fake key JSON and what the deploy channel shows of a Secret hold CANARY, and
every value a fulfil generates is kept as one too. Each test drives the
checks, and the fulfils, through a state where values are read, judged,
generated and moved, and what comes out (stdout, stderr, the journal, any
exception's text, and every argv kubectl, ssh, gcloud or gh was given) must
not hold one: a value moves on a standard input only. This test must never
be weakened: a check or a fulfil that needs to show a value is wrong, not
the test."""

from __future__ import annotations

import json

import pytest

from deploy_world import CANARY, run, world  # noqa: F401 - the fixture
from pubdeploy import load
from pubdeploy.model import Need, Result
from pubdeploy.registry import types
from pubdeploy.walk import walk

STATES = {
    "all well": lambda w: None,
    "a bad cookie in the cluster": lambda w: w.cluster["namespaces"]["example"]["secrets"]["example-page-secrets"]
    .update({"cookie-secret": (CANARY + "+/+/").encode()}),
    "a bad cookie in Bitwarden": lambda w: w.env.update({"EXAMPLE_COOKIE_SECRET": CANARY + "+/+/" * 6}),
    "a variable that differs from Bitwarden": lambda w: w.env.update({"EXAMPLE_USER": CANARY + "-other"}),
    "a Secret without its key": lambda w: w.cluster["namespaces"]["example"]["secrets"]["example-files"]
    .update({"other": CANARY.encode()}) or w.cluster["namespaces"]["example"]["secrets"]["example-files"]
    .pop("token"),
    "nothing reachable": lambda w: w.http.clear(),
    "kubectl forbidden": lambda w: w.cluster.update({"forbidden": True}),
    "GitHub forbidden": lambda w: w.github.update({"forbidden": True}),
    "outside with-secrets": lambda w: w.env.pop("PUBKIT_SECRETS_PROJECT"),
    "nothing in the cluster": lambda w: w.cluster["namespaces"].pop("example") and None,
    "no cookie in Bitwarden, nor its Secret": lambda w: w.env.pop("EXAMPLE_COOKIE_SECRET") and
    w.cluster["namespaces"]["example"]["secrets"].pop("example-page-secrets") and None,
    "over the deploy channel": lambda w: setattr(w, "channel", "deploy"),
    "over the deploy channel, before secret-keys": lambda w: setattr(w, "channel", "deploy") or
    w.cluster.update({"secret_keys_verb": False}),
    "GitHub without its secrets": lambda w: w.github.update({"secrets": set()}),
    "a key to make": lambda w: w.block["needs"].append({
        "type": "gcp.service-account-key", "account": "example-files", "project": "example-project",
        "bitwarden": "example-files-key"}),
    "a key Bitwarden refuses": lambda w: w.block["needs"].append({
        "type": "gcp.service-account-key", "account": "example-files", "project": "example-project",
        "bitwarden": "example-files-key"}) or setattr(w, "bitwarden_refuses", True),
    "kubectl refusing writes": lambda w: w.cluster["namespaces"]["example"]["secrets"].pop("example-files")
    and w.cluster.update({"refuse_writes": True}),
}


@pytest.mark.parametrize("state", sorted(STATES))
@pytest.mark.parametrize("argv", [("check",), ("check", "--json"),
                                  ("check", "--offline", "--json"), ("walk", "--fulfil", "--yes"),
                                  ("walk", "--fulfil", "--yes", "--json")])
def test_no_value_is_printed(world, capsys, state, argv):
    STATES[state](world)
    run(world, capsys, *argv)
    assert world.code in (0, 1)
    for text in world.outputs:
        assert CANARY not in text
    assert not world.leaked(), world.leaked()[0][:500]


def test_an_exception_holding_a_value_is_not_shown(world, capsys):
    class Leaky:
        type, grade, budget, offline, schema = "example.leaky", "none", 1.0, True, {}

        def default_name(self, params):
            return None

        def depends_on(self, need, needs):
            return []

        def check(self, need, ctx):
            raise ValueError(f"the value is {CANARY}")

        def fulfil(self, need, ctx):
            raise NotImplementedError("phase 2")

    need = Need("example.leaky", "one", {})
    journal = walk({need.id: need}, {"example.leaky": Leaky()}, world.context(), service={})
    world.journal = journal.document()
    (_, result), = journal.entries
    assert result.state == "unknown"
    assert result.summary == "the check failed (ValueError)"
    assert CANARY not in journal.json()


def test_a_value_in_the_rendered_manifests_is_not_shown(world, capsys):
    world.rendered += ("---\napiVersion: v1\nkind: Secret\nmetadata: {name: example-held, namespace: example}\n"
                       f"stringData: {{cookie: {CANARY}}}\n")
    run(world, capsys, "check", "--offline")
    assert CANARY not in world.stdout + world.stderr


def test_every_result_of_the_sound_fixture_is_free_of_values(world):
    ctx = world.context()
    plan = load(world.root, world.config, ctx)
    journal = walk(plan.needs, types(), ctx, service={})
    world.journal = journal.document()
    assert all(isinstance(r, Result) for _, r in journal.entries)
    assert CANARY not in journal.json()


def test_a_fulfil_that_raises_holding_a_value_is_not_shown(world):
    from pubdeploy.walk import fulfil  # noqa: PLC0415

    class Leaky:
        type, grade, budget, offline, schema = "example.leaky", "auto", 1.0, True, {}

        def default_name(self, params):
            return None

        def depends_on(self, need, needs):
            return []

        def check(self, need, ctx):
            return Result("missing", "not there")

        def fulfil(self, need, ctx):
            raise ValueError(f"the value is {CANARY}")

    need = Need("example.leaky", "one", {})
    kinds = {"example.leaky": Leaky()}
    ctx = world.context()
    journal = fulfil(walk({need.id: need}, kinds, ctx, service={}), kinds, ctx, {need.id})
    world.journal = journal.document()
    (_, result), = journal.entries
    assert result.state == "missing" and result.details[0].startswith("fulfil failed: the fulfil failed (ValueError)")
    assert CANARY not in journal.json()


def test_generated_values_stay_in_the_walk(world, capsys):
    """ctx.values holds what a fulfil made: never journaled, printed or kept."""
    world.env.pop("EXAMPLE_COOKIE_SECRET")
    run(world, capsys, "walk", "--fulfil", "--yes", "--json")
    made = world.written["example-cookie-secret"]
    assert made in world.values
    assert made not in "".join(world.outputs) + json.dumps(world.journal)


def test_the_types_walked_are_pubsecs(world):
    """The seven reach the walk by their entry points, as installed, and are pubsec's."""
    from pubdeploy.registry import load as registry  # noqa: PLC0415
    from deploy_world import OURS  # noqa: PLC0415
    loaded = registry()
    assert {kind: loaded.origin[kind] for kind in OURS} == dict.fromkeys(OURS, "pubsec"), loaded.warnings
    assert all(type(loaded.types[kind]).__module__.startswith("pubsec.needs.") for kind in OURS)


def test_the_hook_asks_once_and_says_no_token(world, monkeypatch):
    """prepare() asks for the token once in a process, for every unit, and keeps it out of what it says."""
    import pubsec.walk  # noqa: PLC0415
    asked: list[str] = []
    monkeypatch.setattr(pubsec.walk, "ask_hidden", lambda prompt: asked.append(prompt) or world.token)
    first, second = world.context(), world.context()
    assert pubsec.walk.prepare(first, [], True) is None
    assert pubsec.walk.prepare(second, [], True) is None
    assert len(asked) == 1 and "example" in asked[0]
    assert first.bitwarden_writer is second.bitwarden_writer is not None
    assert CANARY not in "".join(asked)


def test_the_hook_without_a_terminal_or_a_project_asks_nothing(world, monkeypatch):
    import pubsec.walk  # noqa: PLC0415
    monkeypatch.setattr(pubsec.walk, "ask_hidden", lambda prompt: pytest.fail("asked for a token"))
    ctx = world.context()
    assert pubsec.walk.prepare(ctx, [], False) is None and ctx.bitwarden_writer is None
    ctx.env.pop("PUBKIT_SECRETS_PROJECT")
    said = pubsec.walk.prepare(ctx, [], True)
    assert ctx.bitwarden_writer is None and "no Bitwarden project" in said


def test_without_a_terminal_the_token_comes_from_the_file_alone(world, monkeypatch, tmp_path):
    import pubsec.walk  # noqa: PLC0415
    monkeypatch.setattr(pubsec.walk, "_writers", {})
    monkeypatch.setattr(pubsec.walk, "ask_hidden", lambda prompt: pytest.fail("asked for a token"))
    token = tmp_path / "write-token"
    token.write_text(world.token + "\n")
    ctx = world.context()
    ctx.env["PUBSEC_WRITE_TOKEN"] = "never-read"
    ctx.env["PUBSEC_WRITE_TOKEN_FILE"] = str(token)
    assert pubsec.walk.prepare(ctx, [], False) is None
    assert ctx.bitwarden_writer is not None and world.token in (getattr(ctx.bitwarden_writer, "token", None), getattr(ctx.bitwarden_writer, "_token", None))


def test_a_token_file_that_cannot_be_read_gives_no_writer(world, monkeypatch, tmp_path):
    import pubsec.walk  # noqa: PLC0415
    monkeypatch.setattr(pubsec.walk, "_writers", {})
    ctx = world.context()
    ctx.env["PUBSEC_WRITE_TOKEN_FILE"] = str(tmp_path / "gone")
    said = pubsec.walk.prepare(ctx, [], False)
    assert ctx.bitwarden_writer is None and "no Bitwarden write token" in said


def test_the_hook_with_an_empty_token_gives_no_writer(world, monkeypatch):
    import pubsec.walk  # noqa: PLC0415
    monkeypatch.setattr(pubsec.walk, "ask_hidden", lambda prompt: "")
    ctx = world.context()
    said = pubsec.walk.prepare(ctx, [], True)
    assert ctx.bitwarden_writer is None and "no Bitwarden write token" in said


def test_the_writer_finds_the_secret_by_its_identifier_and_writes_in_memory(monkeypatch):
    """BitwardenWriter looks the name up among identifiers, reading no value,
    and a refusal it raises holds neither the token nor the value."""
    import pubsec.bitwarden  # noqa: PLC0415
    import pubsec.service_account_key  # noqa: PLC0415
    from pubsec.walk import BitwardenWriter  # noqa: PLC0415
    token, value = f"{CANARY}-write-token", f"{CANARY}-value"
    calls: list[tuple] = []
    monkeypatch.setattr(pubsec.bitwarden, "ensure", lambda: None)
    monkeypatch.setattr(pubsec.service_account_key, "find_project", lambda t, name: ("project-id", "org-id"))
    monkeypatch.setattr(pubsec.bitwarden, "names", lambda t, org, project: calls.append(("names", org, project))
                        or {"example-key": ["secret-id"]})
    monkeypatch.setattr(pubsec.bitwarden, "values", lambda t, ids: pytest.fail("a value was read"))

    def write(t, org, project, name, given, note, secret=None):
        calls.append(("write", org, project, name, secret))
        if name == "refused":
            raise pubsec.bitwarden.WriteFailed(pubsec.bitwarden.scrub(f"403 for {given} with {t}", (t, given)))
    monkeypatch.setattr(pubsec.bitwarden, "write", write)
    writer = BitwardenWriter(token, "example")
    writer.write("example-key", value, "a note")
    assert calls == [("names", "org-id", "project-id"), ("write", "org-id", "project-id", "example-key", "secret-id")]
    with pytest.raises(pubsec.bitwarden.WriteFailed) as refused:
        writer.write("refused", value, "a note")
    assert CANARY not in str(refused.value) and "[hidden]" in str(refused.value)
    assert CANARY not in repr(writer.__dict__.get("project"))
