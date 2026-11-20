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
from pytest_bdd import given, parsers, scenarios, then, when

from pubdeploy.contract import Need, Result, problems
from pubdeploy.testing.world import CANARY, run, walk_needs

# The types pubsec offers.
OURS = {"bitwarden.secret", "bitwarden.generated", "gcp.service-account-key", "github.secret",
        "github.variable", "github.deploy-settings", "k8s.secret"}

scenarios("canary.feature")

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
    "outside with-secrets": lambda w: w.env.pop("PUBRULES_SECRETS_PROJECT"),
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


@given(parsers.parse('the deploy world with {state}'))
def in_state(world, state):
    STATES[state](world)


@when(parsers.parse('pubdeploy runs "{argv}"'))
def runs(world, ctx, argv):
    run(world, ctx, *argv.split())


@then("no value is printed, passed to a program or kept in the journal")
def no_value(world):
    assert world.code in (0, 1)
    for text in world.outputs:
        assert CANARY not in text
    assert not world.leaked(), world.leaked()[0][:500]


class Leaky:
    """A need type that holds a value where it must not: in what its check, or its fulfil, raises."""

    type, budget, offline, schema = "example.leaky", 1.0, True, {}

    def __init__(self, raises_in: str) -> None:
        self.raises_in = raises_in
        self.grade = "none" if raises_in == "check" else "auto"

    def default_name(self, params):
        return None

    def depends_on(self, need, needs):
        return []

    def check(self, need, ctx):
        if self.raises_in == "check":
            raise ValueError(f"the value is {CANARY}")
        return Result("missing", "not there")

    def fulfil(self, need, ctx):
        raise ValueError(f"the value is {CANARY}")


@given(parsers.parse("a need type whose {part} raises, holding a value"))
def leaky(world, part):
    world.leaky = Leaky(part)


LEAKY = Need("example.leaky", "one", {})


@when("that need is walked")
def leaky_walked(ctx, world):
    ctx.attempt(lambda: walk_needs(world, [LEAKY], {LEAKY.type: world.leaky}))


@when("that need is walked and fulfilled")
def leaky_fulfilled(ctx, world):
    ctx.attempt(lambda: walk_needs(world, [LEAKY], {LEAKY.type: world.leaky}, fulfil=[LEAKY.id]))


@given("the rendered manifests hold a Secret with a value")
def rendered_secret(world):
    world.rendered += ("---\napiVersion: v1\nkind: Secret\nmetadata: {name: example-held, namespace: example}\n"
                       f"stringData: {{cookie: {CANARY}}}\n")


@when("the fixture's needs are walked")
def fixture_walked(ctx, world):
    ctx.attempt(lambda: walk_needs(world))


@then("every need came to a result")
def every_result(world):
    needs = world.journal["needs"]
    assert needs and all(n["state"] in ("ready", "missing", "drift", "blocked", "unknown") for n in needs), needs


@given("Bitwarden holds no cookie")
def no_cookie(world):
    world.env.pop("EXAMPLE_COOKIE_SECRET")


@then("the value the fulfil made stays in the walk")
def made_stays(world):
    """ctx.values holds what a fulfil made: never journaled, printed or kept."""
    made = world.written["example-cookie-secret"]
    assert made in world.values
    assert made not in "".join(world.outputs) + json.dumps(world.journal)


@when("the need types are loaded")
def types_loaded(ctx):
    """The seven reach the walk by their entry points, as installed: where each came from, and its
    package, each a need type by pubdeploy's contract."""
    from importlib.metadata import entry_points  # noqa: PLC0415

    def loaded():
        found = {}
        for point in entry_points(group="sustenaut.needs"):
            kind = point.load()
            assert not problems(kind), (point.name, problems(kind))
            found[kind.type] = {"origin": point.dist.name,
                                "package": ".".join(type(kind).__module__.split(".")[:2])}
        return {kind: found[kind] for kind in OURS}
    ctx.attempt(loaded)


@given("a terminal that answers the write token")
def terminal_answers(world, monkeypatch):
    import pubsec.walk  # noqa: PLC0415
    world.asked = []
    monkeypatch.setattr(pubsec.walk, "ask_hidden", lambda prompt: world.asked.append(prompt) or world.token)


@given("a terminal that answers nothing")
def terminal_empty(world, monkeypatch):
    import pubsec.walk  # noqa: PLC0415
    world.asked = []
    monkeypatch.setattr(pubsec.walk, "ask_hidden", lambda prompt: world.asked.append(prompt) or "")


@given("a terminal that must not be asked")
def terminal_unasked(world, monkeypatch):
    import pubsec.walk  # noqa: PLC0415
    world.asked = []
    monkeypatch.setattr(pubsec.walk, "ask_hidden", lambda prompt: pytest.fail("asked for a token"))


@given("the walk names no Bitwarden project")
def no_project(world):
    world.env.pop("PUBRULES_SECRETS_PROJECT")


@given("a write token file holding the write token, and the token in the environment too")
def token_file(world, tmp_path):
    token = tmp_path / "write-token"
    token.write_text(world.token + "\n")
    world.env.update({"PUBSEC_WRITE_TOKEN": "never-read", "PUBSEC_WRITE_TOKEN_FILE": str(token)})


@given("a write token file that cannot be read")
def token_file_gone(world, tmp_path):
    world.env["PUBSEC_WRITE_TOKEN_FILE"] = str(tmp_path / "gone")


@when(parsers.re(r"the hook prepares (?P<count>a unit|two units) (?P<how>with|without) a terminal"))
def hook_prepares(ctx, world, count, how):
    """What pubsec's sustenaut.walk hook said for each unit, what it asked, and the writers it gave them."""
    import pubsec.walk  # noqa: PLC0415

    def prepared():
        contexts = [world.context() for _ in range(1 if count == "a unit" else 2)]
        said = [pubsec.walk.prepare(c, [], how == "with") for c in contexts]
        writers = [c.bitwarden_writer for c in contexts if c.bitwarden_writer is not None]
        return {"said": said, "asked": getattr(world, "asked", []), "units with a writer": len(writers),
                "writers": len({id(w) for w in writers}),
                "token from the file": any(world.token in (getattr(w, "token", None), getattr(w, "_token", None))
                                           for w in writers)}
    ctx.attempt(prepared)


@given(parsers.parse('Bitwarden\'s SDK, whose project holds "{name}" as "{secret}"'))
def sdk(ctx, monkeypatch, name, secret):
    import pubsec.bitwarden  # noqa: PLC0415
    import pubsec.service_account_key  # noqa: PLC0415
    ctx.calls = []
    monkeypatch.setattr(pubsec.bitwarden, "ensure", lambda: None)
    monkeypatch.setattr(pubsec.service_account_key, "find_project", lambda t, project: ("project-id", "org-id"))
    monkeypatch.setattr(pubsec.bitwarden, "names", lambda t, org, project: ctx.calls.append(["names", org, project])
                        or {name: [secret]})
    monkeypatch.setattr(pubsec.bitwarden, "values", lambda t, ids: pytest.fail("a value was read"))

    def write(t, org, project, written, given, note, secret=None):
        ctx.calls.append(["write", org, project, written, secret])
        if written == "refused":
            raise pubsec.bitwarden.WriteFailed(pubsec.bitwarden.scrub(f"403 for {given} with {t}", (t, given)))
    monkeypatch.setattr(pubsec.bitwarden, "write", write)


@when(parsers.parse('the writer writes "{name}"'))
def writer_writes(ctx, name):
    """BitwardenWriter looks the name up among identifiers, reading no value; what it was
    asked, and the project it keeps, are the result."""
    from pubsec.walk import BitwardenWriter  # noqa: PLC0415
    writer = BitwardenWriter(f"{CANARY}-write-token", "example")

    def written():
        writer.write(name, f"{CANARY}-value", "a note")
        return {"calls": ctx.calls, "project": repr(writer.__dict__.get("project"))}
    ctx.attempt(written)
