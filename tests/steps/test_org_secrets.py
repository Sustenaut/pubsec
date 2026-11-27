"""Steps for `pubsec org-secrets`, against a fake gh: `gh api --include`
answers from an organization kept in a JSON file, as GitHub's REST API does,
and `gh secret set --no-store` prints a stand-in for the sealed box, which
names the public key it was sealed to. Each call is logged with what it read
on its standard input. Nothing reaches the network."""

from __future__ import annotations

import base64
import json
import os
import sys

import pytest
from pytest_bdd import given, parsers, scenarios, then

scenarios("org-secrets.feature")

KEY = "-----BEGIN RSA PRIVATE KEY-----\nTOPSECRETKEYBODY\n-----END RSA PRIVATE KEY-----"
CLIENT_ID = "Iv23liDataReader01"
VALUES = {"DATA_READER_CLIENT_ID": CLIENT_ID, "DATA_READER_KEY": KEY}
REPOSITORIES = {"pubpr": 101, "other-repo": 202, "third-repo": 303}
BLOCK = {"org": "example-org", "repositories": ["pubpr"],
         "app": {"client_id": {"from": "data-reader-client-id", "to": "DATA_APP_CLIENT_ID"},
                 "key": {"from": "data-reader-key", "to": "DATA_APP_KEY"}}}

FAKE_GH = f"""#!{sys.executable}
import base64, json, os, sys, urllib.parse
args = sys.argv[1:]
read = sys.stdin.read()
with open(os.environ["GH_LOG"], "a") as log:
    log.write(json.dumps({{"args": args, "read": read}}) + "\\n")
with open(os.environ["GH_STATE"]) as f:
    state = json.load(f)

def save():
    with open(os.environ["GH_STATE"], "w") as f:
        json.dump(state, f)

if args[:2] == ["secret", "set"]:
    print(base64.b64encode(f"sealed-for-{{state['key_id']}}:{{read.rstrip(chr(10))}}".encode()).decode())
    sys.exit(0)

def answer(status, body=None):
    print(f"HTTP/2.0 {{status}} X\\r\\nContent-Type: application/json\\r\\n\\r\\n" + ("" if body is None else json.dumps(body)))
    if status >= 400:
        sys.stderr.write(f"gh: (HTTP {{status}})\\n")
    sys.exit(1 if status >= 400 else 0)

method = args[args.index("-X") + 1]
url = urllib.parse.urlsplit(next(a for a in args[1:] if a.startswith(("orgs/", "repos/"))))
query = urllib.parse.parse_qs(url.query)
parts = url.path.split("/")
body = json.loads(read) if read else None
if parts[0] == "repos":
    repo = state["repositories"].get(parts[2])
    answer(200, {{"id": repo, "name": parts[2]}}) if repo else answer(404, {{"message": "Not Found"}})
if state.get("deny"):
    answer(403, {{"message": "Resource not accessible by integration"}})
org, kinds = parts[1], parts[3]
held = state[kinds]
if parts[4:] == ["public-key"]:
    answer(200, {{"key_id": state["key_id"], "key": "the-public-key"}})
if len(parts) == 4:
    if method == "GET":
        answer(200, {{"total_count": len(held)}})
    held[body["name"]] = {{"value": body["value"], "visibility": body["visibility"], "repos": body["selected_repository_ids"]}}
    save()
    answer(201, {{}})
name = parts[4]
there = held.get(name)
if len(parts) == 5:
    if method == "GET":
        if there is None:
            answer(404, {{"message": "Not Found"}})
        answer(200, {{"name": name, "visibility": there["visibility"], **({{"value": there["value"]}} if "value" in there else {{}})}})
    if method == "PATCH":
        there["value"] = body["value"]
    if method == "PUT":
        held[name] = {{"sealed": body["encrypted_value"], "key_id": body["key_id"], "visibility": body["visibility"],
                      "repos": body.get("selected_repository_ids", [])}}
    save()
    answer(204 if there else 201)
if len(parts) == 6 and method == "GET":
    size, page = int(query["per_page"][0]), int(query["page"][0])
    ids = sorted(there["repos"])[(page - 1) * size:page * size]
    answer(200, {{"total_count": len(there["repos"]), "repositories": [{{"id": i}} for i in ids]}})
if len(parts) == 7 and method == "PUT":
    if int(parts[6]) not in there["repos"]:
        there["repos"].append(int(parts[6]))
    save()
    answer(204)
answer(404, {{"message": "Not Found"}})
"""


@pytest.fixture
def gh(tmp_path, env):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "gh"
    fake.write_text(FAKE_GH)
    fake.chmod(0o755)
    state = tmp_path / "gh-state.json"
    state.write_text(json.dumps({"repositories": REPOSITORIES, "key_id": "key-1", "secrets": {}, "variables": {}}))
    env["GH_STATE"] = str(state)
    env["GH_LOG"] = str(tmp_path / "gh.log")
    env["PATH"] = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
    return tmp_path


def _state(gh):
    return json.loads((gh / "gh-state.json").read_text())


def _change(gh, change):
    state = _state(gh)
    change(state)
    (gh / "gh-state.json").write_text(json.dumps(state))


def _calls(gh):
    log = gh / "gh.log"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def _writes(gh):
    return [c for c in _calls(gh) if c["args"][:1] == ["api"] and c["args"][c["args"].index("-X") + 1] != "GET"]


@given("a pubrules.json whose org_secrets block names an app's client id and key for pubpr")
def config(repo, gh):
    (repo / "pubrules.json").write_text(json.dumps({"kind": "utility", "org_secrets": BLOCK}))


@given(parsers.parse("a pubrules.json whose org_secrets block reads {text}"))
def config_text(repo, gh, text):
    (repo / "pubrules.json").write_text(json.dumps({"kind": "utility", "org_secrets": json.loads(text)}))


@given("Bitwarden has both values")
def both(env):
    env.update(VALUES)


@given(parsers.parse("Bitwarden's \"{name}\" is {what}"))
def is_what(env, name, what):
    variable = name.upper().replace("-", "_")
    if what == "missing":
        del env[variable]
    else:
        env[variable] = what.strip('"')


@given(parsers.parse('the org has the secret "{name}", visible to "{repos}"'))
def has_secret(gh, name, repos):
    ids = [REPOSITORIES[r] for r in repos.split(",") if r]
    _change(gh, lambda s: s["secrets"].update({name: {"sealed": "old", "key_id": "key-0",
                                                       "visibility": "selected", "repos": ids}}))


@given(parsers.parse('the org has the secret "{name}", visible to all repositories'))
def has_wide_secret(gh, name):
    _change(gh, lambda s: s["secrets"].update({name: {"sealed": "old", "key_id": "key-0",
                                                       "visibility": "all", "repos": []}}))


@given(parsers.parse('the org has the variable "{name}" as "{value}", visible to "{repos}"'))
def has_variable(gh, name, value, repos):
    ids = [REPOSITORIES[r] for r in repos.split(",") if r]
    _change(gh, lambda s: s["variables"].update({name: {"value": value, "visibility": "selected", "repos": ids}}))


@given(parsers.parse('the org has the variable "{name}" as the client id, visible to "{repos}"'))
def has_variable_client_id(gh, name, repos):
    has_variable(gh, name, CLIENT_ID, repos)


@given("gh's login may not manage the org's secrets")
def denied(gh):
    _change(gh, lambda s: s.update(deny=True))


@then(parsers.parse('the secret "{name}" is sealed to the org\'s key, with the key\'s value'))
def secret_sealed(gh, name):
    held = _state(gh)["secrets"][name]
    assert held["key_id"] == "key-1"
    assert base64.b64decode(held["sealed"]).decode() == f"sealed-for-key-1:{KEY}"


@then(parsers.parse('the variable "{name}" holds the client id'))
def variable_holds(gh, name):
    assert _state(gh)["variables"][name]["value"] == CLIENT_ID


@then(parsers.parse('the {kind} "{name}" is visible to selected repositories: "{repos}"'))
def visible_to(gh, kind, name, repos):
    held = _state(gh)[f"{kind}s"][name]
    assert held["visibility"] == "selected"
    assert sorted(held["repos"]) == sorted(REPOSITORIES[r] for r in repos.split(","))


@then("no selection was replaced: repositories were added one at a time")
def added_alone(gh):
    calls = _calls(gh)
    assert not any("--repos" in c["args"] or "-r" in c["args"] for c in calls)
    methods = [c["args"][c["args"].index("-X") + 1] for c in calls if c["args"][:1] == ["api"]]
    assert "DELETE" not in methods
    for call in _writes(gh):
        if call["read"]:
            body = json.loads(call["read"])
            assert body.get("selected_repository_ids", []) == [] or "secrets" in " ".join(call["args"]), call


@then(parsers.parse('the secret "{name}" was set keeping "{repos}" selected'))
def kept_selection(gh, name, repos):
    put = [json.loads(c["read"]) for c in _writes(gh) if f"orgs/example-org/actions/secrets/{name}" in c["args"]]
    assert [p["selected_repository_ids"] for p in put] == [sorted(REPOSITORIES[r] for r in repos.split(","))]


@then("gh wrote nothing")
def wrote_nothing(gh):
    assert _writes(gh) == []
    assert not any(c["args"][:2] == ["secret", "set"] for c in _calls(gh))


@then(parsers.parse("gh was called {count:d} times"))
def called(gh, count):
    assert len(_calls(gh)) == count


@then("no value is printed or on a command line")
def no_value(gh, result):
    printed = result.stdout + result.stderr
    assert "TOPSECRETKEYBODY" not in printed
    assert CLIENT_ID not in printed
    for call in _calls(gh):
        line = " ".join(call["args"])
        assert "TOPSECRETKEYBODY" not in line and CLIENT_ID not in line, call
