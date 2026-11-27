"""`pubsec org-secrets`: set an organization's Actions secrets and variables
from what pubrules.json names, visible to the repositories it lists.

`org_secrets` is one app's values for one organization, or a list of them. Its
`app` takes the github_app block's slots, any of them, and checks their values
the same way:

    "org_secrets": {
      "org": "some-org",
      "repositories": ["some-repo"],
      "app": {
        "client_id": {"from": "some-app-client-id", "to": "SOME_APP_CLIENT_ID"},
        "key":       {"from": "some-app-key", "to": "SOME_APP_KEY"}
      }
    }

As in app-secrets, an app's id, installation id and client id go as variables
(a workflow reads `vars.X`) and its key as a secret. Each is visible to selected
repositories, and the run adds the ones listed, one at a time, to its
selection: a repository already selected stays, and none is ever taken off. An
existing one visible to all or to private repositories is not narrowed: the
run refuses before writing anything, as narrowing it would take it from others.

    ./with-secrets ./pubsec org-secrets --check   # reports drift, writes nothing
    ./with-secrets ./pubsec org-secrets

It reads the values with-secrets exported and checks them, then GitHub's side,
and shows the plan before it writes; nothing is written unless all of that
passed. `--check` says, per name, whether it exists, is visible to selected
repositories, and which of the listed repositories it is not visible to, and
for a variable whether its value is the one in Bitwarden. A secret's value
cannot be compared: GitHub never returns one.

Everything goes through gh, signed in as someone who may manage the
organization's secrets (an owner, with the admin:org scope). A secret's value
reaches `gh secret set --no-store` on its standard input, which seals it to
the organization's public key and prints only the sealed box; that goes to
`gh api` on its standard input too. No value is printed or on a command line.
`gh secret set --org --repos` is not used: it replaces the selection.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

from .app_secrets import SLOTS, env_name, slot_problems, wrong_value
from .bitwarden import scrub

BLOCK = "org_secrets"
SETTINGS = {"org", "repositories", "app"}
OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+")
NEEDS_ADMIN = ("this gh login may not manage {org}'s Actions secrets and variables: that takes an "
               "organization owner with the admin:org scope (gh auth refresh -h github.com -s admin:org), "
               "or a token with the organization's Secrets and Variables permissions")
PAGE = 100


class Stop(Exception):
    """Something that ends the run, with what to tell the person running it."""


@dataclass
class Item:
    """One named value for one organization, and what GitHub has of it."""

    org: str
    slot: str
    source: str
    name: str
    kind: str
    repositories: list[str]
    exists: bool = False
    visibility: str | None = None
    selected: set[int] = field(default_factory=set)
    value: str | None = None

    @property
    def path(self) -> str:
        return f"orgs/{self.org}/actions/{self.kind}s/{self.name}"

    @property
    def label(self) -> str:
        return f"{self.kind} {self.name}"


def app_problems(app: Any) -> list[str]:
    """What is wrong with one org_secrets block: one phrase each."""
    if not isinstance(app, dict):
        return ["each must be an object, with org, repositories and app"]
    out = [f"{key} is not a setting; it takes org, repositories and app" for key in sorted(app.keys() - SETTINGS)]
    org = app.get("org")
    if not (isinstance(org, str) and OWNER.fullmatch(org)):
        out.append('"org" is not an organization\'s name')
    repositories = app.get("repositories")
    if not (isinstance(repositories, list) and repositories):
        out.append('"repositories" must list the repositories, by name, that may read them')
    else:
        out += [f"{json.dumps(name)} is not a repository's name, without its owner" for name in repositories
                if not (isinstance(name, str) and REPOSITORY.fullmatch(name) and name not in (".", ".."))]
    slots = app.get("app")
    if not (isinstance(slots, dict) and slots):
        return [*out, f'"app" must name one or more of {", ".join(SLOTS)}']
    out += [f"{key} is not a setting; app takes {', '.join(SLOTS)}" for key in sorted(slots.keys() - SLOTS.keys())]
    for slot in SLOTS:
        if slot in slots:
            out += slot_problems(slot, slots[slot])
    return out


def problems(block: Any) -> list[str]:
    """What is wrong with an org_secrets block, one or a list, including a name used twice."""
    apps = block if isinstance(block, list) else [block]
    if not apps:
        return ["it lists nothing"]
    if out := [problem for app in apps for problem in app_problems(app)]:
        return out
    names = [(item.org.lower(), item.kind, item.name) for item in plan(block)]
    return [f"two of them set the {kind} {name} in {org}" for org, kind, name in sorted(set(names))
            if names.count((org, kind, name)) > 1]


def plan(block: Any) -> list[Item]:
    """Every value the block names, in order."""
    apps = block if isinstance(block, list) else [block]
    return [Item(app["org"], slot, app["app"][slot]["from"], app["app"][slot]["to"], kind,
                 list(dict.fromkeys(app["repositories"])))
            for app in apps for slot, kind in SLOTS.items() if slot in app["app"]]


def gh_api(method: str, path: str, what: str, org: str, body: Any = None) -> Any:
    """One call to GitHub's API through gh; its answer, or None for a 404 to a GET."""
    argv = ["gh", "api", "--include", "-X", method, "-H", "Accept: application/vnd.github+json",
            "-H", "X-GitHub-Api-Version: 2022-11-28", path]
    if body is not None:
        argv += ["--input", "-"]
    done = subprocess.run(argv, input="" if body is None else json.dumps(body), text=True,
                          capture_output=True, check=False)
    head, _, rest = done.stdout.replace("\r\n", "\n").partition("\n\n")
    status = head.split()[1] if head.startswith("HTTP/") and len(head.split()) > 1 else ""
    if not status.isdigit():
        said = done.stderr.strip() or f"gh exited {done.returncode}"
        raise Stop(f"gh could not ask GitHub for {what}: {said}")
    try:
        answer = json.loads(rest) if rest.strip() else None
    except ValueError:
        answer = None
    code = int(status)
    if code < 300:
        return answer
    if code == 404 and method == "GET":
        return None
    if code == 403:
        raise Stop(f"GitHub answered {what} with 403: {NEEDS_ADMIN.format(org=org)}")
    if code == 401:
        raise Stop(f"GitHub answered {what} with 401: gh is not signed in (gh auth login)")
    said = answer.get("message", "") if isinstance(answer, dict) else ""
    raise Stop(f"GitHub answered {what} with {code} {said}".rstrip())


def public_key(org: str) -> dict:
    key = gh_api("GET", f"orgs/{org}/actions/secrets/public-key", f"{org}'s public key for secrets", org)
    if key is None:
        raise Stop(f"there is no organization {org}, or this gh login cannot see its secrets: "
                   + NEEDS_ADMIN.format(org=org))
    if not (isinstance(key, dict) and key.get("key_id") and key.get("key")):
        raise Stop(f"GitHub's answer for {org}'s public key has no key_id and key")
    return key


def probe(org: str, items: list[Item]) -> dict | None:
    """Ask for something that needs the same rights as the writes, so a login
    that lacks them stops here: the public key, when there is a secret to seal."""
    if any(item.kind == "secret" for item in items):
        return public_key(org)
    if gh_api("GET", f"orgs/{org}/actions/variables?per_page=1", f"{org}'s variables", org) is None:
        raise Stop(f"there is no organization {org}, or this gh login cannot see its variables: "
                   + NEEDS_ADMIN.format(org=org))
    return None


def repository_ids(org: str, names: list[str]) -> dict[str, int]:
    out = {}
    for name in names:
        found = gh_api("GET", f"repos/{org}/{name}", f"the repository {org}/{name}", org)
        if not isinstance(found, dict) or not isinstance(found.get("id"), int):
            raise Stop(f"there is no repository {org}/{name}, or this gh login cannot see it")
        out[name] = found["id"]
    return out


def read_state(item: Item) -> None:
    """What GitHub has of the item: whether it is there, who sees it, and a variable's value."""
    found = gh_api("GET", item.path, f"the {item.label} in {item.org}", item.org)
    if found is None:
        return
    item.exists = True
    item.visibility = found.get("visibility") if isinstance(found, dict) else None
    item.value = found.get("value") if isinstance(found, dict) and item.kind == "variable" else None
    if item.visibility != "selected":
        return
    for page in itertools.count(1):
        listed = gh_api("GET", f"{item.path}/repositories?per_page={PAGE}&page={page}",
                        f"the repositories that see the {item.label} in {item.org}", item.org)
        repositories = listed.get("repositories", []) if isinstance(listed, dict) else []
        item.selected |= {repository["id"] for repository in repositories}
        if len(repositories) < PAGE:
            return


def drift(item: Item, ids: dict[str, int], value: str) -> list[str]:
    """How GitHub's side differs from the config, one phrase each; none when it matches."""
    if not item.exists:
        return ["missing"]
    if item.visibility != "selected":
        return [f"visible to {item.visibility or 'unknown'} repositories, not selected ones"]
    out = []
    if item.kind == "variable" and item.value != value:
        out.append("its value differs from Bitwarden's")
    if missing := [name for name in item.repositories if ids[name] not in item.selected]:
        out.append(f"not visible to {', '.join(missing)}")
    return out


def sealed(item: Item, value: str) -> str:
    """The value sealed to the organization's public key by gh, which prints only that."""
    done = subprocess.run(["gh", "secret", "set", item.name, "--org", item.org, "--no-store"],
                          input=value, text=True, capture_output=True, check=False)
    box = done.stdout.strip()
    if done.returncode != 0 or not box:
        said = scrub(done.stderr, (value,)).strip() or f"gh exited {done.returncode}"
        raise Stop(f"gh could not seal the {item.label}: {said}")
    return box


def write(item: Item, ids: dict[str, int], value: str, key: dict | None) -> None:
    """Set the item's value, keeping who already sees it, then add each listed repository."""
    if item.kind == "secret":
        box = sealed(item, value)
        if public_key(item.org)["key_id"] != key["key_id"]:
            raise Stop(f"{item.org}'s public key changed while the {item.label} was sealed; run this again")
        # The selection as it is, so that the write keeps it, whatever GitHub
        # takes an absent list to mean; the listed repositories are added below.
        gh_api("PUT", item.path, f"the {item.label}", item.org,
               {"encrypted_value": box, "key_id": key["key_id"], "visibility": "selected",
                "selected_repository_ids": sorted(item.selected)})
        print(f"  set      {item.label} in {item.org}")
    elif not item.exists:
        gh_api("POST", f"orgs/{item.org}/actions/variables", f"the new {item.label}", item.org,
               {"name": item.name, "value": value, "visibility": "selected", "selected_repository_ids": []})
        print(f"  set      {item.label} in {item.org}")
    elif item.value != value:
        gh_api("PATCH", item.path, f"the {item.label}", item.org, {"value": value})
        print(f"  set      {item.label} in {item.org}")
    else:
        print(f"  same     {item.label} in {item.org}: its value is already Bitwarden's")
    for name in item.repositories:
        if ids[name] in item.selected:
            continue
        gh_api("PUT", f"{item.path}/repositories/{ids[name]}", f"adding {name} to the {item.label}", item.org)
        print(f"  added    {name} to {item.label}")


def values(items: list[Item]) -> dict[str, str] | None:
    """The values with-secrets exported, each checked; None, having said why, if one is wrong."""
    out: dict[str, str] = {}
    failed = False
    print("Names and values")
    for item in items:
        if item.source in out:
            continue
        value = os.environ.get(env_name(item.source))
        if value is None:
            print(f"  MISSING  {item.source}")
            failed = True
        elif (wrong := wrong_value(item.slot, value)) is not None:
            print(f"  BAD      {item.source} {wrong} ({len(value)} characters)")
            failed = True
        else:
            print(f"  ok       {item.source} ({len(value)} characters)")
            out[item.source] = value
    if failed:
        print("Nothing was written. Fix those in Bitwarden, or the names in pubrules.json, and run "
              "this through ./with-secrets, which reads them.")
        return None
    return out


def sync(config: dict, check: bool) -> int:
    if BLOCK not in config:
        raise Stop(f"pubrules.json has no {BLOCK} block")
    if bad := problems(config[BLOCK]):
        raise Stop(f"pubrules.json: {BLOCK}: {'; '.join(bad)}")
    items = plan(config[BLOCK])
    if (given := values(items)) is None:
        return 1
    orgs = list(dict.fromkeys(item.org for item in items))
    keys, ids = {}, {}
    for org in orgs:
        mine = [item for item in items if item.org == org]
        keys[org] = probe(org, mine)
        ids[org] = repository_ids(org, list(dict.fromkeys(name for item in mine for name in item.repositories)))
        for item in mine:
            read_state(item)
    drifted = 0
    for org in orgs:
        print(f"In {org}:")
        for item in (item for item in items if item.org == org):
            if found := drift(item, ids[org], given[item.source]):
                drifted += 1
                print(f"  drift    {item.label}: {'; '.join(found)}")
            else:
                seen = "" if item.kind == "variable" else " (its value is not compared)"
                print(f"  ok       {item.label}: visible to {', '.join(item.repositories)}{seen}")
    if check:
        print("A secret's value is never compared: GitHub never returns one.")
        if drifted:
            print(f"{drifted} of {len(items)} differ. --check: nothing was written.")
            return 1
        print(f"All {len(items)} match. --check: nothing was written.")
        return 0
    if wide := [item for item in items if item.exists and item.visibility != "selected"]:
        names = ", ".join(f"{item.label} in {item.org}" for item in wide)
        raise Stop(f"{names}: visible to more than selected repositories. pubsec only adds repositories to a "
                   "selection, and narrowing it would take it from others, so nothing was written. Make it "
                   "visible to selected repositories on GitHub, or delete it, and run this again.")
    print("Writing")
    for item in items:
        write(item, ids[item.org], given[item.source], keys[item.org])
    print(f"Done: {len(items)} values, each visible to its listed repositories and those it already had.")
    return 0


def run(config: dict, check: bool) -> int:
    try:
        return sync(config, check)
    except Stop as error:
        print(f"pubsec org-secrets: {error}")
        return 1
