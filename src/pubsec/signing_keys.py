"""`pubsec signing-key backup`: copy the signing keys repositories declare to Bitwarden.

A repository says which signing keys it uses, and where each is backed up, in
pubrules.json:

    "signing_keys": [
      {"path": "corpus/.publet/signing.key",
       "bitwarden": {"project": {"id": "PROJECT-UUID", "name": "Pub"},
                     "name": "pub-signing-key-example"}}
    ]

`path` is from the repository's root, or from the home directory when it
starts with "~/": a key kept outside any repository is declared by the one
whose tools use it. The project is found by its id; its name is a label for
people, and a run warns when Bitwarden's name for it has changed. A plain
string is taken as an id when it is a UUID, else as a name, in any case.

    pubsec signing-key backup [--under DIR] [--dry-run]

reads the declarations of this repository, or of every repository directly
under DIR, and writes each key that is on this machine and not yet in its
Bitwarden project, with Bitwarden's SDK, from memory. A secret already
there is found by name among the project's identifiers, and only the values
of those named as the keys are read, to compare. It asks for an access
token that may read and write those projects at a hidden prompt. A secret
already there with the same value is left alone; one with another value is
never overwritten, and fails the run. --dry-run says what it would write and
asks for nothing. No key or token is printed, put on a command line or
written anywhere else.

    pubsec signing-key restore [NAME ...] [--under DIR] [--dry-run]

is the other way: each declared key that is not on this machine (only those
NAMEd, when any are) is read from its Bitwarden project, its value alone,
and written to its declared path, readable by its owner alone (0600, in a
directory only the owner may enter). A key already on this machine is never
overwritten, and a name the project does not hold, or holds twice, fails
the run. The token may be one that only reads. A restored corpus key is the
key file alone: `pubdoc corpus init` (or `pub sign --restore-key`) then
rebuilds the corpus's store around it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

CONFIG = "pubrules.json"
FIELD = "signing_keys"
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
# Where a corpus keeps the key pub signs with: a package's corpus/, or a
# corpus at the repository's root.
KEY_PLACES = ("corpus/.publet/signing.key", ".publet/signing.key")


@dataclass(frozen=True)
class Declared:
    repo: Path
    path: Path
    project: str  # the project's id, or the name a plain string gave
    name: str
    label: str | None = None  # the project's name, as the declaration gives it

    @property
    def shown(self) -> str:
        return f"{self.label} ({self.project})" if self.label else self.project


def problems(block: object) -> list[str]:
    """What is wrong with a pubrules.json `signing_keys` block: one phrase each."""
    if block is None:
        return []
    if not isinstance(block, list):
        return [f"{FIELD} must be a list"]
    out: list[str] = []
    names: set[tuple[str, str]] = set()
    for i, entry in enumerate(block):
        where = f"{FIELD}[{i}]"
        if not isinstance(entry, dict):
            out.append(f"{where} must be an object")
            continue
        out += [f"{where}: {key} is not a setting" for key in sorted(entry.keys() - {"path", "bitwarden"})]
        path = entry.get("path")
        if not (isinstance(path, str) and path.strip()):
            out.append(f"{where} needs a path")
        elif Path(path).is_absolute():
            out.append(f"{where}: path is from the repository's root, or starts with ~/: {path}")
        elif not path.startswith("~/") and ".." in Path(path).parts:
            out.append(f"{where}: path leaves the repository: {path}")
        bitwarden = entry.get("bitwarden")
        if not isinstance(bitwarden, dict):
            out.append(f"{where} needs bitwarden, with a project and a name")
            continue
        out += [f"{where}: bitwarden.{key} is not a setting" for key in sorted(bitwarden.keys() - {"project", "name"})]
        project, name = bitwarden.get("project"), bitwarden.get("name")
        if isinstance(project, dict):
            out += [f"{where}: bitwarden.project.{key} is not a setting"
                    for key in sorted(project.keys() - {"id", "name"})]
            if not (isinstance(project.get("id"), str) and UUID.fullmatch(project["id"])):
                out.append(f"{where}: bitwarden.project.id must be the project's id, a UUID")
            if "name" in project and not (isinstance(project["name"], str) and project["name"].strip()):
                out.append(f"{where}: bitwarden.project.name, if given, is the project's name")
            project = project.get("id")
        elif not (isinstance(project, str) and project.strip()):
            out.append(f"{where} needs bitwarden.project: {{\"id\": …, \"name\": …}}, or the project's id or name")
        if not (isinstance(name, str) and NAME.fullmatch(name)):
            out.append(f"{where}: bitwarden.name must be a letter, then letters, digits, _ and -")
        elif (project, name) in names:
            out.append(f"{where}: {name} is declared twice")
        names.add((project, name))
    return out


def declared(repo: Path, config: dict) -> list[Declared]:
    out = []
    for entry in config.get(FIELD) or []:
        path = Path(entry["path"]).expanduser() if entry["path"].startswith("~/") else repo / entry["path"]
        project = entry["bitwarden"]["project"]
        if isinstance(project, dict):
            out.append(Declared(repo, path, project["id"], entry["bitwarden"]["name"], project.get("name")))
        else:
            out.append(Declared(repo, path, project, entry["bitwarden"]["name"]))
    return out


def undeclared(repo: Path, config: dict) -> list[Path]:
    """The corpus keys here that pubrules.json does not declare."""
    named = {Path(entry.get("path", "")) for entry in config.get(FIELD) or [] if isinstance(entry, dict)}
    return [repo / place for place in KEY_PLACES if (repo / place).is_file() and Path(place) not in named]


def repositories(under: Path | None) -> list[Path]:
    """This repository, or every one directly under `under` (and `under` itself)."""
    if under is None:
        return [Path.cwd()]
    candidates = [under, *sorted(p for p in under.iterdir() if p.is_dir())]
    return [p for p in candidates if (p / CONFIG).is_file()]


def matching(projects: list[dict], project: str) -> list[dict]:
    """The projects `project` names: by id when it is a UUID; else by exact name,
    then by name in any case ("pub" for "Pub")."""
    if UUID.fullmatch(project):
        return [p for p in projects if str(p.get("id", "")).lower() == project.lower()]
    exact = [p for p in projects if p.get("name") == project]
    return exact or [p for p in projects if str(p.get("name", "")).casefold() == project.casefold()]


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _read_declarations(under: Path | None, point_out: bool = False
                       ) -> tuple[dict[tuple[str, str], list[Declared]], bool]:
    """Every repository's declared keys, by (project, name); and whether a
    pubrules.json was unusable. With `point_out`, also says which corpus keys
    on this machine no pubrules.json declares."""
    failed = False
    keys: dict[tuple[str, str], list[Declared]] = {}
    for repo in repositories(under):
        try:
            config = json.loads((repo / CONFIG).read_text(encoding="utf-8"))
        except ValueError:
            print(f"{repo / CONFIG}: not JSON; skipped")
            failed = True
            continue
        if wrong := problems(config.get(FIELD)):
            for phrase in wrong:
                print(f"{repo / CONFIG}: {phrase}")
            failed = True
            continue
        if point_out:
            for path in undeclared(repo, config):
                print(f"{path}: a signing key {CONFIG} does not declare; add it to {FIELD} to back it up")
        for key in declared(repo, config):
            keys.setdefault((key.project, key.name), []).append(key)
    return keys, failed


def _grouped(first: dict[tuple[str, str], Declared]) -> tuple[dict[str, list[str]], dict[str, str], list[str]]:
    """The planned names by project, each project's title, and the projects
    in title order."""
    groups: dict[str, list[str]] = {}
    for project, name in first:
        groups.setdefault(project, []).append(name)
    titles = {project: next((first[(project, n)].shown for n in names if first[(project, n)].label), project)
              for project, names in groups.items()}
    return groups, titles, sorted(groups, key=titles.get)


def _projects(token: str) -> list[dict] | None:
    """The projects `token` sees, and Bitwarden's SDK ready; None, said, when not."""
    from .bitwarden import ensure  # noqa: PLC0415
    from .github_app import BwsFailed, _listed, bws  # noqa: PLC0415
    try:
        projects = _listed(bws(token, "project", "list", "--output", "json", "--color", "no"))
    except BwsFailed as error:
        print(f"bws: {error}")
        return None
    if why := ensure():
        print(why)
        return None
    return projects


def _one(projects: list[dict], project: str, names: list[str], what: str) -> dict | None:
    """The one project `project` names; None, said, when the token sees not one."""
    found = matching(projects, project)
    if len(found) == 1:
        return found[0]
    sees = ", ".join(sorted(str(p.get("name")) for p in projects)) or "none"
    print(f"this token sees {len(found)} projects that are {project}, not one (it sees: {sees}); "
          f"not {what}: {', '.join(names)}")
    return None


def _write_new(path: Path, value: str) -> None:
    """`value` into a new file at `path`, readable by its owner alone; never
    over a file already there."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as out:
        out.write(value)


def _restore_one(token: str, held: list[str], name: str, places: list[Declared]) -> bool:
    """Write `name`'s one value to each of `places`: whether it was."""
    from .bitwarden import WriteFailed, values as stored_values  # noqa: PLC0415
    if len(held) != 1:
        print(f"  {name}: the project holds it {len(held)} times, not once; not restored")
        return False
    try:
        value = stored_values(token, held).get(held[0])
    except WriteFailed as error:
        print(f"  {name}: Bitwarden: {error}")
        return False
    if not value:
        print(f"  {name}: Bitwarden gave no value; not restored")
        return False
    done = True
    for key in places:
        try:
            _write_new(key.path, value)
        except FileExistsError:
            print(f"  {name}: {key.path} appeared meanwhile; left alone")
            done = False
            continue
        print(f"  {name}: restored to {key.path}")
    return done


def restore(under: Path | None, wanted: list[str], dry_run: bool) -> int:
    from .bitwarden import WriteFailed, names as stored_names  # noqa: PLC0415
    from .github_app import ask_hidden  # noqa: PLC0415

    keys, failed = _read_declarations(under)
    for name in sorted(set(wanted) - {name for _, name in keys}):
        print(f"{name}: no {CONFIG} here declares it")
        failed = True
    plan: dict[tuple[str, str], list[Declared]] = {}
    for (project, name), places in sorted(keys.items()):
        if wanted and name not in wanted:
            continue
        for key in places:
            if key.path.exists():
                print(f"{name}: already at {key.path}; left alone")
        if missing := [key for key in places if not key.path.exists()]:
            plan[(project, name)] = missing
    if not plan:
        if not failed:
            print("nothing to restore")
        return 1 if failed else 0
    groups, titles, order = _grouped({k: v[0] for k, v in plan.items()})
    if dry_run:
        for project in order:
            print(f"Keys that would be restored from {titles[project]}:")
            for name in groups[project]:
                for key in plan[(project, name)]:
                    print(f"  {name}  {key.path}")
        return 1 if failed else 0

    token = ask_hidden(f"Bitwarden access token that may read {', '.join(titles[p] for p in order)}: ")
    if not token:
        print("no token given; nothing written")
        return 1
    if (projects := _projects(token)) is None:
        return 1
    for project in order:
        names = groups[project]
        if not (found := _one(projects, project, names, "restored")):
            failed = True
            continue
        try:
            ids = stored_names(token, found["organizationId"], found["id"])
        except WriteFailed as error:
            print(f"Bitwarden: {error}")
            failed = True
            continue
        print(f"Keys being restored from {titles[project]}:")
        for name in names:
            if not _restore_one(token, ids.get(name, []), name, plan[(project, name)]):
                failed = True
    return 1 if failed else 0


def run(under: Path | None, dry_run: bool) -> int:
    from .bitwarden import WriteFailed, write  # noqa: PLC0415
    from .bitwarden import names as stored_names, values as stored_values  # noqa: PLC0415
    from .github_app import ask_hidden  # noqa: PLC0415

    keys, failed = _read_declarations(under, point_out=True)
    # The same name may be declared by several checkouts of one repository:
    # one value is backed up, and two values under one name are a mistake.
    plan: dict[tuple[str, str], tuple[Declared, str]] = {}
    for (project, name), places in sorted(keys.items()):
        here = [(key, key.path.read_text(encoding="utf-8")) for key in places if key.path.is_file()]
        if not here:
            print(f"{name}: not on this machine ({', '.join(str(key.path) for key in places)})")
            continue
        if len({_digest(value) for _, value in here}) > 1:
            print(f"{name}: different keys at {', '.join(str(key.path) for key, _ in here)}; none backed up")
            failed = True
            continue
        plan[(project, name)] = here[0]

    groups, titles, order = _grouped({k: v[0] for k, v in plan.items()})
    if plan:
        print(f"Projects: {', '.join(titles[p] for p in order)}")
    if dry_run or not plan:
        for project in order:
            print(f"Keys that would be backed up to {titles[project]}, unless already there:")
            for name in groups[project]:
                print(f"  {name}  {plan[(project, name)][0].path}")
        return 1 if failed else 0

    token = ask_hidden(f"Bitwarden access token that may read and write {', '.join(titles[p] for p in order)}: ")
    if not token:
        print("no token given; nothing written")
        return 1
    if (projects := _projects(token)) is None:
        return 1
    for project in order:
        names = groups[project]
        if not (found := _one(projects, project, names, "backed up")):
            failed = True
            continue
        labels = {plan[(project, n)][0].label for n in names} - {None}
        for label in sorted(labels - {found.get("name")}):
            print(f"warning: the project {project} is named {found.get('name')} in Bitwarden, "
                  f"not {label} as declared")
        # The names first, from identifiers alone; then the values of the
        # secrets named as these keys are, to compare, and of no others.
        try:
            ids = {name: found_ids for name, found_ids in
                   stored_names(token, found["organizationId"], found["id"]).items() if name in names}
            held = stored_values(token, [i for found_ids in ids.values() for i in found_ids])
        except WriteFailed as error:
            print(f"Bitwarden: {error}")
            failed = True
            continue
        values = {name: [_digest(str(held.get(i, ""))) for i in found_ids] for name, found_ids in ids.items()}
        del held
        print(f"Keys being backed up to {titles[project]}:")
        for name in names:
            key, value = plan[(project, name)]
            if name in values:
                if values[name] == [_digest(value)]:
                    print(f"  {name}: already backed up")
                else:
                    print(f"  {name}: another value is stored under this name; not overwritten")
                    failed = True
                continue
            try:
                write(token, found["organizationId"], found["id"], name, value,
                      f"signing key, a copy of {key.path} (declared in {key.repo / CONFIG})")
            except WriteFailed as error:
                print(f"  {name}: Bitwarden refused the write: {error}")
                failed = True
                continue
            print(f"  {name}: backed up from {key.path}")
    return 1 if failed else 0
