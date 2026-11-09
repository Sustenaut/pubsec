"""The `sustenaut.walk` hook: Bitwarden's write token for a walk that wants one.

Before a `pubdeploy walk --fulfil` acts, when a need it will fulfil
requires a write token and a terminal is there, pubkit calls `prepare(ctx,
plan, terminal)` of each package that offers the hook. This one asks for a
Bitwarden access token with write access at a hidden prompt, once in the
process, finds the project (PUBKIT_SECRETS_PROJECT, which ./with-secrets
sets, else with-secrets.json's), and gives the walk a writer, which keeps
the token in this process only: Bitwarden's SDK takes each value in memory.
"""

from __future__ import annotations

import getpass
import json
import sys
from pathlib import Path
from typing import Any

# One token a process: every unit of a walk shares the writer.
_writers: dict[str, Any] = {}


class BitwardenWriter:
    """Writes to the Bitwarden project with a write token, which it keeps
    only for this process. The secret to update is found by name among the
    project's identifiers, without reading any value."""

    def __init__(self, token: str, project: str) -> None:
        self._token, self.project = token, project
        self._ids: tuple[str, str] | None = None

    def write(self, name: str, value: str, note: str) -> None:
        from .bitwarden import ensure, names, write  # noqa: PLC0415
        from .service_account_key import find_project  # noqa: PLC0415
        if why := ensure():
            raise RuntimeError(why)
        if self._ids is None:
            self._ids = find_project(self._token, self.project)
        project, organization = self._ids
        found = names(self._token, organization, project).get(name, [])
        if len(found) > 1:
            raise RuntimeError(f"{len(found)} secrets in {self.project} are named {name}: delete all but one")
        write(self._token, organization, project, name, value, note, found[0] if found else None)


def ask_hidden(prompt: str) -> str:
    """A typed answer, not echoed, the prompt on standard error, so --json's output is the document alone."""
    try:
        return getpass.getpass(prompt, stream=sys.stderr).strip()
    except EOFError:
        return ""


def project_of(root: Path, env: Any) -> str | None:
    """The Bitwarden project the walk writes to: the one ./with-secrets read, else with-secrets.json's."""
    if env.get("PUBKIT_SECRETS_PROJECT"):
        return env["PUBKIT_SECRETS_PROJECT"]
    try:
        project = json.loads((Path(root) / "with-secrets.json").read_text(encoding="utf-8")).get("project")
    except (OSError, ValueError, AttributeError):
        return None
    return project if isinstance(project, str) and project else None


def prepare(ctx: Any, plan: Any, terminal: bool) -> str | None:
    """Give the walk a writer, asking for the token at most once; a line for
    the walk to print when there is none."""
    if ctx.bitwarden_writer is not None or not terminal:
        return None
    project = project_of(ctx.root, ctx.env)
    if project is None:
        return ("pubsec: no Bitwarden project to write to: run the walk through ./with-secrets, "
                "or where with-secrets.json names one")
    if project not in _writers:
        token = ask_hidden(f"Bitwarden access token with write access to {project} (hidden, and not kept): ")
        _writers[project] = BitwardenWriter(token, project) if token else None
    ctx.bitwarden_writer = _writers[project]
    if ctx.bitwarden_writer is None:
        return "pubsec: no Bitwarden write token was given, so nothing is written to Bitwarden"
    return None
