"""The need types pubsec offers pubkit's deploy walk, and what they share.

Each is installed under the entry-point group `sustenaut.needs` as an
instance, and the walk reaches it through the provider contract alone (the
names pubkit's README lists under "Provider contract"): a check or a fulfil
uses the Context it is given by attribute, and returns a Result, pubsec's
own, with the fields the walk reads. Nothing here imports pubkit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

FULFIL_BUDGET = 60.0  # seconds, for a type that declares none
SUMMARY = 120  # the longest summary, in characters, as the walk keeps it

# A need's secret: the Kubernetes Secret it fills, as pubkit's deploy block
# schema gives it, so the schema of a type here checks it the same way.
SECRET: dict[str, Any] = {
    "type": "object", "required": ["name"], "additionalProperties": False,
    "x-phrase": "must be an object with the Secret's name, and maybe key and decode",
    "properties": {
        "name": {"type": "string", "pattern": r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$",
                 "x-phrase": "must be a Secret's name, in lower case"},
        "key": {"type": "string", "pattern": r"^[-._a-zA-Z0-9]{1,253}$",
                "x-phrase": "must be a key of a Secret: letters, digits, - . _"},
        "decode": {"enum": ["base64"]},
    },
}


@dataclass
class Result:
    """What a check or a fulfil found: the fields the walk reads of one."""
    state: str  # ready, missing, drift, blocked or unknown
    summary: str  # one line, no value
    fix: str = ""  # what a person does when it is not ready: a command or a place, never a value
    details: list[str] = field(default_factory=list)
    fixable: bool = True  # False when the fulfil cannot make what the check found
    step: str = ""  # which of its steps the fulfil takes, for a type with several

    def __post_init__(self) -> None:
        line = " ".join(self.summary.split())
        self.summary = line if len(line) <= SUMMARY else line[:SUMMARY - 1] + "…"


@dataclass
class Ran:
    """A command's exit code and output, for a tool pubsec runs itself (gcloud)."""
    returncode: int
    stdout: str = ""
    stderr: str = ""


class Base:
    """What every type here shares. A `singleton` is named by the namespace."""
    type = ""
    schema: dict[str, Any] = {"type": "object", "additionalProperties": False, "properties": {}}
    grade = "none"
    budget = 1.0
    fulfil_budget = FULFIL_BUDGET
    offline = False
    singleton = False
    needs_of_context: tuple[str, ...] = ()  # what requires() says, for every need of the type

    def default_name(self, params: dict[str, Any]) -> str | None:
        return None

    def depends_on(self, need: Any, needs: Any) -> list[str]:
        return []

    def check(self, need: Any, ctx: Any) -> Result:
        raise NotImplementedError

    def requires(self, need: Any) -> tuple[str, ...]:
        return self.needs_of_context

    def action(self, need: Any, ctx: Any) -> str:
        return "fulfil it"

    def fulfil(self, need: Any, ctx: Any) -> Result:
        return Result("unknown", f"{self.type} has no fulfil", fix="see the check's fix")


def env_name(name: str) -> str:
    """The name ./with-secrets exports a secret under."""
    return name.upper().replace("-", "_")


def schema(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "object", "additionalProperties": False, "properties": properties}
    if required:
        out["required"] = list(required)
    return out


def with_secret(properties: dict[str, Any]) -> dict[str, Any]:
    return {**properties, "secret": SECRET}


def secret_of(need: Any) -> dict[str, Any] | None:
    secret = need.params.get("secret")
    return secret if isinstance(secret, dict) else None


def failed(what: str, ran: Any, hidden: tuple[bytes, ...] = ()) -> Result:
    """A fulfil's failure, with the last line the command said, any hidden value taken out."""
    last = (ran.stderr.strip().splitlines() or [f"exit {ran.returncode}"])[-1][:300]
    for value in hidden:
        for part in [value, *value.splitlines()]:
            if part:
                last = last.replace(part.decode(errors="replace"), "[hidden]")
    return Result("missing", what, fix=last)


def kubectl_json(ctx: Any, *args: str) -> tuple[Any, Any]:
    """kubectl's JSON answer to `args` -o json, or None, and how it ran."""
    ran = ctx.kubectl([*args, "-o", "json"])
    if ran.returncode != 0:
        return None, ran
    try:
        return json.loads(ran.stdout), ran
    except ValueError:
        return None, Ran(1, "", "kubectl's answer is not JSON")


def not_found(ran: Any) -> bool:
    return "(NotFound)" in ran.stderr or " not found" in ran.stderr


def kubectl_refused(ran: Any, ns: str, what: str) -> Result:
    """`unknown`, saying what access is missing, or what kubectl said."""
    last = (ran.stderr.strip().splitlines() or [f"exit {ran.returncode}"])[-1]
    if ran.returncode == 127:
        return Result("unknown", f"kubectl did not run, to read {what}", fix="install kubectl, or give --kubectl CMD")
    if "(Forbidden)" in ran.stderr or "forbidden" in ran.stderr:
        return Result("unknown", f"kubectl may not read {what} in {ns}",
                      fix=f"use a kubeconfig that may get {what} in {ns} ({last})")
    return Result("unknown", f"kubectl could not read {what} in {ns}", fix=f"kubectl said: {last}")


def status_of(error: Exception) -> int | None:
    """The HTTP status of a refusal ctx.gh raised, which carries it as `status`."""
    status = getattr(error, "status", None)
    return status if isinstance(status, int) else None


def github_refused(error: Exception, what: str) -> Result:
    if status_of(error) in (401, 403):
        return Result("unknown", f"GitHub refused to show {what}",
                      fix="sign gh in as someone who administers the repository (gh auth login)")
    return Result("unknown", f"GitHub could not be asked for {what}", fix=f"gh said: {str(error)[:200]}")


def reads(spec: dict[str, Any], secret: str) -> bool:
    """Whether a pod spec reads the Secret: env, envFrom, a volume or a projected one."""
    def listed(value: Any) -> list[dict[str, Any]]:
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    for container in listed(spec.get("containers")) + listed(spec.get("initContainers")):
        for env in listed(container.get("env")):
            if ((env.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name") == secret:
                return True
        if any((e.get("secretRef") or {}).get("name") == secret for e in listed(container.get("envFrom"))):
            return True
    for volume in listed(spec.get("volumes")):
        if (volume.get("secret") or {}).get("secretName") == secret:
            return True
        if any((s.get("secret") or {}).get("name") == secret
               for s in listed((volume.get("projected") or {}).get("sources"))):
            return True
    return False


def readers(ctx: Any, secret: str) -> list[str]:
    """The Deployments in the namespace whose pods read the Secret, as the
    cluster holds them: what a restart reaches is what runs."""
    found, _ran = kubectl_json(ctx, "-n", ctx.namespace, "get", "deployment")
    out = []
    for item in (found or {}).get("items") or []:
        spec = ((item.get("spec") or {}).get("template") or {}).get("spec") or {}
        if reads(spec, secret):
            out.append(str((item.get("metadata") or {}).get("name")))
    return sorted(set(out))


def restart(ctx: Any, secret: str) -> list[str]:
    """Restart each Deployment reading the Secret, so its pods read the new one: a detail each."""
    out = []
    for name in readers(ctx, secret):
        ran = ctx.kubectl(["-n", ctx.namespace, "rollout", "restart", f"deployment/{name}"])
        if ran.returncode == 0:
            out.append(f"restarted Deployment/{name}, which reads Secret {secret}")
        elif not not_found(ran):
            out.append(f"Deployment/{name} was not restarted: {failed('', ran).fix}")
    return out
