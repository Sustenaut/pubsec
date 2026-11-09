"""k8s.secret: a Secret in the namespace, with its keys, each value of a
known shape having it, read through the walk's kubectl channel; and the
shapes a value may be required to have, which bitwarden.generated makes.

The Secret is read with `get secret NAME -o json` on the admin channel, and
by its keys' names alone over the deploy channel, with the server's
`secret-keys` verb. Its fulfil makes it from the needs whose secret fills
it, each giving its value: the manifest reaches kubectl on its standard
input, never in argv or a file, and the Deployments that read it are then
restarted."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from . import Base, Ran, Result, failed, kubectl_refused, not_found, restart, schema, secret_of

KEYS = {"type": "array", "items": {"type": "string", "pattern": r"^[-._a-zA-Z0-9]{1,253}$"},
        "x-phrase": "must list the Secret's keys"}
AES = (16, 24, 32)
URL_SAFE = re.compile(rb"[A-Za-z0-9_-]*")
STANDARD = re.compile(rb"[A-Za-z0-9+/]*={0,2}")


@dataclass(frozen=True)
class Shape:
    """A value with a form the program reading it requires."""
    what: str
    problem: Callable[[bytes], str | None]


def url_decoded(value: bytes) -> bytes | None:
    """`value` as oauth2-proxy decodes it: '=' trimmed from the end, then
    unpadded URL-safe base64, where line breaks are skipped (Go's
    base64.RawURLEncoding). None when it is not that."""
    text = value.rstrip(b"=").replace(b"\r", b"").replace(b"\n", b"")
    if not URL_SAFE.fullmatch(text) or len(text) % 4 == 1:
        return None
    return base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))


def cookie_secret(value: bytes) -> str | None:
    """Why oauth2-proxy refuses `value` as its cookie secret, or None. It
    takes the URL-safe base64 decoding when that is an AES key's length, and
    the bytes as they are otherwise, which must then be one."""
    decoded = url_decoded(value)
    if len(value) in AES or (decoded is not None and len(decoded) in AES):
        return None
    shape = f"{len(value)} bytes" + (f", {len(decoded)} after URL-safe base64 decoding"
                                     if decoded is not None else "")
    rule = "; oauth2-proxy needs 16, 24 or 32 bytes, as they are or after URL-safe base64 decoding"
    stripped = value.strip()
    if stripped != value and cookie_secret(stripped) is None:
        return f"{shape}, with white space around it{rule}: drop the trailing newline"
    if STANDARD.fullmatch(stripped) and (b"+" in stripped or b"/" in stripped):
        try:
            length = len(base64.b64decode(stripped, validate=True))
        except binascii.Error:
            length = 0
        if length in AES:
            return (f"{shape}: it is standard base64 (with + or /) of {length} bytes{rule}; "
                    "make it URL-safe, + as - and / as _, as `openssl rand -base64 32 | tr -- '+/' '-_'` does")
    return shape + rule


def hex_32(value: bytes) -> str | None:
    if re.fullmatch(rb"[0-9a-f]{64}", value):
        return None
    return f"{len(value)} bytes; it must be 64 lower-case hex digits, 32 bytes"


def base64_32(value: bytes) -> str | None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return f"{len(value)} bytes, not base64; it must be base64 of 32 bytes"
    if len(decoded) != 32:
        return f"{len(value)} bytes, base64 of {len(decoded)} bytes; it must be base64 of 32 bytes"
    return None


# The shapes a value may be required to have, by the name a need gives.
SHAPES = {"oauth2-proxy-cookie": Shape("oauth2-proxy's cookie secret", cookie_secret),
          "hex-32": Shape("32 bytes as hex", hex_32),
          "base64-32": Shape("32 bytes as base64", base64_32)}
SHAPE = {"enum": sorted(SHAPES)}


def secret_data(doc: dict[str, Any]) -> dict[str, bytes]:
    """A Secret's keys and values: data decoded, stringData as it is."""
    out = {}
    for key, value in (doc.get("data") or {}).items():
        try:
            out[key] = base64.b64decode(value or "", validate=True)
        except (binascii.Error, TypeError):
            out[key] = b""
    for key, value in (doc.get("stringData") or {}).items():
        out[key] = str(value).encode()
    return out


def read(ctx: Any, ns: str, name: str) -> dict[str, bytes] | str | None:
    """The Secret's keys and values, None when it is not there, or why it could not be read."""
    ran = ctx.kubectl(["-n", ns, "get", "secret", name, "-o", "json"])
    if ran.returncode == 0:
        try:
            return secret_data(json.loads(ran.stdout))
        except (ValueError, AttributeError):
            return "kubectl's answer is not JSON"
    err = ran.stderr.strip().splitlines()[-1:] or [f"exit {ran.returncode}"]
    if not_found(ran):
        return None
    if "(Forbidden)" in ran.stderr or "forbidden" in ran.stderr:
        return f"kubectl may not read Secrets in {ns}: the deploy identity needs get on secrets there ({err[0]})"
    return f"kubectl failed: {err[0]}"


def wrong_keys(name: str, need: Any, data: dict[str, bytes]) -> list[str]:
    """What is wrong with a Secret that is there, for the need: each key it
    lists, and the shape of each it gives one for."""
    shapes = {k: SHAPES[s] for k, s in need.params.get("shapes", {}).items()}
    out = []
    for key in need.params.get("keys", []):
        if key not in data:
            out.append(f"Secret {name} has no key {key}, which need {need.id} reads")
        elif (shape := shapes.get(key)) and (why := shape.problem(data[key])) is not None:
            out.append(f"Secret {name} key {key} (need {need.id}), {shape.what}: {why}")
    return out


class Secret(Base):
    """A Secret in the namespace, with its keys, and values of a known shape having it."""
    type = "k8s.secret"
    grade = "auto"
    budget = 5.0
    fulfil_budget = 60.0
    needs_of_context = ("kubectl-write",)
    schema = schema({"keys": KEYS, "shapes": {"type": "object", "additionalProperties": SHAPE,
                                              "x-phrase": "must give a shape by key"}})

    def fillers(self, need: Any, ctx: Any) -> list[Any]:
        """The needs whose secret fills this Secret, in the plan."""
        return [n for n in ctx.needs.values() if (secret_of(n) or {}).get("name") == need.name]

    def made_from(self, need: Any, ctx: Any) -> list[str]:
        """The needs it is made from: when a fulfil changes one's value, the walk makes it again."""
        return [n.id for n in self.fillers(need, ctx)]

    def action(self, need: Any, ctx: Any) -> str:
        sources = ", ".join(n.id for n in self.fillers(need, ctx))
        return f"apply Secret {need.name} in {ctx.namespace} from {sources}, and restart what reads it"

    def check(self, need: Any, ctx: Any) -> Result:
        result = self.found(need, ctx)
        # Made only from the needs that fill it, and only when each gives its value.
        fillers = self.fillers(need, ctx)
        result.fixable = bool(fillers) and all(callable(getattr(ctx.types.get(n.type), "value", None))
                                               for n in fillers)
        return result

    def exists(self, need: Any, ctx: Any, source: str) -> Result:
        """Over the deploy channel, which shows no Secret's data: its key names,
        as the server's `secret-keys` verb lists them, or, where the server has
        no such verb yet, whether it is there by name alone."""
        ns, name = ctx.namespace, need.name
        missing = Result("missing", f"Secret {name} is not in {ns}", fix=f"make it in {ns}, from what fills it ({source})")
        ran = ctx.kubectl(["-n", ns, "secret-keys", name])
        if ran.returncode == 0:
            try:
                keys = json.loads(ran.stdout)
            except ValueError:
                keys = None
            if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                return Result("unknown", f"the server's secret-keys did not list Secret {name}'s keys",
                              fix="see the server's deploy program")
            lacking = [k for k in need.params.get("keys", []) if k not in keys]
            if lacking:
                return Result("drift", f"Secret {name} has no key {lacking[0]}, which need {need.id} reads",
                              fix=f"put the right value in Secret {name} in {ns}, from what fills it ({source})",
                              details=[f"Secret {name} has no key {k}" for k in lacking])
            return Result("ready", f"Secret {name} in {ns} has keys {', '.join(sorted(keys))}; their values "
                                   f"are not checked over the deploy channel")
        if not_found(ran):
            return missing
        if ran.returncode != 2:
            return kubectl_refused(Ran(ran.returncode, "", ran.stderr), ns, "Secrets")
        ran = ctx.kubectl(["-n", ns, "get", "secret", name, "-o", "name"])
        if ran.returncode == 0 and ran.stdout.strip() == f"secret/{name}":
            return Result("ready", f"Secret {name} is in {ns}",
                          details=["keys not checked on this channel: the server has no secret-keys verb"])
        if not_found(ran):
            return missing
        return kubectl_refused(Ran(ran.returncode, "", ran.stderr), ns, "Secrets")

    def fulfil(self, need: Any, ctx: Any) -> Result:
        ns, name = ctx.namespace, need.name
        data: dict[str, bytes] = {}
        sources = []
        for filler in self.fillers(need, ctx):
            secret = secret_of(filler) or {}
            if not secret.get("key"):
                return Result("missing", f"{filler.id} names no key of Secret {name} to fill",
                              fix=f"give {filler.id}'s secret a key")
            value = ctx.types[filler.type].value(filler, ctx)
            if value is None:
                return Result("missing", f"{filler.id}'s value is not in this walk",
                              fix="run the walk through ./with-secrets, which reads Bitwarden")
            if secret.get("decode") == "base64":
                try:
                    value = base64.b64decode(value, validate=True)
                except (binascii.Error, ValueError):
                    return Result("drift", f"{filler.id}'s value is not base64, as its secret's decode says",
                                  fix=f"make {filler.name} again")
            data[secret["key"]] = value
            sources.append(filler.id.replace("bitwarden.generated:", "Bitwarden ")
                           .replace("bitwarden.secret:", "Bitwarden "))
        if lacking := [k for k in need.params.get("keys", []) if k not in data]:
            return Result("missing", f"no need fills key {lacking[0]} of Secret {name}",
                          fix=f"add a need whose secret fills {name} key {lacking[0]}")
        manifest = json.dumps({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                               "metadata": {"name": name, "namespace": ns},
                               "data": {k: base64.b64encode(v).decode() for k, v in sorted(data.items())}})
        ran = ctx.kubectl(["-n", ns, "apply", "-f", "-"], input=manifest.encode())
        if ran.returncode != 0:
            return failed(f"kubectl apply of Secret {name} in {ns} failed", ran, tuple(data.values()))
        size = sum(len(v) for v in data.values())
        return Result("ready", f"made Secret {name} in {ns} from {', '.join(sources)}, {size} bytes",
                      details=restart(ctx, name))

    def found(self, need: Any, ctx: Any) -> Result:
        ns, name = ctx.namespace, need.name
        source = need.implied_by or "deploy.needs"
        if ctx.channel == "deploy":
            return self.exists(need, ctx, source)
        data = read(ctx, ns, name)
        if data is None:
            return Result("missing", f"Secret {name} is not in {ns}",
                          fix=f"make it in {ns}, from what fills it ({source})")
        if isinstance(data, str):
            if "may not read Secrets" in data:
                return Result("unknown", f"kubectl may not read Secret {name} in {ns}", fix=data)
            return Result("unknown", f"Secret {name} in {ns} could not be read", fix=data)
        keys = tuple(need.params.get("keys", []))
        bad = wrong_keys(name, need, data)
        del data
        if bad:
            return Result("drift", bad[0], fix=f"put the right value in Secret {name} in {ns}, "
                                                f"from what fills it ({source})", details=bad)
        listed = f" has keys {', '.join(keys)}" if keys else " is there"
        return Result("ready", f"Secret {name} in {ns}{listed}")


secret = Secret()
