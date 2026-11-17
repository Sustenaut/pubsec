"""bitwarden.adopt: keep a value that lives only in a cluster Secret by copying
it into Bitwarden, so the walk finds it there and the Secret is left as it is.

A service that ran before its deploy block had a secret made by hand, such as a
hash key or oauth2-proxy's cookie secret. Declared as bitwarden.generated, a walk
would make a new one, which signs everyone out or costs every site a full check.
Declared as bitwarden.adopt, it copies the cluster's value instead, once:

    {"type": "bitwarden.adopt", "name": "auth-access-hash-key",
     "secret": {"name": "auth-secrets", "key": "access-hash-key"},
     "format": "[0-9a-f]{64}", "note": "copied from auth-secrets, as hex-32"}

The check is `ready` when Bitwarden has the name; `missing` when it lacks it and
the Secret's key holds a value of the format (or shape), which the fulfil copies;
`blocked` when the Secret holds none, or one of another form: then nothing is kept,
and bitwarden.generated should make one. The value travels from kubectl's answer
to the Bitwarden writer in memory: never in argv, a log or the journal. Since the
need names the Secret it came from as its `secret`, the walk's k8s.secret for it
is filled from the same value, and finds it ready.
"""

from __future__ import annotations

import re
from typing import Any

from . import SECRET, Result, schema
from .bitwarden import BitwardenSecret
from .k8s import SHAPE, SHAPES, read

ADOPTED_SECRET = {**SECRET, "required": ["name", "key"],
                  "x-phrase": "must be an object with the Secret's name and the key its value is in"}
FORMAT = {"type": "string", "minLength": 1, "maxLength": 200,
          "x-phrase": "must be a regular expression the whole value matches, such as [0-9a-f]{64}"}
NOTE = {"type": "string", "maxLength": 200, "x-phrase": "must be a short note for Bitwarden, no value"}


class BitwardenAdopt(BitwardenSecret):
    """A value the cluster already holds, copied into Bitwarden once."""
    type = "bitwarden.adopt"
    grade = "auto"
    budget = 4.0  # one kubectl read of the Secret, over the admin channel's kept connection
    fulfil_budget = 60.0
    needs_of_context = ("write-token",)
    keeps_value = True  # the Secret it fills already holds the value: nothing makes it again
    schema = schema({"secret": ADOPTED_SECRET, "format": FORMAT, "shape": SHAPE, "note": NOTE}, ("secret",))

    def secret_shape(self, params: dict[str, Any]) -> str | None:
        return params.get("shape")

    def _form(self, need: Any, value: bytes) -> str | None:
        """Why the value is not of the need's format and shape, or None."""
        pattern = need.params.get("format")
        if pattern is not None:
            try:
                if not re.fullmatch(pattern.encode(), value):
                    return f"it does not match the format {pattern}"
            except re.error:
                return f"the format {pattern} is not a regular expression"
        shape = need.params.get("shape")
        if shape is not None and (why := SHAPES[shape].problem(value)) is not None:
            return f"it is not {SHAPES[shape].what}: {why}"
        return None

    def _cluster(self, need: Any, ctx: Any) -> tuple[bytes | None, Result | None]:
        """The Secret's value, or the result when there is none to keep."""
        secret, key = need.params["secret"]["name"], need.params["secret"]["key"]
        where = f"Secret {secret} key {key} in {ctx.namespace}"
        if ctx.channel == "deploy":
            return None, Result("unknown", f"{where} is read over the admin channel or from the plane",
                                fix="run the walk with --server HOST, the admin channel, or from the plane")
        found = read(ctx, ctx.namespace, secret)
        if isinstance(found, str):
            return None, Result("unknown", f"{where} could not be read", fix=found[:300])
        if not found or not found.get(key):
            return None, Result("blocked", f"not in Bitwarden, and Secret {secret} key {key} holds no value to keep",
                                fixable=False, fix=f"let bitwarden.generated make {need.name}: change the need's type")
        value = found[key]
        if (why := self._form(need, value)) is not None:
            return None, Result("blocked", f"not in Bitwarden, and Secret {secret} key {key} is not one to keep",
                                details=[why], fixable=False,
                                fix=f"let bitwarden.generated make {need.name}: change the need's type")
        return value, None

    def action(self, need: Any, ctx: Any) -> str:
        secret = need.params["secret"]
        return (f"copy key {secret['key']} of Secret {secret['name']} in {ctx.namespace} into Bitwarden as "
                f"{need.name} (the value is never printed)")

    def check(self, need: Any, ctx: Any) -> Result:
        value, result = self.present(need, ctx)
        if result is not None and result.state != "missing":
            return result
        if result is None:
            raw = str(value).encode()
            if (why := self._form(need, raw)) is not None:
                return Result("drift", f"{need.name} is in Bitwarden, and {why}"[:200], details=[why], fixable=False,
                              fix=f"put the value {need.params['secret']['name']} holds in Bitwarden as {need.name}")
            return Result("ready", f"{need.name} is in Bitwarden: {len(raw)} bytes")
        value, found = self._cluster(need, ctx)
        if found is not None:
            return found
        secret = need.params["secret"]
        return Result("missing", f"{need.name} is not in Bitwarden; Secret {secret['name']} key {secret['key']} "
                                 f"holds {len(value)} bytes to keep",
                      fix="./with-secrets ./pubdeploy walk --fulfil --server HOST copies it")

    def fulfil(self, need: Any, ctx: Any) -> Result:
        if ctx.bitwarden_writer is None:
            return Result("missing", "there is no Bitwarden write token", fix="run the walk at a terminal")
        value, found = self._cluster(need, ctx)
        if found is not None:
            return found
        secret = need.params["secret"]
        note = need.params.get("note") or f"copied from Secret {secret['name']} key {secret['key']}"
        text = value.decode("utf-8", "replace")
        try:
            ctx.bitwarden_writer.write(need.name, text, note)
        except Exception as e:  # noqa: BLE001 - the writer's failure is the need's, said without a value
            return Result("missing", f"Bitwarden refused {need.name} ({type(e).__name__})",
                          fix=str(e).replace(text, "[hidden]")[:300])
        ctx.values[need.name] = value
        return Result("ready", f"copied {need.name} into Bitwarden: {len(value)} bytes, the value Secret "
                               f"{secret['name']} holds")


bitwarden_adopt = BitwardenAdopt()
