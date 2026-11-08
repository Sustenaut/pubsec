"""Writing a secret to Bitwarden Secrets Manager with Bitwarden's own SDK, and
finding the secret to write.

The bws CLI takes a value only on its command line, where every local user can
read it for as long as the write takes. The SDK takes it in memory, so a command
that writes something secret comes here. The secret to write is found by name in
the SDK's identifiers, which hold an id, a name and the projects and no value:
`bws secret list` gives every value of the project, which a lookup does not need.

The SDK is not a dependency of pubsec, which has none, and it has compiled wheels
for only some platforms. `ensure` installs it
for this run alone, from bitwarden-sdk.lock, by hash, as what it is given is a write
token and a private key. uv checks the hashes only with --require-hashes on `uv pip
install`: `uvx --with-requirements` installs a wrong one without a word.
"""

from __future__ import annotations

import atexit
import shutil
import subprocess
import sys
import tempfile
from importlib import resources
from uuid import UUID

LOCK = "bitwarden-sdk.lock"


class WriteFailed(Exception):
    """A lookup or a write Bitwarden refused, with hidden values taken out of its message."""


def scrub(text: str, hidden: tuple[str, ...]) -> str:
    """`text` with every hidden value, and each line of one, taken out."""
    for value in hidden:
        for part in [value, *value.splitlines()]:
            if part:
                text = text.replace(part, "[hidden]")
    return text


def ensure() -> str | None:
    """Return nothing once the SDK can be imported, or say why it can't."""
    try:
        import bitwarden_sdk  # noqa: F401, PLC0415
    except ImportError:
        pass
    else:
        return None
    if shutil.which("uv") is None:
        return "this command fetches Bitwarden's SDK with uv, which is not installed: curl -LsSf https://astral.sh/uv/install.sh | sh"
    target = tempfile.mkdtemp(prefix="pubsec-bitwarden-")
    atexit.register(shutil.rmtree, target, ignore_errors=True)
    with resources.as_file(resources.files("pubsec") / LOCK) as lock:
        done = subprocess.run(["uv", "pip", "install", "--quiet", "--require-hashes", "--python", sys.executable,
                               "--target", target, "-r", str(lock)], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        return f"Bitwarden's SDK could not be installed: {done.stderr.strip()}"
    sys.path.insert(0, target)
    try:
        import bitwarden_sdk  # noqa: F401, PLC0415
    except ImportError as error:
        return f"Bitwarden's SDK was installed but can't be imported: {error}"
    return None


# The SDK's client, logged in, by token: one login a process for each.
_clients: dict[str, object] = {}


def _client(token: str):  # noqa: ANN202 - the SDK's client, logged in
    if token in _clients:
        return _clients[token]
    from bitwarden_sdk import BitwardenClient  # noqa: PLC0415
    try:
        client = BitwardenClient()
        answer = client.auth().login_access_token(token)
    except Exception as error:  # noqa: BLE001  # the SDK raises bare Exceptions, and they may quote what it was given
        raise WriteFailed(scrub(str(error), (token,)) or type(error).__name__) from None
    if not answer.success:
        raise WriteFailed(scrub(str(answer.error_message), (token,)))
    _clients[token] = client
    return client


def names(token: str, organization: str, project: str) -> dict[str, list[str]]:
    """Each name in the project and its secrets' ids. Only identifiers are
    asked for, so no secret's value reaches this process."""
    client = _client(token)
    try:
        answer = client.secrets().list(organization)
    except Exception as error:  # noqa: BLE001  # as in _client
        raise WriteFailed(scrub(str(error), (token,)) or type(error).__name__) from None
    if not answer.success or answer.data is None:
        raise WriteFailed(scrub(str(answer.error_message), (token,)))
    out: dict[str, list[str]] = {}
    for secret in answer.data.data:
        if project.lower() in {str(p).lower() for p in secret.project_ids or []}:
            out.setdefault(secret.key, []).append(str(secret.id))
    return out


def values(token: str, ids: list[str]) -> dict[str, str]:
    """The values of the secrets `ids`, by id: those, and no other."""
    if not ids:
        return {}
    client = _client(token)
    try:
        answer = client.secrets().get_by_ids(ids)
    except Exception as error:  # noqa: BLE001  # as in _client
        raise WriteFailed(scrub(str(error), (token,)) or type(error).__name__) from None
    if not answer.success or answer.data is None:
        raise WriteFailed(scrub(str(answer.error_message), (token,)))
    return {str(secret.id): secret.value for secret in answer.data.data}


def write(token: str, organization: str, project: str, name: str, value: str, note: str,
          secret: str | None = None) -> None:
    """Create the secret `name`, or update `secret`, in the project. The token and the value
    stay in this process."""
    hidden = (token, value)
    client = _client(token)
    try:
        if secret is None:
            answer = client.secrets().create(UUID(organization), name, value, note, [UUID(project)])
        else:
            answer = client.secrets().update(organization, secret, name, value, note, [UUID(project)])
    except Exception as error:  # noqa: BLE001  # as in _client
        raise WriteFailed(scrub(str(error), hidden) or type(error).__name__) from None
    if not answer.success:
        raise WriteFailed(scrub(str(answer.error_message), hidden))
