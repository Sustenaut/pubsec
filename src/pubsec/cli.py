"""`pubsec`: the commands that hold a secret value, a write token or a private key.

    pubsec run [--cwd DIR] -- COMMAND [ARGS...]
    pubsec app-secrets [--check]
    pubsec github-app create [--replace] [--dry-run] MANIFEST
    pubsec service-account-key create --account EMAIL --secret NAME [--bitwarden-project NAME] [--replace] [--dry-run]
    pubsec signing-key backup [--under DIR] [--dry-run]
    pubsec types
    pubsec --version

A repository runs its pinned pubsec as ./pubsec, which pubkit's `sync` writes
beside ./pubkit, and its ./with-secrets runs `./pubsec run`. The deploy need
types (`pubsec types`) are installed for pubdeploy's walk, which loads them by
their `sustenaut.needs` entry points.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__

CONFIG = "pubkit.json"


def read_config(root: Path) -> dict:
    path = root / CONFIG
    if not path.is_file():
        sys.exit(f"pubsec: no {CONFIG} here")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        sys.exit(f"pubsec: {CONFIG} is not JSON")
    if not isinstance(config, dict):
        sys.exit(f"pubsec: {CONFIG} is not a JSON object")
    return config


def confined(path: Path, what: str) -> Path:
    """`path`, resolved, when it lies in the working directory or a temporary
    directory (the system's, or the Actions runner's RUNNER_TEMP), so a
    mistyped or malicious argument cannot reach a file elsewhere; otherwise
    pubsec stops, naming `what`."""
    bases = [Path.cwd(), Path(tempfile.gettempdir())]
    if os.environ.get("RUNNER_TEMP"):
        bases.append(Path(os.environ["RUNNER_TEMP"]))
    resolved = path.resolve()
    if any(resolved.is_relative_to(base.resolve()) for base in bases):
        return resolved
    sys.exit(f"pubsec: {what} ({path}) must be in the working directory or a temporary directory")


def types() -> int:
    """The need types pubsec offers, as `pubdeploy types` lists them."""
    from .needs.bitwarden import bitwarden_generated, bitwarden_secret  # noqa: PLC0415
    from .needs.gcp import service_account_key  # noqa: PLC0415
    from .needs.github import deploy_settings, github_secret, github_variable  # noqa: PLC0415
    from .needs.k8s import secret  # noqa: PLC0415
    offered = (bitwarden_secret, bitwarden_generated, service_account_key, github_secret, github_variable,
               deploy_settings, secret)
    rows = [("type", "grade", "budget", "offline", "fulfil", "keys")]
    for kind in sorted(offered, key=lambda k: k.type):
        required = set(kind.schema.get("required", []))
        keys = [f"{k}{'' if k in required else '?'}" for k in kind.schema.get("properties", {})]
        rows.append((kind.type, kind.grade, f"{kind.budget:g} s", "yes" if kind.offline else "no",
                     f"{kind.fulfil_budget:g} s", ", ".join(keys) or "-"))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]) - 1)]
    for row in rows:
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths)) + "  " + row[-1])
    print(f"{len(offered)} types, pubsec {__version__}'s, for pubdeploy")
    return 0


def main(argv: list[str] | None = None) -> int:
    given = sys.argv[1:] if argv is None else argv
    if given[:1] == ["run"]:
        # Its own parser: everything after -- is the command, with its own options.
        from .run import main as run  # noqa: PLC0415
        return run(given)
    parser = argparse.ArgumentParser(prog="pubsec", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"pubsec {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("run", help="run one command with with-secrets.json's Bitwarden secrets in its "
                                    "environment: run [--cwd DIR] -- COMMAND")
    p = commands.add_parser("app-secrets", help="send the secrets this repository's pubkit.json "
                                                "names to it, through ./with-secrets")
    p.add_argument("--check", action="store_true", help="check the values, and send nothing")
    p = commands.add_parser("github-app", help="make a GitHub App from a manifest, and put its "
                                               "values in Bitwarden")
    github_app = p.add_subparsers(dest="github_app_command", required=True)
    p = github_app.add_parser("create", help="go through GitHub's app-manifest flow, in a browser, "
                                             "then write the app's id, key and installation id")
    p.add_argument("manifest", type=Path, metavar="MANIFEST",
                   help="the app's manifest, with a pubkit section naming its owner, "
                        "Bitwarden project and secret prefix")
    p.add_argument("--replace", action="store_true",
                   help="overwrite secrets that already have those names, instead of refusing")
    p.add_argument("--dry-run", action="store_true", help="show the plan, and do nothing")
    p = commands.add_parser("service-account-key", help="make a Google Cloud service account key, and put it "
                                                        "in Bitwarden, with no file or command line holding it")
    service_account_key = p.add_subparsers(dest="service_account_key_command", required=True)
    p = service_account_key.add_parser("create", help="make a new key beside the account's others, and write it "
                                                      "to a secret")
    p.add_argument("--account", required=True, metavar="EMAIL", help="the service account")
    p.add_argument("--secret", required=True, metavar="NAME", help="the secret to write")
    p.add_argument("--bitwarden-project", metavar="NAME",
                   help="the Bitwarden project; by default, the one with-secrets.json names")
    p.add_argument("--replace", action="store_true",
                   help="overwrite a secret that already has that name, instead of refusing")
    p.add_argument("--dry-run", action="store_true", help="show the plan, and do nothing")
    p = commands.add_parser("signing-key", help="back up the signing keys pubkit.json declares to Bitwarden")
    signing_key = p.add_subparsers(dest="signing_key_command", required=True)
    p = signing_key.add_parser("backup", help="write each declared key on this machine that its Bitwarden "
                                              "project lacks, never overwriting one")
    p.add_argument("--under", type=Path, metavar="DIR",
                   help="every repository directly under DIR, not this one")
    p.add_argument("--dry-run", action="store_true", help="say what would be written, and ask for nothing")
    commands.add_parser("types", help="the deploy need types pubsec offers pubdeploy's walk")
    args = parser.parse_args(given)
    root = Path.cwd()
    if args.command == "app-secrets":
        from .app_secrets import run as app_secrets  # noqa: PLC0415
        return app_secrets(read_config(root), args.check)
    if args.command == "github-app":
        from .github_app import run as github_app  # noqa: PLC0415
        return github_app(confined(args.manifest, "the manifest"), args.replace, args.dry_run)
    if args.command == "service-account-key":
        from .service_account_key import run as service_account_key  # noqa: PLC0415
        return service_account_key(root, args.account, args.secret, args.bitwarden_project, args.replace,
                                   args.dry_run)
    if args.command == "signing-key":
        from .signing_keys import run as signing_key_backup  # noqa: PLC0415
        return signing_key_backup(args.under.expanduser() if args.under else None, args.dry_run)
    return types()


if __name__ == "__main__":
    sys.exit(main())
