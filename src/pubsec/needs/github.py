"""github.secret, github.variable and github.deploy-settings: what the
repository on GitHub holds, through the API (`ctx.gh`). A secret is checked by name: GitHub never returns its value. A
variable's value is compared only with the one Bitwarden gives it, run
through ./with-secrets, and never shown.

A fulfil sets what the secrets and github_app blocks name, as
`pubsec app-secrets` does (ctx.send, the value on gh's standard
input), from the environment ./with-secrets gives. A variable pubrules.json's
variables block declares is the state file's, so its fulfil only proposes.

A declared variable may come with its default (`default`, the variables block's,
version 2: the code's own constant, any JSON value). Unset, or empty as a deploy
renders one nothing sets, it is ready at its default, which the code then takes; set
to a value equal to it, compared canonically, it says so."""

from __future__ import annotations

import json
from typing import Any

from . import Base, Result, at_once, env_name, github_refused, schema, status_of

GITHUB_NAME = {"type": "string", "pattern": r"^(?!GITHUB_)[A-Z_][A-Z0-9_]*$",
               "x-phrase": "must be upper case letters, digits and _, not starting GITHUB_"}
FROM = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", "x-phrase": "must be a secret's name"}
ENVIRONMENT = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
               "x-phrase": "must be an environment's name"}
# The names the server's deploy job reads, and how each is kept on GitHub. pubrules
# keeps the same table (pubrules/deploy/implied.py, DEPLOY_SETTINGS), which implies
# this need from it: a change to one is made in both.
DEPLOY_SETTINGS = {"SUSTENAUT_SERVER": "variable", "SUSTENAUT_KNOWN_HOSTS": "variable",
                   "SUSTENAUT_DEPLOY_SSH_KEY": "secret", "TS_GH_OAUTH_CLIENT_ID": "secret",
                   "TS_GH_OAUTH_SECRET": "secret"}
SERVER_ENVIRONMENT = "server"  # k8s-deploy.yml's environment input, by default
NO_ORIGIN = Result("unknown", "origin is not a GitHub repository",
                   fix="run this in a clone whose origin is the repository on GitHub")


def where(slug: str, environment: str | None) -> str:
    return f"{slug}, environment {environment}" if environment else slug


def path(slug: str, kind: str, name: str, environment: str | None) -> str:
    plural = f"{kind}s"
    if environment:
        return f"repos/{slug}/environments/{environment}/{plural}/{name}"
    return f"repos/{slug}/actions/{plural}/{name}"


def github_name(need: Any) -> str:
    return need.params.get("to") or need.name.rsplit("/", 1)[-1]


def entries(ctx: Any) -> list[dict[str, Any]]:
    """What the secrets and github_app blocks send, as app_secrets plans it."""
    from ..app_secrets import BLOCK, OTHERS, config_problems, plan  # noqa: PLC0415
    if (BLOCK not in ctx.config and OTHERS not in ctx.config) or config_problems(ctx.config):
        return []
    return plan(ctx.config)


def send(ctx: Any, kind: str, name: str, source: str, environment: str | None) -> Result:
    """Set one secret or variable from Bitwarden's value of `source`."""
    value = ctx.env.get(env_name(source)) if ctx.env.get("PUBRULES_SECRETS_PROJECT") else None
    if value is None:
        return Result("missing", f"{source} is not in this walk's environment",
                      fix=f"put {source} in Bitwarden, and run the walk through ./with-secrets")
    refused = ctx.send(kind, name, ctx.slug, value, environment)
    if refused is not None:
        return Result("missing", f"gh refused {kind} {name}", fix=refused.replace(value, "[hidden]")[:300])
    return Result("ready", f"set {kind} {name} in {where(ctx.slug, environment)} from Bitwarden's {source}, "
                           f"{len(value.encode())} bytes")


def setter(kind: str, name: str, slug: str, environment: str | None, source: str | None) -> str:
    if source:
        return f"put {source} in Bitwarden, then ./with-secrets ./pubsec app-secrets"
    env = f" --env {environment}" if environment else ""
    return f"gh {kind} set {name} -R {slug}{env}"


class GitHubSecret(Base):
    type = "github.secret"
    grade = "auto"
    budget = 3.0
    fulfil_budget = 30.0
    kind = "secret"
    schema = schema({"from": FROM, "to": GITHUB_NAME, "environment": ENVIRONMENT})

    def grade_for(self, need: Any) -> str:
        return "auto" if need.params.get("from") else "human"

    def action(self, need: Any, ctx: Any) -> str:
        return f"gh {self.kind} set {github_name(need)} from Bitwarden's {need.params.get('from')}"

    def fulfil(self, need: Any, ctx: Any) -> Result:
        return send(ctx, self.kind, github_name(need), need.params["from"], need.params.get("environment"))

    def check(self, need: Any, ctx: Any) -> Result:
        if not ctx.slug:
            return NO_ORIGIN
        name, env = github_name(need), need.params.get("environment")
        try:
            ctx.gh("GET", path(ctx.slug, "secret", name, env), None)
        except Exception as e:  # noqa: BLE001 - ctx.gh's refusal: an error with its HTTP status
            if not hasattr(e, "status"):
                raise
            if status_of(e) == 404:
                return Result("missing", f"secret {name} is not set in {where(ctx.slug, env)}",
                              fix=setter("secret", name, ctx.slug, env, need.params.get("from")))
            return github_refused(e, f"secret {name}")
        return Result("ready", f"secret {name} is set in {where(ctx.slug, env)}")


class GitHubVariable(GitHubSecret):
    """A variable the secrets or github_app blocks fill from Bitwarden (auto),
    or one the variables block declares, whose value is the state file's (propose)."""
    type = "github.variable"
    grade = "auto"
    kind = "variable"
    # default: any JSON value, null included, so its presence, not its value, says there is one.
    schema = schema({"from": FROM, "to": GITHUB_NAME, "environment": ENVIRONMENT, "declared": {"type": "boolean"},
                     "default": {}})

    def grade_for(self, need: Any) -> str:
        return "auto" if need.params.get("from") and not need.params.get("declared") else "propose"

    def fulfil(self, need: Any, ctx: Any) -> Result:
        if self.grade_for(need) == "auto":
            return super().fulfil(need, ctx)
        name = github_name(need)
        repo = ctx.slug.rsplit("/", 1)[-1] if ctx.slug else "REPOSITORY"
        return Result("missing", f"variable {name} is the state file's",
                      fix=f"in the owner's state file, under \"{repo}\": add to its variables\n"
                          f"  \"{name}\": <its value>\nthen pubrules variables --apply {repo}")

    def check(self, need: Any, ctx: Any) -> Result:
        if not ctx.slug:
            return NO_ORIGIN
        name, env, source = github_name(need), need.params.get("environment"), need.params.get("from")
        try:
            found = ctx.gh("GET", path(ctx.slug, "variable", name, env), None) or {}
        except Exception as e:  # noqa: BLE001 - ctx.gh's refusal: an error with its HTTP status
            if not hasattr(e, "status"):
                raise
            if status_of(e) == 404:
                if "default" in need.params:
                    return Result("ready", f"variable {name} is not set in {where(ctx.slug, env)}: "
                                           f"default ({shown(need.params['default'])})")
                return Result("missing", f"variable {name} is not set in {where(ctx.slug, env)}",
                              fix=setter("variable", name, ctx.slug, env, source))
            return github_refused(e, f"variable {name}")
        value = found.get("value") if isinstance(found, dict) else None
        if "default" in need.params:
            if not value:
                return Result("ready", f"variable {name} is empty in {where(ctx.slug, env)}: "
                                       f"default ({shown(need.params['default'])})")
            if same(need.params["default"], value):
                return Result("ready", f"variable {name} is set in {where(ctx.slug, env)}, to its default, "
                                       f"which leaving it unset would give too")
        if need.params.get("declared") and not value:
            return Result("missing", f"variable {name} is empty in {where(ctx.slug, env)}",
                          fix="give it its value in the state file, then pubrules variables --apply")
        wanted = ctx.env.get(env_name(source)) if source else None
        if wanted is not None and wanted != value:
            return Result("drift", f"variable {name} in {where(ctx.slug, env)} is not Bitwarden's {source}",
                          fix="./with-secrets ./pubsec app-secrets")
        compared = " and is Bitwarden's" if wanted is not None else ""
        return Result("ready", f"variable {name} is set in {where(ctx.slug, env)}{compared}")


def canonical(value: Any) -> str:
    """A JSON value as one string, however it was spaced or its keys ordered (pubrules'
    variables.canonical, kept here as pubsec reads no pubrules)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def same(default: Any, value: str) -> bool:
    """Whether a variable GitHub holds is its default: a string as it is, anything else
    as the JSON GitHub's string parses to, as a state file sends it."""
    if isinstance(default, str):
        return value == default
    try:
        return canonical(json.loads(value)) == canonical(default)
    except ValueError:
        return False


def shown(default: Any) -> str:
    """A default in a check's line: a string as it is, null as unset, JSON compact. A
    default is the code's constant, public in pubrules.json, so it may be shown."""
    if default is None:
        return "unset"
    return default if isinstance(default, str) else canonical(default)


class DeploySettings(Base):
    """The five names the server's deploy job reads, on the repository or in
    the environment the job runs in: each scope listed once."""
    type = "github.deploy-settings"
    grade = "auto"
    budget = 3.0
    fulfil_budget = 60.0
    singleton = True
    schema = schema({"environment": ENVIRONMENT})

    def missing(self, need: Any, ctx: Any) -> tuple[list[str], Result | None]:
        """The settings set nowhere. The four listings are asked at once, as
        one after another overran the budget."""
        env = need.params.get("environment", SERVER_ENVIRONMENT)
        held: set[tuple[str, str]] = set()
        asked = [(kind, scope) for kind in ("secret", "variable")
                 for scope in (f"repos/{ctx.slug}/actions", f"repos/{ctx.slug}/environments/{env}")]
        answers = at_once(ctx.gh, [("GET", f"{scope}/{kind}s?per_page={100 if kind == 'secret' else 30}", None)
                                   for kind, scope in asked])
        for (kind, scope), found in zip(asked, answers):
            if isinstance(found, Exception):
                if status_of(found) == 404 and "environments" in scope:
                    continue
                return [], github_refused(found, f"the {kind}s of {ctx.slug}")
            held |= {(kind, str(item.get("name"))) for item in (found or {}).get(f"{kind}s") or []
                     if isinstance(item, dict)}
        return [name for name, kind in DEPLOY_SETTINGS.items() if (kind, name) not in held], None

    def action(self, need: Any, ctx: Any) -> str:
        return "gh secret set and gh variable set the deploy settings the secrets block names"

    def check(self, need: Any, ctx: Any) -> Result:
        if not ctx.slug:
            return NO_ORIGIN
        env = need.params.get("environment", SERVER_ENVIRONMENT)
        missing, refused = self.missing(need, ctx)
        if refused:
            return refused
        if missing:
            named = {e["to"] for e in entries(ctx)}
            return Result("missing", f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} set neither "
                                     f"in {ctx.slug} nor its {env} environment",
                          fix="name them in pubrules.json's secrets block, then ./with-secrets ./pubsec app-secrets",
                          fixable=all(m in named for m in missing))
        return Result("ready", f"the {len(DEPLOY_SETTINGS)} deploy settings are set in {ctx.slug} or its {env} "
                               "environment")

    def fulfil(self, need: Any, ctx: Any) -> Result:
        missing, refused = self.missing(need, ctx)
        if refused:
            return Result("missing", refused.summary, fix=refused.fix)
        done, sent = [], {e["to"]: e for e in entries(ctx)}
        for name in missing:
            entry = sent.get(name)
            if entry is None:
                return Result("missing", f"the secrets block does not name {name}",
                              fix="name it in pubrules.json's secrets block")
            made = send(ctx, entry["kind"], name, entry["from"], entry.get("environment"))
            if made.state != "ready":
                return made
            done.append(name)
        return Result("ready", f"set {', '.join(done) or 'nothing'} from Bitwarden")


github_secret = GitHubSecret()
github_variable = GitHubVariable()
deploy_settings = DeploySettings()
