# pubsec

The commands and deploy need types that hold a secret value, a write token or
a private key in memory, kept apart from [pubkit](https://github.com/Sustenaut/pubkit),
which only reads *about* secrets (their names, keys, lengths and declarations).
The rule that draws the line: code that holds a secret, a write token or a key
lives here; code that reads a declaration stays in pubkit.

pubsec has no runtime dependencies. Bitwarden's SDK is installed for a run, by
hash, by the commands that write (see "Making a service account key"), and
`bws`, `gh` and `gcloud` are programs it runs.

A repository runs its pinned pubsec as `./pubsec`, which pubkit's `sync` writes
beside `./pubkit` wherever there is a `with-secrets.json` or a `deploy` block.
It runs the release wheel pubkit pins, through `uvx`, checking its sha256 on
every run:

```sh
./pubsec --version
./pubsec types
```

## Services: `./with-secrets`

A service runs every command that needs a secret through `./with-secrets`:

```sh
./with-secrets terraform plan
./with-secrets scripts/setup-backup.sh
```

It reads a Bitwarden Secrets Manager project with the `bws` CLI, using a
read-only machine account's token (`BWS_ACCESS_TOKEN`, or that line in the
repository's git-ignored `.env`), and runs the command with the secrets in
its environment only: the calling shell never holds them, and no master
password is asked for. It stops, naming the projects the token can see, when
it cannot see the one configured. `with-secrets.json` is the repository's:

| Setting | Meaning |
|---|---|
| `project` | The project's name or id |
| `terraform.dir` | Where the Terraform files are |
| `terraform.secrets` | `declared`: a secret named like a declared variable in upper case (`HCLOUD_TOKEN` for `hcloud_token`) goes as `TF_VAR_hcloud_token` and under no other name. `map`: the names `terraform.names_from` lists go as `TF_VAR_secret_values` (declare it ephemeral) and `TF_VAR_secret_revisions` |
| `aliases` | Optional: files (paths from the repository root), each `{"aliases": {"NAME": "secret"}}`, that also export the secret named `secret` as `NAME`, for a tool that reads a fixed name (the Tailscale Terraform provider reads `TAILSCALE_OAUTH_CLIENT_ID`). Keep each file next to the code that needs it. An alias of a secret Bitwarden does not have is reported and skipped |

Every other secret goes under its name in upper case, `-` as `_`, and
`PUBKIT_SECRETS_PROJECT` names the project they came from, so pubkit's deploy
walk can tell a secret that is absent from one that was never read.

`./with-secrets` is one line, which pubkit manages: it runs `./pubsec run --cwd
"$PWD" -- COMMAND`, so the repository's pinned pubsec does the work, in the
directory it is called from, and needs `uv` (for `./pubsec`) and `bws`.
`pubsec run` can be called directly too:

```sh
./pubsec run -- terraform plan        # in the repository's root
./pubsec run --cwd "$PWD" -- make deploy
```

Its exit code is the command's, 127 when the command is not there and 126 when
it may not run, and 1, before anything runs, for a setting it can't use.

## Sending secrets to a repository

A repository names the values it needs in its `pubkit.json`. A GitHub App has
three, in `github_app`, which may also be a list of apps. `secrets` lists any
others, each with a `kind` of `secret` or `variable`:

```json
"github_app": {
  "id":              { "from": "some-app-id", "to": "SOME_APP_ID" },
  "installation_id": { "from": "some-app-installation-id", "to": "SOME_APP_INSTALLATION_ID" },
  "key":             { "from": "some-app-key", "to": "SOME_APP_KEY" }
},
"secrets": [
  { "from": "some-token", "to": "SOME_TOKEN", "kind": "secret" },
  { "from": "some-user", "to": "SOME_USER", "kind": "variable" },
  { "from": "some-deploy-key", "to": "SOME_DEPLOY_KEY", "kind": "secret", "environment": "some-env" }
]
```

`from` is the secret's name in the Bitwarden project `./with-secrets` reads, and
`to` its name on GitHub. An app's id and installation id go as variables and its
key as a secret, on the repository `origin` points at and no other. `environment`,
on an entry in `secrets`, puts it in that GitHub environment, which must already
exist, instead of the repository's own:

```sh
./with-secrets ./pubsec app-secrets --check   # checks only, sends nothing
./with-secrets ./pubsec app-secrets
```

It writes nothing until every one is there and looks right (digits for an app's
ids, BEGIN and END lines for its key, and not empty for the others). It prints names and lengths, never a value,
and each value reaches `gh` on its standard input. An app installed on several
owners has a different installation id on each, so each repository names its own
owner's. `pubkit sync --check` checks both blocks.

## Creating a GitHub App

`pubsec github-app create` makes an app with GitHub's
[manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)
and puts its three values in Bitwarden, under names `pubsec app-secrets` can then
send on. The manifest is the repository's own: GitHub's fields, and a `pubkit`
section GitHub never sees (the name it had when this command was pubkit's),
naming the owner (`org` or `user`), the Bitwarden project (its name or id) and
the prefix of the secrets' names:

```json
{
  "name": "some-app",
  "url": "https://example.org",
  "public": false,
  "default_permissions": { "contents": "read" },
  "pubkit": {
    "org": "some-org",
    "bitwarden_project": "some-project",
    "secret_prefix": "some-app"
  }
}
```

```sh
./pubsec github-app create --dry-run some-app.json   # shows the plan, and does nothing
./pubsec github-app create some-app.json
```

It goes in this order, so that a refusal comes before there is an app to clean up:

1. It shows the app, the project and the three names: `some-app-app-id`,
   `some-app-app-key` and `some-app-installation-id`. `--dry-run` ends here.
2. It asks for a Bitwarden access token with write access to the project, at a
   hidden prompt. It is never read from `.env` or a file and never kept, and it
   reaches `bws` only in its environment. `./with-secrets`' read-only token will
   not do for the writes.
3. It looks for the names in the project, among the secrets' identifiers, which
   Bitwarden's SDK gives without any value, and refuses if one is there.
   `--replace` overwrites them instead.
4. A server on 127.0.0.1 opens a page that posts the manifest to GitHub, with a
   random `state` that must come back. You confirm the app on GitHub, which
   redirects to the server with a code, and the code becomes the app and its key.
5. Your browser opens the app's install page. Signing with the new key, pubsec
   watches `GET /app/installations` until the app is installed on the owner, takes
   the installation's id, and says which repositories it reaches: all of them, or
   the list of those selected. Opening that page may install the app on every
   repository straight away, with no step in which to choose. To narrow it, go to
   the owner's settings, then GitHub Apps, then Configure beside the app, and pick
   "Only select repositories"; the run has printed the link. The installation's id
   stays the same, so this can wait until after the run.
6. It shows what it will write, and writes only when you type `yes`. If a write
   fails it offers to try the ones left with another token.

The key is never printed or written to disk: it stays in memory, so if the run
ends before it is written, it is gone, and pubsec gives the app's settings page,
where you make a new one or delete the app. The same goes for a client secret and
webhook secret, which GitHub also returns and pubsec does not keep. The values are
written with Bitwarden's SDK, which takes them in memory, so the key is on no command
line (see "Making a service account key" for how it is installed).

A pull token for `ghcr.io` is no app's to give, so it stays a manual step.

## Making a service account key

`pubsec service-account-key create` makes a Google Cloud service account key and
puts it in Bitwarden, so an app outside Google Cloud can have one without the key
ever being in a file, on a command line, or in Terraform's state:

```sh
./pubsec service-account-key create --dry-run --account NAME@PROJECT.iam.gserviceaccount.com --secret some-key
./pubsec service-account-key create --account NAME@PROJECT.iam.gserviceaccount.com --secret some-key
```

It shows the plan, and asks for a Bitwarden access token with write access to the
project, at a hidden prompt, as `github-app create` does. The project is the one
`with-secrets.json` names, or `--bitwarden-project`. It refuses if the secret is
there, found by name among the identifiers; `--replace` overwrites it. On a typed
`yes`, `gcloud` writes the key to pubsec's pipe, and Bitwarden's SDK writes it,
base64-encoded, from memory. If that write fails the new key is deleted from
Google. The account's other keys are left working, and listed, so whatever holds
one can move over before it is deleted.

The SDK is not a dependency of pubsec: the command installs it with `uv` for that
run alone, by the hashes in `src/pubsec/bitwarden-sdk.lock`. Its wheels are under
Bitwarden's own SDK licence, not pubsec's.

## Backing up signing keys

A repository names every signing key it uses, and where it is backed up, in
`pubkit.json`:

```json
"signing_keys": [
  {"path": "corpus/.publet/signing.key",
   "bitwarden": {"project": {"id": "PROJECT-UUID", "name": "Pub"},
                 "name": "pub-signing-key-example"}}
]
```

The project is found by its `id`; `name` is a label for people, and a run
warns when Bitwarden's name for the project has changed. A plain string is
taken as an id when it is a UUID, else as a name, in any case.

`path` is from the repository's root, or from the home directory when it
starts with `~/`: a key kept outside any repository, such as one under
`~/.config`, is declared by the repository whose tools use it. `pubkit sync
--check` refuses a block it can't use.

    pubsec signing-key backup [--under DIR] [--dry-run]

reads the declarations of this repository, or of every repository directly
under `DIR`, and writes each declared key that is on this machine and not yet
in its project, with Bitwarden's SDK, from memory. The access token, which
must be able to read and write those projects, is asked for at a hidden
prompt. A secret already there is found by name among the project's
identifiers, and only the values of those named as the declared keys are read,
to compare: one with the same value is left alone; another value under the
same name is never overwritten and fails the run, as do two different keys
declared under one name. A key pubkit.json does not declare, at
`corpus/.publet/signing.key` or `.publet/signing.key`, is pointed out.
`--dry-run` lists what it would write and asks for nothing. No key or token
is printed or put on a command line.

## Making what a service needs

pubkit's `deploy walk` checks every need of a repository's `deploy` block, and
with `--fulfil` makes what is missing (pubkit's README, "Declaring what a
service needs"). Seven of its types are pubsec's, installed under the
entry-point group `sustenaut.needs`, so a repository's `deploy.providers` lists
pubsec at the release pubkit pins (`pubkit sync` adds it). `./pubsec types`
lists them:

| type | its check | its fulfil | it needs |
| --- | --- | --- | --- |
| bitwarden.secret | the secret is in the Bitwarden project ./with-secrets read: its length | none: a person puts it there | ./with-secrets |
| bitwarden.generated | as bitwarden.secret, and the value has its shape | a new value of its shape, written to Bitwarden, and kept for the Secret it fills | a write token |
| gcp.service-account-key | the key in Bitwarden is one of the account's live keys | a new key, written to Bitwarden, deleted from Google if that fails | gcloud, a write token |
| github.secret | it is set, on the repository or in its environment | `gh secret set` of what the secrets and github_app blocks name, from Bitwarden, as `pubsec app-secrets` does | ./with-secrets |
| github.variable | it is set, and is Bitwarden's value when one is named; one the variables block declares is the state file's, and only proposed | `gh variable set`, as above | ./with-secrets |
| github.deploy-settings | the five names the server's deploy job reads are set on the repository or its server environment | each the secrets block names, set from Bitwarden | ./with-secrets |
| k8s.secret | the Secret has its keys, each value of a known shape having it; over the deploy channel, its key names alone | a Secret manifest from the values of the needs that fill it, on kubectl's standard input, then a restart of each Deployment in the cluster whose pods read it | kubectl that writes |

The write token is asked for by pubsec's `sustenaut.walk` hook, `bitwarden =
"pubsec.walk:prepare"`: before a walk fulfils a need that wants one, at a
terminal, pubkit calls it, and it asks once in the process, at a hidden prompt,
for a Bitwarden access token with write access to the project ./with-secrets
read (`PUBKIT_SECRETS_PROJECT`, else `with-secrets.json`'s). The writer it gives
the walk keeps the token in the process only, finds the secret to update by name
among the identifiers, and writes the value from memory with the SDK. A walk
from GitHub Actions, or with `--yes` and no terminal, asks for none, and those
needs are unknown, saying so.

A value moves only on a standard input: never in an argv, a file, a log or the
journal. pubkit is installed wherever a deploy block is walked or checked, CI
included, and pubsec with it, as `sync --check` validates every need with its
type's schema; in CI without a write token pubsec reads nothing. The trust
boundary is the token, not the code.

### The provider contract

pubsec imports nothing of pubkit at runtime. A check or a fulfil uses the
walk's Context by these names alone, which pubkit lists in its README under
"Provider contract" and does not change without saying so in its changelog:
`root`, `config`, `block`, `namespace`, `unit`, `channel`, `kubectl`, `server`,
`gh`, `send`, `bitwarden_writer`, `http_get`, `env`, `now`, `rendered`,
`offline`, `slug`, `zones`, `resolve`, `values`, `types`, `needs`, `results`,
`sleep` and `dispatched`. It returns its own `Result`, with `state`, `summary`,
`fix`, `details`, `fixable` and `step`. `tests/steps/test_contract.py` fails when
pubsec uses another name or imports pubkit.

## Developing

```sh
make venv     # .venv from tests/requirements.lock, with this checkout editable
make check    # ./pubkit sync --check, and the Gherkin suite with its coverage
```

The suite runs every command end to end against stand-ins for `bws`, `gh`,
`gcloud`, `uv`, a browser and Bitwarden's SDK, and the seven types through
pubkit's own walk (pubkit is a test dependency, pinned in
`tests/requirements.txt`). Every fake value in the deploy scenarios holds a
canary, and `tests/steps/test_canary.py` fails when one reaches an output, the
journal, an exception's text or a command line.

## Releasing

With [pubrel](https://github.com/Sustenaut/pubrel), like the other Sustenaut
packages. A pull request that changes `src/` or `pyproject.toml` records what it
changes (`pubrel add fixed "…"`, or `internal` for no release), and CI checks it.
To release, run `pubrel prepare` on an up-to-date main in a checkout holding the
release key (`corpus/.publet`, gitignored): it sets `version` in `pyproject.toml`
(`__version__` reads it), signs the release and opens its pull request. Merging
that tags `vX.Y.Z` and makes the release, and `wheel.yml` then attaches
`pubsec-X.Y.Z-py3-none-any.whl`, the wheel pubkit pins by its sha256.

## Licence

Apache-2.0.
