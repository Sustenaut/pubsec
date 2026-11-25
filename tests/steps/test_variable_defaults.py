"""Steps for github.variable's defaults: its check against a fake of GitHub's
variables API, which answers 404 for a variable it doesn't hold."""

from __future__ import annotations

import json
from types import SimpleNamespace

from pytest_bdd import given, parsers, scenarios, when

from pubsec.needs.github import GitHubVariable

scenarios("variable-defaults.feature")

SLUG = "example-org/example"


class Refused(Exception):
    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status = status


def github(held: dict):
    def gh(method, url, body):
        name = url.rsplit("/", 1)[-1]
        if name not in held:
            raise Refused(404)
        return {"name": name, "value": held[name]}
    return gh


@given(parsers.parse('GitHub holds no variable "{name}"'), target_fixture="held")
def holds_none(name):
    return {}


@given(parsers.re(r'GitHub holds "(?P<name>[A-Z_]+)" as ["\'](?P<value>.*)["\']$'), target_fixture="held")
def holds(name, value):
    return {name: value}


def check(pubtest_ctx, held, name, params):
    need = SimpleNamespace(name=name, type="github.variable", params={"declared": True, **params})
    ctx = SimpleNamespace(slug=SLUG, gh=github(held), env={}, config={})
    pubtest_ctx.attempt(lambda: vars(GitHubVariable().check(need, ctx)))


@when(parsers.parse('the declared variable "{name}" with the default \'{default}\' is checked'))
def checked(pubtest_ctx, held, name, default):
    check(pubtest_ctx, held, name, {"default": json.loads(default)})


@when(parsers.parse('the declared variable "{name}" with no default is checked'))
def checked_plain(pubtest_ctx, held, name):
    check(pubtest_ctx, held, name, {})


@when("github.variable's schema is read")
def schema_read(pubtest_ctx):
    pubtest_ctx.attempt(lambda: GitHubVariable.schema)
