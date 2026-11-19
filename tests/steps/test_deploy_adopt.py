"""Steps for bitwarden.adopt in pubdeploy's walk, against the fakes pubdeploy.testing
keeps: the shared steps are pubdeploy.testing's."""

from __future__ import annotations

from pytest_bdd import given, parsers, scenarios, then

import pytest
pytestmark = pytest.mark.usefixtures("world")  # every scenario in pubdeploy.testing's world
from pubdeploy.testing.steps import entry, namespace

scenarios("deploy-adopt.feature")


@given(parsers.parse('the need "{need_id}" takes the format "{pattern}" and no shape'))
def takes_format(world, need_id, pattern):
    need = entry(world, need_id)
    need.pop("shape", None)
    need["format"] = pattern


@then(parsers.parse('Bitwarden was given the cluster\'s "{secret}" "{key}" as "{name}", noted "{note}"'))
def given_clusters(world, secret, key, name, note):
    assert world.written[name].encode() == namespace(world)["secrets"][secret][key]
    assert world.notes[name] == note


@then(parsers.parse('"{need_id}" says to fix it with "{text}"'))
def fix_says(world, need_id, text):
    assert text in need_of(world, need_id)["fix"]


@then(parsers.parse('the detail of "{need_id}" says "{text}"'))
def detail_says(world, need_id, text):
    assert any(text in d for d in need_of(world, need_id)["details"]), need_of(world, need_id)


@then(parsers.parse('the journal says "{need_id}" is {state}, "{text}"'))
def journal_says(world, need_id, state, text):
    need = need_of(world, need_id)
    assert need["state"] == state and text in need["summary"], need


def need_of(world, need_id):
    found = [n for n in world.journal["needs"] if n["id"] == need_id]
    assert found, need_id
    return found[0]
