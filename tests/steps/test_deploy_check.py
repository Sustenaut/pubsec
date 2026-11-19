"""Steps for pubsec's types in pubdeploy check, against fakes of everything it touches: the shared ones are pubdeploy.testing's."""

from __future__ import annotations

from pytest_bdd import scenarios

import pytest
pytestmark = pytest.mark.usefixtures("world")  # every scenario in pubdeploy.testing's world

scenarios("deploy-check.feature")
