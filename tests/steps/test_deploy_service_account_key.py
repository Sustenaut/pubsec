"""Steps for gcp.service-account-key in pubdeploy's walk, against fakes: the shared ones are pubdeploy.testing's."""

from __future__ import annotations

from pytest_bdd import scenarios

import pytest
pytestmark = pytest.mark.usefixtures("world")  # every scenario in pubdeploy.testing's world

scenarios("deploy-service-account-key.feature")
