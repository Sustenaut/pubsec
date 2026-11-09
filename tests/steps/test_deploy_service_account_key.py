"""Steps for gcp.service-account-key in pubdeploy's walk, against fakes: the shared ones are deploy_steps.py's."""

from __future__ import annotations

from pytest_bdd import scenarios

from deploy_steps import *  # noqa: F403 - the shared steps, and the fixtures pytest-bdd keeps them as

scenarios("deploy-service-account-key.feature")
