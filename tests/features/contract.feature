Feature: pubsec reaches pubdeploy's walk through the provider contract alone
  The Context names pubdeploy.contract holds, no import of pubkit or
  pubdeploy in pubsec's code, and in its tests only pubdeploy.contract and
  pubdeploy.testing.

  Scenario: Only the contract is used
    When the names pubsec's code reads from a Context, and not in the contract, are gathered
    Then the result is "[]"

  Scenario: Nothing of pubrules is imported
    When pubsec's imports of pubkit or pubdeploy are gathered
    Then the result is "[]"

  Scenario: The tests import only the contract and the harness of pubdeploy
    When the modules of pubdeploy pubsec's tests import, beside the contract and the harness, are gathered
    Then the result is "[]"
