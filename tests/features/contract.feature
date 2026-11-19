Feature: pubsec reaches pubdeploy's walk through the provider contract alone
  The Context names pubdeploy's README lists under Provider contract, and no
  import of pubrules or pubdeploy outside the tests.

  Scenario: Only the contract is used
    When the names pubsec's code reads from a Context, and not in the contract, are gathered
    Then the result is "[]"

  Scenario: Nothing of pubrules is imported
    When pubsec's imports of pubkit or pubdeploy are gathered
    Then the result is "[]"

  Scenario: The contract is on pubdeploy's context
    When the names of the contract that pubdeploy's Context lacks are gathered
    Then the result is "[]"
