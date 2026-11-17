Feature: pubsec reaches pubdeploy's walk through the provider contract alone
  The Context names pubdeploy's README lists under Provider contract, and no
  import of pubrules or pubdeploy outside the tests.

  Scenario: Only the contract is used
    Then only the contract is used

  Scenario: Nothing of pubrules is imported
    Then nothing of pubrules is imported

  Scenario: The contract is on pubdeploys context
    Then the contract is on pubdeploys context
