Feature: pubsec says which release it is, and which need types it offers
  A quick check that ./pubsec runs the wheel pubrules pins: its version, and
  the nine types pubdeploy's walk loads from it.

  Background:
    Given a scratch directory
    And the program under test is "pubsec"

  Scenario: --version names the release
    When I run "pubsec --version"
    Then it succeeds
    And it prints "pubsec "

  Scenario: types lists the nine types, as pubdeploy types does
    When I run "pubsec types"
    Then it succeeds
    And it prints "bitwarden.generated      auto     0.5 s"
    And it prints "k8s.secret"
    And it prints "gcp.service-account-key  auto     10 s"
    And it prints "gcp.workload-identity    propose  10 s"
    And it prints "bitwarden.adopt          auto     4 s"
    And it prints "9 types"

  Scenario: Without pubrules.json app-secrets says so
    When I run "pubsec app-secrets"
    Then the exit code is 1
    And stderr mentions "no pubrules.json here"
