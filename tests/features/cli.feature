Feature: pubsec says which release it is, and which need types it offers
  A quick check that ./pubsec runs the wheel pubkit pins: its version, and
  the seven types pubdeploy's walk loads from it.

  Scenario: --version names the release
    When I run pubsec "--version"
    Then it succeeds
    And it prints "pubsec "

  Scenario: types lists the seven types, as pubdeploy types does
    When I run pubsec "types"
    Then it succeeds
    And it prints "bitwarden.generated      auto"
    And it prints "k8s.secret"
    And it prints "gcp.service-account-key  auto   4 s"
    And it prints "7 types"

  Scenario: Without pubkit.json app-secrets says so
    When I run pubsec "app-secrets"
    Then the exit code is 1
    And stderr mentions "no pubkit.json here"
