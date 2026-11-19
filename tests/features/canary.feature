Feature: No secret value is ever shown
  The canary: no secret value reaches what pubdeploy prints when it walks
  pubsec's types, nor what pubsec's write-token hook says. Every fake value
  holds CANARY, and what comes out (stdout, stderr, the journal, any
  exception's text, every argv a program was given) must not hold one. These
  scenarios must never be weakened: a check or a fulfil that needs to show a
  value is wrong, not the scenario.

  Scenario Outline: No value is printed, in any state, by any command
    Given the deploy world with <state>
    When pubdeploy runs "<command>"
    Then no value is printed, passed to a program or kept in the journal

    Examples:
      | state                                         | command                    |
      | GitHub forbidden                              | check                      |
      | GitHub forbidden                              | check --json               |
      | GitHub forbidden                              | check --offline --json     |
      | GitHub forbidden                              | walk --fulfil --yes        |
      | GitHub forbidden                              | walk --fulfil --yes --json |
      | GitHub without its secrets                    | check                      |
      | GitHub without its secrets                    | check --json               |
      | GitHub without its secrets                    | check --offline --json     |
      | GitHub without its secrets                    | walk --fulfil --yes        |
      | GitHub without its secrets                    | walk --fulfil --yes --json |
      | a Secret without its key                      | check                      |
      | a Secret without its key                      | check --json               |
      | a Secret without its key                      | check --offline --json     |
      | a Secret without its key                      | walk --fulfil --yes        |
      | a Secret without its key                      | walk --fulfil --yes --json |
      | a bad cookie in Bitwarden                     | check                      |
      | a bad cookie in Bitwarden                     | check --json               |
      | a bad cookie in Bitwarden                     | check --offline --json     |
      | a bad cookie in Bitwarden                     | walk --fulfil --yes        |
      | a bad cookie in Bitwarden                     | walk --fulfil --yes --json |
      | a bad cookie in the cluster                   | check                      |
      | a bad cookie in the cluster                   | check --json               |
      | a bad cookie in the cluster                   | check --offline --json     |
      | a bad cookie in the cluster                   | walk --fulfil --yes        |
      | a bad cookie in the cluster                   | walk --fulfil --yes --json |
      | a key Bitwarden refuses                       | check                      |
      | a key Bitwarden refuses                       | check --json               |
      | a key Bitwarden refuses                       | check --offline --json     |
      | a key Bitwarden refuses                       | walk --fulfil --yes        |
      | a key Bitwarden refuses                       | walk --fulfil --yes --json |
      | a key to make                                 | check                      |
      | a key to make                                 | check --json               |
      | a key to make                                 | check --offline --json     |
      | a key to make                                 | walk --fulfil --yes        |
      | a key to make                                 | walk --fulfil --yes --json |
      | a variable that differs from Bitwarden        | check                      |
      | a variable that differs from Bitwarden        | check --json               |
      | a variable that differs from Bitwarden        | check --offline --json     |
      | a variable that differs from Bitwarden        | walk --fulfil --yes        |
      | a variable that differs from Bitwarden        | walk --fulfil --yes --json |
      | all well                                      | check                      |
      | all well                                      | check --json               |
      | all well                                      | check --offline --json     |
      | all well                                      | walk --fulfil --yes        |
      | all well                                      | walk --fulfil --yes --json |
      | kubectl forbidden                             | check                      |
      | kubectl forbidden                             | check --json               |
      | kubectl forbidden                             | check --offline --json     |
      | kubectl forbidden                             | walk --fulfil --yes        |
      | kubectl forbidden                             | walk --fulfil --yes --json |
      | kubectl refusing writes                       | check                      |
      | kubectl refusing writes                       | check --json               |
      | kubectl refusing writes                       | check --offline --json     |
      | kubectl refusing writes                       | walk --fulfil --yes        |
      | kubectl refusing writes                       | walk --fulfil --yes --json |
      | no cookie in Bitwarden, nor its Secret        | check                      |
      | no cookie in Bitwarden, nor its Secret        | check --json               |
      | no cookie in Bitwarden, nor its Secret        | check --offline --json     |
      | no cookie in Bitwarden, nor its Secret        | walk --fulfil --yes        |
      | no cookie in Bitwarden, nor its Secret        | walk --fulfil --yes --json |
      | nothing in the cluster                        | check                      |
      | nothing in the cluster                        | check --json               |
      | nothing in the cluster                        | check --offline --json     |
      | nothing in the cluster                        | walk --fulfil --yes        |
      | nothing in the cluster                        | walk --fulfil --yes --json |
      | nothing reachable                             | check                      |
      | nothing reachable                             | check --json               |
      | nothing reachable                             | check --offline --json     |
      | nothing reachable                             | walk --fulfil --yes        |
      | nothing reachable                             | walk --fulfil --yes --json |
      | outside with-secrets                          | check                      |
      | outside with-secrets                          | check --json               |
      | outside with-secrets                          | check --offline --json     |
      | outside with-secrets                          | walk --fulfil --yes        |
      | outside with-secrets                          | walk --fulfil --yes --json |
      | over the deploy channel                       | check                      |
      | over the deploy channel                       | check --json               |
      | over the deploy channel                       | check --offline --json     |
      | over the deploy channel                       | walk --fulfil --yes        |
      | over the deploy channel                       | walk --fulfil --yes --json |
      | over the deploy channel, before secret-keys   | check                      |
      | over the deploy channel, before secret-keys   | check --json               |
      | over the deploy channel, before secret-keys   | check --offline --json     |
      | over the deploy channel, before secret-keys   | walk --fulfil --yes        |
      | over the deploy channel, before secret-keys   | walk --fulfil --yes --json |

  Scenario: An exception holding a value is not shown
    Given the deploy world with all well
    And a need type whose check raises, holding a value
    And the secret "canary-7f3e"
    When that need is walked
    Then the result's "needs.0.state" is "unknown"
    And the result's "needs.0.summary" is "the check failed (ValueError)"
    And no secret appears in what it produced

  Scenario: A value in the rendered manifests is not shown
    Given the deploy world with all well
    And the rendered manifests hold a Secret with a value
    When pubdeploy runs "check --offline"
    Then no value is printed, passed to a program or kept in the journal

  Scenario: Every result of the sound fixture is free of values
    Given the deploy world with all well
    And the secret "canary-7f3e"
    When the fixture's needs are walked
    Then every need came to a result
    And no secret appears in what it produced

  Scenario: A fulfil that raises holding a value is not shown
    Given the deploy world with all well
    And a need type whose fulfil raises, holding a value
    And the secret "canary-7f3e"
    When that need is walked and fulfilled
    Then the result's "needs.0.state" is "missing"
    And the result's "needs.0.details.0" is "fulfil failed: the fulfil failed (ValueError); this is a fault in example.leaky's fulfil: report it"
    And no secret appears in what it produced

  Scenario: Generated values stay in the walk
    Given the deploy world with all well
    And Bitwarden holds no cookie
    When pubdeploy runs "walk --fulfil --yes --json"
    Then the value the fulfil made stays in the walk

  Scenario: The types walked are pubsec's
    When the need types are loaded
    Then the result is:
      """
      {"bitwarden.secret": {"origin": "pubsec", "package": "pubsec.needs"},
       "bitwarden.generated": {"origin": "pubsec", "package": "pubsec.needs"},
       "gcp.service-account-key": {"origin": "pubsec", "package": "pubsec.needs"},
       "github.secret": {"origin": "pubsec", "package": "pubsec.needs"},
       "github.variable": {"origin": "pubsec", "package": "pubsec.needs"},
       "github.deploy-settings": {"origin": "pubsec", "package": "pubsec.needs"},
       "k8s.secret": {"origin": "pubsec", "package": "pubsec.needs"}}
      """

  Scenario: The hook asks once and says no token
    Given the deploy world with all well
    And a terminal that answers the write token
    When the hook prepares two units with a terminal
    Then the result's "said" is "[null, null]"
    And the result's "asked" is "["Bitwarden access token with write access to example (hidden, and not kept): "]"
    And the result's "units with a writer" is "2"
    And the result's "writers" is "1"

  Scenario: The hook without a terminal asks nothing
    Given the deploy world with all well
    And a terminal that must not be asked
    When the hook prepares a unit without a terminal
    Then the result's "said" is "[null]"
    And the result's "units with a writer" is "0"

  Scenario: The hook without a project asks nothing
    Given the deploy world with all well
    And a terminal that must not be asked
    And the walk names no Bitwarden project
    When the hook prepares a unit with a terminal
    Then the result's "said" is "["pubsec: no Bitwarden project to write to: run the walk through ./with-secrets, or where with-secrets.json names one"]"
    And the result's "units with a writer" is "0"

  Scenario: Without a terminal the token comes from the file alone
    Given the deploy world with all well
    And a terminal that must not be asked
    And a write token file holding the write token, and the token in the environment too
    When the hook prepares a unit without a terminal
    Then the result's "said" is "[null]"
    And the result's "units with a writer" is "1"
    And the result's "token from the file" is "true"

  Scenario: A token file that cannot be read gives no writer
    Given the deploy world with all well
    And a write token file that cannot be read
    When the hook prepares a unit without a terminal
    Then the result's "said" is "["pubsec: no Bitwarden write token was given, so nothing is written to Bitwarden"]"
    And the result's "units with a writer" is "0"

  Scenario: The hook with an empty token gives no writer
    Given the deploy world with all well
    And a terminal that answers nothing
    When the hook prepares a unit with a terminal
    Then the result's "said" is "["pubsec: no Bitwarden write token was given, so nothing is written to Bitwarden"]"
    And the result's "units with a writer" is "0"

  Scenario: The writer finds the secret by its identifier and writes in memory
    Given Bitwarden's SDK, whose project holds "example-key" as "secret-id"
    And the secret "canary-7f3e"
    When the writer writes "example-key"
    Then the result's "calls" is "[["names", "org-id", "project-id"], ["write", "org-id", "project-id", "example-key", "secret-id"]]"
    And no secret appears in what it produced

  Scenario: A write Bitwarden refuses holds neither the token nor the value
    Given Bitwarden's SDK, whose project holds "example-key" as "secret-id"
    And the secret "canary-7f3e"
    When the writer writes "refused"
    Then it is refused, saying "[hidden]"
    And no secret appears in what it produced
