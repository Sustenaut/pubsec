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
    Then an exception holding a value is not shown

  Scenario: A value in the rendered manifests is not shown
    Then a value in the rendered manifests is not shown

  Scenario: Every result of the sound fixture is free of values
    Then every result of the sound fixture is free of values

  Scenario: A fulfil that raises holding a value is not shown
    Then a fulfil that raises holding a value is not shown

  Scenario: Generated values stay in the walk
    Then generated values stay in the walk

  Scenario: The types walked are pubsecs
    Then the types walked are pubsecs

  Scenario: The hook asks once and says no token
    Then the hook asks once and says no token

  Scenario: The hook without a terminal or a project asks nothing
    Then the hook without a terminal or a project asks nothing

  Scenario: Without a terminal the token comes from the file alone
    Then without a terminal the token comes from the file alone

  Scenario: A token file that cannot be read gives no writer
    Then a token file that cannot be read gives no writer

  Scenario: The hook with an empty token gives no writer
    Then the hook with an empty token gives no writer

  Scenario: The writer finds the secret by its identifier and writes in memory
    Then the writer finds the secret by its identifier and writes in memory
