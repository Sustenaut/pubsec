Feature: pubsec org-secrets sets an organization's secrets and variables for the repositories it lists
  pubrules.json's org_secrets block names them, as github_app does a repository's.
  An app's client id goes as a variable and its key as a secret, each visible to
  selected repositories. The listed ones are added one at a time, and none is
  ever taken off. Nothing is written until the values and GitHub's side check
  out, and no value is printed or on a command line.

  Background:
    Given a scratch directory
    And the program under test is "pubsec"

  Scenario: A new client id and key are set, visible to the listed repository
    Given a pubrules.json whose org_secrets block names an app's client id and key for pubpr
    And Bitwarden has both values
    When I run "pubsec org-secrets"
    Then it succeeds
    And it prints "drift    variable DATA_APP_CLIENT_ID: missing"
    And it prints "set      secret DATA_APP_KEY in example-org"
    And it prints "added    pubpr to secret DATA_APP_KEY"
    And it prints "added    pubpr to variable DATA_APP_CLIENT_ID"
    And it does not print "yes"
    And the variable "DATA_APP_CLIENT_ID" holds the client id
    And the variable "DATA_APP_CLIENT_ID" is visible to selected repositories: "pubpr"
    And the secret "DATA_APP_KEY" is sealed to the org's key, with the key's value
    And the secret "DATA_APP_KEY" is visible to selected repositories: "pubpr"
    And no selection was replaced: repositories were added one at a time
    And no value is printed or on a command line

  Scenario: An existing secret gets the new value, and keeps who sees it
    Given a pubrules.json whose org_secrets block names an app's client id and key for pubpr
    And Bitwarden has both values
    And the org has the secret "DATA_APP_KEY", visible to "pubpr"
    And the org has the variable "DATA_APP_CLIENT_ID" as "Iv23liOldClient", visible to "pubpr"
    When I run "pubsec org-secrets"
    Then it succeeds
    And the secret "DATA_APP_KEY" is sealed to the org's key, with the key's value
    And the secret "DATA_APP_KEY" was set keeping "pubpr" selected
    And the secret "DATA_APP_KEY" is visible to selected repositories: "pubpr"
    And the variable "DATA_APP_CLIENT_ID" holds the client id
    And it does not print "added"
    And no value is printed or on a command line

  Scenario: Repositories already selected stay when the listed one is added
    Given a pubrules.json whose org_secrets block names an app's client id and key for pubpr
    And Bitwarden has both values
    And the org has the secret "DATA_APP_KEY", visible to "other-repo,third-repo"
    And the org has the variable "DATA_APP_CLIENT_ID" as the client id, visible to "other-repo"
    When I run "pubsec org-secrets"
    Then it succeeds
    And the secret "DATA_APP_KEY" was set keeping "other-repo,third-repo" selected
    And the secret "DATA_APP_KEY" is visible to selected repositories: "other-repo,third-repo,pubpr"
    And the variable "DATA_APP_CLIENT_ID" is visible to selected repositories: "other-repo,pubpr"
    And it prints "same     variable DATA_APP_CLIENT_ID in example-org"
    And no selection was replaced: repositories were added one at a time

  Scenario: --check with nothing to change writes nothing, and succeeds
    Given a pubrules.json whose org_secrets block names an app's client id and key for pubpr
    And Bitwarden has both values
    And the org has the secret "DATA_APP_KEY", visible to "pubpr,other-repo"
    And the org has the variable "DATA_APP_CLIENT_ID" as the client id, visible to "pubpr"
    When I run "pubsec org-secrets --check"
    Then it succeeds
    And it prints "ok       variable DATA_APP_CLIENT_ID: visible to pubpr"
    And it prints "ok       secret DATA_APP_KEY: visible to pubpr (its value is not compared)"
    And it prints "GitHub never returns one"
    And it prints "All 2 match. --check: nothing was written."
    And gh wrote nothing

  Scenario: --check reports drift, writes nothing, and fails
    Given a pubrules.json whose org_secrets block names an app's client id and key for pubpr
    And Bitwarden has both values
    And the org has the secret "DATA_APP_KEY", visible to "other-repo"
    And the org has the variable "DATA_APP_CLIENT_ID" as "Iv23liOldClient", visible to "pubpr"
    When I run "pubsec org-secrets --check"
    Then the exit code is 1
    And it prints "drift    secret DATA_APP_KEY: not visible to pubpr"
    And it prints "drift    variable DATA_APP_CLIENT_ID: its value differs from Bitwarden's"
    And it prints "2 of 2 differ. --check: nothing was written."
    And gh wrote nothing
    And no value is printed or on a command line

  Scenario: --check reports a missing secret and one visible to all repositories
    Given a pubrules.json whose org_secrets block names an app's client id and key for pubpr
    And Bitwarden has both values
    And the org has the variable "DATA_APP_CLIENT_ID" as the client id, visible to "pubpr"
    When I run "pubsec org-secrets --check"
    Then the exit code is 1
    And it prints "drift    secret DATA_APP_KEY: missing"
    And it prints "1 of 2 differ."
    And gh wrote nothing

  Scenario: An existing secret visible to all repositories is never narrowed
    Given a pubrules.json whose org_secrets block names an app's client id and key for pubpr
    And Bitwarden has both values
    And the org has the secret "DATA_APP_KEY", visible to all repositories
    When I run "pubsec org-secrets"
    Then the exit code is 1
    And it prints "drift    secret DATA_APP_KEY: visible to all repositories, not selected ones"
    And it prints "secret DATA_APP_KEY in example-org: visible to more than selected repositories"
    And gh wrote nothing

  Scenario Outline: A value missing or wrong in Bitwarden stops everything before GitHub is asked
    Given a pubrules.json whose org_secrets block names an app's client id and key for pubpr
    And Bitwarden has both values
    But Bitwarden's "<name>" is <what>
    When I run "pubsec org-secrets"
    Then the exit code is 1
    And it prints "<says>"
    And it prints "Nothing was written."
    And gh was called 0 times

    Examples:
      | name                  | what        | says                                                 |
      | data-reader-key       | missing     | MISSING  data-reader-key                             |
      | data-reader-client-id | missing     | MISSING  data-reader-client-id                       |
      | data-reader-client-id | "5551234"   | BAD      data-reader-client-id is not a client id    |
      | data-reader-client-id | "Iv 23"     | BAD      data-reader-client-id is not a client id    |
      | data-reader-key       | "nonsense"  | BAD      data-reader-key is not a private key        |

  Scenario: A gh login that may not manage the org's secrets is told what it needs
    Given a pubrules.json whose org_secrets block names an app's client id and key for pubpr
    And Bitwarden has both values
    And gh's login may not manage the org's secrets
    When I run "pubsec org-secrets"
    Then the exit code is 1
    And it prints "with 403"
    And it prints "an organization owner with the admin:org scope"
    And gh wrote nothing

  Scenario: A repository that is not there stops the run before anything is written
    Given a pubrules.json whose org_secrets block reads {"org": "example-org", "repositories": ["no-such-repo"], "app": {"key": {"from": "data-reader-key", "to": "DATA_APP_KEY"}}}
    And Bitwarden has both values
    When I run "pubsec org-secrets"
    Then the exit code is 1
    And it prints "there is no repository example-org/no-such-repo"
    And gh wrote nothing

  Scenario: A client id alone is set as a variable, with no secret to seal
    Given a pubrules.json whose org_secrets block reads {"org": "example-org", "repositories": ["pubpr", "other-repo"], "app": {"client_id": {"from": "data-reader-client-id", "to": "DATA_APP_CLIENT_ID"}}}
    And Bitwarden has both values
    When I run "pubsec org-secrets"
    Then it succeeds
    And the variable "DATA_APP_CLIENT_ID" holds the client id
    And the variable "DATA_APP_CLIENT_ID" is visible to selected repositories: "pubpr,other-repo"
    And no value is printed or on a command line

  Scenario: No org_secrets block is said plainly
    Given a file "pubrules.json" holding "{"kind": "utility"}"
    When I run "pubsec org-secrets"
    Then the exit code is 1
    And it prints "pubrules.json has no org_secrets block"

  Scenario Outline: A wrong org_secrets block is refused before anything is read
    Given a pubrules.json whose org_secrets block reads <block>
    And Bitwarden has both values
    When I run "pubsec org-secrets"
    Then the exit code is 1
    And it prints "<says>"
    And gh was called 0 times

    Examples:
      | block                                                                                                                                  | says                                          |
      | []                                                                                                                                     | it lists nothing                              |
      | "x"                                                                                                                                    | each must be an object                        |
      | {"org": "o/x", "repositories": ["r"], "app": {"key": {"from": "k", "to": "K"}}}                                                        | "org" is not an organization's name           |
      | {"org": "o", "repositories": [], "app": {"key": {"from": "k", "to": "K"}}}                                                             | "repositories" must list                      |
      | {"org": "o", "repositories": ["o/r"], "app": {"key": {"from": "k", "to": "K"}}}                                                        | "o/r" is not a repository's name              |
      | {"org": "o", "repositories": ["r"], "app": {}}                                                                                         | "app" must name one or more of                |
      | {"org": "o", "repositories": ["r"], "app": {"token": {"from": "k", "to": "K"}}}                                                        | token is not a setting                        |
      | {"org": "o", "repositories": ["r"], "app": {"key": {"from": "k", "to": "GITHUB_K"}}}                                                   | key's "to" must be upper case                 |
      | {"org": "o", "repositories": ["r"], "app": {"key": {"from": "-k", "to": "K"}}}                                                         | key's "from" is not a secret's name           |
      | {"org": "o", "repositories": ["r"], "app": {"key": {"from": "k"}}}                                                                     | key needs "from"                              |
      | {"org": "o", "repositories": ["r"], "app": {"key": {"from": "k", "to": "K"}}, "visibility": "all"}                                     | visibility is not a setting                   |
      | [{"org": "o", "repositories": ["r"], "app": {"key": {"from": "k", "to": "K"}}}, {"org": "O", "repositories": ["s"], "app": {"key": {"from": "j", "to": "K"}}}] | two of them set the secret K in o |
