Feature: bitwarden.adopt keeps a value the cluster already holds by copying it into Bitwarden
  A secret made by hand before a service had its deploy block lives only in its
  Secret. Declared as bitwarden.adopt, the walk copies it into Bitwarden once,
  instead of making a new one, and leaves the Secret as it is. The value goes
  from kubectl's answer to the Bitwarden writer in memory: never in argv, a log
  or the journal (every fake value holds a canary, and no output may).

  Background:
    Given the example service
    And the need "bitwarden.generated:example-cookie-secret" is dropped
    And the deploy block also needs {"type": "bitwarden.adopt", "name": "example-cookie-secret", "secret": {"name": "example-page-secrets", "key": "cookie-secret"}, "shape": "oauth2-proxy-cookie", "note": "copied from example-page-secrets"}

  Scenario: A value already in Bitwarden is ready, and the cluster is not read for it
    When I run pubdeploy "check"
    Then "bitwarden.adopt:example-cookie-secret" is ready, "example-cookie-secret is in Bitwarden: 32 bytes"
    And no output holds a value

  Scenario: A value only the cluster holds is missing, and the plan says what the copy touches
    Given Bitwarden has no "example-cookie-secret"
    And "no" is typed at the prompt
    When I run pubdeploy "walk" "--fulfil"
    Then "bitwarden.adopt:example-cookie-secret" is missing, "Secret example-page-secrets key cookie-secret holds 32 bytes to keep"
    And stderr mentions "bitwarden.adopt:example-cookie-secret: copy key cookie-secret of Secret example-page-secrets in example into Bitwarden as example-cookie-secret (the value is never printed)"
    And Bitwarden was given nothing
    And no output holds a value

  Scenario: The fulfil copies the cluster's value, and the Secret is left as it is
    Given Bitwarden has no "example-cookie-secret"
    When I run pubdeploy "walk" "--fulfil" "--yes"
    Then it succeeds
    And "bitwarden.adopt:example-cookie-secret" is ready, "(fulfilled)"
    And Bitwarden was given the cluster's "example-page-secrets" "cookie-secret" as "example-cookie-secret", noted "copied from example-page-secrets"
    And "k8s.secret:example-page-secrets" is ready
    And kubectl was given nothing to write
    And no output holds a value

  Scenario Outline: A Secret with nothing to keep is blocked, and the fix says to generate one
    Given Bitwarden has no "example-cookie-secret"
    And <cluster>
    When I run pubdeploy "check" "--json"
    Then the journal says "bitwarden.adopt:example-cookie-secret" is blocked, "<said>"
    And "bitwarden.adopt:example-cookie-secret" says to fix it with "let bitwarden.generated make example-cookie-secret"

    Examples:
      | cluster                                                  | said                                         |
      | the Secret "example-page-secrets" is not in the cluster  | holds no value to keep                       |
      | the key "cookie-secret" is missing from the Secret "example-page-secrets" | holds no value to keep                   |
      | the Secret "example-page-secrets" holds "cookie-secret" as 20 bytes | is not one to keep                |

  Scenario: A format the value must match is a regular expression
    Given Bitwarden has no "example-cookie-secret"
    And the need "bitwarden.adopt:example-cookie-secret" takes the format "[0-9a-f]{64}" and no shape
    When I run pubdeploy "check" "--json"
    Then the journal says "bitwarden.adopt:example-cookie-secret" is blocked, "is not one to keep"
    And the detail of "bitwarden.adopt:example-cookie-secret" says "it does not match the format [0-9a-f]{64}"

  Scenario: A format that is not a regular expression says so
    Given Bitwarden has no "example-cookie-secret"
    And the need "bitwarden.adopt:example-cookie-secret" takes the format "[0-9" and no shape
    When I run pubdeploy "check" "--json"
    Then the detail of "bitwarden.adopt:example-cookie-secret" says "the format [0-9 is not a regular expression"

  Scenario: A value in Bitwarden of another form is drift, which the walk does not overwrite
    Given Bitwarden's "example-cookie-secret" is 20 bytes
    When I run pubdeploy "check"
    Then "bitwarden.adopt:example-cookie-secret" is drift, "example-cookie-secret is in Bitwarden, and it is not"

  Scenario: Over the deploy channel the cluster's value is not read
    Given Bitwarden has no "example-cookie-secret"
    And the walk reads the cluster over the deploy channel
    When I run pubdeploy "check"
    Then "bitwarden.adopt:example-cookie-secret" is unknown, "is read over the admin channel or from the plane"

  Scenario: A Secret kubectl may not read is unknown
    Given Bitwarden has no "example-cookie-secret"
    And kubectl may not read anything
    When I run pubdeploy "check"
    Then "bitwarden.adopt:example-cookie-secret" is unknown, "could not be read"

  Scenario: Outside ./with-secrets nothing is looked for
    Given the environment is not ./with-secrets'
    When I run pubdeploy "check"
    Then "bitwarden.adopt:example-cookie-secret" is unknown, "is not looked for outside ./with-secrets"

  Scenario: A refused write keeps the need missing, and says why without the value
    Given Bitwarden has no "example-cookie-secret"
    And Bitwarden refuses every write
    When I run pubdeploy "walk" "--fulfil" "--yes"
    Then "bitwarden.adopt:example-cookie-secret" is missing
    And no output holds a value

  Scenario: Without a write token the copy waits for one
    Given Bitwarden has no "example-cookie-secret"
    And the walk has no terminal
    When I run pubdeploy "walk" "--fulfil" "--yes"
    Then "bitwarden.adopt:example-cookie-secret" is unknown, "not fulfilled: needs a Bitwarden write token"
