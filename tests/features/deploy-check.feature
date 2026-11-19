Feature: pubdeploy check walks pubsec's needs with the rest, and changes nothing
  Each need is checked in order, through kubectl, the GitHub API, HTTP,
  the DNS, and the environment ./with-secrets gives: ready, missing,
  drift, blocked or unknown. A need still checked while one it waits for
  is not ready is blocked when its own check finds it missing. A check that
  overruns its budget, or is refused, is unknown, and says what access is
  missing. No value is ever printed: every fake value here holds a canary,
  and no output may.

  Background:
    Given the example service

  Scenario: Every need is ready
    When I run pubdeploy "check"
    Then it succeeds
    And it prints "ready   k8s.secret:example-page-secrets  Secret example-page-secrets in example has keys cookie-secret"
    And it prints "ready   github.gate:example  DEPLOY_EXAMPLE is on, and the 15 needs before it are ready"
    And it prints "ready   deploy.rollout:example  main's abc1234 is deployed, and 2 Deployments are ready"
    And it prints "ready   upstream:storage  storage answers 200 at /healthz in"
    And it prints "deploy: 18 needs, 18 ready, 0 missing, 0 drift, 0 blocked, 0 unknown"

  Scenario: Without the namespace every k8s need waits for it, and the GitHub needs stay ready
    Given the namespace "example" is not in the cluster
    When I run pubdeploy "check"
    Then the exit code is 1
    And "k8s.namespace:example" is missing
    And it prints "ssh root@server.example.eu sustenaut-app example"
    And every "k8s.secret" need is blocked, "waits for k8s.namespace:example"
    And every "k8s.manifests" need is blocked, "waits for k8s.namespace:example"
    And every "github.secret" need is ready
    And every "github.variable" need is ready
    And "github.gate:example" is drift

  Scenario: A cookie secret of the wrong shape is drift, in k8s.py's words
    Given the Secret "example-page-secrets" holds "cookie-secret" as 20 bytes
    When I run pubdeploy "check"
    Then the exit code is 1
    And "k8s.secret:example-page-secrets" is drift
    And it prints "Secret example-page-secrets key cookie-secret (need k8s.secret:example-page-secrets), oauth2-proxy's cookie secret: 20 bytes, 15 after URL-safe base64 decoding; oauth2-proxy needs 16, 24 or 32 bytes"

  Scenario: A Secret without a key the manifests read is drift
    Given the Secret "example-files" has no key "token"
    When I run pubdeploy "check"
    Then "k8s.secret:example-files" is drift
    And it prints "Secret example-files has no key token, which need k8s.secret:example-files reads"

  Scenario: A Secret that is not there is missing, and the gate open too early is drift
    Given the Secret "example-files" is not in the cluster
    When I run pubdeploy "check"
    Then "k8s.secret:example-files" is missing
    And "github.gate:example" is drift
    And it prints "DEPLOY_EXAMPLE is on while 1 need is missing"
    And it prints "gh variable set DEPLOY_EXAMPLE -R example-org/example --body off, until they are ready"

  Scenario: kubectl that may not read is unknown, and says what access is missing
    Given kubectl may not read anything
    When I run pubdeploy "check"
    Then the exit code is 1
    And "k8s.namespace:example" is unknown
    And it prints "kubectl may not read namespaces in example"
    And it prints "use a kubeconfig that may get namespaces in example"
    And "k8s.secret:example-files" is unknown
    And it prints "kubectl may not read Secrets in example: the deploy identity needs get on secrets there"

  Scenario: kubectl that is not installed is unknown
    Given kubectl is not installed
    When I run pubdeploy "check"
    Then "k8s.namespace:example" is unknown
    And it prints "install kubectl, or give --kubectl CMD"

  Scenario: GitHub that refuses is unknown, and says how to sign in
    Given GitHub refuses every request
    When I run pubdeploy "check"
    Then "github.secret:EXAMPLE_TOKEN" is unknown
    And it prints "sign gh in as someone who administers the repository (gh auth login)"

  Scenario: Outside a GitHub repository the GitHub needs are unknown
    Given origin is not a GitHub repository
    When I run pubdeploy "check"
    Then "github.secret:EXAMPLE_TOKEN" is unknown
    And "deploy.rollout:example" is unknown
    And it prints "origin is not a GitHub repository"

  Scenario: A secret GitHub does not hold is missing, and says how it is sent
    Given GitHub holds no secret "EXAMPLE_TOKEN"
    When I run pubdeploy "check"
    Then "github.secret:EXAMPLE_TOKEN" is missing
    And it prints "put example-token in Bitwarden, then ./with-secrets ./pubsec app-secrets"

  Scenario: A variable that differs from Bitwarden's is drift, and neither value is shown
    Given Bitwarden's "example-user" is another value
    When I run pubdeploy "check"
    Then "github.variable:EXAMPLE_USER" is drift
    And it prints "variable EXAMPLE_USER in example-org/example is not Bitwarden's example-user"

  Scenario: A declared variable that is empty is missing
    Given the variable "EXAMPLE_SETTING" is ""
    When I run pubdeploy "check"
    Then "github.variable:EXAMPLE_SETTING" is missing
    And it prints "variable EXAMPLE_SETTING is empty in example-org/example"

  Scenario: The server's settings must all be there, on the repository or its server environment
    Given GitHub holds no secret "TS_GH_OAUTH_SECRET"
    And GitHub holds no variable "SUSTENAUT_KNOWN_HOSTS"
    When I run pubdeploy "check"
    Then "github.deploy-settings:example" is missing
    And it prints "SUSTENAUT_KNOWN_HOSTS, TS_GH_OAUTH_SECRET are set neither in example-org/example nor its server environment"

  Scenario: A Bitwarden secret that is not in the project is missing
    Given Bitwarden has no "example-files-token"
    When I run pubdeploy "check"
    Then "bitwarden.secret:example-files-token" is missing
    And it prints "put example-files-token in the Bitwarden project example, and give the read-only machine account access to it"

  Scenario: A generated secret of the wrong shape is drift, said by its length alone
    Given Bitwarden's "example-cookie-secret" is 20 bytes
    When I run pubdeploy "check"
    Then "bitwarden.generated:example-cookie-secret" is drift
    And it prints "example-cookie-secret is not oauth2-proxy's cookie secret: 20 bytes"

  Scenario Outline: A generated secret of each shape is ready when it has it
    Given the need "bitwarden.generated:example-cookie-secret" has the shape "<shape>"
    And Bitwarden's "example-cookie-secret" is <value>
    When I run pubdeploy "check"
    Then "bitwarden.generated:example-cookie-secret" is <state>

    Examples:
      | shape     | value                  | state |
      | hex-32    | 64 hex digits          | ready |
      | hex-32    | 20 bytes               | drift |
      | base64-32 | base64 of 32 bytes     | ready |
      | base64-32 | base64 of 16 bytes     | drift |
      | base64-32 | 20 bytes               | drift |

  Scenario: No value is printed, whatever the checks find
    Given the Secret "example-page-secrets" holds "cookie-secret" as 20 bytes
    And Bitwarden's "example-cookie-secret" is 20 bytes
    And Bitwarden's "example-user" is another value
    When I run pubdeploy "check" "--json"
    Then the exit code is 1
    And no output holds a value
