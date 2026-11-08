Feature: pubsec run runs one command with the repository's secrets in its environment
  What ./with-secrets runs: the Bitwarden project with-secrets.json names is
  read with bws and a read-only token, from BWS_ACCESS_TOKEN or the
  repository's .env, and each secret reaches the command, and only it, under
  its name, or Terraform's as TF_VAR_. Nothing is written to disk.

  Scenario: Secrets reach the command under their names, and Terraform's as TF_VAR_
    Given a service whose Terraform declares "hcloud_token"
    And Bitwarden holds "HCLOUD_TOKEN" as "h1" and "restic-password" as "r1" in the project "infra"
    When I run "pubsec run" with the token "tok"
    Then it succeeds
    And the command sees "TF_VAR_hcloud_token" as "h1"
    And the command sees "RESTIC_PASSWORD" as "r1"
    And the command sees "PUBKIT_SECRETS_PROJECT" as "infra"
    And the command does not see "HCLOUD_TOKEN"
    And the calling shell's environment is unchanged

  Scenario: In map mode the listed names go to Terraform as two maps
    Given a service whose Terraform takes its secrets as a map of "linear-api-key"
    And Bitwarden holds "linear-api-key" as "lin" and "slack-bot-token" as "xoxb" in the project "infra"
    When I run "pubsec run" with the token "tok"
    Then it succeeds
    And the command sees "TF_VAR_secret_values" as "{"linear-api-key":"lin"}"
    And the command sees "LINEAR_API_KEY" as "lin"
    And the command sees "SLACK_BOT_TOKEN" as "xoxb"

  Scenario: A token that cannot see the project stops before running anything
    Given a service whose Terraform declares "hcloud_token"
    And Bitwarden holds "HCLOUD_TOKEN" as "h1" and "restic-password" as "r1" in the project "other"
    When I run "pubsec run" with the token "tok"
    Then it fails
    And stderr mentions "can't see the project infra"
    And the command did not run

  Scenario: With no token, it says where to put one
    Given a service whose Terraform declares "hcloud_token"
    When I run "pubsec run" with no token
    Then it fails
    And stderr mentions "BWS_ACCESS_TOKEN=..."

  Scenario: The command's exit code is pubsec run's
    Given a service whose Terraform declares "hcloud_token"
    And Bitwarden holds "HCLOUD_TOKEN" as "h1" and "restic-password" as "r1" in the project "infra"
    When I run "pubsec run" with the token "tok" and a command that exits 7
    Then the exit code is 7

  Scenario: An aliases file also exports a secret under the name a tool reads
    Given a service whose Terraform declares "hcloud_token"
    And the aliases file "infra/aliases.json" maps "TAILSCALE_OAUTH_CLIENT_ID" to "ts-tf-client-id"
    And Bitwarden holds "ts-tf-client-id" as "c1" and "restic-password" as "r1" in the project "infra"
    When I run "pubsec run" with the token "tok"
    Then it succeeds
    And the command sees "TAILSCALE_OAUTH_CLIENT_ID" as "c1"
    And the command sees "TS_TF_CLIENT_ID" as "c1"
    And the command sees "RESTIC_PASSWORD" as "r1"

  Scenario: An alias of a secret that is not in Bitwarden is reported and skipped
    Given a service whose Terraform declares "hcloud_token"
    And the aliases file "infra/aliases.json" maps "TAILSCALE_OAUTH_CLIENT_ID" to "missing"
    And Bitwarden holds "HCLOUD_TOKEN" as "h1" and "restic-password" as "r1" in the project "infra"
    When I run "pubsec run" with the token "tok"
    Then it succeeds
    And stderr mentions "no secret 'missing' in Bitwarden"
    And the command does not see "TAILSCALE_OAUTH_CLIENT_ID"

  Scenario: An alias must be usable as an environment variable name
    Given a service whose Terraform declares "hcloud_token"
    And the aliases file "infra/aliases.json" maps "tailscale-id" to "ts-tf-client-id"
    And Bitwarden holds "ts-tf-client-id" as "c1" and "restic-password" as "r1" in the project "infra"
    When I run "pubsec run" with the token "tok"
    Then it fails
    And stderr mentions "not usable as an environment variable name"
    And the command did not run

  Scenario: The token can come from the repository's .env
    Given a service whose Terraform declares "hcloud_token"
    And Bitwarden holds "HCLOUD_TOKEN" as "h1" and "restic-password" as "r1" in the project "infra"
    And the file ".env" reads "export BWS_ACCESS_TOKEN='tok'"
    When I run "pubsec run" with no token
    Then it succeeds
    And the command sees "TF_VAR_hcloud_token" as "h1"

  Scenario: pubsec run runs the command in --cwd
    Given a service whose Terraform declares "hcloud_token"
    And Bitwarden holds "HCLOUD_TOKEN" as "h1" and "restic-password" as "r1" in the project "infra"
    When I run "pubsec run --cwd infra" with the token "tok"
    Then it succeeds
    And the command ran in "infra"

  Scenario: pubsec run needs a command after --
    Given a service whose Terraform declares "hcloud_token"
    When I run pubsec "run"
    Then the exit code is 2
    And stderr mentions "usage: pubsec run"

  Scenario: Without with-secrets.json it says what the file is for
    Given a service whose Terraform declares "hcloud_token"
    And Bitwarden holds "HCLOUD_TOKEN" as "h1" and "restic-password" as "r1" in the project "infra"
    And the repository has no "with-secrets.json"
    When I run "pubsec run" with the token "tok"
    Then it fails
    And stderr mentions "it names the Bitwarden project to read"
    And the command did not run

  Scenario: A Terraform mode it doesn't know stops before running anything
    Given a service whose Terraform declares "hcloud_token"
    And Bitwarden holds "HCLOUD_TOKEN" as "h1" and "restic-password" as "r1" in the project "infra"
    And the file "with-secrets.json" reads "{"project": "infra", "terraform": {"secrets": "maps"}}"
    When I run "pubsec run" with the token "tok"
    Then it fails
    And stderr mentions "terraform.secrets is "declared" or "map", not "maps""
    And the command did not run

  Scenario: pubsec run says when the command is not there
    Given a service whose Terraform declares "hcloud_token"
    And Bitwarden holds "HCLOUD_TOKEN" as "h1" and "restic-password" as "r1" in the project "infra"
    When I run "pubsec run" with the token "tok" and the command "no-such-command"
    Then the exit code is 127
    And stderr mentions "no-such-command: not found"
