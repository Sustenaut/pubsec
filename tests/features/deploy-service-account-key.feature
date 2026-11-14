Feature: gcp.service-account-key: a key in Bitwarden that is one of the account's live keys
  The check reads the account and its keys through gcloud, and the key
  through the environment ./with-secrets gives. Its fulfil makes a key,
  writes it to Bitwarden with the walk's writer, and deletes it from Google
  when that fails. No value is shown: a key is named by six characters of
  its id, and every fake value holds a canary.

  Background:
    Given the example service


  Scenario: A key in Bitwarden that is one of the account's live keys is ready
    Given the deploy block also needs {"type": "gcp.service-account-key", "account": "example-files", "project": "example-project", "bitwarden": "example-files-key"}
    And Bitwarden holds "example-files-key" as the live key "0123456789abcdef0123456789abcdef01234567" of "example-files@example-project.iam.gserviceaccount.com"
    When I run pubdeploy "walk"
    Then "gcp.service-account-key:example-files-key" is ready, "key 012345 is live"
    And no output holds a value

  Scenario: A key that is not one of the account's live keys is drift
    Given the deploy block also needs {"type": "gcp.service-account-key", "account": "example-files@example-project.iam.gserviceaccount.com", "bitwarden": "example-files-key"}
    And Bitwarden holds "example-files-key" as a key "fedcba9876543210fedcba9876543210fedcba98" the account does not have
    When I run pubdeploy "walk"
    Then "gcp.service-account-key:example-files-key" is drift, "the key in Bitwarden is not one of the account's live keys: make a new one"

  Scenario: An account that is not there is Terraform's, and is not acted on
    Given the deploy block also needs {"type": "gcp.service-account-key", "account": "example-gone", "project": "example-project", "bitwarden": "example-files-key"}
    When I run pubdeploy "walk" "--fulfil" "--yes"
    Then "gcp.service-account-key:example-files-key" is missing
    And it prints "the account is Terraform's: add it in the stack and apply"
    And Bitwarden was given nothing

  Scenario: Without gcloud the key is unknown
    Given the deploy block also needs {"type": "gcp.service-account-key", "account": "example-files", "project": "example-project", "bitwarden": "example-files-key"}
    And gcloud is not installed
    When I run pubdeploy "walk"
    Then "gcp.service-account-key:example-files-key" is unknown, "gcloud did not run"

  Scenario: A key not in Bitwarden is made, written there, and is live
    Given the deploy block also needs {"type": "gcp.service-account-key", "account": "example-files", "project": "example-project", "bitwarden": "example-files-key"}
    When I run pubdeploy "walk" "--fulfil" "--yes"
    Then "gcp.service-account-key:example-files-key" is ready, "(fulfilled)"
    And it prints "made key 111111 of example-files@example-project.iam.gserviceaccount.com, and wrote it to Bitwarden as example-files-key"
    And Bitwarden was given "example-files-key" as a key of "example-files@example-project.iam.gserviceaccount.com"
    And no output holds a value

  Scenario: A key Bitwarden refuses is deleted from Google
    Given the deploy block also needs {"type": "gcp.service-account-key", "account": "example-files", "project": "example-project", "bitwarden": "example-files-key"}
    And Bitwarden refuses every write
    When I run pubdeploy "walk" "--fulfil" "--yes"
    Then "gcp.service-account-key:example-files-key" is missing
    And it prints "key 111111 was deleted from Google, as nothing holds it"
    And "example-files@example-project.iam.gserviceaccount.com" has no key
    And no output holds a value

  Scenario: A key gcloud's account may not make is blocked, naming where that is granted
    Given the deploy block also needs {"type": "gcp.service-account-key", "account": "example-files", "project": "example-project", "bitwarden": "example-files-key"}
    And gcloud may not make keys
    And PUBSEC_GCP_KEYS_GRANTED_IN is "the infra repository's keys.tf"
    When I run pubdeploy "walk" "--fulfil" "--yes"
    Then it prints "may not make keys of example-files@example-project.iam.gserviceaccount.com"
    And it prints "add the account to the infra repository's keys.tf"
    And "example-files@example-project.iam.gserviceaccount.com" has no key

  # --- auth.sign-in-client --------------------------------------------------------
