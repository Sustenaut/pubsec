Feature: gcp.service-account-key: a key in Bitwarden that is one of the account's live keys
  The check lists the account's keys through gcloud, in one call when the
  account is there (each call takes seconds), and reads the key
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
    And gcloud was called once
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

  Scenario: A key an organization policy forbids is blocked, naming the policy
    Given the deploy block also needs {"type": "gcp.service-account-key", "account": "example-files", "project": "example-project", "bitwarden": "example-files-key"}
    And an organization policy forbids service account keys
    When I run pubdeploy "walk" "--fulfil" "--yes"
    Then it prints "an organization policy forbids keys of example-files@example-project.iam.gserviceaccount.com"
    And it prints "constraints/iam.disableServiceAccountKeyCreation is enforced on example-project"
    And "example-files@example-project.iam.gserviceaccount.com" has no key

  # --- gcp.workload-identity -------------------------------------------------------

  Scenario: A workload that may act as the account is ready, and needs no key
    Given the deploy block also needs {"type": "gcp.workload-identity", "account": "example-files", "project": "example-project", "serviceaccount": "app", "pool": "projects/123456/locations/global/workloadIdentityPools/services", "granted_in": "the infra repository's identity.tf"}
    And "example/app" may act as "example-files@example-project.iam.gserviceaccount.com" through the pool "projects/123456/locations/global/workloadIdentityPools/services"
    When I run pubdeploy "walk"
    Then "gcp.workload-identity:app" is ready, "example/app may act as example-files@example-project.iam.gserviceaccount.com"
    And gcloud was called once

  Scenario: A workload that may not is missing, and the walk proposes the grant without acting
    Given the deploy block also needs {"type": "gcp.workload-identity", "account": "example-files", "project": "example-project", "serviceaccount": "app", "pool": "projects/123456/locations/global/workloadIdentityPools/services", "granted_in": "the infra repository's identity.tf"}
    And "example/other" may act as "example-files@example-project.iam.gserviceaccount.com" through the pool "projects/123456/locations/global/workloadIdentityPools/services"
    When I run pubdeploy "walk" "--fulfil" "--yes"
    Then "gcp.workload-identity:app" is missing, "example/app may not act as"
    And it prints "grant roles/iam.workloadIdentityUser on example-files@example-project.iam.gserviceaccount.com to principal://iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/services/subject/system:serviceaccount:example:app"
    And it prints "to example-files's row in the infra repository's identity.tf"

  Scenario: An account that is not there is Terraform's
    Given the deploy block also needs {"type": "gcp.workload-identity", "account": "example-gone", "project": "example-project", "serviceaccount": "app", "pool": "projects/123456/locations/global/workloadIdentityPools/services"}
    When I run pubdeploy "walk"
    Then "gcp.workload-identity:app" is missing, "service account example-gone@example-project.iam.gserviceaccount.com is not there"

  Scenario: Without gcloud the grant is unknown
    Given the deploy block also needs {"type": "gcp.workload-identity", "account": "example-files", "project": "example-project", "serviceaccount": "app", "pool": "projects/123456/locations/global/workloadIdentityPools/services", "granted_in": "the infra repository's identity.tf"}
    And gcloud is not installed
    When I run pubdeploy "walk"
    Then "gcp.workload-identity:app" is unknown, "gcloud did not run"

  # --- auth.sign-in-client --------------------------------------------------------
