Feature: pubsec signing-key restore writes a declared key back from Bitwarden
  On a machine that lacks a key pubrules.json declares (another checkout, a
  rebuilt laptop), `pubsec signing-key restore` reads that key's value from
  its Bitwarden project, and that value alone, and writes it to the declared
  path, readable by its owner alone. It never overwrites a key, and never
  prints one.

  Background:
    Given a scratch directory
    And the program under test is "pubsec"

  Scenario: A dry run says what it would restore, and asks for nothing
    Given a repository that declares a key at "corpus/.publet/signing.key" as "pub-signing-key-demo"
    When I run "pubsec signing-key restore --dry-run"
    Then it succeeds
    And it prints "Keys that would be restored from the-project:"
    And it prints "  pub-signing-key-demo  "
    And nothing was asked of Bitwarden

  Scenario: A missing key is written back, its owner's alone, and never printed
    Given a repository that declares a key at "corpus/.publet/signing.key" as "pub-signing-key-demo"
    And the project already holds the corpus key as "pub-signing-key-demo"
    When I restore the keys, giving the token "tok"
    Then it succeeds
    And it prints "  pub-signing-key-demo: restored to"
    And "corpus/.publet/signing.key" holds the corpus key, readable by its owner alone
    And Bitwarden gave pubsec the value of "s1" alone
    And neither the key nor the token is in what it printed
    And the SDK wrote nothing

  Scenario: A key already on this machine is left alone, and Bitwarden is not asked
    Given a repository that declares its corpus key as "pub-signing-key-demo" in the project "the-project"
    When I restore the keys, giving the token "tok"
    Then it succeeds
    And it prints "pub-signing-key-demo: already at"
    And it prints "nothing to restore"
    And nothing was asked of Bitwarden

  Scenario: A key the project does not hold fails, and nothing is written
    Given a repository that declares a key at "corpus/.publet/signing.key" as "pub-signing-key-demo"
    When I restore the keys, giving the token "tok"
    Then it fails
    And it prints "pub-signing-key-demo: the project holds it 0 times, not once; not restored"
    And the file "corpus/.publet/signing.key" does not exist

  Scenario: Only the keys named are restored
    Given a repository that declares a key at "corpus/.publet/signing.key" as "pub-signing-key-demo"
    When I run "pubsec signing-key restore pub-signing-key-other --dry-run"
    Then it fails
    And it prints "pub-signing-key-other: no pubrules.json here declares it"
