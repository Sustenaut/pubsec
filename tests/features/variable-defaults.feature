Feature: A declared variable with a default is ready unset, at its default
  pubrules.json's variables block (version 2) may give a declared variable its default,
  the code's own constant, any JSON value. github.variable's check, against a fake of
  GitHub's variables API for example-org/example, takes one unset or empty (as a
  deploy renders a variable nothing sets) as ready at its default; one set to a value
  equal to it, canonically, as set to its default; and any other value as the state's.

  Scenario Outline: Unset or empty, a variable with a default is ready at it: <case>
    Given GitHub <holds>
    When the declared variable "EXAMPLE_SETTING" with the default '<default>' is checked
    Then the result's "state" is "ready"
    And the result's "summary" is "variable EXAMPLE_SETTING is <how> in example-org/example: default (<shown>)"

    Examples:
      | case             | holds                                  | default            | how     | shown            |
      | unset, a string  | holds no variable "EXAMPLE_SETTING"    | "120"              | not set | 120              |
      | empty, a string  | holds "EXAMPLE_SETTING" as ""          | "120"              | empty   | 120              |
      | unset, null      | holds no variable "EXAMPLE_SETTING"    | null               | not set | unset            |
      | unset, JSON      | holds no variable "EXAMPLE_SETTING"    | {"b": [1], "a": 2} | not set | {"a":2,"b":[1]}  |

  Scenario Outline: Set to its default, canonically, it says so: <case>
    Given GitHub holds "EXAMPLE_SETTING" as '<value>'
    When the declared variable "EXAMPLE_SETTING" with the default '<default>' is checked
    Then the result's "state" is "ready"
    And the result's "summary" is "variable EXAMPLE_SETTING is set in example-org/example, to its default, which leaving it unset would give too"

    Examples:
      | case                     | value              | default            |
      | the same string          | 120                | "120"              |
      | JSON however spaced      | { "a": 2, "b":[1] } | {"b": [1], "a": 2} |
      | a number, as the state sends it | 120         | 120                |

  Scenario Outline: Set to another value, it is the state's, and ready: <case>
    Given GitHub holds "EXAMPLE_SETTING" as '<value>'
    When the declared variable "EXAMPLE_SETTING" with the default '<default>' is checked
    Then the result's "state" is "ready"
    And the result's "summary" is "variable EXAMPLE_SETTING is set in example-org/example"

    Examples:
      | case                              | value    | default |
      | another string                    | 28800    | "120"   |
      | a JSON string, not the number     | "120"    | 120     |
      | not JSON, where the default is    | soon     | null    |

  Scenario: Without a default, unset is still missing
    Given GitHub holds no variable "EXAMPLE_SETTING"
    When the declared variable "EXAMPLE_SETTING" with no default is checked
    Then the result's "state" is "missing"
    And the result's "summary" is "variable EXAMPLE_SETTING is not set in example-org/example"

  Scenario: Without a default, empty is still missing
    Given GitHub holds "EXAMPLE_SETTING" as ""
    When the declared variable "EXAMPLE_SETTING" with no default is checked
    Then the result's "state" is "missing"
    And the result's "summary" is "variable EXAMPLE_SETTING is empty in example-org/example"

  Scenario: The need's schema takes a default of any JSON value
    When github.variable's schema is read
    Then the result's "properties.default" is "{}"
