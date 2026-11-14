# How iam-trace evaluates a request

This is the summary written before implementation (step 1 of the project plan), kept up to date
with what the engine does. Each rule links to the AWS page it comes from. Where the docs are
ambiguous, the rule is marked and the differential test decides.

## Order of evaluation

Source: [How AWS enforcement code logic evaluates requests](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).

| Step | Name in traces | Rule |
|---|---|---|
| 0 | | Every request is implicitly denied, except that the account root user has full access in its own account. |
| 1 | `explicit_deny` | Any applicable Deny in any policy (identity, resource-based, boundary, session, SCP, RCP) is final. |
| 2 | `rcp` | RCPs of the resource owner's account: every organization level must have an applicable Allow. |
| 3 | `scp` | SCPs of the principal's account: every level must have an applicable Allow. |
| 4 | `resource_policy` | A resource-based Allow can be final within one account; see "Who a resource policy names". |
| 5 | `identity_policy` | An identity-based policy must allow. |
| 6 | `permissions_boundary` | The boundary, if any, must allow. |
| 7 | `session_policy` | Session policies, if any, must allow (role sessions and federated users only). |

The trace lists every step that ran and the statements that matched. `deciding_step` is the step
where evaluation stopped.

## Cross-account requests

Source: [Cross-account policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html).

"The request is allowed only if both evaluations return a decision of Allow." The principal's
account must allow (identity policy, boundary, session policy, SCPs) and the resource owner's
account must allow (resource-based policy, RCPs). A resource-based policy naming the principal's
account (rather than the principal) is enough for the resource side.

## Who a resource policy names

Source: the enforcement-logic page above and
[Permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html).

Within one account:

| The resource policy names | Identity policy needed? | Limited by an implicit deny in boundary / session policy? |
|---|---|---|
| The IAM user's ARN | No | No |
| The role session ARN (`sts::...:assumed-role/...`) | No | No |
| The federated user ARN | No | No |
| `"*"`, including with an `aws:PrincipalArn` condition | No | No |
| The role ARN (for a session of that role) | No | Yes |
| The IAM user who created a federated session | No | Yes |
| The account (`123456789012` or `...:root`) | Yes (delegates to IAM) | Yes |

An explicit deny anywhere still wins.

Role trust policies and KMS key policies must explicitly allow the principal; an identity policy
alone is never enough for `sts:AssumeRole` on a role or for a KMS key operation.

## Organizations policies

Source: [Resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html).

- SCPs do not apply to the management account or to service-linked roles.
- RCPs apply only to the services AWS lists (85 prefixes, copied into `servicerules.py`), not to
  resources in the management account, service-linked roles, AWS managed KMS keys, or
  `kms:RetireGrant`. They apply to every principal, including ones outside the organization and
  root users.
- Neither ever grants anything.

## Policy elements

Source: [IAM JSON policy element reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html).

- `Action`/`NotAction`: case-insensitive; `*` and `?` wildcards in the action name.
- `Resource`/`NotResource`: case-sensitive. The first five ARN components are matched one by one;
  wildcards in the resource part match across `/` and `:`. (Ambiguous: decided by the
  differential test.)
- `Principal`/`NotPrincipal`: `NotPrincipal` only with Deny and only in resource-based policies
  ([NotPrincipal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html)).
  A principal with a permissions boundary is never excluded by `NotPrincipal`.
- Policy variables ([variables](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html)):
  only with `Version: 2012-10-17`; in `Resource` only after the fifth colon; defaults
  `${key, 'default'}`; escapes `${*}`, `${?}`, `${$}`; a substituted value never acts as a
  wildcard; a resource with an unresolvable variable matches nothing.

## Conditions

Sources: [condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html),
[set operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html),
[Condition element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).

- Operators: String (6), Numeric (6), Date (6), Bool, BinaryEquals, IpAddress/NotIpAddress,
  Arn (4), Null, each with `IfExists` (except Null) and `ForAllValues:`/`ForAnyValue:`.
- All operators AND; all keys within an operator AND; values within a key OR.
- Condition key names are case-insensitive.
- Missing key: positive operators false; negated operators true; `IfExists` true.
- `ForAllValues` is true when the key is missing or empty; `ForAnyValue` is false.
- Dates: ISO 8601 or epoch seconds. IP: CIDR, a bare address is /32 (or /128).

## Hard cases and where they are tested

| Case | Where |
|---|---|
| NotAction with Deny | `tests/unit/test_evaluate.py`, differential `notaction_deny` |
| ARN wildcards | `tests/unit/test_matching.py`, differential `arn_wildcards` |
| IfExists, including negated operators with Deny | `tests/unit/test_conditions.py`, differential `if_exists` |
| ForAllValues on an empty set | `tests/unit/test_conditions.py`, differential `for_all_values` |
| Policy variables | `tests/unit/test_matching.py`, `tests/unit/test_conditions.py`, differential `variables` |
| Boundaries | `tests/known_answer`, differential `boundaries` |
| Cross-account resource policies | `tests/unit/test_evaluate.py`, differential `cross_account` |
| Grants by principal type, RCPs, session policies, trust and key policies | `tests/handwritten/test_simulator_gaps.py` (the simulator cannot model these) |
