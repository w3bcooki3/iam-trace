# Limitations

What iam-trace does not do, does approximately, or has decided without confirmation from AWS.
Each item says what to expect. If you hit one that matters to you, open an issue with the policy
and request.

## Not yet confirmed against AWS

The live differential run (`differential` workflow) has not been run yet. Until it has, these
choices rest on reading the docs, not on AWS's answers:

- **Wildcards in the first five ARN components** of `Resource` are matched per component, and a
  pattern with fewer than six components is matched as a whole string.
- **A single-value operator on a multivalued key** (for example `StringEquals` on `aws:TagKeys`)
  matches if any value matches. The docs do not cover this.
- **Negated Numeric, Date and IP operators with a missing key** evaluate to true, following the
  general rule for negated operators. The operator table on the AWS page lists only the String
  and ARN negations as true.
- **Duplicate keys** in a JSON object: the last value wins (as in most JSON parsers) and a warning
  is attached to the policy.

Disagreements found by the live run are stored in `tests/differential/fixtures/`. Each one stays
an expected failure until it is fixed or explained here.

The property tests (`tests/property`) and the escalation benchmark (`tests/benchmark`) do not
replace that run. They show that iam-trace follows the rules it is meant to follow on many random
policies and on every documented escalation path, but the rules themselves come from AWS's
documentation and pathfinding.cloud. Where a document is wrong or silent, so is the test.

## What the AWS simulator cannot check

These are covered only by hand-written tests that quote the AWS docs
(`tests/handwritten/test_simulator_gaps.py`), because `iam:SimulateCustomPolicy` cannot model them:

- RCPs ("the policy simulator ... does not support resource control policies").
- Session policies (scope-down policies are not accepted).
- Callers that are role sessions, federated users or service principals, so the rules for
  resource policies naming a session ARN, a role ARN or a federated user.
- Role trust policies (resource-policy simulation is not supported for IAM roles).
- More than one permissions boundary or more than one resource policy.
- SCP matched statements (the simulator returns only the decision).

## Not modelled

- **Service-specific authorization** beyond the two cases the IAM docs name (role trust policies
  and KMS key policies need an explicit allow). Not modelled: S3 ACLs, Object Ownership and Block
  Public Access; S3 Access Point policies; VPC endpoint policies; KMS grants; AWS RAM shares;
  Lambda and other services that require an explicit allow in their resource policy.
- **Request context.** iam-trace fills in `aws:PrincipalArn`, `aws:PrincipalAccount`,
  `aws:PrincipalType`, `aws:username` (IAM users), `aws:PrincipalServiceName` (service principals)
  and `aws:ResourceAccount`. For `can`, every other key, including ones AWS always sends such as
  `aws:SourceIp` or `aws:SecureTransport`, must be supplied with `--context`. A key you do not
  supply is treated as missing, with AWS's missing-key semantics. The escalation analysis does
  more; see "Conditions in the escalation analysis" below.
- **Which services support which global condition keys.** Like the simulator, iam-trace does not
  know that a service ignores, say, `aws:TagKeys`.
- **Principal forms**: unique IDs (`AIDA...`, `AROA...`) and `CanonicalUser` are not matched. The
  role path of an assumed-role session is not in its ARN; pass `--role-arn` when the role has a
  path.
- **Federated-user session policies.** The enforcement-logic page says a session policy that
  allows the action leads to Allow only for role sessions. iam-trace allows it for federated user
  sessions as well. That step of the AWS flowchart is unclear.
- **Policy validation** is not as complete as IAM Access Analyzer's `ValidatePolicy`: size limits,
  unknown condition keys and action names that don't exist are not rejected.

## Action catalog

- AWS's JSON reference has no access-level field. Access levels are derived from annotation flags
  (see `src/iamtrace/catalog/__init__.py`). The weekly refresh compares the result with the HTML
  reference and lists every mismatch in its pull request.
- The repository ships without a catalog until the `catalog-refresh` workflow (or
  `python -m iamtrace.catalog.refresh src/iamtrace/catalog/data`) has run once. `can` and `escalate`
  work without one; `expand`, `diff` and `--blast-radius` need it.
- The HTML parser in `scripts/check_access_levels.py` was written to the documented page layout
  and tested against a fixture of that layout, not yet against the live pages.

## Semantic diff

- Conditions are compared by equality. Replacing a condition with a looser one shows as one grant
  removed and one added, not as a broadening.
- Resource coverage treats the narrower pattern's wildcards as literal text. That is exact for
  common cases (`b/*` covers `b/x/*`) and conservative otherwise: it never claims coverage that
  doesn't hold, but may report a change that is already covered.
- `NotAction` in an Allow expands to every catalog action except the listed ones, so a diff
  involving one can be long.

## Escalation analysis

- The technique list is a snapshot of [pathfinding.cloud](https://pathfinding.cloud) (see
  `NOTICE` for the commit). New techniques appear only when the data file is updated. Paths
  nobody has documented there yet are not checked. [Coverage](coverage.md) shows how each
  documented path is detected.
- Techniques that take over existing resources (a running Lambda function, an EC2 instance, an
  SSM-managed host) are reported as "possible": an IAM export does not list those resources or
  which role each one uses. They do not form paths. A resource inventory (`--inventory`, from
  `iam-trace inventory collect`) fixes this for every existing-resource technique in the list.
- ECS tasks are short-lived: an inventory lists the tasks running when it was collected. A Batch
  job definition with several roles (one per node range or container) is listed once per role.
  A launch template is judged by its default version's instance profile.
- With an inventory, each permission is evaluated against the resource's own ARN. Permissions
  that AWS also checks on a second resource (the SSM document for `ssm:SendCommand`, the job
  queue for `batch:SubmitJob`, the cluster for `ecs:ExecuteCommand`, the CodeDeploy application)
  are checked on the main resource only.
- Grants scoped to specific non-IAM resources are checked against the resource patterns in the
  principal's own policies and `"*"`, not against an inventory.
- The service principal a passed role must trust is a table (`SERVICE_PRINCIPALS` in
  `escalate.py`, with alternatives in `ALSO_TRUSTED`), checked against pathfinding.cloud's
  prerequisites by the benchmark. Where it is missing, the finding is "possible". A role's other
  requirements in those prerequisites (an existing Batch queue, a Cognito identity pool with
  unauthenticated access, a second role for EMR's instances) are not checked.
- Only one account export is analysed. Roles in other accounts are not followed, and SCPs must be
  supplied with `--scp`.
- The blast radius counts actions allowed on `Resource: "*"` only.
- Run time grows with principals times techniques. On made-up accounts from
  `scripts/synthetic_account.py`, analysing every principal takes about 2 seconds for 200 users
  and 200 roles and about 6 seconds for 400 and 400, on one core. The web app runs the same
  Python in the browser and is slower: an account of 200 users and 200 roles with conditions in
  every policy takes about 10 seconds. Much larger accounts are best analysed one starting
  principal at a time (`--principal`).
- Joining a group (iam:AddUserToGroup) counts as admin only if the group's policies, added to
  the user's own, allow everything. A group that grants a step towards admin (assuming an admin
  role, say) is not followed.

## Conditions in the escalation analysis

- Tags come from the export: `aws:PrincipalTag/*` for the caller, `aws:ResourceTag/*` and
  `iam:ResourceTag/*` for a user or role target. Tags of other resources (a Lambda function, an
  S3 bucket) are not known, so a condition on them is not met.
- A failed check is tried again with the values its conditions name, for these keys only.
  Chosen by the attacker, so the step is open: `aws:RequestedRegion`, `aws:SecureTransport`,
  `aws:UserAgent`, `aws:Referer`, `aws:RequestTag/*`, `aws:TagKeys`, `sts:RoleSessionName`,
  `sts:SourceIdentity`, `aws:SourceIdentity`, `sts:ExternalId`. Gated: MFA
  (`aws:MultiFactorAuthPresent`, `aws:MultiFactorAuthAge`), network (`aws:SourceIp`,
  `aws:SourceVpc`, `aws:SourceVpce`, `aws:VpcSourceIp`) and time (`aws:CurrentTime`,
  `aws:EpochTime`). Any other key, for example `aws:PrincipalOrgID` or `aws:CalledVia`, is left
  missing, as before.
- The search tries up to two gated keys at once and stops after 256 evaluations for one check;
  a check that needs more stays denied.
- A gated technique records the gates per target; when one of its targets is open the technique
  is listed as open and the gated targets are named separately.
- Gates are judged per step. A path that needs MFA at one step and a network location at another
  lists both; iam-trace does not model that an attacker who has one may also have the other.

## Entry points

- The export does not say which IAM users have access keys or a console password. Without a
  credential report every user is listed as an entry point; with one, users with neither are left
  out. The report is a snapshot: AWS regenerates it at most every four hours, and a key created
  after it was generated is not in it.
- The export does not list the account's OIDC and SAML providers, so a trust policy naming a
  provider that no longer exists is still reported.
- For a role trusted by another account, the probe gives the caller allow-all identity policies:
  that account controls them, so the worst case is assumed.
- Scores are a ranking aid, not a measurement: the exposure (anyone, a large group, another
  account, a leaked user key) times what the principal reaches.

## Data access

- Covers S3 buckets and KMS keys from the inventory. Object ACLs, access points, S3 Object
  Ownership, VPC endpoint policies and KMS grants are not modelled.
- Object access is checked on one probe object in the bucket. A bucket policy that treats key
  prefixes differently (for example `reports/*` and `public/*`) is judged on that object only.
- The bucket's default encryption key is assumed for every object. Objects uploaded with another
  key, or with SSE-S3, are not tracked one by one.
- Block Public Access is honoured through RestrictPublicBuckets (bucket or account setting).
  ACL-based public access is not checked.
- Outside principals are probed with allow-all identity policies, because their own account
  decides those.

## Terraform plans

- Resources covered: aws_iam_policy, aws_iam_role (trust policy, inline_policy,
  managed_policy_arns), aws_iam_role_policy, aws_iam_user_policy, aws_iam_group_policy, the
  three policy attachment resources, aws_iam_user, aws_iam_group,
  aws_iam_user_group_membership, aws_s3_bucket_policy and aws_kms_key. aws_iam_policy_attachment
  (the exclusive one), aws_iam_group_membership and permission boundaries are not applied yet.
- A value Terraform only knows at apply time is not guessed. A policy ARN or role name that
  refers to a resource created in the same plan is resolved through the configuration's
  references; other unknown values are reported and left out.
- Bucket and key policies are reviewed as documents but not applied to an inventory, so the
  account comparison covers IAM principals only.
- The plan JSON can contain secrets from your configuration. iam-trace reads it locally and
  prints only policy documents and resource addresses.

## Fix plans

- Narrowed Allow statements are generated only when they stay readable: a wildcard action is
  listed out if it covers at most 25 actions, and a wildcard resource if at most 30 resources of
  that kind exist. Otherwise the change keeps its Deny. Listing resources means ones created later
  are not covered; the plan says so.
- The "also no longer allows" check probes the old and new documents with every action they
  mention against every known role, user and policy. Resources the export does not describe
  (buckets, functions) are probed with one placeholder each.
- The SCP version is limited by aws:PrincipalArn. SCPs do not apply to the management account or
  service-linked roles, and one SCP may hold at most 5,120 characters.
- Only confirmed paths are cut. Possible techniques (resources not in the export) are counted in
  the plan but not covered by its check; a resource inventory confirms or rules them out.
- Paths that need MFA, a network location or a time window are left alone unless
  `--include-gated` is given.
- The search is exact (branch and bound) up to 200,000 steps; past that the best plan found is
  returned and marked as possibly not the smallest. It is still verified.
- A plan checks that no path is left. It does not check what else the denied permission was
  used for: the consequence line says what the principal can no longer do.

## Web page

- The first load is about 13 MB (Pyodide, the package and the catalog); the browser caches it.
- The attack graph draws the starting principal's paths and its possible techniques (up to six
  targets). Every other principal is listed in Findings rather than drawn.
- Recommended fixes name the permissions behind each step of a path. They do not check whether
  removing a permission would break something else that relies on it.
  A local build without `--pyodide` loads Pyodide from `cdn.jsdelivr.net` instead.
- Large account exports are analysed in a background worker in the browser tab. The page stays
  usable, but an account with hundreds of roles and users can take a minute; the CLI is faster.
- Diff is only available when the site was built with a catalog.

## Unused access

- Last accessed data covers services over the last 400 days. A service used only before that
  looks unused.
- AWS records attempts, including failed ones, so a service someone tried and was denied counts
  as used. That errs towards keeping access.
- `iam:PassRole` is not tracked by AWS, so it is never removed. Other actions that AWS checks
  without an API call of their own may look unused; review edits that remove a service a
  workload relies on indirectly.
- Action-level data covers management actions of some services only (EC2, IAM, Lambda and S3,
  among others), so edits work per service and never narrow a service to the actions it used.
- A pattern whose service part has a wildcard (`s*:Get*`) is left as it is: it can't be split
  into services without listing every service.
- Roles kept for emergencies (break-glass) are meant to be unused. The report lists them; whether
  to keep them is your call.
- Edits to a policy are suggested only when every user and role that has it has a report. Groups
  count through their members.

## Input

- A policy in an account export that iam-trace cannot read is left out, with a warning. AWS
  accepted it, so it is probably a form iam-trace does not know; until it is supported, results
  can miss what that policy allows or denies. The web app lists such policies after an analysis.
- Element names and the Effect value are case-sensitive, as AWS documents; a policy written with
  `"effect": "allow"` is refused with a message saying so. Context key names are not
  case-sensitive.
- JSON is read strictly. Files with comments or trailing commas must be fixed first; the message
  says where.
- The web app reads uploads up to 50 MB (200 MB once a `.gz` is unpacked).

