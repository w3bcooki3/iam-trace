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
  `NOTICE` for the commit). New techniques appear only when the data file is updated.
- Techniques that take over existing resources (a running Lambda function, an EC2 instance, an
  SSM-managed host) are reported as "possible": an IAM export does not list those resources or
  which role each one uses. They do not form paths. A resource inventory (`--inventory`, from
  `iam-trace inventory collect`) fixes this for Lambda functions, EC2 instances, CodeBuild
  projects, CloudFormation stacks, Glue dev endpoints, SageMaker notebooks, Step Functions state
  machines and App Runner services. Launch templates, Batch, CodeDeploy, ECS tasks and Bedrock
  AgentCore stay "possible": they involve several resources or short-lived ones.
- With an inventory, each permission is evaluated against the resource's own ARN. Permissions
  that AWS also checks on a second resource (for example the SSM document for
  `ssm:SendCommand`) are checked on the main resource only.
- Grants scoped to specific non-IAM resources are checked against the resource patterns in the
  principal's own policies and `"*"`, not against an inventory.
- The service principal a passed role must trust is a best-effort table
  (`SERVICE_PRINCIPALS` in `escalate.py`). Where it is missing, the finding is "possible".
- Only one account export is analysed. Roles in other accounts are not followed, and SCPs must be
  supplied with `--scp`.
- The blast radius counts actions allowed on `Resource: "*"` only.
- Run time grows with principals times techniques. A synthetic account of 200 users and 200
  roles takes about 3 seconds for every principal on one core; much larger accounts are best
  analysed one starting principal at a time (`--principal`).

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

- The export does not say which IAM users have access keys or a console password, so every user
  is listed as an entry point.
- The export does not list the account's OIDC and SAML providers, so a trust policy naming a
  provider that no longer exists is still reported.
- For a role trusted by another account, the probe gives the caller allow-all identity policies:
  that account controls them, so the worst case is assumed.
- Scores are a ranking aid, not a measurement: the exposure (anyone, a large group, another
  account, a leaked user key) times what the principal reaches.

## Fix plans

- A plan is made of Deny statements. Each one names the Allow statements that grant the
  permission, so you can narrow those instead, but narrowing is not generated or checked.
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
- Large account exports run in the browser tab and can take several seconds; the CLI is faster.
- Diff is only available when the site was built with a catalog.
