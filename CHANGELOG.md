# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - unreleased

### Added

- Unused access: `iam-trace usage collect` gets IAM's last accessed data for every user and role
  (read-only), and `iam-trace unused` turns it into policy edits that remove services nobody who
  has the policy used for `--days` days (default 90), then analyses the account again to show
  which paths to admin that closes. Edits only take access away (checked by a property test),
  keep `iam:PassRole` (AWS does not track it), and leave a policy alone if anyone who shares it
  has no report. In the web app: a Last accessed input tab and an Unused access screen.
- Property tests (`tests/property`, Hypothesis, development only): random policies and accounts
  check that an explicit Deny always wins, an Allow never takes access away, boundaries and SCPs
  only restrict, statement and export order change nothing, a trust or key policy is needed for
  AssumeRole and KMS, a verified fix plan leaves no open path when re-applied independently (as
  Denies, narrowed Allows and an SCP), and the fix plan's solver matches brute force.
- Escalation benchmark: `tests/benchmark/bench.py` builds an account for each of the 91 AWS paths
  in pathfinding.cloud from its own description and checks it is found, then tries 1,136 near
  misses (a permission removed or denied, an SCP, a permissions boundary, a target that is not
  admin, PassRole limited to another service or role, a role trusted by another service) that
  must not be. All 91 are confirmed, 23 of them with a resource inventory, with no false alarm.
  `docs/coverage.md` has the table, and a test fails if any path gets worse.
- Resource inventory: `inventory collect` also records Batch job definitions, running ECS tasks,
  EC2 launch templates, and Bedrock AgentCore runtimes, custom code interpreters and browsers,
  with their roles. Every existing-resource technique can now be confirmed.
- Terraform plans: `iam-trace terraform plan.json` reviews the IAM changes in a plan (diff, new
  escalation techniques, new risky patterns per document). With `--auth-details` it applies the
  plan to the export, including policies created in the same plan and attached by reference, and
  reports new and removed paths to admin, new admins and new entry points. `--format markdown`
  writes a pull-request comment, and the GitHub Action takes `terraform-plan`, `auth-details` and
  `fail-on-terraform`. A Terraform plan screen does the same in the app.
- Data access: `iam-trace data` and a Data access screen rate every S3 bucket and KMS key in the
  inventory by who can read and write it (directly, by escalating, from outside the account),
  worst first, with the routes. Reading an SSE-KMS bucket needs kms:Decrypt on its key too;
  public bucket policies are checked against the key and S3 Block Public Access.
  `inventory collect` now records buckets (policy, default encryption key, Block Public Access)
  and customer managed keys (key policy). The Overview gets a Data exposure card.
- Fix plans come in three verified forms: Deny statements, the granting Allow statements
  narrowed (actions removed, resources listed or excluded, policies that grant nothing else
  deleted), and one SCP. Each narrowing names what else it stops allowing and who else a shared
  policy affects. "Apply as" in the Fix plan card switches between them; `fix --out-dir` writes
  all three.
- Credential report: `iam-trace credentials collect` fetches the IAM credential report
  (read-only), and `entry-points --credential-report` and a new Data input tab use it. Users with
  no password and no active access key are no longer entry points; old or unused keys and
  passwords without MFA rank higher and are explained with their dates; root user access keys
  are critical.
- Fix plans: `iam-trace fix` and a Fix plan card on the Overview give the fewest Deny statements
  that cut every path to admin, from one principal or from all of them. Denials are scoped to the
  target role, user or policy wherever possible. Choosing them is a weighted minimum hitting set
  over the routes to admin, solved exactly; the plan is then applied to a copy of the account and
  analysed again, and only a plan that leaves no path is called verified. Each change names the
  statement that grants the permission. Downloads, a JSON format and `--out-dir` write the
  policies; the HTML report includes the plan.
- Entry points: `iam-trace entry-points` and an Entry points card on the Overview list where an
  attack could start, worst first: IAM users, and roles that someone outside the account can
  assume. Trust policies are tested with the evaluator (can a GitHub workflow in a repository you
  don't own assume this role? one in another repository of the organisation? any identity of
  this OIDC provider? an unauthenticated Cognito identity? an unrelated account? the named
  account without ExternalId?) and combined with the escalation analysis. "Analyse from here"
  re-runs the analysis from that principal.
- Policy check rule `open-federated-trust`: a trust policy open to every identity of a provider,
  such as GitHub Actions with an audience condition but no subject condition.
- Condition-aware escalation analysis: tags from the export are used, and failed checks are
  tried again with the values their conditions name. Steps that only need values the attacker
  chooses (region, request tags, ExternalId) are open; steps that need MFA, a network location
  or a time window are gated and labelled. Paths say whether they are open or what they need,
  and open paths are listed first. `escalate --strict-context` turns this off.
- The example account gains role/github-deploy (trusted by any GitHub repository) and
  role/break-glass (admin, assumable with MFA).
- Search and commands: Ctrl K (Cmd K on a Mac), or / outside a text field, opens one search box
  for every screen, principal (at-risk principals first), documentation topic and heading, plus
  common commands such as Download report, Load the example account and switching mode. Keyboard
  only works throughout; on phones it opens from a button in the top bar.
- Report: Download report in the app saves a single HTML file with the verdict, the shortest path
  from each starting principal, what to fix first and every principal at risk, plus the scope and
  limits of the analysis. It has no scripts and no external references, opens offline and prints
  to PDF.
- What if I cut this step: in the attack graph, any technique can be cut, and every recommended
  fix on the Overview has Simulate. iam-trace searches all confirmed steps in the analysis again
  and says whether the attacker still reaches an admin-equivalent principal; if so it draws the
  other route. Cuts are not saved and do not change the analysis.
- Link previews (Open Graph and Twitter card) and README screenshots.
- Policy check: `iam-trace check` and a new screen in the app flag 15 risky patterns, each with
  where it is, why it matters and how to fix it. Examples: full admin, `iam:PassRole` on any
  role, Allow with `NotAction`, public principals, `ForAllValues` in an Allow, a typo in a Deny,
  and every permission a pathfinding.cloud technique needs. Works on policy files or every
  policy in an account export (with what each is attached to). Text, JSON and SARIF output;
  `--fail-on` for CI. The GitHub Action lists the findings a pull request introduces (not ones
  already there) and fails on them with the new `fail-on-check` input.
- Resource inventory: `iam-trace inventory collect` lists existing Lambda functions, EC2
  instances, CodeBuild projects, CloudFormation stacks, Glue dev endpoints, SageMaker notebooks,
  Step Functions state machines and App Runner services with their roles, using read-only AWS CLI
  calls. `escalate --inventory` and a new Data input tab use it to confirm techniques that take
  over an existing resource (naming the resource) or rule them out. Kinds that could not be
  collected stay "possible". On the example account, 25 possible findings become 17.
- The example account has a user who may update one Lambda function, and an example inventory.
- What would change the answer (`can --what-if`, and a card under every Evaluate result): for a
  denied request, the smallest fix (the Deny to remove, a context value, or the missing Allow for
  each layer that refused, as JSON); for an allowed one, the statements and context keys it
  depends on; and near misses with the reason. Every suggestion is checked by evaluating again.
  "Try this change" applies a fix and evaluates again.
- Who can (`iam-trace who-can` and a new screen): every principal in an account export that can
  perform an action on a resource, directly, through a confirmed escalation path, or named by the
  resource policy but outside the export. The app draws the answer as a graph: every route ends
  at the resource, escalation hops are labelled with their technique, and selecting a principal
  finds it in the lists.
- Evaluate: the request panel scrolls on its own and the Evaluate button stays in view.
- Documentation redesigned: one topic per page with its own address, a contents sidebar with
  full-text search, "On this page" links, previous and next, and a contents panel on phones.
- Your work is saved in the browser (IndexedDB) and comes back after a refresh, including the
  last analysis. The top bar says "Saved in this browser" or "Not saved"; leaving with unsaved
  data asks first. Settings, Saved data, lists every saved item with its size and time, and can
  delete one item, delete everything, or turn saving off.
- A complete web app: an Overview dashboard with the verdict, metrics, paths to admin,
  recommended fixes and principals at risk; a full-screen attack graph with three node styles;
  Findings with search, filters and downloads (text, SARIF, JSON); Data input with file drop,
  validation, a principal picker, organization SCPs and an optional blast-radius count.
  Evaluate and Policy diff use the same design. Documentation, this changelog and settings
  (light, dark or system mode; bold, restrained or brand-colour style) are inside the app.
- Marked as beta in the app and README. New README sections on who iam-trace is for and how it
  relates to pathfinding.cloud, PMapper, Cloudsplaining, iam-lens and AWS's own tools; a
  `ROADMAP.md` with the plan to 1.0.
- "Report a wrong answer" links next to every Evaluate result and graph finding. They open a
  prefilled GitHub issue; 12-digit account IDs are replaced with `111122223333` first.
- Project files: `CONTRIBUTING.md`, `SECURITY.md` (private vulnerability reporting),
  `CODE_OF_CONDUCT.md`, issue forms (wrong answer, bug, feature), a pull request template and
  Dependabot for workflow actions.
- Release workflow: pushing a `v*` tag checks the version and changelog, runs every check and
  publishes to PyPI with trusted publishing and attestations, then creates the GitHub release.
- Package metadata for PyPI: SPDX licence, classifiers, keywords and project links.
  `iam-trace --version` prints the version.
- `web_api.analyze_account`: one call returns the analysis from a starting principal, a summary of
  every principal with its shortest path to admin, and accepts organization SCPs.

### Changed

- Analysis is several times faster on large accounts, with identical results. Cheap
  over-approximations skip checks that cannot succeed (a trust policy that cannot name the
  caller, identity policies that cannot cover the action on that resource), repeated ARN and
  action matching is cached, and the web app's two runs (from everyone, then from the chosen
  principal) share their per-principal results. A property test checks that switching the
  shortcuts off changes nothing, and `scripts/synthetic_account.py` writes the large made-up
  accounts used to measure it.
- Fix plans are much faster. The exact search for the fewest changes no longer tries the same
  combination in different orders, drops routes that a smaller route already covers, and prunes
  with a stronger lower bound. On random seven-principal accounts the slowest plan went from
  17 seconds to about 1, and the average from 1.3 to 0.4 seconds; the plans stay optimal
  (checked against brute force).
- The technique list follows pathfinding.cloud again (`scripts/sync_catalog.py`): four paths need
  the permissions upstream now lists (codedeploy-001, ec2instanceconnect-003, gamelift-001,
  omics-001), and ec2-004, which upstream renamed to ec2-005, is gone. 91 techniques.
- The web app runs the analysis engine in a background worker, so the page stays responsive
  while a large account is analysed. Long operations show a Cancel button, which stops the
  engine and starts a fresh one.
- Web app design review: flat surfaces instead of glows, gradients and frosted glass (which also
  made scrolling slow); a neutral palette with a blue accent; type that scales with the window;
  pages that use wide screens; no status badges in the top bar.
- Policy diff and Policy check fill the screen; results open in a full-screen sheet with Back to
  editing (Esc) and a short entrance animation that respects reduced motion.
- The attack graph's paths panel is a docked, collapsible column with each path as a list of
  steps; on phones it slides over the graph, and the graph opens at a readable size.
- The changelog page has a version index and filters beside readable-width notes.
- Scrolling: one scroll area per screen (tables no longer scroll inside the page), each screen
  opens at the top, and long tables become labelled cards on phones.
- Renamed from IAM Lens to iam-trace (the name was taken). The package installs as `iam-trace`,
  the command is `iam-trace`, the Python module is `iamtrace` and the catalog variable is
  `IAMTRACE_CATALOG`.
- `escalate` skips techniques a principal's policies cannot allow before evaluating them in
  full; results are unchanged (tested) and a 400-principal account takes 3 s instead of 24 s.

### Security

- Wildcard matching rewritten to run in linear time. The previous regex translation could take
  minutes on a crafted pattern such as `a*a*a*...b`, which would stall a CI job.
- Malformed input no longer crashes: `"Statement": null`, deeply nested JSON, files with a UTF-8
  byte-order mark and incomplete account exports now give a clear error. Added a fuzz suite.
- The Action escapes file names, actions, conditions and errors from the pull request before
  putting them in its Markdown comment.
- Workflows: third-party actions pinned to commit SHAs, inputs passed through environment
  variables, checkout credentials not persisted in read-only jobs.
- `catalog refresh` refuses to replace a directory holding anything other than catalog files and
  validates the service URLs it is given.
- Web app: Pyodide is bundled into the published site, so the page loads no third-party code; the
  Content-Security-Policy allows neither `unsafe-eval` nor inline styles.

### Fixed

- Found by the property tests: iam:AddUserToGroup (iam-013) counted as admin whatever the group
  allowed. It now counts only for a group whose policies, added to the user's own under the
  user's boundary and SCPs, allow everything.
- Found by the property tests: when a technique reached one target only with MFA (or a network
  location or time window) and another without, the whole technique, and so the principal's admin
  access, was reported as needing it. Self-escalations and existing resources now keep each
  target's conditions apart, as paths to other principals already did.
- Found by the property tests: a principal that could make itself admin on its own (for example
  with iam:AttachUserPolicy) and was also allowed everything only with MFA was reported as admin
  only with MFA. The unconditional route now wins, so the verdict no longer looks safer than it is.
- Found by the benchmark: batch-001 and gamelift-001 now accept a role trusted by
  batch.amazonaws.com or ec2.amazonaws.com, as pathfinding.cloud describes them, and were missed
  before; cognitoidentity-001 checks the role's web identity trust for Cognito and is confirmed
  instead of possible; cloudformation-005 (a change set on a stack with a service role), which
  passes no role, was never reported and is now checked against existing stacks.
- Markdown escaping in pull-request comments no longer breaks HTML entities (an apostrophe showed
  as `&\#x27;`).
- The selected Data input tab no longer has a glow ring, and the five tabs fit one row on wide
  screens.
- The escalation analysis evaluated every check with no request context, so steps allowed only
  in a given region or with given request tags were missed, and conditions on principal or role
  tags were never met.
- Row highlights no longer stick after a tap on touch screens.
- Settings and Changelog were hard to read on phones: Settings is now one column of compact
  options with a section list (a tab strip on small screens), and the Changelog shows each entry
  as a title and a description, with counts per kind and long groups folded.
- Phones no longer show the focus-mode button, which had no effect there.
- Overview header buttons no longer wrap onto two lines; the request summary on an Evaluate
  result no longer breaks long ARNs mid-word.

- The access-level check now accepts actions the HTML reference lists under several levels
  ("Tagging, Write"). Against the live reference: 21,484 actions, 0 mismatches.

## [0.1.0]

### Added

- M5: GitHub Action (`action/`) that comments the semantic diff on pull requests touching
  policy files and can fail on new escalation techniques; static web page (`web/`) running the
  same engine in the browser with Pyodide 0.29.3, published by the `pages` workflow; examples.

- M4: `iam-trace escalate`. Checks every principal in an account export
  (`aws iam get-account-authorization-details`), or a single policy, against pathfinding.cloud's
  92 privilege-escalation techniques, each cited with its pathfinding.cloud page and first
  public source. Builds a graph of assume-role, pass-role and credential edges and reports the
  shortest paths to admin-equivalent principals. `--blast-radius` counts what reachable
  principals can do. `--baseline` reports only findings new since the previous policy version.
  Text, JSON and SARIF output; `--fail-on` for CI.

- M3: `iam-trace diff`, a semantic diff of two policies. Newly allowed, no longer allowed, newly
  denied and removed denies, grouped by access level. Permissions-management actions and actions
  used in known escalation paths are highlighted. Reordering, Sid changes, splitting statements
  and writing out a wildcard are not changes. Text, JSON, SARIF and Markdown output;
  `--fail-on` for CI.
- M2: action catalog from AWS's machine-readable Service Authorization Reference, with access
  levels derived from its annotation flags; `iam-trace catalog refresh|info`; `iam-trace expand`;
  weekly refresh workflow that also compares access levels with the HTML reference.

- M1: evaluation engine and `iam-trace can`.
  - Identity, resource-based, permissions boundary, session, SCP and RCP policies.
  - Evaluation order from the AWS enforcement-logic page, including the same-account rules for
    resource-policy grants to users, roles, role sessions and federated users, and the
    cross-account rule that both accounts must allow.
  - Action/NotAction, Resource/NotResource, Principal/NotPrincipal, wildcards, policy variables
    (defaults and the `${*}`, `${?}`, `${$}` escapes).
  - All condition operators, `IfExists`, `ForAllValues`, `ForAnyValue` and `Null`.
  - A trace for every decision; text, JSON and SARIF output.
  - Known-answer tests from the AWS evaluation docs and hand-written tests for cases the
    simulator cannot model.
  - Differential test generator (228 cases) and a manual workflow that runs it against
    `iam:SimulateCustomPolicy`.
