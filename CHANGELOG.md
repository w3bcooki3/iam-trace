# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - unreleased

### Added

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
- Policy check: `iam-trace check` and a new screen in the app flag 14 risky patterns, each with
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
