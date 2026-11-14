# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - unreleased

### Added

- A complete web app: an Overview dashboard with the verdict, metrics, paths to admin,
  recommended fixes and principals at risk; a full-screen attack graph with three node styles;
  Findings with search, filters and downloads (text, SARIF, JSON); Data input with file drop,
  validation, a principal picker, organization SCPs and an optional blast-radius count.
  Evaluate and Policy diff use the same design. Documentation, this changelog and settings
  (light, dark or system mode; bold, restrained or brand-colour style) are inside the app.
- `web_api.analyze_account`: one call returns the analysis from a starting principal, a summary of
  every principal with its shortest path to admin, and accepts organization SCPs.

### Changed

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
