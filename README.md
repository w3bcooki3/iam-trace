# iam-trace

iam-trace explains what AWS IAM policies allow. It answers three questions:

1. **Can principal P do action A on resource R?** Yes or no, with a trace of the evaluation step
   and the statement that decided it.
2. **What does this policy change actually grant?** A semantic diff: newly allowed and denied
   actions and resources, grouped by access level. Reordering statements is not a change.
3. **If this principal is compromised, what can an attacker do?** Known privilege-escalation
   techniques, multi-step paths to admin-equivalent principals, and the blast radius.

The engine is a typed Python package with no dependencies. It makes no network calls when it
evaluates, so the same code runs in the CLI, in CI and in the browser.

## Status

<!-- counts:start -->
Offline tests: **543 passed**, 0 failed, 0 expected failures (open differential disagreements), 1 skipped.

Live differential run: **not run yet**. See "Differential testing" below.
<!-- counts:end -->

The skipped test is the placeholder for stored differential fixtures, which don't exist until the
first live run. The counts are written by `scripts/update_readme_counts.py`, and CI fails if they
are out of date.

## Install

Python 3.11 or newer.

    pip install git+https://github.com/w3bcooki3/iam-trace

`expand`, `diff` and `escalate --blast-radius` need the action catalog. If the installed package
doesn't include one yet, download it once (about 10 MB, from AWS's public endpoint):

    iam-trace catalog refresh
    iam-trace catalog info

## Usage

### can

    iam-trace can \
      --principal arn:aws:iam::111122223333:user/alice \
      --action s3:GetObject \
      --resource arn:aws:s3:::example-app/data.csv --resource-account 111122223333 \
      --identity examples/policies/developer.json \
      --resource-policy examples/policies/bucket-policy.json \
      --context aws:SecureTransport=true

Output:

    Decision: Allow  (stopped at: identity_policy)
    Request:  arn:aws:iam::111122223333:user/alice
              s3:GetObject on arn:aws:s3:::example-app/data.csv

    Trace:
      1. explicit_deny         pass            no applicable Deny statement
      2. resource_policy       no match        no resource-based policy allows the action
      3. identity_policy       pass            an identity-based policy allows the action
           - developer.json (identity): ReadAppBucket [Allow]

Inputs:

- Policies: `--identity`, `--resource-policy` and `--session-policy` can each be repeated, plus
  `--boundary`. `--scp` and `--rcp` take one organization level per flag, root first, with files
  comma-separated.
- Principals: `--principal` accepts IAM users, roles, assumed-role sessions, federated users,
  account root, `service:lambda.amazonaws.com` or `anonymous`. A role ARN is evaluated as a
  session of that role, because roles act only through their sessions.
- S3 ARNs carry no account, so pass `--resource-account`. Without it, iam-trace assumes the
  principal's account and says so in the warnings.
- Context: give keys with `--context KEY=VALUE`. Repeat a key to give it several values;
  `KEY=[]` sets an empty set.

### expand

    iam-trace expand 's3:Put*' 'iam:*Policy*'
    iam-trace expand --policy examples/policies/developer.json

This lists the concrete actions each pattern covers, grouped by access level. For a `NotAction`
statement, it lists every action the statement covers.

### diff

    iam-trace diff old.json new.json
    iam-trace diff old.json new.json --format markdown --fail-on highlighted

The diff reports four kinds of change: newly allowed, no longer allowed, newly denied, and denies
removed. Within each kind, entries are grouped by access level.

A `!` marks permissions-management actions and actions that appear in known escalation paths.
This catches `iam:PassRole`, which AWS classifies as Write.

Widening a resource or dropping a condition counts as newly allowed. Statement order, Sids,
value order, splitting statements and writing out a wildcard do not count as changes.

Use `/dev/null` for a file that was added or deleted.

### escalate

    aws iam get-account-authorization-details > auth.json
    iam-trace escalate --auth-details auth.json --principal arn:aws:iam::111122223333:user/dev --blast-radius

On the example account in `examples/account/`:

    Escalation paths
      1. user/dev --[sts-001]--> role/ops --[ec2-001]--> role/ec2-admin
         allowed every action on every resource

Each technique cites its [pathfinding.cloud](https://pathfinding.cloud) page and the research
that first documented it. To check a single policy without an account export:

    iam-trace escalate --policy new.json --baseline old.json --fail-on new

### Output formats and exit codes

Every command supports `--format text|json|sarif`; `diff` also supports `markdown`.

| Exit code | Meaning |
|---|---|
| 0 | Success. For `can`, the request is allowed. |
| 1 | For `can`, the request is denied. For `diff` and `escalate`, a `--fail-on` condition matched. |
| 2 | A usage error, an unreadable file, or a policy AWS would reject. |

## GitHub Action

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  iam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: w3bcooki3/iam-trace/action@main
        with:
          paths: "policies/**/*.json"
          fail-on-escalation: "true"   # fail if a changed identity policy allows a new technique
          fail-on-diff: "never"        # or any | new-allow | highlighted
```

The action reviews policy files that changed between the PR's base and head. It posts or updates
one comment, and also writes the review to the job summary.

JSON files that aren't policy documents are ignored. For pull requests from forks, the token is
read-only, so the review goes to the job summary only.

## Web app

`web/` is a single-page app that runs the same engine in the browser with
[Pyodide](https://pyodide.org) 0.29.3. The `pages` workflow publishes it to GitHub Pages.

- **Overview**: the verdict for the chosen starting principal, paths to admin, recommended fixes
  ordered by how many paths each breaks, technique categories, blast radius and every principal
  ranked by exposure.
- **Attack graph**: who the attacker can become, full screen, with details for every principal
  and technique. Three node styles.
- **Findings**: every technique for every principal, searchable, with text, SARIF and JSON
  downloads.
- **Data input**: drop an account export or a single policy, add organization SCPs, choose the
  starting principal. The input is validated before it runs.
- **Evaluate a request** and **Policy diff**: the `can` and `diff` commands with a full trace.
- **Documentation**, **changelog** and **settings** (light, dark or system mode; three styles;
  brand colour), all inside the app.

Why Pyodide rather than a TypeScript port: the app runs the exact code the CLI and the tests run,
so the two can't drift apart. The cost is a one-time download of about 13 MB, which the browser
caches.

Nothing you load leaves the page. The published site bundles the Pyodide runtime, so the
Content-Security-Policy allows scripts, styles and network requests from the site itself and
nowhere else. Neither `eval` nor inline styles are allowed, and the page has no forms.

To build it locally:

    python scripts/build_web.py                       # loads Pyodide from cdn.jsdelivr.net
    python scripts/build_web.py --pyodide DIR         # bundles an unpacked pyodide@0.29.3 package
    python -m http.server -d web/dist

## Security

iam-trace reads policies; it never needs AWS credentials except for the optional differential run,
which needs only `iam:SimulateCustomPolicy`. Inputs are treated as hostile:

- Wildcard matching runs in linear time, so a crafted `Action` or `Resource` pattern cannot
  stall a CI job. A fuzz suite feeds malformed and deeply nested policies to every entry point
  and checks that each one fails with a clear error, never a traceback or a hang.
- Text that comes from a pull request (file names, action names, conditions, error messages) is
  escaped before it goes into the Action's Markdown comment.
- The workflows pin every third-party action to a commit SHA, pass inputs through environment
  variables rather than `${{ }}` interpolation in scripts, and do not keep the checkout token
  where it is not needed.
- `catalog refresh` only replaces a directory that contains nothing but catalog files, and only
  fetches from AWS's catalog host.

Report security problems through GitHub's private vulnerability reporting on the repository.

## How evaluation works

The steps are explicit deny, then RCPs, SCPs, resource-based policies, identity-based policies,
the permissions boundary and session policies. Cross-account requests need an Allow from both
accounts.

The detailed rules are in [docs/evaluation.md](docs/evaluation.md), with a link to the AWS page
behind each one. That page also covers which principal a resource policy names, and why that
decides whether boundaries limit the grant.

## Testing

| Suite | What it checks |
|---|---|
| `tests/unit` | Operators, matching, evaluation flow, catalog, diff, escalate, CLI, the Action's review step, the web API. |
| `tests/known_answer` | Every worked example in AWS's evaluation docs. See [SOURCES.md](tests/known_answer/SOURCES.md). |
| `tests/handwritten` | Cases the AWS simulator cannot model, each quoting the AWS docs. |
| `tests/differential` | 228 generated policy/request pairs. Offline they must evaluate; the live run compares them with AWS. |

CI (`ci.yml`) runs the offline suites, ruff and mypy on Python 3.11, 3.12 and 3.13 for every
push. Nothing in CI talks to AWS.

### Differential testing

The `differential` workflow is manual. It sends every generated case to
`iam:SimulateCustomPolicy` and compares AWS's answer with iam-trace. Every disagreement is
stored as a fixture in `tests/differential/fixtures/`, and the workflow opens a pull request with
the fixtures and the updated pass count.

The workflow needs an IAM user whose only permission is
[docs/differential-iam-policy.json](docs/differential-iam-policy.json):

```json
{"Effect": "Allow", "Action": "iam:SimulateCustomPolicy", "Resource": "*"}
```

Store that user's access keys as the repository secrets `AWS_DIFF_ACCESS_KEY_ID` and
`AWS_DIFF_SECRET_ACCESS_KEY`. The simulator API is free, and a run makes about 230 calls. To run
it locally instead:

    pip install -e '.[differential]'
    python -m tests.differential.runner

## Cost

Everything here uses free services:

- The AWS policy simulator API and AWS's public catalog endpoint.
- GitHub Actions and GitHub Pages, both free for public repositories.
- The Pyodide package from npm, fetched at build time.

No step creates AWS resources.

## Limitations

The most important ones:

- **Not yet checked against AWS:** the live differential run hasn't been done yet. A few
  behaviours the docs don't settle are listed as unconfirmed, including how wildcards behave in
  the first five ARN components.
- **Service-specific rules:** only role trust policies and KMS key policies are modelled as
  needing an explicit allow. S3 ACLs, Block Public Access, VPC endpoint policies, KMS grants and
  similar are not modelled.
- **Request context:** context keys other than the principal and account keys must be supplied.
  A key you don't supply is treated as missing.
- **Catalog access levels:** access levels are derived from AWS's annotation flags, because the
  JSON reference has no access-level field.
- **Diff conditions:** the diff compares conditions by equality.
- **Escalation analysis:** it can't see existing resources, such as Lambda functions, that an
  attacker could take over, so those techniques are reported as "possible".

The full list is in [docs/limitations.md](docs/limitations.md).

## Repository layout

    src/iamtrace/          the package
      model.py            policy parsing and validation
      conditions.py       condition operators
      arn.py, matching.py, wildcard.py, variables.py
      principals.py       principals and resource-policy grant kinds
      evaluate.py         the decision engine and traces
      servicerules.py     RCP service list, trust/key policy rules
      catalog/            action catalog loader and refresh
      expand.py, diff.py, escalate.py
      output.py           text / JSON / SARIF
      cli.py, pr_review.py, web_api.py
      data/               escalation technique data (see NOTICE)
    tests/                unit, known_answer, handwritten, differential
    action/               GitHub Action
    web/                  static page
    scripts/              README counts, access-level check, web build
    docs/                 evaluation rules, limitations, differential IAM policy
    examples/             sample policies and an account export

## Licence

MIT; see [LICENSE](LICENSE). The escalation technique data comes from pathfinding.cloud under
Apache-2.0; see [NOTICE](NOTICE).
