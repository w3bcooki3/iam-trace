# Roadmap

Where iam-trace is going, in the order it should happen. The guiding rule: **earn trust before
adding features.** A security tool is only useful if people can rely on its answers, so each
stage starts with what makes the previous one more trustworthy.

Want to help? Pick an item, open an issue saying you are on it, and ask questions there. Items
marked *good first issue* need no deep IAM knowledge.

Current version: **0.2.0 (beta)**.

---

## Stage 1: Prove it (0.3)

Goal: anyone can see how accurate iam-trace is, and install it in one line.

- [ ] **Run the comparison with AWS.** Send the 228 generated cases to AWS's policy simulator
      (free; needs one IAM user limited to `iam:SimulateCustomPolicy`). Store every disagreement
      as a test, fix or document each one, and publish the match rate in the README and the app.
- [ ] **Grow the comparison.** Generate cases from real-world policy shapes (wildcards in ARNs,
      `NotAction`, multi-valued conditions, cross-account grants) until the set covers every
      branch of the engine.
- [ ] **Publish to PyPI** so `pip install iam-trace` works, with signed releases built by a
      workflow (trusted publishing, no stored tokens). The workflow is ready
      (`.github/workflows/release.yml`); the first upload is next.
- [x] **Community basics:** `CONTRIBUTING.md`, `SECURITY.md` (how to report a vulnerability),
      issue and pull-request templates, a code of conduct. *good first issue*
- [x] **Feedback loop in the app:** a "Report a wrong answer" link that opens a pre-filled
      GitHub issue with the request and decision. It never includes policies unless the user
      pastes them in. *good first issue*

## Stage 2: See more (0.4 to 0.5)

Goal: fewer blind spots, so fewer "possible" findings and fewer surprises.

- [x] **Policy check.** A new screen and `iam-trace check` command that flags risky patterns on
      their own, each with a plain explanation and a suggested fix: `"Action": "*"`,
      `iam:PassRole` on `*`, admin access without conditions, wildcard principals in trust
      policies, `NotAction` with Allow, missing `aws:SourceAccount` on service trust, unused
      `Deny` statements. This covers what Cloudsplaining users expect, in the iam-trace style.
      Done: 15 rules, in the CLI, the app and the GitHub Action.
- [x] **Resource inventory.** Most "possible" findings come from techniques that take over an
      existing resource (a Lambda function, an EC2 instance) whose role the IAM export doesn't
      show. `iam-trace inventory collect` (read-only) lists eight kinds of resource with their
      roles; `escalate --inventory` and the app confirm those findings or rule them out.
      Next: launch templates, ECS services and Batch.
- [ ] **Resource policies in the analysis.** Accept S3 bucket policies, KMS key policies, SQS,
      SNS and Lambda resource policies alongside the account export. They matter most for
      "who can reach this resource" and cross-account access, so they pair with those items.
- [ ] **Organization view.** Load an AWS Organizations export (SCPs and RCPs per OU) once and
      apply the right guardrails to each account automatically.
- [ ] **Cross-account paths.** Load several account exports and follow role trust across them.
- [x] **Smarter context.** Take conditions into account instead of assuming an empty request.
      Done: the escalation analysis uses tags from the export and tries the values conditions
      name; steps that need MFA, a network location or a time window are labelled, and open
      paths come first. Next: the same toggles on the Evaluate screen.
- [x] **Entry points.** Find where an attack would start: roles open to GitHub repositories you
      don't own, any identity of an OIDC provider, other accounts without ExternalId, and IAM
      users, ranked by what they reach. Done: `iam-trace entry-points` and the Overview card.
- [ ] **More service rules.** S3 Block Public Access and ACLs, VPC endpoint policies, KMS
      grants, and services that require an explicit allow in their resource policy.

## Stage 3: Fix, not just find (0.6 to 0.8)

Goal: go from "here is the problem" to "here is the change, and here is proof it works".

- [x] **What-if mode.** Cut a step on the graph and see whether another route to admin is left.
      Done: Cut this step, and Show on graph from the fix plan.
- [x] **Generated fixes.** Produce the policy change and prove it works.
      Done: `iam-trace fix` and the Fix plan card give the fewest Deny statements that cut every
      path, verified by analysing the changed account again, and `can --what-if` does the same
      for one request. Next: generate the narrowed Allow statement as an alternative to a Deny,
      and an SCP version for organisations.
- [ ] **Infrastructure as code.** Read Terraform plans and CloudFormation templates, so risky
      IAM changes are caught before they are deployed, in the same pull-request comment as today.
      Terraform done (`iam-trace terraform` and the Terraform plan screen); CloudFormation next.
- [x] **Drift over time.** Compare two exports of the same account and report new paths, new
      admins and permissions that grew.
      Done: `iam-trace drift` and the Account drift screen.
- [x] **"Who can" questions.** "Who can read this bucket?" and "who can become this role?",
      answered across the whole export.
      Done: `iam-trace who-can` and a Who can screen with an access graph. "Who can become
      this role" is the same query with `sts:AssumeRole` on the role's ARN.
- [x] **Shareable reports.** Export a self-contained HTML or PDF report from the app for
      audits and tickets, still generated locally.
      Done: Download report, on the Overview and the Attack graph; the file runs no scripts.

## Stage 4: 1.0

Goal: dependable for teams of any size, and easy to contribute to.

- [ ] **Large accounts:** run the analysis in a background worker with progress, and stay
      responsive at 5,000 principals and above.
- [ ] **Stable interfaces:** versioned JSON and SARIF output, and a documented Python API.
- [ ] **A documentation site** with guides, recipes ("audit a new account in ten minutes") and
      the full limitations list.
- [ ] **Upstream contributions:** send techniques or variants found while building iam-trace
      back to pathfinding.cloud.
- [ ] **1.0 criteria:** a published match rate against AWS's simulator with every
      disagreement explained, no known wrong answers open, and at least a few teams using it.

---

## Not planned

To stay focused, iam-trace will not:

- **Call AWS on your behalf from the web app.** Files in, answers out; no credentials in the
  browser.
- **Become a general cloud security platform.** Configuration checks for EC2, networks or
  logging are covered well by other tools. iam-trace stays about identity and access.
- **Collect usage data.** No analytics, now or later.

## How to suggest something

Open an issue describing the problem you want solved, not only the feature. "I couldn't tell
whether X was safe" is the most useful kind of request.
