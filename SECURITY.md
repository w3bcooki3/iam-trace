# Security policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub private vulnerability reporting).

Include what you found, how to reproduce it, and what an attacker could do with it. You will get
a reply within a week. Once it is fixed, you will be credited in the changelog unless you prefer
not to be.

## What counts

- Anything that makes the web app send your data anywhere, or run code it shouldn't.
- Input (a policy, an export, a pull request) that crashes, hangs or misleads iam-trace or its
  GitHub Action.
- Ways to get the GitHub Action to post or run something the repository owner did not intend.

A wrong Allow or Deny for an ordinary policy is a correctness bug rather than a vulnerability:
please use the [wrong answer](https://github.com/w3bcooki3/iam-trace/issues/new?template=wrong_answer.yml)
form for those. If a wrong answer could hide a real escalation path in practice, report it
privately as above.

## Supported versions

Only the latest release receives fixes while iam-trace is below 1.0.

## How iam-trace protects you

- The web app runs entirely in the browser. Its Content-Security-Policy only allows the site's
  own files; it allows no `eval`, inline scripts or inline styles, and it has no analytics.
- No AWS credentials are needed. The CLI and the app only read files.
- Workflows pin third-party actions to commit SHAs and pass untrusted input through environment
  variables, never into scripts.
