# Contributing to iam-trace

Thanks for helping. iam-trace is a security tool, so the most valuable contributions are the ones
that make its answers more trustworthy: a wrong answer reported, a missing case tested, a
confusing explanation made clear.

## Ways to help

- **Report a wrong answer.** If iam-trace says Allow and AWS says Deny (or the other way round),
  open a [wrong answer](https://github.com/w3bcooki3/iam-trace/issues/new?template=wrong_answer.yml)
  issue. The app has a "Report a wrong answer" link that fills in the request for you. Remove
  anything sensitive from policies before you paste them.
- **Report a bug or confusing wording** with the [bug report](https://github.com/w3bcooki3/iam-trace/issues/new?template=bug_report.yml) form.
- **Pick an item from the [roadmap](ROADMAP.md).** Comment on the matching issue (or open one)
  before you start, so nobody duplicates work. Items marked *good first issue* need no deep IAM
  knowledge.
- **Improve the documentation**, in `README.md`, `docs/` or the in-app docs in `web/index.html`.
  Plain words beat jargon.

Security problems go through private reporting instead; see [SECURITY.md](SECURITY.md).

## Set up

Python 3.11 or newer. No runtime dependencies.

```
git clone https://github.com/w3bcooki3/iam-trace
cd iam-trace
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

The web app:

```
python scripts/build_web.py
python -m http.server -d web/dist
```

Then open <http://localhost:8000>. The page needs to be served, not opened as a file.

## Before you open a pull request

Run the same checks CI runs:

```
ruff format --check .
ruff check .
mypy src
pytest -q
python scripts/update_readme_counts.py --check
```

If you changed test counts, run `python scripts/update_readme_counts.py` to update the README.

## How we work

- **Tests first for engine changes.** A change to evaluation logic needs a test that fails
  before it and passes after. If the behaviour comes from AWS's documentation, cite the page in
  the test (see `tests/known_answer/SOURCES.md`).
- **Small pull requests**, one change each, with a line in `CHANGELOG.md` under the next version.
- **No new runtime dependencies.** The engine must run offline and inside Pyodide.
- **Plain, specific writing** in docs, messages and the UI: no marketing language, no emojis.
  Say what happens and what to do next.
- **Escalation techniques** come from [pathfinding.cloud](https://pathfinding.cloud). New
  techniques belong there first; iam-trace imports them (see `NOTICE`).

## Releasing

Maintainers only. Releases go to PyPI through trusted publishing, so no token is stored anywhere.

One-time setup:

1. On [pypi.org](https://pypi.org), add a pending trusted publisher (Account settings,
   Publishing): project `iam-trace`, owner `w3bcooki3`, repository `iam-trace`, workflow
   `release.yml`, environment `pypi`.
2. On GitHub, create an environment named `pypi` (Settings, Environments). Adding yourself as a
   required reviewer means each upload waits for your approval.

Each release:

1. Set the version in `pyproject.toml` and `src/iamtrace/__init__.py`.
2. In `CHANGELOG.md`, change `## [x.y.z] - unreleased` to today's date, e.g.
   `## [0.2.0] - 2026-11-20`.
3. Commit, then tag and push: `git tag v0.2.0 && git push origin main v0.2.0`.

The `release` workflow checks the tag matches the version and the changelog has a dated section,
runs every check, uploads to PyPI with signed attestations, and creates the GitHub release with
the changelog section as its notes. If a check fails nothing is published; fix it, delete the
tag (`git push --delete origin v0.2.0 && git tag -d v0.2.0`) and tag again.

## Licence

By contributing you agree that your contribution is licensed under the MIT licence in
[LICENSE](LICENSE).
