"""The IAM credential report: which users have a password, MFA and active access keys.

An account export lists users and their policies but not their credentials. Without them every
user has to be treated as a possible entry point. The credential report says which users can
actually be used from outside (an active access key, or a console password), how old each key
is and when it was last used, and whether the root user has access keys.

Get it with the AWS CLI (read-only):

    aws iam generate-credential-report
    aws iam get-credential-report > credentials.json

Either that JSON output or the CSV inside it (`--query Content --output text | base64 -d`) is
accepted.
"""

from __future__ import annotations

import base64
import binascii
import csv
import datetime as dt
import io
import json
from dataclasses import dataclass, field
from typing import Any

STALE_DAYS = 90  # a key not rotated, or not used, for longer than this is called stale


class CredentialError(ValueError):
    """The file is not a credential report."""


@dataclass(frozen=True)
class AccessKey:
    number: int
    last_rotated: str | None
    last_used: str | None
    age_days: int | None
    unused_days: int | None  # days since last use; None if never used

    @property
    def never_used(self) -> bool:
        return self.last_used is None


@dataclass(frozen=True)
class UserCredentials:
    name: str
    arn: str
    password: bool
    password_last_used: str | None
    mfa: bool
    active_keys: list[AccessKey] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        """Can someone outside use this user: an active key or a console password?"""
        return bool(self.active_keys) or self.password

    def stale_keys(self) -> list[AccessKey]:
        return [
            k
            for k in self.active_keys
            if (k.age_days or 0) > STALE_DAYS or k.never_used or (k.unused_days or 0) > STALE_DAYS
        ]


@dataclass
class CredentialReport:
    users: dict[str, UserCredentials]
    root: UserCredentials | None
    generated: str | None
    now: dt.datetime


REQUIRED = {"user", "arn", "password_enabled", "mfa_active", "access_key_1_active", "access_key_2_active"}


def _date(value: str) -> str | None:
    v = (value or "").strip()
    if not v or v in ("N/A", "no_information", "not_supported"):
        return None
    return v


def _parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        when = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=dt.UTC)


def _days(now: dt.datetime, value: str | None) -> int | None:
    when = _parse_time(value)
    return None if when is None else max(0, (now - when).days)


def parse_credential_report(text: str, *, now: str | None = None) -> CredentialReport:
    """Parse the CSV, or the JSON that `aws iam get-credential-report` prints."""
    raw = text.lstrip("﻿").strip()
    generated: str | None = None
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            content = data["Content"]
            generated = data.get("GeneratedTime")
            raw = base64.b64decode(content, validate=True).decode("utf-8").strip()
        except (json.JSONDecodeError, KeyError, TypeError, binascii.Error, UnicodeDecodeError) as e:
            raise CredentialError(
                "expected the CSV credential report, or the JSON `aws iam get-credential-report` prints"
            ) from e
    rows = list(csv.DictReader(io.StringIO(raw)))
    if not rows or not REQUIRED <= set(rows[0].keys()):
        raise CredentialError(
            "not a credential report: the header should start with user,arn,user_creation_time,password_enabled"
        )
    clock = _parse_time(now or generated) or dt.datetime.now(dt.UTC)
    users: dict[str, UserCredentials] = {}
    root = None
    for r in rows:
        keys = []
        for n in (1, 2):
            if r.get(f"access_key_{n}_active", "").lower() != "true":
                continue
            rotated = _date(r.get(f"access_key_{n}_last_rotated", ""))
            used = _date(r.get(f"access_key_{n}_last_used_date", ""))
            keys.append(AccessKey(n, rotated, used, _days(clock, rotated), _days(clock, used)))
        creds = UserCredentials(
            name=r["user"],
            arn=r["arn"],
            password=r["password_enabled"].lower() == "true",
            password_last_used=_date(r.get("password_last_used", "")),
            mfa=r["mfa_active"].lower() == "true",
            active_keys=keys,
        )
        if r["user"] == "<root_account>" or r["arn"].endswith(":root"):
            root = creds
        else:
            users[creds.arn] = creds
    return CredentialReport(users=users, root=root, generated=generated, now=clock)


def describe_user(c: UserCredentials) -> tuple[str, str, str]:
    """(who can get in, detail, fix) for an entry point, from the user's real credentials."""
    who: list[str] = []
    detail: list[str] = []
    fix: list[str] = []
    if c.active_keys:
        n = len(c.active_keys)
        who.append(f"anyone holding its {n} active access key{'s' if n != 1 else ''}")
        for k in c.active_keys:
            facts = []
            if k.age_days is not None:
                facts.append(f"{k.age_days} days old")
            if k.never_used:
                facts.append("never used")
            elif k.unused_days is not None:
                facts.append(f"not used for {k.unused_days} days" if k.unused_days > 1 else "used recently")
            detail.append(f"Access key {k.number}: {', '.join(facts)}.")
        stale = c.stale_keys()
        unused = [k for k in c.active_keys if k.never_used or (k.unused_days or 0) > STALE_DAYS]
        if unused:
            fix.append(
                "Remove access key " + " and ".join(str(k.number) for k in unused) + ": an unused key is pure risk."
            )
        elif stale:
            fix.append(
                "Rotate access key " + " and ".join(str(k.number) for k in stale) + f" (older than {STALE_DAYS} days)."
            )
        fix.append("Prefer roles with short-lived credentials, for example IAM Identity Center.")
    if c.password:
        who.append("its console password" + ("" if c.mfa else " without MFA"))
        if not c.mfa:
            fix.append("Turn on MFA for the console sign-in.")
    text = " or ".join(who) if who else "nobody: it has no password and no active access key"
    if c.active_keys and c.password and not c.mfa:
        text = f"{who[0]}, or {who[1]}"
    return text, " ".join(detail), " ".join(fix)


def collect_credential_report(run: Any, *, sleep: Any = None, tries: int = 15) -> str:
    """Ask AWS for a fresh credential report and return it as `get-credential-report` JSON.

    `run` is a runner from iamtrace.collect (it calls the AWS CLI and parses its JSON). Two
    read-only calls: generate-credential-report until it says COMPLETE, then get-credential-report.
    """
    import time

    from iamtrace.collect import CollectError

    wait = sleep or time.sleep
    for i in range(tries):
        state = (run(["iam", "generate-credential-report"]) or {}).get("State")
        if state == "COMPLETE":
            break
        wait(min(2 * (i + 1), 10))
    else:
        raise CollectError("the credential report was not ready in time; try again in a minute")
    out = run(["iam", "get-credential-report"])
    if not isinstance(out, dict) or "Content" not in out:
        raise CollectError("get-credential-report returned no report")
    return json.dumps(out, indent=2) + "\n"
