"""ARN parsing and Resource/NotResource matching.

How iam-trace matches a Resource pattern against a requested resource:
- "*" matches everything, including the "*" used for actions with no resource type.
- Otherwise both are split into six components on the first five colons. The first five
  (arn, partition, service, region, account) are matched one by one, so a wildcard cannot span
  a colon there. The sixth (the resource part) may itself contain colons and slashes, and a
  wildcard in it matches across them (for example "arn:aws:s3:::*log*" matches
  "arn:aws:s3:::my-logs/file").
- Matching is case-sensitive.
- Policy variables are substituted only in the resource part, which is the only place the docs
  allow them ("only in the resource portion of the ARN, after the fifth colon").
- A pattern that is not a six-part ARN is matched as a whole string.

The AWS docs don't say exactly how wildcards in the first five components behave in the
Resource element. This is one of the cases the differential test settles.
"""

from __future__ import annotations

from dataclasses import dataclass

from iamtrace.conditions import split_arn_text
from iamtrace.context import Context
from iamtrace.variables import substitute
from iamtrace.wildcard import glob_match


@dataclass(frozen=True)
class Arn:
    partition: str
    service: str
    region: str
    account: str
    resource: str

    @classmethod
    def parse(cls, text: str) -> Arn | None:
        parts = text.split(":", 5)
        if len(parts) != 6 or parts[0] != "arn":
            return None
        return cls(*parts[1:])

    def __str__(self) -> str:
        return f"arn:{self.partition}:{self.service}:{self.region}:{self.account}:{self.resource}"


def resource_matches(pattern: str, resource: str, ctx: Context, variables: bool) -> bool:
    if pattern == "*":
        return True
    if resource == "*":
        return False
    pparts = split_arn_text(pattern)
    rparts = resource.split(":", 5)
    if len(pparts) != 6 or len(rparts) != 6:
        segs = substitute(pattern, ctx, False)
        assert segs is not None
        return glob_match(segs, resource)
    for i in range(5):
        if not glob_match(pparts[i], rparts[i]):
            return False
    segs = substitute(pparts[5], ctx, variables)
    if segs is None:
        # "A resource containing a variable with no value matches no resource."
        return False
    return glob_match(segs, rparts[5])


def account_of(resource: str) -> str | None:
    arn = Arn.parse(resource)
    if arn and arn.account:
        return arn.account
    return None


def service_of_action(action: str) -> str:
    return action.split(":", 1)[0].lower()
