"""Gates: the request context a permission needs, and whether an attacker can supply it.

The escalation analysis asks thousands of questions of the form "can principal P call action A
on resource R?". AWS answers them with a request context the analysis does not have: whether the
caller used MFA, its source IP or VPC endpoint, the region it called, the tags it sent. Evaluating
with an empty context, as a plain `can` does, is a specific assumption (no MFA, no network
location, no tags) and it is wrong in both directions: a permission that needs a region or a
request tag looks impossible although the attacker simply sends one.

So when a check fails, `find_gates` looks at the condition keys of the policies involved and tries
the values those conditions name (made concrete, as what-if does):

- Keys the attacker chooses freely: the region, the transport, request tags and tag keys, the
  user agent, the session name, source identity and ExternalId. A check that passes with only
  these is *open*: anyone holding the credentials can do it.
- Keys the attacker has to *have*: MFA (aws:MultiFactorAuthPresent/Age), a network location
  (aws:SourceIp, aws:SourceVpc, aws:SourceVpce, aws:VpcSourceIp), or a time window
  (aws:CurrentTime, aws:EpochTime). A check that needs these is *gated*, and the gate says which.

Everything else (the principal's own ARN, tags fixed by the account, keys we know nothing about)
is not searched: such a check stays denied, as before.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterable
from itertools import combinations, product
from typing import Any

from iamtrace.model import Policy
from iamtrace.whatif import _candidates

ATTACKER = "attacker"
MFA = "mfa"
NETWORK = "network"
TIME = "time"
GATED_KINDS = (MFA, NETWORK, TIME)

_EXACT: dict[str, str] = {
    "aws:requestedregion": ATTACKER,
    "aws:securetransport": ATTACKER,
    "aws:useragent": ATTACKER,
    "aws:referer": ATTACKER,
    "aws:tagkeys": ATTACKER,
    "sts:rolesessionname": ATTACKER,
    "sts:sourceidentity": ATTACKER,
    "aws:sourceidentity": ATTACKER,
    "sts:externalid": ATTACKER,
    "aws:multifactorauthpresent": MFA,
    "aws:multifactorauthage": MFA,
    "aws:sourceip": NETWORK,
    "aws:sourcevpc": NETWORK,
    "aws:sourcevpce": NETWORK,
    "aws:vpcsourceip": NETWORK,
    "aws:currenttime": TIME,
    "aws:epochtime": TIME,
}

LABELS = {MFA: "MFA", NETWORK: "a network location", TIME: "a time window"}

Gate = tuple[str, str, str]  # (kind, condition key, value that satisfies it)


def kind_of(key: str) -> str | None:
    k = key.lower()
    if k in _EXACT:
        return _EXACT[k]
    if k.startswith("aws:requesttag/"):
        return ATTACKER
    return None


def _date_candidates(op: str, values: Iterable[str]) -> list[str]:
    base = op.split(":")[-1].removesuffix("IfExists").lower()
    out = []
    for v in values:
        try:
            when = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            continue
        if "less" in base:
            when -= dt.timedelta(days=1)
        elif "greater" in base:
            when += dt.timedelta(days=1)
        out.append(when.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return out


def condition_values(policies: Iterable[Policy]) -> dict[str, tuple[str, list[str]]]:
    """For every searchable condition key in the policies: (kind, values worth trying)."""
    found: dict[str, tuple[str, list[str]]] = {}
    for pol in policies:
        for st in pol.statements:
            for op, block in (st.condition or {}).items():
                for key, raw in block.items():
                    kind = kind_of(key)
                    if kind is None:
                        continue
                    values = tuple(str(v) for v in (raw if isinstance(raw, list | tuple) else [raw]))
                    cands = _date_candidates(op, values) if "date" in op.lower() else _candidates(op, values, None)
                    entry = found.setdefault(key, (kind, []))
                    for c in cands:
                        if c is not None and c not in entry[1]:
                            entry[1].append(c)
    return {k: v for k, v in found.items() if v[1]}


def find_gates(
    allowed: Callable[[dict[str, Any]], bool],
    context: dict[str, Any],
    policies: Iterable[Policy],
    *,
    budget: int = 256,
) -> frozenset[Gate] | None:
    """The fewest gated context values that make `allowed` true, with attacker-chosen keys set
    however helps. frozenset() means open (attacker-chosen values alone suffice); None means no
    tried context allows it."""
    cands = condition_values(policies)
    if not cands:
        return None
    attacker = [k for k, (kind, _) in cands.items() if kind == ATTACKER and k not in context]
    gated = [k for k, (kind, _) in cands.items() if kind in GATED_KINDS and k not in context]
    if not attacker and not gated:
        return None
    # Attacker keys may also be left out: some conditions only apply when a key is present.
    a_options = [[None, *cands[k][1]] for k in attacker]
    tries = 0
    for size in range(0, min(2, len(gated)) + 1):
        for keys in combinations(gated, size):
            for values in product(*(cands[k][1] for k in keys)):
                for a_values in product(*a_options):
                    tries += 1
                    if tries > budget:
                        return None
                    ctx = dict(context)
                    ctx.update({k: v for k, v in zip(attacker, a_values, strict=True) if v is not None})
                    ctx.update(dict(zip(keys, values, strict=True)))
                    if size == 0 and not any(v is not None for v in a_values):
                        continue  # the plain context: already known to be denied
                    if allowed(ctx):
                        return frozenset((cands[k][0], k, v) for k, v in zip(keys, values, strict=True))
    return None


def describe(gates: Iterable[Gate]) -> list[dict[str, str]]:
    """Gates as JSON-ready entries, with a phrase for people."""
    out = []
    for kind, key, value in sorted(set(gates)):
        if kind == MFA:
            text = "the caller signed in with MFA"
        elif kind == NETWORK:
            text = f"the request comes from {key.split(':', 1)[-1]} {value}"
        else:
            text = f"the request is made at {value}"
        out.append({"kind": kind, "key": key, "value": value, "text": text})
    return out


def summary(gates: Iterable[Gate]) -> str:
    kinds = sorted({g[0] for g in gates})
    return "open" if not kinds else "needs " + " and ".join(LABELS[k] for k in kinds)
