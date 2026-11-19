"""Policy documents: parsing, validation and a normalized, immutable representation.

The grammar follows "IAM JSON policy element reference" in the IAM User Guide:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html

Normalization rules (all lossless for evaluation):
- Statement may be a single object or a list; we always store a tuple.
- Action/Resource/... may be a string or a list; we always store a tuple of strings.
- Condition values may be strings, numbers, booleans or lists; we store tuples of strings,
  with booleans written as "true"/"false" the way IAM compares them.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# Imported lazily inside parse to avoid a cycle (conditions imports PolicyError from here).


class PolicyError(ValueError):
    """Raised for a policy document AWS would reject, or that iam-trace cannot interpret."""


class PolicyType(StrEnum):
    IDENTITY = "identity"
    RESOURCE = "resource"  # resource-based policies, including role trust policies and key policies
    BOUNDARY = "boundary"
    SESSION = "session"
    SCP = "scp"
    RCP = "rcp"


# Policy types whose statements must not carry Principal and must carry Resource/NotResource.
_IDENTITY_LIKE = {PolicyType.IDENTITY, PolicyType.BOUNDARY, PolicyType.SESSION}

# The only two policy language versions AWS has published. Variables need 2012-10-17.
_VERSIONS = {"2012-10-17", "2008-10-17"}

_KNOWN_STATEMENT_KEYS = {
    "Sid",
    "Effect",
    "Principal",
    "NotPrincipal",
    "Action",
    "NotAction",
    "Resource",
    "NotResource",
    "Condition",
}

# Normalized condition block: operator -> key -> values
ConditionBlock = Mapping[str, Mapping[str, tuple[str, ...]]]


@dataclass(frozen=True)
class Statement:
    index: int  # position within the policy, 0-based; used in traces
    effect: str  # "Allow" or "Deny"
    sid: str | None = None
    actions: tuple[str, ...] | None = None
    not_actions: tuple[str, ...] | None = None
    resources: tuple[str, ...] | None = None  # None with not_resources None means "not specified"
    not_resources: tuple[str, ...] | None = None
    principal: Any = None  # raw Principal element ("*" or a mapping of lists)
    not_principal: Any = None
    condition: ConditionBlock = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.sid if self.sid else f"Statement[{self.index}]"


@dataclass(frozen=True)
class Policy:
    id: str
    type: PolicyType
    version: str | None
    statements: tuple[Statement, ...]
    warnings: tuple[str, ...] = ()

    @property
    def variables_enabled(self) -> bool:
        # "If you don't include the Version element, ... variables such as ${aws:username}
        # aren't recognized as variables and are instead treated as literal strings."
        return self.version == "2012-10-17"

    # -- constructors ---------------------------------------------------------

    @classmethod
    def from_json(cls, text: str | bytes, *, policy_id: str, policy_type: PolicyType) -> Policy:
        """Parse JSON text (see iamtrace.documents: strict JSON, any Unicode encoding, duplicate
        keys recorded as warnings, since JSON parsers silently keep the last one)."""
        from iamtrace.documents import load_json

        parsed = load_json(text, policy_id)
        policy = cls.parse(parsed.value, policy_id=policy_id, policy_type=policy_type)
        if parsed.duplicates:
            warn = tuple(f"duplicate key {k!r}: the last value is used" for k in parsed.duplicates)
            policy = Policy(policy.id, policy.type, policy.version, policy.statements, policy.warnings + warn)
        return policy

    @classmethod
    def parse(cls, doc: Any, *, policy_id: str, policy_type: PolicyType) -> Policy:
        from iamtrace.conditions import normalize_condition

        if not isinstance(doc, Mapping):
            raise PolicyError(f"{policy_id}: policy must be a JSON object")
        warnings: list[str] = []
        version = doc.get("Version")
        if version is not None and (not isinstance(version, str) or version not in _VERSIONS):
            raise PolicyError(f'{policy_id}: unknown Version {version!r} (use "2012-10-17")')
        if version is None:
            warnings.append("no Version element: policy variables are treated as literal text")
        raw = doc.get("Statement")
        if raw is None:
            raise PolicyError(f"{policy_id}: missing Statement{_case_hint(doc, 'Statement')}")
        raw_list = [raw] if isinstance(raw, Mapping) else raw
        if not isinstance(raw_list, list) or not raw_list:
            raise PolicyError(f"{policy_id}: Statement must be an object or a non-empty list")

        statements = []
        for i, s in enumerate(raw_list):
            where = f"{policy_id} Statement[{i}]"
            if not isinstance(s, Mapping):
                raise PolicyError(f"{where}: must be an object")
            unknown = set(s) - _KNOWN_STATEMENT_KEYS
            if unknown:
                fixes = [
                    f"{k!r} should be {_KNOWN_LOWER[k.lower()]!r}" for k in sorted(unknown) if k.lower() in _KNOWN_LOWER
                ]
                hint = f" (element names are case-sensitive: {', '.join(fixes)})" if fixes else ""
                raise PolicyError(f"{where}: unknown element(s) {sorted(unknown)}{hint}")
            effect = s.get("Effect")
            if effect not in ("Allow", "Deny"):
                hint = (
                    f" (the value is case-sensitive: use {str(effect).capitalize()!r})"
                    if isinstance(effect, str) and effect.lower() in ("allow", "deny")
                    else ""
                )
                raise PolicyError(f"{where}: Effect must be Allow or Deny, got {effect!r}{hint}")
            actions = _strings(s, "Action", where)
            not_actions = _strings(s, "NotAction", where)
            if (actions is None) == (not_actions is None):
                raise PolicyError(f"{where}: exactly one of Action or NotAction is required")
            resources = _strings(s, "Resource", where)
            not_resources = _strings(s, "NotResource", where)
            if resources is not None and not_resources is not None:
                raise PolicyError(f"{where}: Resource and NotResource cannot both be present")
            has_principal = "Principal" in s or "NotPrincipal" in s
            if "Principal" in s and "NotPrincipal" in s:
                raise PolicyError(f"{where}: Principal and NotPrincipal cannot both be present")
            if policy_type in _IDENTITY_LIKE:
                if has_principal:
                    raise PolicyError(f"{where}: {policy_type.value} policies cannot contain Principal")
                if resources is None and not_resources is None:
                    raise PolicyError(f"{where}: Resource or NotResource is required")
            if policy_type is PolicyType.SCP and has_principal:
                raise PolicyError(f"{where}: SCPs cannot contain Principal or NotPrincipal")
            if policy_type is PolicyType.RESOURCE and not has_principal:
                raise PolicyError(f"{where}: resource-based policies require Principal or NotPrincipal")
            if "NotPrincipal" in s:
                if effect != "Deny":
                    # "NotPrincipal must be used with "Effect":"Deny". Using it with
                    # "Effect":"Allow" is not supported."
                    raise PolicyError(f"{where}: NotPrincipal is only supported with Deny")
                if policy_type is not PolicyType.RESOURCE:
                    raise PolicyError(f"{where}: NotPrincipal is only supported in resource-based policies")
            principal = _principal(s.get("Principal"), where) if "Principal" in s else None
            not_principal = _principal(s.get("NotPrincipal"), where) if "NotPrincipal" in s else None
            cond_raw = s.get("Condition", {})
            if not isinstance(cond_raw, Mapping):
                raise PolicyError(f"{where}: Condition must be an object")
            try:
                condition = normalize_condition(cond_raw)
            except PolicyError as e:
                raise PolicyError(f"{where}: {e}") from e
            sid = s.get("Sid")
            if sid is not None and not isinstance(sid, str):
                raise PolicyError(f"{where}: Sid must be a string")
            statements.append(
                Statement(
                    index=i,
                    effect=effect,
                    sid=sid,
                    actions=actions,
                    not_actions=not_actions,
                    resources=resources,
                    not_resources=not_resources,
                    principal=principal,
                    not_principal=not_principal,
                    condition=condition,
                )
            )
        return cls(policy_id, PolicyType(policy_type), version, tuple(statements), tuple(warnings))


_KNOWN_LOWER = {k.lower(): k for k in _KNOWN_STATEMENT_KEYS}


def _case_hint(doc: Mapping[str, Any], name: str) -> str:
    for k in doc:
        if isinstance(k, str) and k.lower() == name.lower() and k != name:
            return f" (found {k!r}: element names are case-sensitive)"
    return ""


def _strings(s: Mapping[str, Any], key: str, where: str) -> tuple[str, ...] | None:
    if key not in s:
        return None
    v = s[key]
    values = (v,) if isinstance(v, str) else tuple(v) if isinstance(v, list) and v else None
    if values is None or not all(isinstance(x, str) for x in values):
        raise PolicyError(f"{where}: {key} must be a string or a non-empty list of strings")
    if any(not x.strip() for x in values):
        raise PolicyError(f"{where}: {key} has an empty value")
    return values


def _principal(v: Any, where: str) -> Any:
    """Normalize a Principal/NotPrincipal element to "*" or {type: (values,...)}."""
    if v == "*":
        return "*"
    if isinstance(v, Mapping) and v:
        out: dict[str, tuple[str, ...]] = {}
        for k, vals in v.items():
            if k not in ("AWS", "Service", "Federated", "CanonicalUser"):
                raise PolicyError(f"{where}: unknown principal type {k!r}")
            if isinstance(vals, str):
                out[k] = (vals,)
            elif isinstance(vals, list) and vals and all(isinstance(x, str) for x in vals):
                out[k] = tuple(vals)
            else:
                raise PolicyError(f"{where}: Principal {k} must be a string or list of strings")
        return out
    raise PolicyError(f'{where}: Principal must be "*" or an object')
