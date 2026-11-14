"""Who is making the request, and how a resource-based policy's Principal element matches them.

The grant kinds come from "Resource-based policies" in the enforcement-logic page:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html

- DIRECT:  the policy names the exact caller (IAM user ARN, role session ARN, federated user ARN,
           a service, or "*"). Within one account this grant is final: an implicit deny in an
           identity policy, boundary or session policy does not limit it.
- ROLE:    the policy names the role ARN of a role session, or the IAM user who created a
           federated session. Limited by an implicit deny in a boundary or session policy, but
           needs no identity-policy allow.
- ACCOUNT: the policy names the caller's account. Within that account this delegates to IAM:
           the identity policy must allow. Across accounts it satisfies the resource side.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_ACCOUNT_ID = re.compile(r"^\d{12}$")


class GrantKind(StrEnum):
    DIRECT = "direct"
    ROLE = "role"
    ACCOUNT = "account"


@dataclass(frozen=True)
class Principal:
    kind: str  # user | role_session | federated_user | root | service | web_identity | anonymous
    arn: str | None
    account: str | None
    role_arn: str | None = None  # role sessions: the role's ARN (with path, if known)
    federating_user_arn: str | None = None  # federated users: the IAM user that called GetFederationToken
    service_name: str | None = None
    federated_provider: str | None = None  # web identity / SAML provider for Federated principals

    # -- constructors ---------------------------------------------------------

    @classmethod
    def from_arn(cls, arn: str, *, role_arn: str | None = None, federating_user_arn: str | None = None) -> Principal:
        parts = arn.split(":", 5)
        if len(parts) != 6 or parts[0] != "arn":
            raise ValueError(f"not an ARN: {arn!r}")
        _, partition, service, _, account, res = parts
        if service == "iam" and res == "root":
            return cls("root", arn, account)
        if service == "iam" and res.startswith("user/"):
            return cls("user", arn, account)
        if service == "iam" and res.startswith("role/"):
            # A role cannot make requests; its sessions do. Model a session of this role.
            name = res.rsplit("/", 1)[1]
            session = f"arn:{partition}:sts::{account}:assumed-role/{name}/session"
            return cls("role_session", session, account, role_arn=arn)
        if service == "sts" and res.startswith("assumed-role/"):
            pieces = res.split("/")
            if len(pieces) < 3:
                raise ValueError(f"malformed assumed-role ARN: {arn!r}")
            derived = f"arn:{partition}:iam::{account}:role/{pieces[1]}"
            return cls("role_session", arn, account, role_arn=role_arn or derived)
        if service == "sts" and res.startswith("federated-user/"):
            return cls("federated_user", arn, account, federating_user_arn=federating_user_arn)
        raise ValueError(f"unsupported principal ARN: {arn!r}")

    @classmethod
    def service(cls, name: str) -> Principal:
        """An AWS service principal such as "lambda.amazonaws.com"."""
        return cls("service", None, None, service_name=name)

    @classmethod
    def web_identity(cls, provider: str) -> Principal:
        return cls("web_identity", None, None, federated_provider=provider)

    @classmethod
    def anonymous(cls) -> Principal:
        return cls("anonymous", None, None)

    # -- properties -----------------------------------------------------------

    @property
    def is_session(self) -> bool:
        return self.kind in ("role_session", "federated_user")

    @property
    def is_service_linked_role(self) -> bool:
        return bool(self.role_arn and ":role/aws-service-role/" in self.role_arn)

    @property
    def has_identity_policies(self) -> bool:
        return self.kind in ("user", "role_session", "federated_user")

    @property
    def principal_arn(self) -> str | None:
        """Value of aws:PrincipalArn: the role ARN for role sessions, otherwise the caller ARN."""
        return self.role_arn if self.kind == "role_session" else self.arn

    @property
    def principal_type(self) -> str | None:
        return {
            "user": "User",
            "role_session": "AssumedRole",
            "federated_user": "FederatedUser",
            "root": "Account",
            "anonymous": "Anonymous",
        }.get(self.kind)

    @property
    def username(self) -> str | None:
        if self.kind == "user" and self.arn:
            return self.arn.rsplit("/", 1)[1]
        return None

    def describe(self) -> str:
        return self.arn or self.service_name or self.federated_provider or self.kind


def _account_principal_matches(value: str, account: str | None) -> bool:
    if account is None:
        return False
    return value == account or value.endswith(f":iam::{account}:root")


def match_principal_element(element: Any, caller: Principal) -> GrantKind | None:
    """Return the strongest grant kind the element gives the caller, or None if it doesn't match."""
    if element == "*":
        return GrantKind.DIRECT
    best: GrantKind | None = None
    order = {GrantKind.DIRECT: 3, GrantKind.ROLE: 2, GrantKind.ACCOUNT: 1}

    def consider(kind: GrantKind) -> None:
        nonlocal best
        if best is None or order[kind] > order[best]:
            best = kind

    for ptype, values in element.items():
        for v in _as_tuple(values):
            if ptype == "AWS":
                if v == "*":
                    consider(GrantKind.DIRECT)
                elif caller.kind in ("service", "web_identity", "anonymous"):
                    continue
                elif caller.arn and v == caller.arn:
                    consider(GrantKind.DIRECT)
                elif (
                    caller.kind == "role_session"
                    and v == caller.role_arn
                    or caller.kind == "federated_user"
                    and v == caller.federating_user_arn
                ):
                    consider(GrantKind.ROLE)
                elif _account_principal_matches(v, caller.account):
                    consider(GrantKind.DIRECT if caller.kind == "root" else GrantKind.ACCOUNT)
            elif ptype == "Service" and caller.kind == "service":
                if v.lower() == (caller.service_name or "").lower():
                    consider(GrantKind.DIRECT)
            elif ptype == "Federated" and caller.kind == "web_identity":
                if v == caller.federated_provider:
                    consider(GrantKind.DIRECT)
    return best


def not_principal_excludes(element: Any, caller: Principal, *, has_boundary: bool) -> bool:
    """True when a NotPrincipal element lists the caller, so the Deny does not apply to them.

    From the NotPrincipal docs:
    - "you must also specify the account ARN of the not-denied principal. Otherwise, the policy
      might deny access to the entire account containing the principal." iam-trace therefore
      excludes a caller only when both the account and the caller itself are listed.
    - For a role session, listing the role ARN (with the account) is enough; listing the
      session ARN also works.
    - "The NotPrincipal element with a Deny effect will always deny any IAM principal that has a
      permissions boundary policy attached."
    """
    if has_boundary:
        return False
    if element == "*":
        return True
    aws = _as_tuple(element.get("AWS", ()))
    if caller.kind == "service":
        services = _as_tuple(element.get("Service", ()))
        return any(v.lower() == (caller.service_name or "").lower() for v in services)
    if caller.kind == "anonymous":
        return False
    account_listed = any(_account_principal_matches(v, caller.account) for v in aws)
    if caller.kind == "root":
        return account_listed
    identities = {caller.arn}
    if caller.kind == "role_session" and caller.role_arn:
        identities.add(caller.role_arn)
    return account_listed and any(v in identities for v in aws)


def _as_tuple(values: Any) -> tuple[str, ...]:
    """Accept both normalized (tuple) and raw JSON (string or list) principal values."""
    if isinstance(values, str):
        return (values,)
    return tuple(values)


def is_account_id(value: str) -> bool:
    return bool(_ACCOUNT_ID.match(value))
