"""iam-trace: explains what AWS IAM policies allow.

The engine is pure Python with no dependencies and makes no network calls, so it runs the same
in the CLI, in CI and in the browser (Pyodide).
"""

from iamtrace.evaluate import (
    Decision,
    MatchedStatement,
    PolicySet,
    Request,
    Result,
    TraceStep,
    evaluate,
)
from iamtrace.model import Policy, PolicyError, PolicyType, Statement
from iamtrace.principals import GrantKind, Principal

__version__ = "0.2.0"

__all__ = [
    "Decision",
    "GrantKind",
    "MatchedStatement",
    "Policy",
    "PolicyError",
    "PolicySet",
    "PolicyType",
    "Principal",
    "Request",
    "Result",
    "Statement",
    "TraceStep",
    "evaluate",
]
