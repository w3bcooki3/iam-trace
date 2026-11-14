"""The HTML parser in scripts/check_access_levels.py, against a page shaped like the reference."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from iamtrace.catalog import Catalog

_spec = importlib.util.spec_from_file_location(
    "check_access_levels", Path(__file__).resolve().parents[2] / "scripts" / "check_access_levels.py"
)
assert _spec and _spec.loader
check = importlib.util.module_from_spec(_spec)
sys.modules["check_access_levels"] = check
_spec.loader.exec_module(check)

PAGE = """
<html><body>
<h1>Actions, resources, and condition keys for AWS Identity and Access Management (IAM)</h1>
<p>AWS Identity and Access Management (IAM) (service prefix: <code>iam</code>) provides ...</p>
<h2>Actions defined by AWS Identity and Access Management (IAM)</h2>
<table>
<tr><th>Actions</th><th>Description</th><th>Access level</th><th>Resource types (*required)</th>
<th>Condition keys</th><th>Dependent actions</th></tr>
<tr><td rowspan="2"><a id="iam-PassRole"></a>PassRole [permission only]</td><td rowspan="2">Grants permission...</td>
<td rowspan="2">Write</td><td>role*</td><td></td><td></td></tr>
<tr><td></td><td>iam:PassedToService</td><td></td></tr>
<tr><td>CreatePolicyVersion</td><td>Grants permission...</td><td>Permissions management</td>
<td>policy*</td><td></td><td></td></tr>
<tr><td>TagRole</td><td>Grants permission...</td><td>Tagging</td><td>role*</td><td></td><td></td></tr>
<tr><td>GetRole</td><td>Grants permission...</td><td>Read</td><td>role*</td><td></td><td></td></tr>
</table>
<h2>Resource types defined by IAM</h2>
<table><tr><th>Resource types</th><th>ARN</th><th>Condition keys</th></tr></table>
</body></html>
"""


def test_parse_page() -> None:
    prefix, levels = check.parse_page(PAGE)
    assert prefix == "iam"
    assert levels == {
        "PassRole": "Write",
        "CreatePolicyVersion": "Permissions management",
        "TagRole": "Tagging",
        "GetRole": "Read",
    }


def test_compare(catalog: Catalog) -> None:
    pages = {"iam": {"PassRole": "Write", "GetRole": "List", "Imaginary": "Read", "TagRole": "Tagging, Write"}}
    mismatches = check.compare(catalog, pages)
    assert ("iam:GetRole", "List", "Read") in mismatches
    assert ("iam:Imaginary", "Read", "(not in JSON)") in mismatches
    assert all(m[0] not in ("iam:PassRole", "iam:TagRole") for m in mismatches)
