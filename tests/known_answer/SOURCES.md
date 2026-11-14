# Known-answer test sources

Each test in `test_aws_doc_examples.py` reproduces a worked example from the AWS IAM User Guide.
The policies are copied from the page and the expected outcome is the one the page states.

| Test | Page | Example |
|---|---|---|
| `test_basics_carlos_logs_bucket_denied` | [Policy evaluation for requests within a single account](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html) | Carlos saves a file to the `-logs` bucket: explicit deny from `DenyS3Logs` |
| `test_basics_carlos_own_bucket_allowed` | same | Carlos saves a file to his own bucket: allowed |
| `test_cross_account_logs_bucket_denied` | [Cross-account policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html) | Demo role writes to the production logs bucket: denied in the trusted account |
| `test_cross_account_production_bucket_allowed` | same | Demo role writes to the production bucket: both accounts allow |
| `test_boundary_shirley_create_user_fails` | [Permissions boundaries for IAM entities](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html) | Shirley calls `iam:CreateUser`: boundary does not allow it |
| `test_boundary_shirley_has_no_permissions` | same | "Shirley does not have permission to perform any operations in AWS" |
| `test_boundary_zhang_create_user_without_boundary_fails` | same | Zhang creates Nikhil without `XCompanyBoundaries`: denied |
| `test_boundary_zhang_create_user_with_boundary_succeeds` | same | Zhang creates Nikhil with `XCompanyBoundaries`: succeeds |
| `test_boundary_zhang_cannot_list_his_bucket` | same | Zhang lists `ZhangBucket`: boundary allows no S3 |
| `test_boundary_zhang_cannot_edit_boundary_policies` | same | `NoBoundaryPolicyEdit` statement |
| `test_boundary_nikhil_changes_own_password` | same | Nikhil changes his password |
| `test_boundary_nikhil_cannot_change_other_password` | same | Implied by `${aws:username}` in the boundary |
| `test_boundary_nikhil_cannot_create_users` | same | Nikhil cannot create users |
| `test_boundary_nikhil_cannot_edit_own_policies` | same | Nikhil cannot edit his own policies |
| `test_boundary_nikhil_reads_s3` | same | Nikhil has read-only S3 |
| `test_boundary_nikhil_logs_bucket_explicitly_denied_despite_resource_policy` | same | Resource policy on `logs` allows Nikhil, boundary denies explicitly |
| `test_boundary_nikhil_secret_via_resource_policy` | same | Secrets Manager resource policy grants Nikhil access despite the boundary |

Notes:

- Nikhil's identity policies are the AWS managed policies `IAMFullAccess` and
  `AmazonS3ReadOnlyAccess`. The tests use only the statements that matter for the examples.
- The Secrets Manager example has no JSON in the docs; the test uses the minimal policy the
  prose describes.
- The single-account evaluation page and the enforcement-code page describe rules but have no
  further worked examples. Their rules are covered in `tests/handwritten/` and `tests/unit/`.
