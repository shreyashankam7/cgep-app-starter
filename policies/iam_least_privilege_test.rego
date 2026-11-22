package compliance.cmmc.iam_least_privilege_test

import rego.v1

import data.compliance.cmmc.iam_least_privilege as iam

doc_cfg(stmts) := {
	"address": "data.aws_iam_policy_document.lambda_data",
	"mode": "data",
	"type": "aws_iam_policy_document",
	"expressions": {"statement": stmts},
}

role_policy_cfg := {
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"expressions": {"policy": {"references": [
		"data.aws_iam_policy_document.lambda_data.json",
		"data.aws_iam_policy_document.lambda_data",
	]}},
}

stmt_of(effect, actions) := {
	"effect": {"constant_value": effect},
	"actions": {"constant_value": actions},
}

with_resources(rs) := {"configuration": {"root_module": {"resources": rs}}}

compliant_input := with_resources([
	doc_cfg([
		stmt_of("Allow", ["dynamodb:PutItem"]),
		stmt_of("Allow", ["kms:ReEncrypt*", "kms:Decrypt"]),
	]),
	role_policy_cfg,
])

# GAP-07 as shipped: service-wide wildcard
service_wildcard_input := with_resources([doc_cfg([stmt_of("Allow", ["dynamodb:*"])]), role_policy_cfg])

bare_wildcard_input := with_resources([doc_cfg([stmt_of("Allow", ["*"])]), role_policy_cfg])

# a wildcard inside a Deny statement is fine
deny_wildcard_input := with_resources([doc_cfg([stmt_of("Deny", ["s3:*"])]), role_policy_cfg])

# effect omitted means Allow
no_effect_input := with_resources([
	doc_cfg([{"actions": {"constant_value": ["s3:*"]}}]),
	role_policy_cfg,
])

# written as raw JSON, so the actions cannot be inspected
raw_json_input := with_resources([{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"expressions": {"policy": {"references": ["aws_dynamodb_table.intake.arn", "aws_dynamodb_table.intake"]}},
}])

test_compliant_passes if count(iam.deny) == 0 with input as compliant_input

test_service_wildcard_fails if {
	some msg in iam.deny with input as service_wildcard_input
	contains(msg, "03.01.05")
	contains(msg, "dynamodb:*")
}

test_bare_wildcard_fails if {
	some msg in iam.deny with input as bare_wildcard_input
	contains(msg, "03.01.05")
}

test_deny_statement_ignored if count(iam.deny) == 0 with input as deny_wildcard_input

test_missing_effect_defaults_to_allow if {
	some msg in iam.deny with input as no_effect_input
	contains(msg, "s3:*")
}

test_raw_json_policy_is_unverifiable if {
	some msg in iam.deny with input as raw_json_input
	contains(msg, "cannot be verified")
}
