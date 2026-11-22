package compliance.cmmc.s3_tls_test

import rego.v1

import data.compliance.cmmc.s3_tls

phi := {
	"address": "aws_s3_bucket.uploads",
	"type": "aws_s3_bucket",
	"values": {"tags_all": {"DataClass": "phi"}},
}

policy_doc(effect, val) := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": effect,
		"Principal": "*",
		"Action": "s3:*",
		"Resource": "*",
		"Condition": {"Bool": {"aws:SecureTransport": val}},
	}],
})

policy_cfg := {
	"address": "aws_s3_bucket_policy.uploads_tls",
	"type": "aws_s3_bucket_policy",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
}

policy_planned(doc) := {
	"address": "aws_s3_bucket_policy.uploads_tls",
	"type": "aws_s3_bucket_policy",
	"values": {"policy": doc},
}

with_policy(doc) := {
	"planned_values": {"root_module": {"resources": [phi, policy_planned(doc)]}},
	"configuration": {"root_module": {"resources": [policy_cfg]}},
}

compliant_input := with_policy(policy_doc("Deny", "false"))

# GAP-03 re-introduced: the bucket policy resource is gone
no_policy_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": []}},
}

allow_input := with_policy(policy_doc("Allow", "false"))

wrong_condition_input := with_policy(policy_doc("Deny", "true"))

# fresh plan: policy text unknown, resource exists
unknown_input := {
	"planned_values": {"root_module": {"resources": [phi, {
		"address": "aws_s3_bucket_policy.uploads_tls",
		"type": "aws_s3_bucket_policy",
		"values": {},
	}]}},
	"configuration": {"root_module": {"resources": [policy_cfg]}},
}

test_compliant_passes if count(s3_tls.deny) == 0 with input as compliant_input

test_no_policy_fails if {
	some msg in s3_tls.deny with input as no_policy_input
	contains(msg, "03.13.08")
	contains(msg, "aws_s3_bucket.uploads")
}

test_allow_instead_of_deny_fails if {
	some msg in s3_tls.deny with input as allow_input
	contains(msg, "03.13.08")
}

test_wrong_condition_fails if {
	some msg in s3_tls.deny with input as wrong_condition_input
	contains(msg, "03.13.08")
}

test_unknown_policy_text_passes_on_presence if count(s3_tls.deny) == 0 with input as unknown_input
