package compliance.cmmc.s3_versioning_test

import rego.v1

import data.compliance.cmmc.s3_versioning

phi := {
	"address": "aws_s3_bucket.uploads",
	"type": "aws_s3_bucket",
	"values": {"tags_all": {"DataClass": "phi"}},
}

other := {
	"address": "aws_s3_bucket.misc",
	"type": "aws_s3_bucket",
	"values": {"tags_all": {"DataClass": "public"}},
}

cfg_with(status) := {
	"address": "aws_s3_bucket_versioning.uploads",
	"type": "aws_s3_bucket_versioning",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"versioning_configuration": [{"status": {"constant_value": status}}],
	},
}

compliant_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": [cfg_with("Enabled")]}},
}

# GAP-04 as shipped: no versioning resource
missing_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": []}},
}

suspended_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": [cfg_with("Suspended")]}},
}

non_phi_input := {
	"planned_values": {"root_module": {"resources": [other]}},
	"configuration": {"root_module": {"resources": []}},
}

test_compliant_passes if count(s3_versioning.deny) == 0 with input as compliant_input

test_missing_fails if {
	some msg in s3_versioning.deny with input as missing_input
	contains(msg, "03.08.09")
	contains(msg, "aws_s3_bucket.uploads")
}

test_suspended_fails if {
	some msg in s3_versioning.deny with input as suspended_input
	contains(msg, "03.08.09")
}

test_non_phi_bucket_ignored if count(s3_versioning.deny) == 0 with input as non_phi_input
