package compliance.cmmc.s3_kms_test

import rego.v1

import data.compliance.cmmc.s3_kms

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

good_cfg := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"rule": [{"apply_server_side_encryption_by_default": [{
			"sse_algorithm": {"constant_value": "aws:kms"},
			"kms_master_key_id": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
		}]}],
	},
}

# aws:kms but no key named, which means the AWS-managed default key
aws_managed_cfg := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "aws:kms"}}]}],
	},
}

compliant_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": [good_cfg]}},
}

# GAP-01 re-introduced: the encryption resource is gone
no_sse_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": []}},
}

aws_managed_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": [aws_managed_cfg]}},
}

non_phi_input := {
	"planned_values": {"root_module": {"resources": [other]}},
	"configuration": {"root_module": {"resources": []}},
}

test_compliant_passes if count(s3_kms.deny) == 0 with input as compliant_input

test_missing_sse_fails if {
	some msg in s3_kms.deny with input as no_sse_input
	contains(msg, "03.13.11")
	contains(msg, "aws_s3_bucket.uploads")
}

test_aws_managed_key_fails if {
	some msg in s3_kms.deny with input as aws_managed_input
	contains(msg, "03.13.11")
}

test_non_phi_bucket_ignored if count(s3_kms.deny) == 0 with input as non_phi_input
