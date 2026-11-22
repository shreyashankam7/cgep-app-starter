package compliance.cmmc.dynamodb_kms_test

import rego.v1

import data.compliance.cmmc.dynamodb_kms

phi := {
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"values": {"tags_all": {"DataClass": "phi"}},
}

other := {
	"address": "aws_dynamodb_table.misc",
	"type": "aws_dynamodb_table",
	"values": {"tags_all": {"DataClass": "public"}},
}

good_cfg := {
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"expressions": {"server_side_encryption": [{
		"enabled": {"constant_value": true},
		"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
	}]},
}

# GAP-02 as shipped: no server_side_encryption block at all
no_block_cfg := {
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"expressions": {"name": {"constant_value": "intake"}},
}

# encryption enabled but no key named, which means the AWS-managed default
no_key_cfg := {
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"expressions": {"server_side_encryption": [{"enabled": {"constant_value": true}}]},
}

compliant_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": [good_cfg]}},
}

no_block_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": [no_block_cfg]}},
}

no_key_input := {
	"planned_values": {"root_module": {"resources": [phi]}},
	"configuration": {"root_module": {"resources": [no_key_cfg]}},
}

non_phi_input := {
	"planned_values": {"root_module": {"resources": [other]}},
	"configuration": {"root_module": {"resources": []}},
}

test_compliant_passes if count(dynamodb_kms.deny) == 0 with input as compliant_input

test_no_block_fails if {
	some msg in dynamodb_kms.deny with input as no_block_input
	contains(msg, "03.13.11")
	contains(msg, "aws_dynamodb_table.intake")
}

test_no_key_fails if {
	some msg in dynamodb_kms.deny with input as no_key_input
	contains(msg, "03.13.11")
}

test_non_phi_table_ignored if count(dynamodb_kms.deny) == 0 with input as non_phi_input
