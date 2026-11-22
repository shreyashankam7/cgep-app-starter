# METADATA
# title: 03.13.11 - PHI tables use a customer-managed KMS key
# description: DynamoDB tables tagged DataClass=phi must enable server-side encryption with an explicit KMS key, not the AWS-owned default.
# custom:
#   framework: cmmc-l2
#   catalog: NIST SP 800-171 Rev 3
#   control_id: SP_800_171_03.13.11
#   cmmc_rev2_id: SC.L2-3.13.11
#   severity: high
#   gap: GAP-02
#   remediation: "Add a server_side_encryption block with enabled = true and kms_key_arn set to your CMK."
package compliance.cmmc.dynamodb_kms

import rego.v1

phi_table contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_dynamodb_table"
	r.values.tags_all.DataClass == "phi"
}

cmk_encrypted(table) if {
	some cfg in input.configuration.root_module.resources
	cfg.address == table.address
	some sse in cfg.expressions.server_side_encryption
	sse.enabled.constant_value == true
	sse.kms_key_arn
}

deny contains msg if {
	some table in phi_table
	not cmk_encrypted(table)
	msg := sprintf(
		"[SP_800_171_03.13.11 | CMMC SC.L2-3.13.11] %s: PHI table is not encrypted with a customer-managed KMS key. Remediation: add server_side_encryption with enabled=true and kms_key_arn.",
		[table.address],
	)
}
