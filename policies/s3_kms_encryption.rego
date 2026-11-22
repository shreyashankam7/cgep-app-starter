# METADATA
# title: 03.13.11 - PHI buckets use a customer-managed KMS key
# description: S3 buckets tagged DataClass=phi must have SSE-KMS configured with an explicit KMS key.
# custom:
#   framework: cmmc-l2
#   catalog: NIST SP 800-171 Rev 3
#   control_id: SP_800_171_03.13.11
#   cmmc_rev2_id: SC.L2-3.13.11
#   severity: high
#   gap: GAP-01
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms and kms_master_key_id set to your CMK."
package compliance.cmmc.s3_kms

import rego.v1

phi_bucket contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket"
	r.values.tags_all.DataClass == "phi"
}

kms_encrypted(bucket) if {
	some cfg in input.configuration.root_module.resources
	cfg.type == "aws_s3_bucket_server_side_encryption_configuration"
	bucket.address in cfg.expressions.bucket.references
	some rule in cfg.expressions.rule
	some d in rule.apply_server_side_encryption_by_default
	d.kms_master_key_id
	d.sse_algorithm.constant_value == "aws:kms"
}

deny contains msg if {
	some bucket in phi_bucket
	not kms_encrypted(bucket)
	msg := sprintf(
		"[SP_800_171_03.13.11 | CMMC SC.L2-3.13.11] %s: PHI bucket is not encrypted with a customer-managed KMS key. Remediation: add an SSE configuration with sse_algorithm=aws:kms and kms_master_key_id.",
		[bucket.address],
	)
}
