# METADATA
# title: 03.08.09 - PHI buckets keep prior versions
# description: S3 buckets tagged DataClass=phi must have versioning enabled so an overwritten or deleted object is recoverable.
# custom:
#   framework: cmmc-l2
#   catalog: NIST SP 800-171 Rev 3
#   control_id: SP_800_171_03.08.09
#   cmmc_rev2_id: MP.L2-3.8.9
#   severity: medium
#   gap: GAP-04
#   mapping_note: "03.08.09 is titled System Backup - Cryptographic Protection; versioning supports its backup intent but is not a literal match."
#   remediation: "Add aws_s3_bucket_versioning for the bucket with status = Enabled."
package compliance.cmmc.s3_versioning

import rego.v1

phi_bucket contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket"
	r.values.tags_all.DataClass == "phi"
}

versioned(bucket) if {
	some cfg in input.configuration.root_module.resources
	cfg.type == "aws_s3_bucket_versioning"
	bucket.address in cfg.expressions.bucket.references
	some v in cfg.expressions.versioning_configuration
	v.status.constant_value == "Enabled"
}

deny contains msg if {
	some bucket in phi_bucket
	not versioned(bucket)
	msg := sprintf(
		"[SP_800_171_03.08.09 | CMMC MP.L2-3.8.9] %s: PHI bucket does not have versioning enabled. Remediation: add aws_s3_bucket_versioning with status=Enabled.",
		[bucket.address],
	)
}
