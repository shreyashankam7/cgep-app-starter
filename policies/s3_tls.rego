# METADATA
# title: 03.13.08 - PHI buckets refuse non-TLS requests
# description: S3 buckets tagged DataClass=phi must have a bucket policy that denies requests made without TLS (aws:SecureTransport = false).
# custom:
#   framework: cmmc-l2
#   catalog: NIST SP 800-171 Rev 3
#   control_id: SP_800_171_03.13.08
#   cmmc_rev2_id: SC.L2-3.13.8
#   severity: high
#   gap: GAP-03
#   limitation: "If the policy text is unknown at plan time, only the presence of a bucket policy resource is enforced."
#   remediation: "Add aws_s3_bucket_policy with a Deny statement conditioned on aws:SecureTransport = false."
package compliance.cmmc.s3_tls

import rego.v1

phi_bucket contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket"
	r.values.tags_all.DataClass == "phi"
}

policy_resources(bucket) := {cfg |
	some cfg in input.configuration.root_module.resources
	cfg.type == "aws_s3_bucket_policy"
	bucket.address in cfg.expressions.bucket.references
}

planned_policy(address) := p if {
	some r in input.planned_values.root_module.resources
	r.address == address
	p := r.values.policy
}

denies_insecure(doc) if {
	some stmt in doc.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

policy_content_ok(cfg) if not planned_policy(cfg.address)

policy_content_ok(cfg) if {
	doc := json.unmarshal(planned_policy(cfg.address))
	denies_insecure(doc)
}

tls_enforced(bucket) if {
	some cfg in policy_resources(bucket)
	policy_content_ok(cfg)
}

deny contains msg if {
	some bucket in phi_bucket
	not tls_enforced(bucket)
	msg := sprintf(
		"[SP_800_171_03.13.08 | CMMC SC.L2-3.13.8] %s: PHI bucket has no policy denying non-TLS requests (aws:SecureTransport=false). Remediation: add aws_s3_bucket_policy with a Deny on aws:SecureTransport=false.",
		[bucket.address],
	)
}
