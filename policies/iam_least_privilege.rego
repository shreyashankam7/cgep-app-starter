# METADATA
# title: 03.01.05 - No wildcard actions in IAM policies
# description: IAM policies must list specific actions. A bare * or a service-wide service:* is denied. IAM policies the plan cannot inspect are denied as unverifiable.
# custom:
#   framework: cmmc-l2
#   catalog: NIST SP 800-171 Rev 3
#   control_id: SP_800_171_03.01.05
#   cmmc_rev2_id: AC.L2-3.1.5
#   severity: high
#   gap: GAP-07
#   remediation: "List only the specific actions the workload uses, and build the policy with an aws_iam_policy_document data source."
package compliance.cmmc.iam_least_privilege

import rego.v1

policy_types := {"aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

wildcard_action(a) if a == "*"

wildcard_action(a) if endswith(a, ":*")

# Terraform treats a missing effect as Allow.
allows(stmt) if not stmt.effect

allows(stmt) if stmt.effect.constant_value == "Allow"

doc_backed(cfg) if {
	some ref in cfg.expressions.policy.references
	startswith(ref, "data.aws_iam_policy_document.")
}

deny contains msg if {
	some cfg in input.configuration.root_module.resources
	cfg.type == "aws_iam_policy_document"
	some stmt in cfg.expressions.statement
	allows(stmt)
	some action in stmt.actions.constant_value
	wildcard_action(action)
	msg := sprintf(
		"[SP_800_171_03.01.05 | CMMC AC.L2-3.1.5] %s: Allow statement uses wildcard action '%s'. Remediation: list only the specific actions the workload needs.",
		[cfg.address, action],
	)
}

deny contains msg if {
	some cfg in input.configuration.root_module.resources
	cfg.type in policy_types
	not doc_backed(cfg)
	msg := sprintf(
		"[SP_800_171_03.01.05 | CMMC AC.L2-3.1.5] %s: IAM policy is not built from an aws_iam_policy_document, so its actions cannot be verified at plan time. Remediation: define it with an aws_iam_policy_document data source.",
		[cfg.address],
	)
}
