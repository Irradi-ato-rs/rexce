# File: policies/release-record.rego
# Metadata Header
# Title: release-record.rego
# Owner(s): SRE, Security, Repo Owners
# Reviewed: 2026-03-13T00:00:00Z
# Purpose: Validate release record evidence including overrides and regulated rules; reads config from policy-settings.yml.
# Guardrails: Overrides must be time-boxed and approved; required fields and supply chain invariants enforced.
# Inputs: JSON payload composed by workflow (see validate-evidence.yml); Data via -d policies/policy-settings.yml
# Outputs: deny[] messages on violations.

package release

config := data["policy-settings"].policy

########################
# Generic helpers
########################

is_bool(x) { type_name(x) == "boolean" }
is_string(x) { type_name(x) == "string" }

lower_str(s) := lower(s)

trim(s) := out {
  out := regex.replace("^\\s+|\\s+$", s, "")
}

has_nonempty(v) {
  is_string(v)
  trim(v) != ""
  lower(v) != "tbd"
  not contains(lower(v), "todo")
  not contains(lower(v), "replace-me")
}

is_rfc3339(ts) {
  is_string(ts)
  regex.match("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:Z|[+-]\\d{2}:\\d{2})$", ts)
}

parse_ns(ts) := ns {
  ns := time.parse_rfc3339_ns(ts)
}

has_label(lbl) {
  some i
  input.meta.pr_labels[i] == lbl
}

has_path(obj, path) {
  count(path) == 0
} else {
  key := path[0]
  obj[key]
  has_path(obj[key], array.slice(path, 1, count(path)))
}

get_path(obj, path) = v {
  count(path) == 0
  v := obj
} else {
  key := path[0]
  v := get_path(obj[key], array.slice(path, 1, count(path)))
}

valid_evidence_ref(ref) {
  is_string(ref)
  startswith(ref, "evidence/")
  not startswith(ref, "/")
  not contains(ref, "://")
  not contains(ref, "..")
  not contains(ref, "\\")
}

is_placeholder(s) {
  is_string(s)
  some t
  t := config.evidence.placeholders.tokens[_]
  contains(lower(s), lower(t))
}

########################
# Regulated mode (derived + override guardrails)
########################

derived_regulated {
  some p
  p := config.regulated.derive_from.fields[_]
  has_path(input, split(p, "."))
  v := get_path(input, split(p, "."))
  v == true
}

override_present { is_bool(input.policy.regulated) }

downgrade_override {
  override_present
  derived_regulated
  input.policy.regulated == false
}

# Guardrails required only for downgrade
override_allowed {
  not downgrade_override
} else {
  downgrade_override

  # PR label
  has_label(config.regulated.override.label)

  # Required policy fields
  not some_missing_field
  some_missing_field {
    f := config.regulated.override.required_fields[_]
    not has_nonempty(get_path(input.policy, [f]))
  }

  # Timestamps shape + bounded expiry
  is_rfc3339(input.policy.approved_at)
  is_rfc3339(input.policy.expires_at)
  expires_within_days(config.regulated.override.max_days)

  # Approvals completed for required roles
  not some_missing_approval
  some_missing_approval {
    r := config.regulated.override.required_approvals[_]
    not approval_present(r)
  }
}

expires_within_days(days) {
  a := input.policy.approved_at
  e := input.policy.expires_at
  parse_ns(e) >= parse_ns(a)
  (parse_ns(e) - parse_ns(a)) / 1000000000 <= days * 86400
}

approval_present(role) {
  some i
  a := input.approvals.required[i]
  lower(a.role) == lower(role)
  has_nonempty(a.approver)
  is_rfc3339(a.approved_at)
}

effective_regulated {
  override_present
  override_allowed
  input.policy.regulated == true
} else {
  override_present
  override_allowed
  input.policy.regulated == false
  false
} else {
  not override_present
  derived_regulated
}

########################
# Required fields
########################

required_paths := { p | p := config.evidence.require[_] }

deny[msg] {
  p := required_paths[_]
  not has_path(input, split(p, "."))
  msg := sprintf("Missing required field: %s", [p])
}

########################
# Regulated readiness invariants
########################

deny[msg] {
  effective_regulated
  is_placeholder(input.operational_readiness.slo.dashboard_url)
  msg := "Regulated mode: slo.dashboard_url must be a real value (not placeholder)"
}

deny[msg] {
  effective_regulated
  is_placeholder(input.operational_readiness.runbook_url)
  msg := "Regulated mode: runbook_url must be a real value (not placeholder)"
}

deny[msg] {
  effective_regulated
  count(input.operational_readiness.rollback.triggers) < config.regulated.operational_readiness.rollback_min_triggers
  msg := sprintf("Regulated mode: rollback.triggers must contain at least %d triggers", [config.regulated.operational_readiness.rollback_min_triggers])
}

########################
# Compliance invariants (PCI => risk_class = high)
########################

deny[msg] {
  input.release.compliance_scope.pci == true
  required := config.compliance.pci.require_risk_class
  input.release.risk_class != required
  msg := sprintf("PCI-scoped releases must have risk_class = %s", [required])
}

########################
# Supply chain invariants
########################

deny[msg] {
  not is_string(input.artifacts.container_image.digest)
  msg := "container_image.digest must be present"
}

deny[msg] {
  is_string(input.artifacts.container_image.digest)
  not some { prefix := config.evidence.supply_chain.container_digest_prefixes[_]; startswith(input.artifacts.container_image.digest, prefix) }
  msg := sprintf("container_image.digest must start with one of: %v", [config.evidence.supply_chain.container_digest_prefixes])
}

########################
# SBOM invariants
########################

deny[msg] {
  not is_string(input.artifacts.sbom.type)
  msg := "SBOM type must be present and a string"
}

deny[msg] {
  input.artifacts.sbom.type != config.evidence.sbom.type
  msg := sprintf("SBOM type must be exactly %s (got: %v)", [config.evidence.sbom.type, input.artifacts.sbom.type])
}

deny[msg] {
  ref := input.artifacts.sbom.ref
  not valid_evidence_ref(ref)
  msg := sprintf("SBOM ref must be a safe relative path under evidence/ (got: %s)", [ref])
}

deny[msg] {
  ref := input.artifacts.sbom.ref
  ref != config.evidence.sbom.exact_ref
  msg := sprintf("SBOM ref must be exactly %s (got: %s)", [config.evidence.sbom.exact_ref, ref])
}

########################
# Provenance invariants
########################

deny[msg] {
  ref := input.artifacts.provenance.ref
  not valid_evidence_ref(ref)
  msg := sprintf("Provenance ref must be a safe relative path under evidence/ (got: %s)", [ref])
}

deny[msg] {
  ref := input.artifacts.provenance.ref
  not allowed_provenance_ref(ref)
  msg := sprintf("Provenance ref must be one of %v (got: %s)", [config.evidence.provenance.allowed_refs], [ref])
}

allowed_provenance_ref(ref) {
  some i
  config.evidence.provenance.allowed_refs[i] == ref
}

########################
# Inventory binding (optional but recommended)
########################

has_inventory {
  input.inventory.files
  type_name(input.inventory.files) == "array"
}

inventory_has(path) {
  some i
  input.inventory.files[i] == path
}

deny[msg] {
  config.evidence.inventory.require_sig_bundle == true
  has_inventory
  ref := input.artifacts.sbom.ref
  not inventory_has(ref)
  msg := sprintf("SBOM ref points to missing file in evidence bundle: %s", [ref])
}

deny[msg] {
  config.evidence.inventory.require_sig_bundle == true
  has_inventory
  ref := input.artifacts.sbom.ref
  not inventory_has(sprintf("%s.sig", [ref]))
  msg := sprintf("Missing SBOM signature file: %s.sig", [ref])
}

deny[msg] {
  config.evidence.inventory.require_sig_bundle == true
  has_inventory
  ref := input.artifacts.sbom.ref
  not inventory_has(sprintf("%s.bundle", [ref]))
  msg := sprintf("Missing SBOM bundle file: %s.bundle", [ref])
}

deny[msg] {
  config.evidence.inventory.require_sig_bundle == true
  has_inventory
  ref := input.artifacts.provenance.ref
  not inventory_has(ref)
  msg := sprintf("Provenance ref points to missing file in evidence bundle: %s", [ref])
}

deny[msg] {
  config.evidence.inventory.require_sig_bundle == true
  has_inventory
  ref := input.artifacts.provenance.ref
  not inventory_has(sprintf("%s.sig", [ref]))
  msg := sprintf("Missing provenance signature file: %s.sig", [ref])
}

deny[msg] {
  config.evidence.inventory.require_sig_bundle == true
  has_inventory
  ref := input.artifacts.provenance.ref
  not inventory_has(sprintf("%s.bundle", [ref]))
  msg := sprintf("Missing provenance bundle file: %s.bundle", [ref])
}

########################
# Explicit downgrade guardrail denials (clear reasons)
########################

deny[msg] {
  downgrade_override
  not has_label(config.regulated.override.label)
  msg := sprintf("Downgrade override requires PR label: %s", [config.regulated.override.label])
}

deny[msg] {
  downgrade_override
  some f
  f := config.regulated.override.required_fields[_]
  not has_nonempty(get_path(input.policy, [f]))
  msg := sprintf("Downgrade override requires non-empty policy.%s", [f])
}

deny[msg] {
  downgrade_override
  not (is_rfc3339(input.policy.approved_at) and is_rfc3339(input.policy.expires_at))
  msg := "Downgrade override requires policy.approved_at and policy.expires_at (RFC3339)"
}

deny[msg] {
  downgrade_override
  not expires_within_days(config.regulated.override.max_days)
  msg := sprintf("Downgrade override requires policy.expires_at within %d days of approved_at", [config.regulated.override.max_days])
}

deny[msg] {
  downgrade_override
  not approval_present("security")
  msg := "Downgrade override requires completed Security approval in approvals.required"
}

deny[msg] {
  downgrade_override
  not approval_present("sre")
  msg := "Downgrade override requires completed SRE approval in approvals.required"
}
