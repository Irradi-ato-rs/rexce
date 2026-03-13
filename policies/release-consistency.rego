# File: policies/release-consistency.rego
# Metadata Header
# Title: release-consistency.rego
# Owner(s): SRE, Security, Repo Owners
# Reviewed: 2026-03-13T00:00:00Z
# Purpose: Cross-file ID, directory binding, timing/causality; canary enforcement for regulated mode.
# Guardrails: Postdeploy requires promotion; signoff.signed_at >= window_end; created_at path binding.
# Inputs: Composite input (release_record + promotion_log + postdeploy + meta); Data via -d policies/policy-settings.yml
# Outputs: deny[] messages on violations.

package consistency

config := data["policy-settings"].policy

########################
# Helpers
########################

is_string(x) { type_name(x) == "string" }

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

has_nonempty(v) {
  is_string(v)
  trim(v) != ""
  lower(v) != "tbd"
  not contains(lower(v), "todo")
  not contains(lower(v), "replace-me")
}

trim(s) := out {
  out := regex.replace("^\\s+|\\s+$", s, "")
}

########################
# Effective regulated (recomputed here using release_record + config)
########################

derived_regulated {
  rr := input.release_record
  some p
  p := config.regulated.derive_from.fields[_]
  v := walk_path(rr, split(p, "."))
  v == true
}

walk_path(obj, path) = v {
  count(path) == 0
  v := obj
} else {
  key := path[0]
  v := walk_path(obj[key], array.slice(path, 1, count(path)))
}

override_present {
  is_string(input.release_record.policy.regulated) == false
  # Present iff boolean; fallback protects from null
  type_name(input.release_record.policy.regulated) == "boolean"
}

downgrade_override {
  override_present
  derived_regulated
  input.release_record.policy.regulated == false
}

approval_present(role) {
  rr := input.release_record
  some i
  a := rr.approvals.required[i]
  lower(a.role) == lower(role)
  has_nonempty(a.approver)
  is_rfc3339(a.approved_at)
}

expires_within_days(days) {
  rr := input.release_record
  parse_ns(rr.policy.expires_at) >= parse_ns(rr.policy.approved_at)
  (parse_ns(rr.policy.expires_at) - parse_ns(rr.policy.approved_at)) / 1000000000 <= days * 86400
}

override_allowed {
  not downgrade_override
} else {
  downgrade_override
  has_label(config.regulated.override.label)
  not some_missing_field
  some_missing_field {
    f := config.regulated.override.required_fields[_]
    not has_nonempty(walk_path(input.release_record.policy, [f]))
  }
  is_rfc3339(input.release_record.policy.approved_at)
  is_rfc3339(input.release_record.policy.expires_at)
  expires_within_days(config.regulated.override.max_days)
  not some_missing_approval
  some_missing_approval {
    r := config.regulated.override.required_approvals[_]
    not approval_present(r)
  }
}

effective_regulated {
  override_present
  override_allowed
  input.release_record.policy.regulated == true
} else {
  override_present
  override_allowed
  input.release_record.policy.regulated == false
  false
} else {
  not override_present
  derived_regulated
}

########################
# Require release_record in composite input
########################

deny[msg] {
  input.release_record == null
  msg := "Missing release_record in consistency validation input"
}

########################
# Directory binding rules
########################

deny[msg] {
  input.meta.release_dir_name != input.release_record.release.id
  msg := sprintf("Directory name must equal release.id (dir=%s id=%s)",
    [input.meta.release_dir_name, input.release_record.release.id])
}

# releases/YYYY/MM/<release.id>
deny[msg] {
  config.validator.created_at_path_binding == true
  not created_at_has_ym_format
  msg := sprintf("release.created_at must be ISO-like 'YYYY-MM-...' (got: %v)", [input.release_record.release.created_at])
}

deny[msg] {
  config.validator.created_at_path_binding == true
  created_at_has_ym_format
  expected := sprintf("releases/%s/%s/%s", [created_at_year, created_at_month, input.release_record.release.id])
  input.meta.release_dir_path != expected
  msg := sprintf("Directory path must equal %s (got: %s)", [expected, input.meta.release_dir_path])
}

created_at_has_ym_format {
  subs := regex.find_all_string_submatch("^(\\d{4})-(\\d{2})-", input.release_record.release.created_at)
  count(subs) > 0
}

created_at_year := y {
  subs := regex.find_all_string_submatch("^(\\d{4})-(\\d{2})-", input.release_record.release.created_at)
  y := subs[0][1]
}

created_at_month := m {
  subs := regex.find_all_string_submatch("^(\\d{4})-(\\d{2})-", input.release_record.release.created_at)
  m := subs[0][2]
}

########################
# Cross-file IDs and process order
########################

deny[msg] {
  input.promotion_log != null
  input.promotion_log.promotion.release_id != input.release_record.release.id
  msg := "promotion.release_id must equal release.id"
}

deny[msg] {
  input.postdeploy != null
  input.postdeploy.postdeploy.release_id != input.release_record.release.id
  msg := "postdeploy.release_id must equal release.id"
}

deny[msg] {
  input.postdeploy != null
  input.promotion_log == null
  msg := "postdeploy-verification cannot exist without promotion-log"
}

########################
# Regulated canary strategy
########################

deny[msg] {
  effective_regulated
  config.regulated.require_canary == true
  input.promotion_log != null
  input.promotion_log.promotion.strategy != "canary"
  msg := "Regulated mode: promotion.strategy must be canary"
}

########################
# Postdeploy timing
########################

postdeploy_finalized {
  input.postdeploy != null
  input.postdeploy.postdeploy.result != "TBD"
}

deny[msg] {
  postdeploy_finalized
  pd := input.postdeploy.postdeploy
  not (is_string(pd.window_end) and pd.window_end != "TBD" and is_rfc3339(pd.window_end))
  msg := "Finalized postdeploy requires window_end (RFC3339, not TBD)"
}

deny[msg] {
  postdeploy_finalized
  so := input.postdeploy.postdeploy.signoff
  not (is_string(so.signed_at) and so.signed_at != "TBD" and is_rfc3339(so.signed_at))
  msg := "Finalized postdeploy requires signoff.signed_at (RFC3339, not TBD)"
}

deny[msg] {
  postdeploy_finalized
  pd := input.postdeploy.postdeploy
  so := pd.signoff
  parse_ns(so.signed_at) < parse_ns(pd.window_end)
  msg := "signoff.signed_at must be >= postdeploy.window_end"
}
