# PDR‑SPEC — Release Evidence Repository (RER)

**Contract**: The governance gate MUST produce a **Policy & Decision Record (PDR)** on every run, even when failing early. PDR is the audit source of truth.

## Directory Structure (under `pdr/`)

```
pdr/
├── meta.json                  # Run meta (repo, ref, sha, run_id, actor, event, runner os)
├── rer-policy-sha256.txt      # Deterministic list of SHA256 for all `.rego` and settings file
├── evidence-dirs.txt          # Sorted list of evidence directories discovered
├── required-refs.txt          # Sorted list of required blob refs from policy settings
├── result.json                # {"ok":true} or {"ok":false,"reason":"..."}
├── summary.md                 # Human-readable summary (PASS/FAIL + reason)
├── logs/
│   ├── release.log            # conftest release namespace output
│   ├── promotion.log          # conftest promotion namespace output
│   ├── consistency.log        # conftest consistency namespace output
│   └── cosign.log             # cosign verify-blob logs for all required refs
└── inputs/
    ├── evidence-dirs.txt      # Copy of discovery output (input to checks)
    └── required-refs.txt      # Copy of policy-required refs (input to cosign)
```

## Content Requirements
- **meta.json**: Include repo/run metadata for traceability.
- **rer-policy-sha256.txt**:
  - Hash all policy `.rego` files **and** the **settings file**.
  - Input list MUST be **sorted**; output MUST preserve that order.
  - Format per line: `<sha256>␠␠<repo-relative-path>`
- **evidence-dirs.txt**: via `releases/**/release-record.yml`; collapse to parent dir; unique + sorted.
- **required-refs.txt**: parse from policy settings (`.required_refs[]`); sorted.
- **result.json / summary.md**: always present; persist early failure reason when applicable.
- **logs/**: capture complete outputs for cosign and conftest (all namespaces).

## Determinism & Enforcement
- Sort before hashing/testing; pin tool versions.
- **Fail‑closed** if no evidence found.
- Execute `cosign verify-blob` for each required ref (`blob` + `.sig` + `.bundle`).
- Run `conftest` namespaces: `release`, `promotion`, `consistency`.
- **Always upload** PDR, even on failure.

> **Location requirement**: This file must remain at the **rexce repository root** (not under `rexce/`).
