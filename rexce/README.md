# Release Evidence‑Validation Repository (RER) — `rexec`

`rexec` is the authoritative **Release Evidence‑Validation Repository (RER)**.
It owns and publishes the policies, settings, tests, and the official
**Xcectua Interface** that all consumer repositories must implement.

`rexec` is strictly **policy-only**:

- Stores OPA/Conftest policies and settings  
- Stores validation tests and fixtures  
- Publishes the Xcectua Interface (consumer governance contract)  
- Runs maintenance‑only workflows (policy testing, release verification)

`rexec` does **not**:

- Store release evidence  
- Validate consumer evidence  
- Run consumer CI/CD pipelines  

Those responsibilities belong entirely to consumer repositories.

---

## Policy Ownership

`rexec` owns and publishes:

- `policies/*.rego`  
- `policies/policy-settings.yml`  
- policy fixtures under `policies/tests/**`  
- documentation under `docs/**`

These define the RER policy suite.

Consumers must always:

- fetch `rexec` at a **pinned tag or commit SHA**
- run conftest using:  
  `-p <checked_out_rexec>/policies`  
  `-d <checked_out_rexec>/policies/policy-settings.yml`

---

## Xcectua Interface (Consumer Governance Contract)

The **Xcectua Interface** is published inside:
rexce/xcectua-interface/

This interface defines:

- the mandatory governance circuit  
- the PDR (Policy Decision Record) specification  
- copy‑exact CI workflow templates  
- `rer.lock.yml` structure and pinning rules  
- `VERSION` (which must match `rexec`’s release tag without the `v`)

All consumer repositories must copy governance files only from the
**Xcectua Interface**. This directory is the **sole source of truth** for
consumer governance templates.

---

## Reference Implementation (Separate Repository)

There is a separate GitHub repository named **Xcectua**.

This is:

- a working, auditable reference implementation of the interface  
- a concrete demonstration of the governance circuit  
- a real CI pipeline showing end‑to‑end enforcement  

It is **not**:

- part of `rexec`  
- a dependency  
- a template source  

Consumers must **not** copy governance files from the Xcectua repo.
They must copy from the **Xcectua Interface published inside `rexec`**.

---

## Maintenance Workflows

`rexec` provides workflows for:

- policy testing  
- documentation validation  
- interface release verification  

These workflows run **only** on changes to:  
`policies/**`, `policies/tests/**`, `.github/**`, `docs/**`, `README.md`.

`rexec` never validates consumer evidence.  
Only consumers run evidence validation via the Xcectua Interface.

---

## Release Tags

`rexec` uses SemVer tags: `vX.Y.Z`.

The release workflow ensures:

- policy tests pass  
- interface templates are present and valid  
- `rexce/xcectua-interface/VERSION` matches the tag (minus `v`)  

This guarantees deterministic, authoritative interface releases.