# Xcectua Interface (Consumer Governance Contract)

The **Xcectua Interface** is the authoritative, versioned consumer governance
contract published by the `rexec` repository. All consumer repositories must
implement this interface exactly as defined.

This interface is:

- **released and versioned by `rexec`**
- **policy‑neutral**
- **copy‑exact and non‑optional**
- **enforced in CI/CD** for all consumers

This directory is the **source of truth** for all consumer governance templates.

---

## What the Interface Provides

Canonical templates for consumer repositories:

- `rer/rer.lock.yml`  
  Pins `rexec` as the policy authority at a specific tag or SHA.

- `.github/workflows/rer-governance-gate.yml`  
  Mandatory governance gate:
  - fail‑closed if no evidence  
  - enforce cosign signature verification  
  - evaluate `release`, `promotion`, and `consistency` policy namespaces  
  - upload a Policy Decision Record (PDR) on every run

- `.github/CODEOWNERS`  
  Protects the governance circuit and the lockfile.

A complete **PDR specification** is provided in:
PDR-SPEC.md

---

## What Consumers Must Not Change

Consumers may **not** modify:

- CI gate logic  
- cosign verification  
- required `.sig` and `.bundle` structure  
- PDR creation rules  
- policy namespace execution  
- lockfile structure (`rer.lock.yml`)  

All these invariants are enforced through the interface.

---

## Reference Implementation (Separate Repository)

There exists a separate repository named **Xcectua**, which:

- implements this interface exactly  
- demonstrates correct end‑to‑end use  
- produces real PDR artifacts  
- shows deterministic governance behavior

Important:

- Xcectua is **not** part of `rexec`.  
- Xcectua is **not** a source of truth.  
- Consumers must **not** copy files from the Xcectua repo.  
- Consumers copy only from this interface directory inside `rexec`.

---

## Versioning Rule

The file:
VERSION
must match the current 'rexec' release tag:
rexec tag: rexec tag: vX.Y.Z interface VERSION: X.Y.Z


This ensures deterministic synchronization across all consumers.

---

## Recommended Enforcement

Consumers should protect `main` and require the status check:
Validate Release Evidence (RER)

This ensures the governance circuit which is the xcectua-interface is active and cannot be bypassed.