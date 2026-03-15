# Policy Decision Record (PDR) Specification

A **Policy Decision Record (PDR)** is an **audit‑grade artifact** produced by the
Xcectua Interface consumer governance gate
(**Validate Release Evidence (RER)**).

A PDR provides a **deterministic, immutable record** of:
- what evidence was evaluated,
- which policies and settings were used,
- which cryptographic verifications were enforced,
- and the final governance decision.

A PDR **MUST be uploaded on every gate run**, including failures.

---

## Purpose

The PDR exists to support:
- release governance audits,
- incident investigation and forensics,
- compliance and regulatory review,
- reproducible validation of past decisions.

The PDR is the **only authoritative output** of the consumer governance gate.

---

## Required Contents

A conformant PDR **MUST capture** the following information.

### 1. Consumer Context
- consumer repository identifier
- commit SHA under validation
- GitHub Actions run metadata:
  - run ID
  - run attempt
  - workflow name

### 2. Policy Authority Context
- `rexec` repository identifier
- pinned `rexec` ref (tag or SHA) as resolved from `rer/rer.lock.yml`
- policy contract paths used:
  - policies path
  - policy settings path

### 3. Policy Integrity
- SHA‑256 hashes of:
  - all evaluated `.rego` policy files
  - the policy settings file

### 4. Evidence Scope
- list of validated evidence directories
- discovery is based on the presence of:
  - `release-record.yml`

### 5. Required References
- list of required evidence references as defined by:
  - `data.policy.signature.verify_refs.required[]`
- enforcement applies to **each evidence directory**

### 6. Cryptographic Verification
- verification of each required reference using `cosign verify-blob`
- enforcement of:
  - evidence blob
  - `.sig` file
  - `.bundle` file
- verification logs captured verbatim

### 7. Policy Evaluation Inputs
- exact wrapper JSON inputs passed to conftest for:
  - `release`
  - `promotion`
  - `consistency`
- one input file per evidence directory and namespace

### 8. Policy Evaluation Logs
- conftest execution logs per namespace:
  - release
  - promotion
  - consistency
- cosign verification logs

### 9. Final Decision
- explicit pass/fail status
- human‑readable summary describing:
  - evaluated evidence
  - required references
  - final outcome

---

## Required Directory Structure

All PDR artifacts **MUST** be written under the `pdr/` directory.

```
pdr/
├── meta.json
├── rer-policy-sha256.txt
├── evidence-dirs.txt
├── required-refs.txt
├── result.json
├── summary.md
├── logs/
│   ├── release.log
│   ├── promotion.log
│   ├── consistency.log
│   └── cosign.log
└── inputs/
    └── <wrapper-input>.json
```

---

## File Semantics

- **meta.json**  
  Immutable metadata describing consumer, run, and policy authority context.

- **rer-policy-sha256.txt**  
  SHA‑256 hashes of all policy and settings files used during evaluation.

- **evidence-dirs.txt**  
  Deterministic list of evidence directories evaluated.

- **required-refs.txt**  
  Required evidence references enforced by policy.

- **inputs/**  
  Exact JSON inputs supplied to conftest for each namespace and evidence directory.

- **logs/**  
  Raw execution logs for conftest and cosign verification.

- **summary.md**  
  Human‑readable decision summary.

- **result.json**  
  Machine‑readable decision result:
  ```json
  { "status": "success" | "failure" }
  ```

---

## Failure Semantics (Fail‑Closed)

- The governance gate is **fail‑closed**.
- Any missing evidence, signature, policy input, or verification failure
  results in a **failed decision**.

---

## Early‑Failure Guarantee

The PDR directory is initialized **before any validation steps execute**.

This guarantees that:
- a PDR artifact is **always uploaded**, even when the gate fails early
  (for example: missing secrets, invalid lockfile, policy fetch failure).

In early‑failure scenarios:
- some PDR files may be absent or empty,
- but the uploaded artifact **MUST still exist** and represent the attempted run.

This behavior is intentional and audit‑preserving.

---

## Immutability Requirements

Consumers **MUST NOT**:
- modify PDR contents after generation,
- filter or redact logs,
- suppress PDR upload on failure.

The PDR is a **non‑optional, non‑negotiable artifact** of the governance circuit.

---

## Compliance Statement

A consumer repository is considered **governance‑compliant** only if:
- the PDR is generated according to this specification, and
- the PDR artifact is uploaded for **every execution** of the
  **Validate Release Evidence (RER)** workflow.

Failure to produce a PDR is a **governance failure**.
