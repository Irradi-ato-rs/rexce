# rexce Compliance Guide (Permanent Contract)

This guide defines how to validate that Xcectua outputs comply with the **rexce ABI contract**.

## Core Principles
- **Reason codes** are immutable snake_case identifiers.
- **Repo IDs** are always `org/repo`.
- **PR URLs** are canonical GitHub pull request URLs.
- **Timestamps** follow UTC RFC 3339 (`YYYY‑MM‑DDTHH:MM:SSZ`).
- **Ordering** is deterministic:
  - reasons → alphabetical
  - repos → alphabetical
  - prs → repo_then_numeric_pr
- Observability artifacts are **not** governance inputs.

## Artifacts to Validate
- `remediated.csv` — columns: repo, pr_url, timestamp, reasons  
- `weekly_reason_rollup.csv` — columns: reason, total_count  
- `slo_report.md` — FAIL lines must use required format  
- `sla_status.csv` — optional, must match schema  
- `site/snapshot.manifest.json` & `site/snapshot.signature` — stable hashing and optional HMAC validation

## Pass/Fail Rules
1. **Schema**: All required columns/fields are present with valid patterns.
2. **Determinism**: Ordering and sorting rules must hold.
3. **Stability**: Reason codes must match ABI regex and canonical identifiers.
4. **SLA**: `status` ∈ {on_track, at_risk, overdue}.
5. **Snapshot**: If `SNAPSHOT_SIGNING_SECRET` is present in CI, signature must verify.

## How to Run
Use the GitHub Action workflow (`.github/workflows/rexce-validation.yml`)  
or run locally:

```bash
python tests/validate_contract.py

The script will exit non‑zero on violations and print a human‑readable report.