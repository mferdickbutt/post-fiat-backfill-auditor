# Post Fiat Backfill Auditor

Self-contained Python auditor that consumes sanitized legacy reward records, authorization snapshots, identity-resolution status, and verification state to flag historical rewards that would now be unauthorized, unresolved, unverifiable, or stale.

Zero external dependencies. Runs with the Python standard library alone.

## What It Does

Given a set of legacy reward records and their associated authorization data, the auditor classifies each reward into one of five violation classes:

| Violation Class | Meaning | Risk Tier |
|---|---|---|
| `unauthorized` | Auth snapshot explicitly denied, revoked, or entirely missing | CRITICAL |
| `unresolved_identity` | Contributor identity never resolved or contributor record missing | HIGH / MEDIUM |
| `missing_verification` | Task verification absent or explicitly unverified | HIGH |
| `stale_auth_snapshot` | Reward issued after auth snapshot expiry | MEDIUM |
| `clean` | All checks pass | LOW |

Output is a deterministic JSON report containing:

- `total_rewards_scanned`, `flagged_reward_count`, `flagged_pft_total`
- `violation_class_counts` -- breakdown by class
- `contributor_risk_rollup` -- per-contributor aggregation with max risk tier
- `remediation_queue` -- sorted by risk tier (critical first), then by PFT amount (highest first)

## Quick Start

```bash
python backfill_auditor.py
```

That's it. The file contains embedded fixtures and a built-in smoke test. No pip install, no config files, no external data.

## How It Works

1. **Build lookup maps** from contributors, auth snapshots, and verification records.
2. **Classify each reward** through a priority-ordered rule chain:
   - Missing snapshot → `unauthorized`
   - Missing contributor → `unresolved_identity`
   - Missing verification → `missing_verification`
   - Explicitly unauthorized snapshot → `unauthorized`
   - Unresolved identity → `unresolved_identity`
   - Expired snapshot at reward time → `stale_auth_snapshot`
   - Revoked snapshot at reward time → `unauthorized`
   - Unverified task → `missing_verification`
   - Otherwise → `clean`
3. **Aggregate** flagged results into contributor-level risk rollups.
4. **Sort** a remediation queue by risk severity and PFT exposure.
5. **Emit** deterministic JSON with stable SHA-256 event fingerprints.

## Using Your Own Data

Replace the `FIXTURES` dict or pass your own data structure to `run_audit()`:

```python
from backfill_auditor import run_audit

result = run_audit(my_fixtures)
```

Each fixture set needs four keys: `contributors`, `auth_snapshots`, `verification_records`, and `legacy_rewards`. See the embedded `FIXTURES` for the expected schema.

## Embedded Test Fixtures

The built-in smoke test covers:

- 4 contributors, 12 reward records
- One unauthorized cluster (bob_build, 2 rewards)
- One unresolved-identity cluster (same, identity never resolved)
- One missing-verification cluster (dave_ops, 1 reward)
- One stale-auth-snapshot case (carol_ux, rewarded after snapshot expiry)
- One clean cluster (alice_dev, 4 rewards + dave_ops clean rewards)
- Dangling reference coverage (3 rewards testing missing snapshot, missing contributor, missing verification individually)

## Running the Smoke Test

```bash
python backfill_auditor.py
```

Expected output: full JSON audit report followed by `--- SMOKE TEST PASSED ---`.

If any assertion fails, the exit code will be non-zero.
