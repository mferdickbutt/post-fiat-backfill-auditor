#!/usr/bin/env python3
"""
Legacy Authorization Exposure Backfill Auditor
Self-contained: no external files or dependencies beyond the Python standard library.
Run with: python backfill_auditor.py
"""

import json
import hashlib
from datetime import datetime, timezone
from enum import Enum


class ViolationClass(Enum):
    UNAUTHORIZED = "unauthorized"
    UNRESOLVED_IDENTITY = "unresolved_identity"
    MISSING_VERIFICATION = "missing_verification"
    STALE_AUTH_SNAPSHOT = "stale_auth_snapshot"
    CLEAN = "clean"


class RiskTier(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


FIXTURES = {
    "contributors": [
        {
            "contributor_id": "ctr_a1b2c3",
            "handle": "alice_dev",
            "wallet": "0xAlice11111111111111111111111111111111111111",
            "identity_resolved": True,
            "identity_resolved_at": "2025-08-15T10:00:00Z",
            "governance_role": "maintainer",
        },
        {
            "contributor_id": "ctr_d4e5f6",
            "handle": "bob_build",
            "wallet": "0xBob22222222222222222222222222222222222222",
            "identity_resolved": False,
            "identity_resolved_at": None,
            "governance_role": "contributor",
        },
        {
            "contributor_id": "ctr_g7h8i9",
            "handle": "carol_ux",
            "wallet": "0xCarol33333333333333333333333333333333333333",
            "identity_resolved": True,
            "identity_resolved_at": "2025-09-01T14:30:00Z",
            "governance_role": "contributor",
        },
        {
            "contributor_id": "ctr_j0k1l2",
            "handle": "dave_ops",
            "wallet": "0xDave44444444444444444444444444444444444444",
            "identity_resolved": True,
            "identity_resolved_at": "2025-10-20T08:00:00Z",
            "governance_role": "reviewer",
        },
    ],
    "auth_snapshots": [
        {
            "snapshot_id": "snap_001",
            "contributor_id": "ctr_a1b2c3",
            "authorized": True,
            "auth_scope": "reward_disbursement",
            "granted_at": "2025-07-01T00:00:00Z",
            "expires_at": "2026-01-01T00:00:00Z",
            "revoked_at": None,
        },
        {
            "snapshot_id": "snap_002",
            "contributor_id": "ctr_d4e5f6",
            "authorized": False,
            "auth_scope": "reward_disbursement",
            "granted_at": None,
            "expires_at": None,
            "revoked_at": None,
        },
        {
            "snapshot_id": "snap_003",
            "contributor_id": "ctr_g7h8i9",
            "authorized": True,
            "auth_scope": "reward_disbursement",
            "granted_at": "2025-09-01T00:00:00Z",
            "expires_at": "2026-03-01T00:00:00Z",
            "revoked_at": None,
        },
        {
            "snapshot_id": "snap_004",
            "contributor_id": "ctr_j0k1l2",
            "authorized": True,
            "auth_scope": "reward_disbursement",
            "granted_at": "2025-10-15T00:00:00Z",
            "expires_at": "2025-12-15T00:00:00Z",
            "revoked_at": None,
        },
        {
            "snapshot_id": "snap_005",
            "contributor_id": "ctr_g7h8i9",
            "authorized": True,
            "auth_scope": "reward_disbursement",
            "granted_at": "2025-06-01T00:00:00Z",
            "expires_at": "2025-08-01T00:00:00Z",
            "revoked_at": None,
        },
    ],
    "verification_records": [
        {
            "verification_id": "ver_001",
            "contributor_id": "ctr_a1b2c3",
            "task_id": "task_alpha",
            "verified": True,
            "verified_at": "2025-09-10T12:00:00Z",
            "verifier": "governance_bot",
        },
        {
            "verification_id": "ver_002",
            "contributor_id": "ctr_d4e5f6",
            "task_id": "task_bravo",
            "verified": False,
            "verified_at": None,
            "verifier": None,
        },
        {
            "verification_id": "ver_003",
            "contributor_id": "ctr_g7h8i9",
            "task_id": "task_charlie",
            "verified": True,
            "verified_at": "2025-09-20T16:00:00Z",
            "verifier": "governance_bot",
        },
        {
            "verification_id": "ver_004",
            "contributor_id": "ctr_j0k1l2",
            "task_id": "task_delta",
            "verified": False,
            "verified_at": None,
            "verifier": None,
        },
        {
            "verification_id": "ver_005",
            "contributor_id": "ctr_j0k1l2",
            "task_id": "task_echo",
            "verified": True,
            "verified_at": "2025-11-05T09:00:00Z",
            "verifier": "peer_review",
        },
    ],
    "legacy_rewards": [
        {
            "reward_id": "rew_001",
            "contributor_id": "ctr_a1b2c3",
            "task_id": "task_alpha",
            "pft_amount": 150.0,
            "rewarded_at": "2025-09-12T00:00:00Z",
            "auth_snapshot_id": "snap_001",
            "verification_id": "ver_001",
        },
        {
            "reward_id": "rew_002",
            "contributor_id": "ctr_a1b2c3",
            "task_id": "task_alpha2",
            "pft_amount": 75.0,
            "rewarded_at": "2025-09-20T00:00:00Z",
            "auth_snapshot_id": "snap_001",
            "verification_id": "ver_001",
        },
        {
            "reward_id": "rew_003",
            "contributor_id": "ctr_a1b2c3",
            "task_id": "task_alpha3",
            "pft_amount": 200.0,
            "rewarded_at": "2025-10-01T00:00:00Z",
            "auth_snapshot_id": "snap_001",
            "verification_id": "ver_001",
        },
        {
            "reward_id": "rew_004",
            "contributor_id": "ctr_d4e5f6",
            "task_id": "task_bravo",
            "pft_amount": 300.0,
            "rewarded_at": "2025-09-25T00:00:00Z",
            "auth_snapshot_id": "snap_002",
            "verification_id": "ver_002",
        },
        {
            "reward_id": "rew_005",
            "contributor_id": "ctr_d4e5f6",
            "task_id": "task_bravo2",
            "pft_amount": 120.0,
            "rewarded_at": "2025-10-05T00:00:00Z",
            "auth_snapshot_id": "snap_002",
            "verification_id": "ver_002",
        },
        {
            "reward_id": "rew_006",
            "contributor_id": "ctr_g7h8i9",
            "task_id": "task_charlie",
            "pft_amount": 250.0,
            "rewarded_at": "2025-09-25T00:00:00Z",
            "auth_snapshot_id": "snap_003",
            "verification_id": "ver_003",
        },
        {
            "reward_id": "rew_007",
            "contributor_id": "ctr_g7h8i9",
            "task_id": "task_charlie2",
            "pft_amount": 100.0,
            "rewarded_at": "2025-10-10T00:00:00Z",
            "auth_snapshot_id": "snap_003",
            "verification_id": "ver_003",
        },
        {
            "reward_id": "rew_008",
            "contributor_id": "ctr_j0k1l2",
            "task_id": "task_delta",
            "pft_amount": 400.0,
            "rewarded_at": "2025-11-10T00:00:00Z",
            "auth_snapshot_id": "snap_004",
            "verification_id": "ver_004",
        },
        {
            "reward_id": "rew_009",
            "contributor_id": "ctr_j0k1l2",
            "task_id": "task_echo",
            "pft_amount": 180.0,
            "rewarded_at": "2025-11-15T00:00:00Z",
            "auth_snapshot_id": "snap_004",
            "verification_id": "ver_005",
        },
        {
            "reward_id": "rew_010",
            "contributor_id": "ctr_a1b2c3",
            "task_id": "task_alpha4",
            "pft_amount": 90.0,
            "rewarded_at": "2025-11-20T00:00:00Z",
            "auth_snapshot_id": "snap_001",
            "verification_id": "ver_001",
        },
        {
            "reward_id": "rew_011",
            "contributor_id": "ctr_g7h8i9",
            "task_id": "task_old_stale",
            "pft_amount": 500.0,
            "rewarded_at": "2025-07-15T00:00:00Z",
            "auth_snapshot_id": "snap_005",
            "verification_id": "ver_003",
        },
        {
            "reward_id": "rew_012",
            "contributor_id": "ctr_j0k1l2",
            "task_id": "task_foxtrot",
            "pft_amount": 220.0,
            "rewarded_at": "2025-11-25T00:00:00Z",
            "auth_snapshot_id": "snap_004",
            "verification_id": "ver_005",
        },
    ],
}


def event_fingerprint(reward_id, contributor_id, task_id, pft_amount):
    raw = f"{reward_id}|{contributor_id}|{task_id}|{pft_amount}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def parse_ts(ts_str):
    if ts_str is None:
        return None
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


def classify_reward(reward, contributor_map, snapshot_map, verification_map):
    contributor = contributor_map.get(reward["contributor_id"])
    snapshot = snapshot_map.get(reward["auth_snapshot_id"])
    verification = verification_map.get(reward["verification_id"])

    rewarded_at = parse_ts(reward["rewarded_at"])

    if snapshot is None:
        return ViolationClass.UNAUTHORIZED

    if contributor is None:
        return ViolationClass.UNRESOLVED_IDENTITY

    if verification is None:
        return ViolationClass.MISSING_VERIFICATION

    if snapshot.get("authorized") is False:
        return ViolationClass.UNAUTHORIZED

    if not contributor["identity_resolved"]:
        return ViolationClass.UNRESOLVED_IDENTITY

    if snapshot.get("expires_at"):
        expires_at = parse_ts(snapshot["expires_at"])
        if expires_at and rewarded_at and rewarded_at >= expires_at:
            return ViolationClass.STALE_AUTH_SNAPSHOT

    if snapshot.get("revoked_at"):
        revoked_at = parse_ts(snapshot["revoked_at"])
        if revoked_at and rewarded_at and rewarded_at >= revoked_at:
            return ViolationClass.UNAUTHORIZED

    if verification.get("verified") is False:
        return ViolationClass.MISSING_VERIFICATION

    return ViolationClass.CLEAN


def determine_risk_tier(violation_class, pft_amount):
    if violation_class == ViolationClass.UNAUTHORIZED:
        return RiskTier.CRITICAL
    if violation_class == ViolationClass.UNRESOLVED_IDENTITY:
        return RiskTier.HIGH if pft_amount >= 200 else RiskTier.MEDIUM
    if violation_class == ViolationClass.MISSING_VERIFICATION:
        return RiskTier.HIGH
    if violation_class == ViolationClass.STALE_AUTH_SNAPSHOT:
        return RiskTier.MEDIUM
    return RiskTier.LOW


def recommended_action_for(violation_class):
    actions = {
        ViolationClass.UNAUTHORIZED: "cooldown_and_recover",
        ViolationClass.UNRESOLVED_IDENTITY: "identity_resolution_required",
        ViolationClass.MISSING_VERIFICATION: "verification_required",
        ViolationClass.STALE_AUTH_SNAPSHOT: "reauth_or_revoke",
        ViolationClass.CLEAN: "no_action",
    }
    return actions.get(violation_class, "review_required")


def tier_sort_key(tier):
    order = {
        RiskTier.CRITICAL: 0,
        RiskTier.HIGH: 1,
        RiskTier.MEDIUM: 2,
        RiskTier.LOW: 3,
    }
    return order.get(tier, 99)


def run_audit(fixtures=None):
    if fixtures is None:
        fixtures = FIXTURES

    contributors = fixtures["contributors"]
    auth_snapshots = fixtures["auth_snapshots"]
    verification_records = fixtures["verification_records"]
    legacy_rewards = fixtures["legacy_rewards"]
    contributor_map = {c["contributor_id"]: c for c in contributors}
    snapshot_map = {s["snapshot_id"]: s for s in auth_snapshots}
    verification_map = {v["verification_id"]: v for v in verification_records}

    results = []
    for reward in legacy_rewards:
        vc = classify_reward(reward, contributor_map, snapshot_map, verification_map)
        fingerprint = event_fingerprint(
            reward["reward_id"],
            reward["contributor_id"],
            reward["task_id"],
            reward["pft_amount"],
        )
        tier = determine_risk_tier(vc, reward["pft_amount"])
        action = recommended_action_for(vc)

        snap = snapshot_map.get(reward["auth_snapshot_id"], {})
        ver = verification_map.get(reward["verification_id"], {})

        contributor = contributor_map.get(reward["contributor_id"])
        results.append(
            {
                "reward_id_or_fingerprint": reward["reward_id"],
                "event_fingerprint": fingerprint,
                "contributor_handle_or_wallet": contributor["handle"]
                if contributor
                else reward["contributor_id"],
                "contributor_id": reward["contributor_id"],
                "task_id": reward["task_id"],
                "pft_amount": reward["pft_amount"],
                "rewarded_at": reward["rewarded_at"],
                "violation_class": vc.value,
                "auth_state": "authorized"
                if snap.get("authorized")
                else "unauthorized",
                "auth_snapshot_id": reward["auth_snapshot_id"],
                "verification_state": "verified"
                if ver.get("verified")
                else "unverified",
                "risk_tier": tier.value,
                "recommended_action": action,
            }
        )

    flagged = [r for r in results if r["violation_class"] != ViolationClass.CLEAN.value]
    flagged_pft = sum(r["pft_amount"] for r in flagged)

    violation_counts = {}
    for r in results:
        vc = r["violation_class"]
        violation_counts[vc] = violation_counts.get(vc, 0) + 1

    contributor_risk = {}
    for r in flagged:
        cid = r["contributor_id"]
        if cid not in contributor_risk:
            c = contributor_map.get(cid)
            contributor_risk[cid] = {
                "contributor_id": cid,
                "contributor_handle_or_wallet": c["handle"] if c else cid,
                "wallet": c["wallet"] if c else "unknown",
                "flagged_reward_count": 0,
                "flagged_pft_total": 0.0,
                "violation_classes": set(),
                "max_risk_tier": "low",
            }
        entry = contributor_risk[cid]
        entry["flagged_reward_count"] += 1
        entry["flagged_pft_total"] += r["pft_amount"]
        entry["violation_classes"].add(r["violation_class"])
        current_tier = r["risk_tier"]
        if tier_sort_key(RiskTier(current_tier)) < tier_sort_key(
            RiskTier(entry["max_risk_tier"])
        ):
            entry["max_risk_tier"] = current_tier

    for entry in contributor_risk.values():
        entry["violation_classes"] = sorted(entry["violation_classes"])

    remediation_queue = sorted(
        [r for r in results if r["violation_class"] != ViolationClass.CLEAN.value],
        key=lambda x: (tier_sort_key(RiskTier(x["risk_tier"])), -x["pft_amount"]),
    )

    output = {
        "audit_meta": {
            "auditor_version": "1.0.0",
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_rewards_scanned": len(legacy_rewards),
            "total_contributors": len(contributors),
        },
        "summary": {
            "total_rewards_scanned": len(legacy_rewards),
            "clean_reward_count": violation_counts.get(ViolationClass.CLEAN.value, 0),
            "flagged_reward_count": len(flagged),
            "flagged_pft_total": round(flagged_pft, 2),
            "violation_class_counts": violation_counts,
        },
        "contributor_risk_rollup": {
            cid: entry
            for cid, entry in sorted(
                contributor_risk.items(),
                key=lambda x: (
                    tier_sort_key(RiskTier(x[1]["max_risk_tier"])),
                    -x[1]["flagged_pft_total"],
                ),
            )
        },
        "remediation_queue": remediation_queue,
    }

    return output


def smoke_test():
    result = run_audit()

    assert result["audit_meta"]["total_rewards_scanned"] >= 10, "Need >= 10 rewards"
    assert result["audit_meta"]["total_contributors"] >= 4, "Need >= 4 contributors"

    vc = result["summary"]["violation_class_counts"]
    assert "unauthorized" in vc, "Missing unauthorized class"
    assert "unresolved_identity" in vc, "Missing unresolved_identity class"
    assert "missing_verification" in vc, "Missing missing_verification class"
    assert "stale_auth_snapshot" in vc, "Missing stale_auth_snapshot class"
    assert "clean" in vc, "Missing clean class"

    assert result["summary"]["flagged_reward_count"] > 0, "Should have flagged rewards"
    assert result["summary"]["flagged_pft_total"] > 0, "Should have flagged PFT total"

    assert len(result["remediation_queue"]) == result["summary"]["flagged_reward_count"]

    queue = result["remediation_queue"]
    for i in range(len(queue) - 1):
        current = tier_sort_key(RiskTier(queue[i]["risk_tier"]))
        next_t = tier_sort_key(RiskTier(queue[i + 1]["risk_tier"]))
        assert current <= next_t, "Remediation queue not sorted by risk tier"

    required_fields = [
        "reward_id_or_fingerprint",
        "contributor_handle_or_wallet",
        "pft_amount",
        "violation_class",
        "auth_state",
        "verification_state",
        "risk_tier",
        "recommended_action",
    ]
    for item in queue:
        for field in required_fields:
            assert field in item, f"Missing field '{field}' in remediation queue item"

    required_top = [
        "total_rewards_scanned",
        "flagged_reward_count",
        "flagged_pft_total",
        "violation_class_counts",
        "contributor_risk_rollup",
        "remediation_queue",
    ]
    for field in required_top:
        assert field in result["summary"] or field in result, (
            f"Missing top-level field '{field}'"
        )

    rollup = result["contributor_risk_rollup"]
    for cid, entry in rollup.items():
        assert "contributor_handle_or_wallet" in entry
        assert "flagged_reward_count" in entry
        assert "flagged_pft_total" in entry
        assert "violation_classes" in entry

    print(json.dumps(result, indent=2))

    dangling_fixtures = {
        "contributors": [
            {
                "contributor_id": "ctr_known",
                "handle": "known_contrib",
                "wallet": "0xKnown",
                "identity_resolved": True,
                "identity_resolved_at": "2025-01-01T00:00:00Z",
                "governance_role": "contributor",
            },
        ],
        "auth_snapshots": [
            {
                "snapshot_id": "snap_ok",
                "contributor_id": "ctr_known",
                "authorized": True,
                "auth_scope": "reward_disbursement",
                "granted_at": "2025-01-01T00:00:00Z",
                "expires_at": "2026-01-01T00:00:00Z",
                "revoked_at": None,
            },
        ],
        "verification_records": [
            {
                "verification_id": "ver_ok",
                "contributor_id": "ctr_known",
                "task_id": "task_known",
                "verified": True,
                "verified_at": "2025-09-01T00:00:00Z",
                "verifier": "governance_bot",
            },
        ],
        "legacy_rewards": [
            {
                "reward_id": "rew_dangle_no_snap",
                "contributor_id": "ctr_known",
                "task_id": "task_a",
                "pft_amount": 100.0,
                "rewarded_at": "2025-10-01T00:00:00Z",
                "auth_snapshot_id": "snap_nonexistent",
                "verification_id": "ver_ok",
            },
            {
                "reward_id": "rew_dangle_no_contrib",
                "contributor_id": "ctr_ghost",
                "task_id": "task_b",
                "pft_amount": 200.0,
                "rewarded_at": "2025-10-01T00:00:00Z",
                "auth_snapshot_id": "snap_ok",
                "verification_id": "ver_ok",
            },
            {
                "reward_id": "rew_dangle_no_ver",
                "contributor_id": "ctr_known",
                "task_id": "task_c",
                "pft_amount": 300.0,
                "rewarded_at": "2025-10-01T00:00:00Z",
                "auth_snapshot_id": "snap_ok",
                "verification_id": "ver_nonexistent",
            },
        ],
    }
    dangling_result = run_audit(dangling_fixtures)
    dangling_queue = dangling_result["remediation_queue"]
    assert dangling_result["summary"]["flagged_reward_count"] == 3, (
        "Dangling refs should flag all 3 rewards"
    )
    violations = {item["violation_class"] for item in dangling_queue}
    assert "unauthorized" in violations, "Missing snapshot should produce unauthorized"
    assert "unresolved_identity" in violations, (
        "Missing contributor should produce unresolved_identity"
    )
    assert "missing_verification" in violations, (
        "Missing verification should produce missing_verification"
    )
    print("\n--- DANGLING REF TESTS PASSED ---")
    print("\n--- SMOKE TEST PASSED ---")
    return result


if __name__ == "__main__":
    smoke_test()
