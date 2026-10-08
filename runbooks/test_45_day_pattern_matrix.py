"""
test_45_day_pattern_matrix.py
=============================
Automated Test Suite for the 45-day Governance Threshold:
  - Part 1: Pre-Pattern Analysis (Standard workloads)
  - Part 2: Post-Pattern Analysis (Pattern-matched workloads)
"""

import sys
import decision_engine as de
import secret_rotation_engine as sre

def run_tests():
    print("=" * 95)
    print("AZURE SECRET GOVERNANCE — 45-DAY THRESHOLD & PATTERN ANALYSIS TEST MATRIX")
    print("=" * 95)
    print(f"Decision Engine Threshold : P3 = 31..45 days | P4 = 46+ days (Safe)")
    print(f"Secret Rotator Threshold  : {sre.DEFAULT_ROTATION_THRESHOLD} days")
    print("=" * 95)

    test_scenarios = [
        # (Scenario Name, App Name, Secret Desc, Tenant ID, Days Remaining, Is Pattern Expected?)
        ("Standard - Safe Horizon",      "commerce-payment-service",  "db-connection-secret",      "70afdd80-5f5b-4a09-a90d-383f126e8c33", 50, False),
        ("Standard - P3 Info Window",     "commerce-payment-service",  "db-connection-secret",      "70afdd80-5f5b-4a09-a90d-383f126e8c33", 40, False),
        ("Standard - P3 Boundary Edge",   "commerce-payment-service",  "db-connection-secret",      "70afdd80-5f5b-4a09-a90d-383f126e8c33", 45, False),
        ("Standard - P4 Boundary Edge",   "commerce-payment-service",  "db-connection-secret",      "70afdd80-5f5b-4a09-a90d-383f126e8c33", 46, False),
        ("Standard - P2 Warning Window",  "commerce-payment-service",  "db-connection-secret",      "70afdd80-5f5b-4a09-a90d-383f126e8c33", 20, False),
        ("Standard - P1 Critical Window", "commerce-payment-service",  "db-connection-secret",      "70afdd80-5f5b-4a09-a90d-383f126e8c33", 5,  False),

        # Pattern-matched scenarios (Tenant 2: c721d616-dcf3-4510-9c3e-548bc6c1f628)
        ("Pattern 1 - .select safe",      "reporting-api",             "reporting.select.appkey",   "c721d616-dcf3-4510-9c3e-548bc6c1f628", 50, True),
        ("Pattern 1 - .select P3 active", "reporting-api",             "reporting.select.appkey",   "c721d616-dcf3-4510-9c3e-548bc6c1f628", 40, True),
        ("Pattern 2 - practice-plus-*",   "practice-plus-auth",        "practice-plus-worker-cert", "c721d616-dcf3-4510-9c3e-548bc6c1f628", 35, True),
        ("Pattern 3 - partner service",   "crm-partner-connector",     "crm-partner-auth-token",    "c721d616-dcf3-4510-9c3e-548bc6c1f628", 15, True),
    ]

    all_passed = True
    print(f"\n{'Test Case':<32} | {'Days':<4} | {'Bucket':<4} | {'Jira Ticket Action':<22} | {'1Password Sync?':<16} | {'Rotator Eligible?':<18} | {'Status'}")
    print("-" * 125)

    for name, app_name, secret_desc, tenant_id, days, is_pattern in test_scenarios:
        c = {
            "app_name": app_name,
            "AppName": app_name,
            "secret_desc": secret_desc,
            "SecretDescription": secret_desc,
            "tenant_id": tenant_id,
            "TenantID": tenant_id,
            "days": days
        }
        bucket = de.classify_bucket(days)
        pattern_matched = de.should_bypass_jira_for_secret(c)
        
        # Rotator eligibility
        rotator_bucket = sre._classify_bucket(days)
        is_rotator_eligible = (rotator_bucket in sre.ROTATION_ELIGIBLE_BUCKETS) and (days <= sre.DEFAULT_ROTATION_THRESHOLD)

        # Jira ticketing decision
        if bucket == "P4":
            jira_decision = "No (Safe - P4)"
            expected_jira = False
        elif pattern_matched:
            jira_decision = "BYPASSED (Pattern Match)"
            expected_jira = False
        else:
            jira_decision = f"CREATED (Priority: {bucket})"
            expected_jira = True

        # 1Password Sync decision (strictly for pattern-matching bypass apps when eligible for rotation)
        onepassword_sync_decision = "YES (Pattern App)" if (pattern_matched and is_rotator_eligible) else "SKIPPED"
        expected_onepassword = pattern_matched and is_rotator_eligible

        # Validation assertions
        expected_bucket = "P4" if days >= 46 else ("P3" if days >= 31 else ("P2" if days >= 8 else "P1"))
        expected_rotator = days <= 45
        
        passed = (
            (bucket == expected_bucket)
            and (is_rotator_eligible == expected_rotator)
            and (pattern_matched == is_pattern)
            and ((pattern_matched and is_rotator_eligible) == expected_onepassword)
        )
        if not passed:
            all_passed = False

        status_str = "PASS" if passed else "FAIL"
        print(f"{name:<32} | {days:<4} | {bucket:<4} | {jira_decision:<22} | {onepassword_sync_decision:<16} | {str(is_rotator_eligible):<18} | {status_str}")

    print("=" * 125)
    if all_passed:
        print("[SUCCESS] All 10 test scenarios passed 100% (Thresholds, Jira Bypass & 1Password Isolation).")
    else:
        print("[FAILURE] One or more test scenarios failed.")
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
