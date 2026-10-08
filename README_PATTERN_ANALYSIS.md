# New Solution (With Pattern Analysis & 1Password)

## Overview
This package contains the upgraded Azure Secret Governance solution with Pattern Analysis and 1Password integration.

## Key Features & Business Rules
1. **45-Day Threshold Lifecycle**:
   - **P1 (Critical)**: 0 to 7 days remaining
   - **P2 (High)**: 8 to 30 days remaining
   - **P3 (Medium)**: 31 to 45 days remaining
   - **P4 (Safe)**: 46+ days remaining (No action required)

2. **Automated Second Tenant Pattern Bypass**:
   - For applications in Tenant 2 matching specific service patterns (*.select*, practice-plus-*, *-partner-*, *-internal-*, svc-automation-*, 	emp-*), Jira ticket creation is **automatically bypassed**.
   - These applications are marked for automated zero-touch rotation.

3. **Automated Metadata Enrichment**:
   - Automatically populates TeamName, ProductName, and DevSecOpsOwnership for pattern-matched apps to eliminate manual sync bottlenecks.

4. **1Password SDK Zero-Touch Rotation**:
   - Rotated secrets for pattern apps are securely written directly to 1Password vaults using the 1Password SDK.
   - Dual routing: Standard apps rotate to Key Vault / SharePoint; pattern apps rotate to 1Password.

5. **Test Suite**:
   - Includes 	est_45_day_pattern_matrix.py covering 10 automated test scenarios across both tenants.
