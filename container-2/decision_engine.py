"""
decision_engine.py — Secret Monitoring Decision Engine (Monitor MCP)
Updated with P1/P2/P3 logic, JiraTicketCreatedDate, AlertHistory, and Ignore threshold.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

# ─────────────────────────────────────────────────────────────────────────────
# BUCKET CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────

def classify_bucket(days: int) -> str:
    if days >= 61:       return "B0"
    if 31 <= days <= 60: return "P3"
    if 8  <= days <= 30: return "P2"
    if 0  <= days <= 7:  return "P1"
    if -7 <= days <= -1: return "ExpiredManualReview" 
    return "Ignore"      # -8 to infinity


# ─────────────────────────────────────────────────────────────────────────────
# STATE MAPS
# ─────────────────────────────────────────────────────────────────────────────

TERMINAL_STATUSES = {"Rotated", "Ignored", "Resolved"}
MONITOR_SKIP_STATUSES = TERMINAL_STATUSES | {"RotatedPendingDeployment"}
CLOSED_NAMES = {"done", "closed", "resolved"}

BUCKET_STAGE = {"P3": 1, "P2": 2, "P1": 3, "ExpiredManualReview": 4}
STATUS_STAGE = {
    "JiraRaised": 1,
    "TeamsAlerted": 2,
    "Escalated": 3,
    "Expired": 4,
    "ExpiredManualReview": 4,
}

ALERT_STATUS_FOR_BUCKET = {
    "P3": "JiraRaised",
    "P2": "TeamsAlerted",
    "P1": "Escalated",
    "ExpiredManualReview": "ExpiredManualReview",
}

SEVERITY_MAP = {
    "P3": {"severity": "INFORMATION", "priority": "Low"},
    "P2": {"severity": "WARNING", "priority": "Medium"},
    "P1": {"severity": "CRITICAL", "priority": "High"},
    "ExpiredManualReview": {"severity": "EXPIRED", "priority": "Highest"},
}

TEAMS_HEADERS = {
    "WARNING": "⚠️ WARNING",
    "CRITICAL": "🚨 CRITICAL",
    "EXPIRED": "⛔ EXPIRED — MANUAL REVIEW REQUIRED",
}

# ─────────────────────────────────────────────────────────────────────────────
# MESSAGE BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def _expiry_notice(days: int) -> str:
    if days < 0:  return f"Expired {abs(days)} days ago"
    if days == 0: return "Secret Expires Today"
    return f"Secret Expiring in {days} days"

def _teams_text(severity: str, c: dict, jira_key: str) -> str:
    days = c["days"]
    days_line = f"Expired: {abs(days)} days ago" if days < 0 else f"Days Remaining: {days} days"
    header = TEAMS_HEADERS.get(severity, severity)

    if severity == "EXPIRED":
        action_req = "Password has ALREADY EXPIRED. A ticket has been raised for manual review."
    elif c.get("bucket") in ("P1", "P2", "P3"):
        action_req = "This secret is scheduled for AUTO-ROTATION. No manual rotation is needed yet."
    else:
        action_req = "Rotate this secret and update all dependent services."

    return (
        f"{header} — Azure Secret Expiry Alert\n"
        f"App Registration: {c['app_name']}\n"
        f"App ID: {c['app_id']}\n"
        f"Secret ID: {c['secret_id']}\n"
        f"Secret Description: {c['secret_desc']}\n"
        f"Expiry Date: {c['expiration']}\n"
        f"{days_line}\n"
        f"Jira Ticket: {jira_key or 'N/A'}\n"
        f"Action Required: {action_req}"
    )

def _escalation_comment(severity: str, c: dict) -> str:
    days = c["days"]
    days_text = f"expired {abs(days)} days ago" if days < 0 else f"now has {days} days remaining"
    
    if severity == "EXPIRED":
        action_req = "MANUAL REVIEW REQUIRED. This secret will NOT be auto-rotated."
    elif c.get("bucket") in ("P1", "P2", "P3"):
        action_req = "This secret is scheduled for AUTO-ROTATION. No manual action is needed yet."
    else:
        action_req = "Immediate rotation required."

    return (
        f"ESCALATION — Secret for {c['app_name']} (Secret ID: {c['secret_id']}) "
        f"{days_text}. Severity upgraded to {severity}. "
        f"A Teams alert has been sent to the security channel. {action_req}"
    )

# ─────────────────────────────────────────────────────────────────────────────
# CANDIDATE BUILDING
# ─────────────────────────────────────────────────────────────────────────────

def _build_candidates(applications: list[dict], now: datetime) -> tuple[list[dict], list[str]]:
    candidates: list[dict] = []
    errors: list[str] = []

    for app in applications:
        app_id = app.get("appId")
        app_name = app.get("displayName") or "Unknown"
        creds = app.get("passwordCredentials") or []

        for cred in creds:
            end_dt_str = cred.get("endDateTime")
            if not end_dt_str: continue
            try:
                exp = datetime.fromisoformat(end_dt_str.replace("Z", "+00:00"))
            except Exception:
                errors.append(f"App '{app_name}' ({app_id}): unparseable endDateTime '{end_dt_str}'")
                continue

            days = (exp - now).days
            candidates.append({
                "app_id": app_id,
                "app_name": app_name,
                "secret_id": cred.get("keyId"),
                "secret_desc": cred.get("displayName") or "N/A",
                "expiration": end_dt_str,
                "days": days,
                "bucket": classify_bucket(days),
            })
    return candidates, errors


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

async def run_secret_monitoring(
    fetch_azure_secrets: Callable[[], Awaitable[dict]],
    get_sharepoint_state: Callable[[], Awaitable[dict]],
    write_sharepoint_row: Callable[..., Awaitable[dict]],
    create_jira_ticket: Callable[..., Awaitable[dict]],
    get_jira_issue: Callable[[str], Awaitable[dict]],
    add_jira_comment: Callable[[str, str], Awaitable[dict]],
    send_teams_alert: Callable[[str], Awaitable[dict]],
) -> dict:
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    summary: dict[str, Any] = {
        "runDate": today,
        "secretsScanned": 0,
        "totalsByBucket": {b: 0 for b in ["B0", "P1", "P2", "P3", "ExpiredManualReview", "Ignore"]},
        "newJiraTickets": 0,
        "newTeamsAlerts": 0,
        "jiraComments": 0,
        "sharepointCreated": 0,
        "sharepointUpdated": 0,
        "errors": [],
    }

    try:
        azure_data = await fetch_azure_secrets()
    except Exception as e:
        summary["errors"].append(f"fetch_azure_secrets failed: {e}")
        return summary

    try:
        sp_data = await get_sharepoint_state()
    except Exception as e:
        summary["errors"].append(f"get_sharepoint_state failed: {e}")
        return summary

    sp_index: dict[tuple[str, str], dict] = {}
    for item in sp_data.get("items", []):
        f = item.get("fields", {})
        sp_index[(f.get("Title"), f.get("SecretID"))] = item

    candidates, build_errors = _build_candidates(azure_data.get("applications", []), now)
    summary["errors"].extend(build_errors)
    summary["secretsScanned"] = len(candidates)

    for c in candidates:
        bucket = c["bucket"]
        summary["totalsByBucket"][bucket] += 1
        existing = sp_index.get((c["app_id"], c["secret_id"]))

        try:
            if existing is None:
                await _handle_new_secret(c, bucket, today, summary, write_sharepoint_row, create_jira_ticket, send_teams_alert)
            else:
                await _handle_existing_secret(c, bucket, existing, today, summary, write_sharepoint_row, create_jira_ticket, get_jira_issue, add_jira_comment, send_teams_alert)
        except Exception as e:
            summary["errors"].append(f"AppID={c['app_id']} SecretID={c['secret_id']}: {e}")

    return summary


# ─────────────────────────────────────────────────────────────────────────────
# NEW SECRET LOGIC
# ─────────────────────────────────────────────────────────────────────────────

async def _handle_new_secret(
    c: dict, bucket: str, today: str, summary: dict,
    write_sharepoint_row, create_jira_ticket, send_teams_alert,
) -> None:

    # Drop entirely — No SP row, No Jira, No Teams
    if bucket in ("B0", "Ignore"):
        return

    sev = SEVERITY_MAP[bucket]
    extra = ""
    if bucket == "ExpiredManualReview":
        extra = ("This secret has ALREADY EXPIRED. It will NOT be auto-rotated. "
                 "Please check manually: if it has already been rotated, update "
                 "the SharePoint AlertStatus to 'Rotated' and close this ticket.")

    issue = await create_jira_ticket(
        app_name=c["app_name"], app_id=c["app_id"], secret_id=c["secret_id"],
        secret_description=c["secret_desc"], expiration_date=c["expiration"],
        days_remaining=c["days"], severity=sev["severity"], priority=sev["priority"],
        extra_note=extra,
    )
    
    jira_key = issue.get("issue_key", "")
    if jira_key:
        summary["newJiraTickets"] += 1
    else:
        summary["errors"].append(f"create_jira_ticket failed for {c['app_id']}: {issue}")

    fields = {
        "Title": c["app_id"],
        "AppName": c["app_name"],
        "SecretID": c["secret_id"],
        "SecretDescription": c["secret_desc"],
        "ExpirationDate": c["expiration"],
        "JiraTicketKey": jira_key,
        "ExpiryNotice": _expiry_notice(c["days"]),
        "LastChecked": today,
        "ExpiryBucket": bucket,
        "AlertHistory": f"[{today}] Alert generated at severity {bucket}.",
    }
    
    # NEW: Stamp the ticket creation date if we made one
    if jira_key:
        fields["JiraTicketCreatedDate"] = today

    if bucket == "P3":
        fields["AlertStatus"] = "JiraRaised"
    else: 
        text = _teams_text(sev["severity"], c, jira_key)
        result = await send_teams_alert(text)
        if result.get("success"):
            fields["AlertStatus"] = ALERT_STATUS_FOR_BUCKET[bucket]
            fields["AlertSentDate"] = today
            summary["newTeamsAlerts"] += 1
        else:
            fields["AlertStatus"] = "JiraRaised"
            summary["errors"].append(f"send_teams_alert failed for {c['app_id']}: {result}")

    await write_sharepoint_row(None, fields)
    summary["sharepointCreated"] += 1


# ─────────────────────────────────────────────────────────────────────────────
# EXISTING SECRET LOGIC
# ─────────────────────────────────────────────────────────────────────────────

async def _handle_existing_secret(
    c: dict, bucket: str, existing: dict, today: str, summary: dict,
    write_sharepoint_row, create_jira_ticket, get_jira_issue,
    add_jira_comment, send_teams_alert,
) -> None:

    f = existing.get("fields", {})
    item_id = existing.get("id")
    alert_status = f.get("AlertStatus", "")
    jira_key = f.get("JiraTicketKey", "")
    notice = _expiry_notice(c["days"])

    if alert_status in MONITOR_SKIP_STATUSES:
        if alert_status == "RotatedPendingDeployment":
            await write_sharepoint_row(item_id, {"ExpiryNotice": notice, "LastChecked": today})
            summary["sharepointUpdated"] += 1
        return

    # Drop entirely for stale secrets
    if bucket in ("B0", "Ignore"):
        return

    # Self-heal missing Jira tickets
    if not jira_key and bucket in SEVERITY_MAP:
        sev = SEVERITY_MAP[bucket]
        extra = "Self-healed — previous ticket reference was missing."
        issue = await create_jira_ticket(
            app_name=c["app_name"], app_id=c["app_id"], secret_id=c["secret_id"],
            secret_description=c["secret_desc"], expiration_date=c["expiration"],
            days_remaining=c["days"], severity=sev["severity"], priority=sev["priority"],
            extra_note=extra,
        )
        jira_key = issue.get("issue_key", "")
        if jira_key:
            summary["newJiraTickets"] += 1
        else:
            summary["errors"].append(f"self-heal create_jira_ticket failed: {issue}")

    jira_open = True
    if jira_key:
        issue_status = await get_jira_issue(jira_key)
        status_name = (issue_status.get("status") or "").strip().lower()
        jira_open = status_name not in CLOSED_NAMES

    if jira_key and not jira_open:
        await write_sharepoint_row(item_id, {"ExpiryNotice": notice, "LastChecked": today})
        summary["sharepointUpdated"] += 1
        return

    current_stage = BUCKET_STAGE.get(bucket)
    existing_stage = STATUS_STAGE.get(alert_status, 0)

    # ── Escalation Logic ───────────────────────────────────────────────────────
    if current_stage is not None and current_stage > existing_stage:
        sev = SEVERITY_MAP[bucket]

        if jira_key:
            await add_jira_comment(jira_key, _escalation_comment(sev["severity"], c))
            summary["jiraComments"] += 1

        # Fetch existing history and append the new escalation to a new line
        existing_history = f.get("AlertHistory", "")
        new_event = f"[{today}] Escalated to severity {bucket}. Teams alert sent."
        updated_history = f"{existing_history}\n{new_event}".strip()

        update_fields: dict[str, str] = {
            "LastChecked": today, 
            "ExpiryNotice": notice,
            "AlertHistory": updated_history,
            "ExpiryBucket": bucket,
        }
        
        if jira_key:
            update_fields["JiraTicketKey"] = jira_key
            # In case this was a self-heal, stamp the date it was created
            if "JiraTicketCreatedDate" not in f:
                update_fields["JiraTicketCreatedDate"] = today

        if bucket != "P3":
            text = _teams_text(sev["severity"], c, jira_key)
            result = await send_teams_alert(text)
            if result.get("success"):
                update_fields["AlertStatus"] = ALERT_STATUS_FOR_BUCKET[bucket]
                update_fields["AlertSentDate"] = today
                summary["newTeamsAlerts"] += 1
            else:
                summary["errors"].append(f"send_teams_alert failed: {result}")
        else:
            update_fields["AlertStatus"] = ALERT_STATUS_FOR_BUCKET[bucket]

        await write_sharepoint_row(item_id, update_fields)
        summary["sharepointUpdated"] += 1

    else:
        update_fields = {
            "LastChecked": today, 
            "ExpiryNotice": notice,
            "ExpiryBucket": bucket
        }
        if jira_key:
            update_fields["JiraTicketKey"] = jira_key
        await write_sharepoint_row(item_id, update_fields)
        summary["sharepointUpdated"] += 1