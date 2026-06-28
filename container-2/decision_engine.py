"""
decision_engine.py — Secret Monitoring Decision Engine (Container 2)
=====================================================================
Changes in this version:
  - Fully dynamic pagination — no hardcoded $top, works for any list size
  - Batch concurrent SharePoint writes (10 in parallel)
  - Batch concurrent Jira ticket creation (5 in parallel)
  - Sequential Teams alerts (one per run, no batching needed)
  - Zero changes needed as list grows — fully self-adapting
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

# ─────────────────────────────────────────────────────────────────────────────
# BATCH SETTINGS — tune here if throttling occurs
# ─────────────────────────────────────────────────────────────────────────────

SP_WRITE_BATCH    = 10   # SharePoint writes in parallel
JIRA_CREATE_BATCH = 5    # Jira ticket creations in parallel
BATCH_PAUSE       = 0.5  # seconds between batches — avoids throttling

# ─────────────────────────────────────────────────────────────────────────────
# BUCKET CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────

def classify_bucket(days: int) -> str:
    if days >= 61:       return "B0"
    if 31 <= days <= 60: return "P3"
    if 8  <= days <= 30: return "P2"
    if 0  <= days <= 7:  return "P1"
    if -7 <= days <= -1: return "ExpiredManualReview"
    return "Ignore"

# ─────────────────────────────────────────────────────────────────────────────
# STATE MAPS
# ─────────────────────────────────────────────────────────────────────────────

TERMINAL_STATUSES    = {"Rotated", "Ignored", "Resolved"}
MONITOR_SKIP_STATUSES = TERMINAL_STATUSES | {"RotatedPendingDeployment"}
CLOSED_NAMES         = {"done", "closed", "resolved"}

BUCKET_STAGE = {"P3": 1, "P2": 2, "P1": 3, "ExpiredManualReview": 4}
STATUS_STAGE = {
    "JiraRaised": 1, "TeamsAlerted": 2,
    "Escalated": 3, "Expired": 4, "ExpiredManualReview": 4,
}

ALERT_STATUS_FOR_BUCKET = {
    "P3": "JiraRaised", "P2": "TeamsAlerted",
    "P1": "Escalated",  "ExpiredManualReview": "ExpiredManualReview",
}

SEVERITY_MAP = {
    "P3": {"severity": "INFORMATION", "priority": "Low"},
    "P2": {"severity": "WARNING",     "priority": "Medium"},
    "P1": {"severity": "CRITICAL",    "priority": "High"},
    "ExpiredManualReview": {"severity": "EXPIRED", "priority": "Highest"},
}

TEAMS_HEADERS = {
    "WARNING":  "⚠️ WARNING",
    "CRITICAL": "🚨 CRITICAL",
    "EXPIRED":  "⛔ EXPIRED — MANUAL REVIEW REQUIRED",
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
        f"App Registration: {c['app_name']}\nApp ID: {c['app_id']}\n"
        f"Secret ID: {c['secret_id']}\nSecret Description: {c['secret_desc']}\n"
        f"Expiry Date: {c['expiration']}\n{days_line}\n"
        f"Jira Ticket: {jira_key or 'N/A'}\nAction Required: {action_req}"
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
        app_id   = app.get("appId")
        app_name = app.get("displayName") or "Unknown"
        creds    = app.get("passwordCredentials") or []
        for cred in creds:
            end_dt_str = cred.get("endDateTime")
            if not end_dt_str:
                continue
            try:
                exp = datetime.fromisoformat(end_dt_str.replace("Z", "+00:00"))
            except Exception:
                errors.append(f"App '{app_name}' ({app_id}): unparseable endDateTime '{end_dt_str}'")
                continue
            days = (exp - now).days
            candidates.append({
                "app_id":      app_id,
                "app_name":    app_name,
                "secret_id":   cred.get("keyId"),
                "secret_desc": cred.get("displayName") or "N/A",
                "expiration":  end_dt_str,
                "days":        days,
                "bucket":      classify_bucket(days),
            })
    return candidates, errors

# ─────────────────────────────────────────────────────────────────────────────
# BATCH HELPERS
# ─────────────────────────────────────────────────────────────────────────────

async def _run_batched(tasks: list, batch_size: int, pause: float = BATCH_PAUSE) -> list:
    """Run a list of coroutines in batches of batch_size with a pause between batches."""
    results = []
    for i in range(0, len(tasks), batch_size):
        batch   = tasks[i:i + batch_size]
        batch_results = await asyncio.gather(*batch, return_exceptions=True)
        results.extend(batch_results)
        if i + batch_size < len(tasks):
            await asyncio.sleep(pause)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

async def run_secret_monitoring(
    fetch_azure_secrets:  Callable[[], Awaitable[dict]],
    get_sharepoint_state: Callable[[], Awaitable[dict]],
    write_sharepoint_row: Callable[..., Awaitable[dict]],
    create_jira_ticket:   Callable[..., Awaitable[dict]],
    get_jira_issue:       Callable[[str], Awaitable[dict]],
    add_jira_comment:     Callable[[str, str], Awaitable[dict]],
    send_teams_alert:     Callable[[str], Awaitable[dict]],
) -> dict:
    now   = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    summary: dict[str, Any] = {
        "runDate": today,
        "secretsScanned": 0,
        "totalsByBucket": {b: 0 for b in ["B0", "P1", "P2", "P3", "ExpiredManualReview", "Ignore"]},
        "newJiraTickets":    0,
        "newTeamsAlerts":    0,
        "jiraComments":      0,
        "sharepointCreated": 0,
        "sharepointUpdated": 0,
        "errors": [],
    }

    # ── Fetch all data ────────────────────────────────────────────────────────
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

    # ── Build SharePoint index ────────────────────────────────────────────────
    sp_index: dict[tuple[str, str], dict] = {}
    for item in sp_data.get("items", []):
        f = item.get("fields", {})
        sp_index[(f.get("Title"), f.get("SecretID"))] = item

    # ── Build candidates ──────────────────────────────────────────────────────
    candidates, build_errors = _build_candidates(azure_data.get("applications", []), now)
    summary["errors"].extend(build_errors)
    summary["secretsScanned"] = len(candidates)

    for c in candidates:
        summary["totalsByBucket"][c["bucket"]] += 1

    # ── Split into new vs existing ────────────────────────────────────────────
    new_secrets      = []
    existing_secrets = []

    for c in candidates:
        existing = sp_index.get((c["app_id"], c["secret_id"]))
        if existing is None:
            new_secrets.append(c)
        else:
            existing_secrets.append((c, existing))

    # ── PHASE 1: Create Jira tickets for new secrets (batched) ───────────────
    # Filter to only actionable new secrets (not B0 or Ignore)
    actionable_new = [c for c in new_secrets if c["bucket"] not in ("B0", "Ignore")]

    async def _create_ticket_for_new(c: dict):
        sev   = SEVERITY_MAP[c["bucket"]]
        extra = ""
        if c["bucket"] == "ExpiredManualReview":
            extra = (
                "This secret has ALREADY EXPIRED. It will NOT be auto-rotated. "
                "Please check manually: if it has already been rotated, update "
                "the SharePoint AlertStatus to 'Rotated' and close this ticket."
            )
        try:
            issue     = await create_jira_ticket(
                app_name=c["app_name"], app_id=c["app_id"],
                secret_id=c["secret_id"], secret_description=c["secret_desc"],
                expiration_date=c["expiration"], days_remaining=c["days"],
                severity=sev["severity"], priority=sev["priority"], extra_note=extra,
            )
            jira_key  = issue.get("issue_key", "")
            return {"c": c, "jira_key": jira_key, "sev": sev, "error": None}
        except Exception as e:
            return {"c": c, "jira_key": "", "sev": sev, "error": str(e)}

    jira_tasks   = [_create_ticket_for_new(c) for c in actionable_new]
    jira_results = await _run_batched(jira_tasks, JIRA_CREATE_BATCH)

    for res in jira_results:
        if isinstance(res, Exception):
            summary["errors"].append(f"Jira batch error: {res}")
            continue
        if res["error"]:
            summary["errors"].append(f"create_jira_ticket failed for {res['c']['app_id']}: {res['error']}")
        elif res["jira_key"]:
            summary["newJiraTickets"] += 1

    # ── PHASE 2: Send Teams alerts + write SharePoint rows for new (batched) ──
    async def _write_new_secret(res: dict):
        c        = res["c"]
        jira_key = res["jira_key"]
        sev      = res["sev"]
        bucket   = c["bucket"]

        fields = {
            "Title":              c["app_id"],
            "AppName":            c["app_name"],
            "SecretID":           c["secret_id"],
            "SecretDescription":  c["secret_desc"],
            "ExpirationDate":     c["expiration"],
            "JiraTicketKey":      jira_key,
            "ExpiryNotice":       _expiry_notice(c["days"]),
            "LastChecked":        today,
            "ExpiryBucket":       bucket,
            "AlertHistory":       f"[{today}] Alert generated at severity {bucket}.",
        }
        if jira_key:
            fields["JiraTicketCreatedDate"] = today

        teams_sent = False
        if bucket != "P3":
            try:
                text   = _teams_text(sev["severity"], c, jira_key)
                result = await send_teams_alert(text)
                if result.get("success"):
                    fields["AlertStatus"]   = ALERT_STATUS_FOR_BUCKET[bucket]
                    fields["AlertSentDate"] = today
                    teams_sent = True
                else:
                    fields["AlertStatus"] = "JiraRaised"
            except Exception as e:
                fields["AlertStatus"] = "JiraRaised"
                return {"action": "sp_created", "teams": False, "error": f"Teams alert failed: {e}"}
        else:
            fields["AlertStatus"] = "JiraRaised"

        try:
            await write_sharepoint_row(None, fields)
            return {"action": "sp_created", "teams": teams_sent, "error": None}
        except Exception as e:
            return {"action": "sp_created", "teams": teams_sent, "error": f"SP write failed: {e}"}

    sp_new_tasks    = [_write_new_secret(res) for res in jira_results if not isinstance(res, Exception)]
    sp_new_results  = await _run_batched(sp_new_tasks, SP_WRITE_BATCH)

    for res in sp_new_results:
        if isinstance(res, Exception):
            summary["errors"].append(f"SP write batch error: {res}")
            continue
        if res.get("error"):
            summary["errors"].append(res["error"])
        else:
            summary["sharepointCreated"] += 1
            if res.get("teams"):
                summary["newTeamsAlerts"] += 1

    # ── PHASE 3: Handle B0 new secrets — SP row only, no Jira ────────────────
    b0_new = [c for c in new_secrets if c["bucket"] == "B0"]

    async def _write_b0(c: dict):
        try:
            await write_sharepoint_row(None, {
                "Title":             c["app_id"],
                "AppName":           c["app_name"],
                "SecretID":          c["secret_id"],
                "SecretDescription": c["secret_desc"],
                "ExpirationDate":    c["expiration"],
                "ExpiryNotice":      _expiry_notice(c["days"]),
                "LastChecked":       today,
                "ExpiryBucket":      "B0",
                "AlertStatus":       "Monitoring",
            })
            return {"error": None}
        except Exception as e:
            return {"error": str(e)}

    b0_results = await _run_batched([_write_b0(c) for c in b0_new], SP_WRITE_BATCH)
    for res in b0_results:
        if isinstance(res, Exception):
            summary["errors"].append(f"B0 write error: {res}")
        elif res.get("error"):
            summary["errors"].append(res["error"])
        else:
            summary["sharepointCreated"] += 1

    # ── PHASE 4: Handle existing secrets (batched) ────────────────────────────
    async def _process_existing(c: dict, existing: dict):
        try:
            result = await _handle_existing_secret(
                c, c["bucket"], existing, today, summary,
                write_sharepoint_row, create_jira_ticket,
                get_jira_issue, add_jira_comment, send_teams_alert,
            )
            return result
        except Exception as e:
            return {"error": f"AppID={c['app_id']} SecretID={c['secret_id']}: {e}"}

    existing_tasks   = [_process_existing(c, ex) for c, ex in existing_secrets]
    existing_results = await _run_batched(existing_tasks, SP_WRITE_BATCH)

    for res in existing_results:
        if isinstance(res, Exception):
            summary["errors"].append(f"Existing batch error: {res}")
        elif res and res.get("error"):
            summary["errors"].append(res["error"])
        elif res:
            if res.get("sp_updated"):   summary["sharepointUpdated"] += 1
            if res.get("jira_created"): summary["newJiraTickets"]    += 1
            if res.get("jira_comment"): summary["jiraComments"]      += 1
            if res.get("teams_sent"):   summary["newTeamsAlerts"]    += 1

    return summary


# ─────────────────────────────────────────────────────────────────────────────
# EXISTING SECRET LOGIC
# ─────────────────────────────────────────────────────────────────────────────

async def _handle_existing_secret(
    c: dict, bucket: str, existing: dict, today: str, summary: dict,
    write_sharepoint_row, create_jira_ticket, get_jira_issue,
    add_jira_comment, send_teams_alert,
) -> dict:
    f            = existing.get("fields", {})
    item_id      = existing.get("id")
    alert_status = f.get("AlertStatus", "")
    jira_key     = f.get("JiraTicketKey", "")
    notice       = _expiry_notice(c["days"])
    result       = {"sp_updated": False, "jira_created": False,
                    "jira_comment": False, "teams_sent": False, "error": None}

    if alert_status in MONITOR_SKIP_STATUSES:
        if alert_status == "RotatedPendingDeployment":
            await write_sharepoint_row(item_id, {"ExpiryNotice": notice, "LastChecked": today})
            result["sp_updated"] = True
        return result

    if bucket in ("B0", "Ignore"):
        return result

    # Self-heal missing Jira ticket
    if not jira_key and bucket in SEVERITY_MAP:
        sev   = SEVERITY_MAP[bucket]
        issue = await create_jira_ticket(
            app_name=c["app_name"], app_id=c["app_id"],
            secret_id=c["secret_id"], secret_description=c["secret_desc"],
            expiration_date=c["expiration"], days_remaining=c["days"],
            severity=sev["severity"], priority=sev["priority"],
            extra_note="Self-healed — previous ticket reference was missing.",
        )
        jira_key = issue.get("issue_key", "")
        if jira_key:
            result["jira_created"] = True

    jira_open = True
    if jira_key:
        issue_status = await get_jira_issue(jira_key)
        status_name  = (issue_status.get("status") or "").strip().lower()
        jira_open    = status_name not in CLOSED_NAMES

    if jira_key and not jira_open:
        await write_sharepoint_row(item_id, {"ExpiryNotice": notice, "LastChecked": today})
        result["sp_updated"] = True
        return result

    current_stage  = BUCKET_STAGE.get(bucket)
    existing_stage = STATUS_STAGE.get(alert_status, 0)

    if current_stage is not None and current_stage > existing_stage:
        sev = SEVERITY_MAP[bucket]

        if jira_key:
            await add_jira_comment(jira_key, _escalation_comment(sev["severity"], c))
            result["jira_comment"] = True

        existing_history = f.get("AlertHistory", "")
        new_event        = f"[{today}] Escalated to severity {bucket}. Teams alert sent."
        updated_history  = f"{existing_history}\n{new_event}".strip()

        update_fields: dict[str, str] = {
            "LastChecked":  today,
            "ExpiryNotice": notice,
            "AlertHistory": updated_history,
            "ExpiryBucket": bucket,
        }
        if jira_key:
            update_fields["JiraTicketKey"] = jira_key
            if "JiraTicketCreatedDate" not in f:
                update_fields["JiraTicketCreatedDate"] = today

        if bucket != "P3":
            text   = _teams_text(sev["severity"], c, jira_key)
            res_t  = await send_teams_alert(text)
            if res_t.get("success"):
                update_fields["AlertStatus"]   = ALERT_STATUS_FOR_BUCKET[bucket]
                update_fields["AlertSentDate"] = today
                result["teams_sent"] = True
            else:
                result["error"] = f"send_teams_alert failed: {res_t}"
        else:
            update_fields["AlertStatus"] = ALERT_STATUS_FOR_BUCKET[bucket]

        await write_sharepoint_row(item_id, update_fields)
        result["sp_updated"] = True

    else:
        update_fields = {
            "LastChecked":  today,
            "ExpiryNotice": notice,
            "ExpiryBucket": bucket,
        }
        if jira_key:
            update_fields["JiraTicketKey"] = jira_key
        await write_sharepoint_row(item_id, update_fields)
        result["sp_updated"] = True

    return result
