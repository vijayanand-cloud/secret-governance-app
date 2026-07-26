"""
decision_engine.py — Secret Monitoring Decision Engine (Container 2)
=====================================================================
Changes in this version:
  - Fully dynamic pagination — no hardcoded $top, works for any list size
  - Batch concurrent SharePoint writes (10 in parallel)
  - Batch concurrent Jira ticket creation (5 in parallel)
  - Sequential Teams alerts (one per run, no batching needed)
  - Zero changes needed as list grows — fully self-adapting
  - OWNER-EMAIL → OWNER-EMAILS (comma-separated) for multi-owner support
    owner_email param renamed to owner_emails (list[str]) — KV value parsed
    at call site in main.py; any-of-list match against AppOwners column.

  - BUCKET SCHEME REVISED (P0 removed, renumbered P1-P5):
      P1  0-3 days   CRITICAL     Teams alert, WITH tagging of a specific person
      P2  4-7 days   CRITICAL     Teams alert, WITHOUT tagging
      P3  8-30 days  WARNING      Teams alert + Jira ticket
      P4  31-60 days INFORMATION  Jira ticket only (no Teams)
      P5  61+ days   -            Safe — logged only, no SharePoint row, no alert
                                   (this is what P4 used to mean before this
                                   renumbering; behavior unchanged, just renamed)
    This replaces the short-lived P0/P1 split from the previous version —
    P0 is gone; everything shifted up by one number instead.

  - TEAMS TAGGING (NEW): P1 alerts now @mention a specific person, whose
    email is read from Key Vault (TEAMS-TAG-EMAIL). Adaptive Card mention
    entities are resolved by email/UPN via the msteams entity format.

  - SECRET VALIDITY PERIOD FROM KEY VAULT (NEW): the number of months a
    newly rotated secret stays valid for was previously hardcoded to 12
    in runbook_rotation.py's create_azure_secret() call. This is a
    DIFFERENT file (rotation happens in runbook_rotation.py, not here) —
    see that file for the actual change. Noted here since it was
    discussed together with the bucket changes.

  - FILTER CHANGED: OWNER-EMAILS list-matching → ManualAppOwners non-blank
    (NEW): monitoring previously only acted on rows whose AppOwners
    matched one of a fixed list configured in Key Vault (OWNER-EMAILS).
    That meant filling in ManualAppOwners on a SharePoint row had NO
    effect on whether monitoring raised a Jira ticket or Teams alert for
    it — the two columns were unrelated as far as this file was
    concerned. Monitoring now gates on ManualAppOwners being non-blank
    instead, both for existing SharePoint rows and for brand-new secrets
    (checked via whether ANY existing row for that app_id already has
    ManualAppOwners filled in). owner_emails/owner_email are still
    accepted as parameters for backwards compatibility but are IGNORED
    by default — set manual_owners_only=False at the call site in
    main.py to fall back to the old AppOwners/OWNER-EMAILS behavior.

  - P5 NOW LANDS IN SecretAlertRegistry (matches runbook_discovery.py's
    v10.2 one-time change): previously P5 rows never reached this file's
    main loop at all, since discovery routed them to IgnoredSecretRegistry.
    Now that discovery writes P5 into SecretAlertRegistry, _handle_existing_
    secret's P5/Ignore branch was fixed — it previously returned immediately
    with NO SharePoint write at all when it saw a P5/Ignore bucket, meaning
    a P5 row's ExpiryBucket/ExpiryNotice/ExpirationDate never refreshed as
    time passed, even once the secret had genuinely aged into P4. It now
    still writes those three fields every run (keeping the bucket-transition
    comparison on a LATER run accurate) while still correctly sending no
    alert and creating no ticket for P5/Ignore.

  - MANUALAPPOWNERS APP-WIDE PROPAGATION (NEW): app ownership is a property
    of the App Registration, not of any one secret — every secret under the
    same app belongs to the same app. If a human fills in ManualAppOwners
    on just ONE secret's row, every OTHER row for that same app_id is now
    automatically backfilled with the same value on the next monitoring
    run, rather than staying blank until someone manually fills in every
    row individually. Runs BEFORE the ownership filter so a sibling row
    backfilled this run is treated as actionable in the SAME run.

  - LITERAL P1/P2/P3/P4 JIRA PRIORITIES (NEW, explicit client requirement):
    SEVERITY_MAP's priority field for P1-P4 is now the literal bucket name
    ("P1"/"P2"/"P3"/"P4"), not Jira's default Highest/High/Medium/Low
    scheme. REQUIRES priorities named exactly "P1"/"P2"/"P3"/"P4" to already
    exist in the Jira project's priority scheme — if they don't, ticket
    creation fails with a 400 from Jira's API. ExpiredManualReview is
    unchanged (still "Highest") — it is not one of the four buckets this
    requirement covers.

  - BLOCKED / AWAITING REPORTER — PAUSED, NOT TERMINAL (NEW): matches the
    two new statuses main.py's jira-status-update endpoint can now set
    (see that file). A row in either state is skipped by monitoring's
    normal escalation/alert logic (same treatment as the true terminal
    statuses) but still gets ExpiryNotice/LastChecked refreshed each run so
    it doesn't look abandoned, and resumes normal monitoring once the Jira
    ticket moves to a different status.
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
    """
    P1  0-3 days   CRITICAL     (most urgent — Teams alert WITH tagging)
    P2  4-7 days   CRITICAL     (Teams alert WITHOUT tagging)
    P3  8-30 days  WARNING      (Teams alert + Jira ticket)
    P4  31-60 days INFORMATION  (Jira ticket only)
    P5  61+ days   SAFE         (logged only, no SharePoint row)
    """
    if days >= 61:       return "P5"
    if 31 <= days <= 60: return "P4"
    if 8  <= days <= 30: return "P3"
    if 4  <= days <= 7:  return "P2"
    if 0  <= days <= 3:  return "P1"
    if -7 <= days <= -1: return "ExpiredManualReview"
    return "Ignore"

# ─────────────────────────────────────────────────────────────────────────────
# STATE MAPS
# ─────────────────────────────────────────────────────────────────────────────

TERMINAL_STATUSES    = {"Rotated", "Ignored", "Resolved"}
# NEW — PAUSED, not permanently terminal. A row here is expected to resume
# normal monitoring once its Jira ticket moves to a different status (the
# jira-status-update endpoint in main.py is what moves it OUT of this state
# again, same mechanism that put it here). Distinct from TERMINAL_STATUSES:
# terminal rows are done forever; paused rows are just quiet for now.
PAUSED_STATUSES       = {"Blocked", "AwaitingReporter"}
MONITOR_SKIP_STATUSES = TERMINAL_STATUSES | PAUSED_STATUSES | {"RotatedPendingDeployment"}
CLOSED_NAMES         = {"done", "closed", "resolved"}

# Stage numbers determine escalation direction — higher stage always wins
# when comparing against a row's current status, so a secret can only ever
# escalate (never silently de-escalate back to a lower-urgency status).
# P1 (0-3 days) is now the highest/most urgent stage.
BUCKET_STAGE = {"P4": 1, "P3": 2, "P2": 3, "P1": 4, "ExpiredManualReview": 5}
STATUS_STAGE = {
    "JiraRaised": 1, "TeamsAlerted": 2,
    "Escalated": 3, "CriticalTagged": 4,
    "Expired": 5, "ExpiredManualReview": 5,
}

# What AlertStatus gets set to when a bucket's action succeeds.
ALERT_STATUS_FOR_BUCKET = {
    "P4": "JiraRaised",       # Jira ticket only
    "P3": "TeamsAlerted",     # Teams + Jira — TeamsAlerted covers both since
                              # both actions happen together for P3
    "P2": "Escalated",        # Teams alert, no tagging
    "P1": "CriticalTagged",   # Teams alert WITH tagging — the new top tier
    "ExpiredManualReview": "ExpiredManualReview",
}

SEVERITY_MAP = {
    # NEW: priority is now the LITERAL bucket name ("P1"/"P2"/"P3"/"P4"), not
    # Jira's default Highest/High/Medium/Low scheme — explicit client
    # requirement. This REQUIRES priorities named exactly "P1", "P2", "P3",
    # "P4" to already exist in the Jira project's priority scheme (Jira
    # Settings → Issues → Priorities, or the project's priority scheme) —
    # if they don't exist yet, ticket creation will fail with a 400 from
    # Jira's API rather than silently falling back to a default.
    # ExpiredManualReview is NOT one of the four buckets covered by this
    # requirement — it keeps Jira's standard "Highest" priority, unchanged.
    "P4": {"severity": "INFORMATION", "priority": "P4"},
    "P3": {"severity": "WARNING",     "priority": "P3"},
    "P2": {"severity": "CRITICAL",    "priority": "P2"},
    "P1": {"severity": "CRITICAL",    "priority": "P1"},
    "ExpiredManualReview": {"severity": "EXPIRED", "priority": "Highest"},
}

TEAMS_HEADERS = {
    "WARNING":  "⚠️ WARNING",
    "CRITICAL": "🚨 CRITICAL",
    "EXPIRED":  "⛔ EXPIRED — MANUAL REVIEW REQUIRED",
}

# Which buckets get a Teams alert at all, and whether that alert tags a
# specific person. P4 (Jira-only) and ExpiredManualReview (ticket-only,
# handled separately) do NOT send Teams alerts.
TEAMS_ALERT_BUCKETS       = {"P1", "P2", "P3"}
TEAMS_TAG_BUCKETS         = {"P1"}   # only P1 tags a specific person

# Which buckets create/maintain a Jira ticket. P1 and P2 are Teams-only —
# no Jira ticket at that stage. A Jira ticket only gets raised once a
# secret reaches P3 (or if it's already expired — ExpiredManualReview).
JIRA_TICKET_BUCKETS       = {"P3", "P4", "ExpiredManualReview"}

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
    bucket = c.get("bucket")
    if severity == "EXPIRED":
        action_req = "Password has ALREADY EXPIRED. A ticket has been raised for manual review."
    elif bucket in ("P1", "P2"):
        action_req = "This secret is scheduled for AUTO-ROTATION. No manual rotation is needed yet."
    elif bucket == "P3":
        action_req = "This secret is scheduled for AUTO-ROTATION. A Jira ticket has also been raised for tracking."
    else:
        action_req = "Rotate this secret and update all dependent services."
    return (
        f"{header} — Azure Secret Expiry Alert\n"
        f"App Registration: {c['app_name']}\nApp ID: {c['app_id']}\n"
        f"Secret ID: {c['secret_id']}\nSecret Description: {c['secret_desc']}\n"
        f"Expiry Date: {c['expiration']}\n{days_line}\n"
        f"Jira Ticket: {jira_key or 'N/A'}\nAction Required: {action_req}"
    )

def _build_teams_mention_payload(alert_text: str, tag_email: str | None) -> dict:
    """
    Builds a Teams Adaptive Card payload. If tag_email is provided, adds an
    @mention entity that Teams resolves by email/UPN — this is the standard
    way to @mention a specific person via an incoming webhook (no need to
    know their internal Teams/AAD object ID ahead of time; Teams resolves
    the mention against the tenant directory by the email/UPN given).
    """
    body_items = [{"type": "TextBlock", "text": alert_text, "wrap": True}]
    msteams_entities = []

    if tag_email:
        mention_text = f"<at>{tag_email}</at>"
        body_items.append({"type": "TextBlock", "text": f"Attention: {mention_text}", "wrap": True})
        msteams_entities.append({
            "type": "mention",
            "text": mention_text,
            "mentioned": {
                "id": tag_email,
                "name": tag_email,
            },
        })

    card_content = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": body_items,
    }
    if msteams_entities:
        card_content["msteams"] = {"entities": msteams_entities}

    return {
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": card_content,
        }]
    }

def _escalation_comment(severity: str, c: dict) -> str:
    days = c["days"]
    days_text = f"expired {abs(days)} days ago" if days < 0 else f"now has {days} days remaining"
    bucket = c.get("bucket")
    if severity == "EXPIRED":
        action_req = "MANUAL REVIEW REQUIRED. This secret will NOT be auto-rotated."
    elif bucket in ("P1", "P2", "P3", "P4"):
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
        app_id      = app.get("appId")
        app_name    = app.get("displayName") or "Unknown"
        creds       = app.get("passwordCredentials") or []
        # NEW — carries the tenant this app was actually fetched from
        # (main.py's fetch_azure_secrets() now scans multiple tenants and
        # tags each app with _sourceTenantId, matching runbook_discovery.py's
        # own pattern). Falls back to "" if somehow absent, so a caller that
        # doesn't set this doesn't crash — write_sharepoint_row's own
        # fallback to GRAPH_TENANT_ID takes over in that case.
        source_tenant_id = app.get("_sourceTenantId", "")
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
                "tenant_id":   source_tenant_id,
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
    fetch_azure_secrets:    Callable[[], Awaitable[dict]],
    get_sharepoint_state:   Callable[[], Awaitable[dict]],
    write_sharepoint_row:   Callable[..., Awaitable[dict]],
    create_jira_ticket:     Callable[..., Awaitable[dict]],
    get_jira_issue:         Callable[[str], Awaitable[dict]],
    add_jira_comment:       Callable[[str, str], Awaitable[dict]],
    send_teams_alert:       Callable[..., Awaitable[dict]],
    move_secret_to_ignored: Callable[..., Awaitable[dict]] | None = None,  # NEW — -8-day abandoned-secret move
    owner_emails:           list[str] | None = None,   # DEPRECATED — see manual_owners_only below
    owner_email:            str = "",                  # DEPRECATED — see manual_owners_only below
    fetch_app_owners:       Callable[[str], Awaitable[str]] | None = None,  # legacy — not used
    get_owned_app_ids:      Callable[[], Awaitable[set]] | None = None,     # legacy — not used
    teams_tag_email:        str = "",                  # person to @mention on P1 alerts (from KV)
    manual_owners_only:     bool = True,                # NEW — filter is now "does ManualAppOwners
                                                         # have anything in it", not an owner-email
                                                         # match against AppOwners. owner_emails/
                                                         # owner_email are IGNORED when this is True
                                                         # (the default) — kept as parameters only so
                                                         # main.py doesn't need to change its call site
                                                         # signature immediately. Set False to restore
                                                         # the old AppOwners/OWNER_EMAILS matching.
) -> dict:
    now   = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    summary: dict[str, Any] = {
        "runDate": today,
        "secretsScanned": 0,
        "totalsByBucket":  {b: 0 for b in ["P5", "P4", "P3", "P2", "P1", "ExpiredManualReview", "Ignore"]},
        "p5LoggedOnly":    0,   # P5 secrets — logged only, no SharePoint entry
        "skippedNotOwned": 0,   # secrets skipped — app not owned by owner_email
        "newJiraTickets":  0,
        "newTeamsAlerts":  0,
        "jiraComments":    0,
        "sharepointCreated": 0,
        "sharepointUpdated": 0,
        "manualOwnersPropagated": 0,   # NEW — sibling rows backfilled with an app-wide ManualAppOwners value
        "movedToIgnored": 0,           # NEW — abandoned secrets (-8+ days, no ticket or Canceled) moved to IgnoredSecretRegistry
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

    # ── NEW: propagate ManualAppOwners app-wide, BEFORE filtering ─────────────
    # App ownership is a property of the APP REGISTRATION, not of any one
    # secret — every secret under the same app belongs to the same app. If a
    # human fills in ManualAppOwners on just ONE secret's row, every OTHER
    # row for that same app_id should get the same value. This runs BEFORE
    # the ownership filter below so a sibling row that gets backfilled THIS
    # run is correctly treated as actionable in the SAME run, not left
    # waiting for a second run to notice the propagated value.
    app_manual_owners_original: dict[str, str] = {}
    for item in sp_data.get("items", []):
        f      = item.get("fields", {})
        app_id = f.get("Title", "")
        manual = (f.get("ManualAppOwners") or "").strip()
        if app_id and manual and app_id not in app_manual_owners_original:
            app_manual_owners_original[app_id] = manual

    propagate_ops: list[tuple[str, dict]] = []   # (item_id, fields) pairs
    for item in sp_data.get("items", []):
        f       = item.get("fields", {})
        app_id  = f.get("Title", "")
        item_id = item.get("id")
        current = (f.get("ManualAppOwners") or "").strip()
        best    = app_manual_owners_original.get(app_id, "")
        if best and not current:
            propagate_ops.append((item_id, {"ManualAppOwners": best}))
            # Update the IN-MEMORY copy too, so every check further down this
            # same run (filtering, sp_app_owners, sp_index) sees the
            # propagated value immediately rather than the stale blank one.
            f["ManualAppOwners"] = best

    if propagate_ops:
        print(f"[INFO] Propagating ManualAppOwners to {len(propagate_ops)} sibling row(s) "
              f"across {len(app_manual_owners_original)} app(s) with an owner set")
        propagate_tasks = [write_sharepoint_row(iid, flds) for iid, flds in propagate_ops]
        propagate_results = await _run_batched(propagate_tasks, SP_WRITE_BATCH)
        propagate_ok = sum(1 for r in propagate_results if not isinstance(r, Exception))
        summary["manualOwnersPropagated"] = propagate_ok
        for r in propagate_results:
            if isinstance(r, Exception):
                summary["errors"].append(f"ManualAppOwners propagation failed: {r}")
    else:
        summary["manualOwnersPropagated"] = 0

    # ── Build SharePoint index ────────────────────────────────────────────────
    # FILTER CHANGE: monitoring now only processes rows where ManualAppOwners
    # is non-blank — this is a deliberate opt-in gate, not the old "does
    # AppOwners match one of a fixed OWNER_EMAILS list from Key Vault" check.
    # ManualAppOwners is admin-filled per app (see runbook_discovery.py — it
    # is the one column discovery itself never writes to), so a row only
    # becomes actionable once a human has explicitly marked that app for
    # monitoring/rotation. owner_emails/owner_email are ignored entirely when
    # manual_owners_only is True (the default). Thanks to the propagation
    # step just above, a sibling row backfilled THIS run is already reflected
    # in sp_data's in-memory fields by the time this filter runs.
    if manual_owners_only:
        effective_owners: list[str] = []   # unused in this mode, kept for the old branch below
    elif owner_emails:
        effective_owners = [e.strip().lower() for e in owner_emails if e.strip()]
    elif owner_email:
        effective_owners = [owner_email.strip().lower()]
    else:
        effective_owners = []   # no filter — process all rows

    sp_index: dict[tuple[str, str], dict] = {}
    skipped_not_owned = 0
    for item in sp_data.get("items", []):
        f = item.get("fields", {})

        if manual_owners_only:
            manual_owners = (f.get("ManualAppOwners") or "").strip()
            if not manual_owners:
                skipped_not_owned += 1
                continue
        elif effective_owners:
            app_owners = (f.get("AppOwners") or "").lower()
            # Row passes if ANY of the owner emails appears in AppOwners
            if not any(email in app_owners for email in effective_owners):
                skipped_not_owned += 1
                continue

        sp_index[(f.get("Title"), f.get("SecretID"))] = item

    summary["skippedNotOwned"] = skipped_not_owned
    if skipped_not_owned:
        if manual_owners_only:
            print(f"[INFO] Skipped {skipped_not_owned} rows — ManualAppOwners is blank")
        else:
            print(f"[INFO] Skipped {skipped_not_owned} rows — not owned by any of: {effective_owners}")

    # ── Build candidates ──────────────────────────────────────────────────────
    candidates, build_errors = _build_candidates(azure_data.get("applications", []), now)
    summary["errors"].extend(build_errors)
    summary["secretsScanned"] = len(candidates)

    for c in candidates:
        summary["totalsByBucket"][c["bucket"]] += 1

    # ── Build app ManualAppOwners map from SP for ownership check on new secrets ─
    # Keyed off ManualAppOwners now, not AppOwners — see the FILTER CHANGE note
    # above. A brand-new secret for an app that already has ManualAppOwners
    # filled in on ANY of its existing rows is treated as actionable, same as
    # discovery/rotation already treat ManualAppOwners as an app-level (not
    # per-secret) signal.
    sp_app_owners: dict[str, str] = {}
    for item in sp_data.get("items", []):
        f      = item.get("fields", {})
        app_id = f.get("Title", "")
        if manual_owners_only:
            owners = (f.get("ManualAppOwners") or "").strip()
        else:
            owners = (f.get("AppOwners") or "").strip()
        if app_id and owners and app_id not in sp_app_owners:
            sp_app_owners[app_id] = owners.lower()

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
    # Only P3/P4/ExpiredManualReview raise a Jira ticket. P1/P2 are
    # Teams-only at this stage — a ticket only appears once the secret
    # ages into P3 on a later run (handled by the escalation logic in
    # _handle_existing_secret for rows that already exist).
    def _is_owned_new(c: dict) -> bool:
        if manual_owners_only:
            # A new secret is actionable only if ITS app already has a
            # non-blank ManualAppOwners on some existing row. A brand-new
            # app with no rows at all yet has no ManualAppOwners anywhere,
            # so it is correctly NOT actionable until an admin fills that
            # column in on at least one of its rows (this matches how
            # runbook_discovery.py leaves ManualAppOwners blank on every
            # newly-created row, active or recovered).
            return c["app_id"] in sp_app_owners
        if not effective_owners:
            return True
        app_owners = sp_app_owners.get(c["app_id"], "")
        if not app_owners:
            return False
        return any(email in app_owners for email in effective_owners)

    actionable_new = [
        c for c in new_secrets
        if c["bucket"] not in ("P5", "Ignore") and _is_owned_new(c)
    ]
    skipped_new_not_owned = len([
        c for c in new_secrets
        if c["bucket"] not in ("P5", "Ignore") and not _is_owned_new(c)
    ])
    if skipped_new_not_owned:
        summary["skippedNotOwned"] += skipped_new_not_owned
        if manual_owners_only:
            print(f"[INFO] Skipped {skipped_new_not_owned} new secrets — app has no ManualAppOwners set")
        else:
            print(f"[INFO] Skipped {skipped_new_not_owned} new secrets — app not owned by {effective_owners}")

    jira_bound_new = [c for c in actionable_new if c["bucket"] in JIRA_TICKET_BUCKETS]
    teams_only_new = [c for c in actionable_new if c["bucket"] not in JIRA_TICKET_BUCKETS]

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

    jira_tasks   = [_create_ticket_for_new(c) for c in jira_bound_new]
    jira_results = await _run_batched(jira_tasks, JIRA_CREATE_BATCH)

    for res in jira_results:
        if isinstance(res, Exception):
            summary["errors"].append(f"Jira batch error: {res}")
            continue
        if res["error"]:
            summary["errors"].append(f"create_jira_ticket failed for {res['c']['app_id']}: {res['error']}")
        elif res["jira_key"]:
            summary["newJiraTickets"] += 1

    # Teams-only new secrets (P1/P2) never get a jira_key — build the same
    # result shape as jira_results so both flow through the same write path.
    teams_only_results = [
        {"c": c, "jira_key": "", "sev": SEVERITY_MAP[c["bucket"]], "error": None}
        for c in teams_only_new
    ]

    all_new_results = [r for r in jira_results if not isinstance(r, Exception)] + teams_only_results

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
            "AppOwners":          c.get("app_owners", ""),
        }
        # NEW — stamp the ACTUAL tenant this app was scanned from, not just
        # whatever write_sharepoint_row's own GRAPH_TENANT_ID fallback would
        # use. Only set if _build_candidates actually carried a tenant_id
        # through (see FIX #2 above) — an empty string here would overwrite
        # write_sharepoint_row's fallback with nothing, so we only include
        # these keys when there's a real value.
        if c.get("tenant_id"):
            fields["TenantID"]   = c["tenant_id"]
            fields["TenantName"] = c["tenant_id"]
        if jira_key:
            fields["JiraTicketCreatedDate"] = today

        teams_sent = False
        if bucket in TEAMS_ALERT_BUCKETS:
            try:
                text      = _teams_text(sev["severity"], c, jira_key)
                tag_email = teams_tag_email if bucket in TEAMS_TAG_BUCKETS else None
                result    = await send_teams_alert(text, tag_email=tag_email)
                if result.get("success"):
                    fields["AlertStatus"]   = ALERT_STATUS_FOR_BUCKET[bucket]
                    fields["AlertSentDate"] = today
                    teams_sent = True
                else:
                    fields["AlertStatus"] = ALERT_STATUS_FOR_BUCKET.get(bucket, "JiraRaised")
            except Exception as e:
                fields["AlertStatus"] = ALERT_STATUS_FOR_BUCKET.get(bucket, "JiraRaised")
                return {"action": "sp_created", "teams": False, "error": f"Teams alert failed: {e}"}
        else:
            fields["AlertStatus"] = ALERT_STATUS_FOR_BUCKET.get(bucket, "JiraRaised")

        try:
            await write_sharepoint_row(None, fields)
            return {"action": "sp_created", "teams": teams_sent, "error": None}
        except Exception as e:
            return {"action": "sp_created", "teams": teams_sent, "error": f"SP write failed: {e}"}

    sp_new_tasks    = [_write_new_secret(res) for res in all_new_results]
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

    # ── PHASE 3: Handle P5 new secrets — log only, NO SharePoint entry ─────────
    p5_new = [c for c in new_secrets if c["bucket"] == "P5"]
    if p5_new:
        summary["p5LoggedOnly"] += len(p5_new)
        print(f"[INFO] P5 secrets (61+ days safe): {len(p5_new)} found — logged only, no SharePoint entry")
        for c in p5_new[:5]:  # log first 5 for visibility
            print(f"  P5: {c['app_name']} ({c['app_id']}) — expires in {c['days']} days")

    # ── PHASE 4: Handle existing secrets (batched) ────────────────────────────
    async def _process_existing(c: dict, existing: dict):
        try:
            result = await _handle_existing_secret(
                c, c["bucket"], existing, today, summary,
                write_sharepoint_row, create_jira_ticket,
                get_jira_issue, add_jira_comment, send_teams_alert,
                teams_tag_email, move_secret_to_ignored,
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
            if res.get("sp_updated"):     summary["sharepointUpdated"]      += 1
            if res.get("jira_created"):   summary["newJiraTickets"]         += 1
            if res.get("jira_comment"):   summary["jiraComments"]           += 1
            if res.get("teams_sent"):     summary["newTeamsAlerts"]         += 1
            if res.get("moved_to_ignored"): summary["movedToIgnored"]       += 1

    return summary


# ─────────────────────────────────────────────────────────────────────────────
# EXISTING SECRET LOGIC
# ─────────────────────────────────────────────────────────────────────────────

async def _handle_existing_secret(
    c: dict, bucket: str, existing: dict, today: str, summary: dict,
    write_sharepoint_row, create_jira_ticket, get_jira_issue,
    add_jira_comment, send_teams_alert, teams_tag_email: str = "",
    move_secret_to_ignored=None,
) -> dict:
    f            = existing.get("fields", {})
    item_id      = existing.get("id")
    alert_status = f.get("AlertStatus", "")
    jira_key     = f.get("JiraTicketKey", "")
    notice       = _expiry_notice(c["days"])
    result       = {"sp_updated": False, "jira_created": False,
                    "jira_comment": False, "teams_sent": False,
                    "moved_to_ignored": False, "error": None}

    if alert_status in MONITOR_SKIP_STATUSES:
        # RotatedPendingDeployment and the new PAUSED_STATUSES (Blocked,
        # AwaitingReporter) still get their ExpiryNotice/LastChecked
        # refreshed each run — so the row doesn't look abandoned/stale in
        # SharePoint — but get NO alert, ticket, or escalation activity.
        # True TERMINAL_STATUSES (Rotated/Ignored/Resolved) get nothing at
        # all, since there's nothing left to keep current on a closed row.
        if alert_status == "RotatedPendingDeployment" or alert_status in PAUSED_STATUSES:
            await write_sharepoint_row(item_id, {"ExpiryNotice": notice, "LastChecked": today})
            result["sp_updated"] = True
        return result

    if bucket == "P5":
        # FIX: previously this returned immediately with NO SharePoint write
        # at all — meaning a P5 row's ExpiryBucket/ExpiryNotice/ExpirationDate
        # never refreshed as time passed, even once the secret had genuinely
        # aged into P4 or further. discovery now writes P5 secrets into
        # SecretAlertRegistry (see v10.2), so monitoring must keep those rows
        # current too, even though P5 still gets no alert and no ticket.
        # Bucket transition (e.g. P5→P4) is still correctly detected on a
        # LATER run once _handle_existing_secret sees the row already exists
        # with ExpiryBucket=P5 but the freshly computed bucket is now P4 —
        # this write is what keeps that comparison accurate.
        update_fields = {
            "LastChecked":     today,
            "ExpiryNotice":    notice,
            "ExpiryBucket":    bucket,
            "ExpirationDate":  c["expiration"],
        }
        await write_sharepoint_row(item_id, update_fields)
        result["sp_updated"] = True
        return result

    if bucket == "Ignore":
        # NEW — the -8-DAY ABANDONMENT CHECK. A secret crossing into "Ignore"
        # (8+ days past expiry) is NOT automatically moved to
        # IgnoredSecretRegistry purely on day count — that would risk yanking
        # a secret someone is actively rotating right now out of view. The
        # actual decision is based on whether there's still a live, open
        # Jira ticket for it:
        #
        #   - No JiraTicketKey at all           → genuinely abandoned, MOVE
        #   - Ticket status is Canceled          → explicitly abandoned, MOVE
        #   - Ticket status is Done/Resolved     → shouldn't still be here if
        #                                          the Jira→SharePoint sync
        #                                          worked (should already be
        #                                          Rotated) — flag as a
        #                                          possible sync-gap anomaly,
        #                                          do NOT move, stays visible
        #   - Ticket is In Progress/To Do/
        #     Blocked/Awaiting Reporter          → someone is actively
        #                                          engaged — do NOT move,
        #                                          stays visible, marked
        #                                          clearly as overdue-but-active
        #   - Any other/unrecognized status       → fail SAFE, do NOT move,
        #                                          log for manual review
        #
        # If move_secret_to_ignored wasn't provided by the caller (main.py),
        # this whole check is skipped and Ignore rows just get the same
        # plain refresh P5 gets — same as before this feature existed.
        if move_secret_to_ignored is None:
            update_fields = {
                "LastChecked":     today,
                "ExpiryNotice":    notice,
                "ExpiryBucket":    bucket,
                "ExpirationDate":  c["expiration"],
            }
            await write_sharepoint_row(item_id, update_fields)
            result["sp_updated"] = True
            return result

        if not jira_key:
            move_reason = "no ticket — never actioned"
            should_move = True
            jira_status_for_note = "none"
        else:
            issue = await get_jira_issue(jira_key)
            jira_status_for_note = (issue.get("status") or "").strip()
            status_lower = jira_status_for_note.lower()
            if status_lower in ("canceled", "cancelled"):
                move_reason = f"ticket {jira_key} canceled"
                should_move = True
            elif status_lower in ("done", "resolved"):
                # This shouldn't normally happen — a Done/Resolved ticket
                # should already have flipped this row to AlertStatus=Rotated
                # via the jira-status-update sync. Finding one still sitting
                # here past -8 days suggests that sync didn't fire for this
                # ticket. Do NOT move it — flag it clearly instead so it gets
                # investigated rather than silently disappearing into Ignored
                # while still technically unrotated in SharePoint's eyes.
                should_move = False
                await write_sharepoint_row(item_id, {
                    "LastChecked":  today,
                    "ExpiryNotice": (f"⚠ SYNC GAP — Jira ticket {jira_key} is "
                                    f"'{jira_status_for_note}' but this row was never "
                                    f"marked Rotated. Check the Jira automation rule."),
                })
                result["sp_updated"] = True
                return result
            else:
                # In Progress / To Do / Blocked / Awaiting Reporter / anything
                # else recognized-but-active — someone is engaged, or the
                # status is simply not one of the abandonment signals. Fail
                # safe: do not move. Mark clearly as overdue-but-active so a
                # human reviewing SecretAlertRegistry sees both facts at once.
                should_move = False

        if not should_move:
            await write_sharepoint_row(item_id, {
                "LastChecked":  today,
                "ExpiryNotice": (f"OVERDUE {abs(c['days'])} days — ticket "
                                f"{jira_key or '(none)'} still "
                                f"'{jira_status_for_note}', not auto-ignored"),
            })
            result["sp_updated"] = True
            return result

        ignored_fields = {
            "Title":             c["app_id"],
            "AppName":           c["app_name"],
            "SecretID":          c["secret_id"],
            "SecretDescription": c["secret_desc"],
            "ExpirationDate":    c["expiration"],
            "DaysExpired":       abs(c["days"]),
            "TenantID":          c.get("tenant_id", ""),
            "TenantName":        c.get("tenant_id", ""),
            "LoggedDate":        today,
            "IgnoreReason":      f"Expired8Plus — {move_reason}",
        }
        move_result = await move_secret_to_ignored(item_id, ignored_fields, move_reason)
        if move_result.get("success"):
            result["moved_to_ignored"] = True
            result["sp_updated"] = True
        else:
            result["error"] = (f"move_secret_to_ignored failed for AppID={c['app_id']} "
                               f"SecretID={c['secret_id']}: {move_result.get('error')}")
        return result

    # Self-heal missing Jira ticket — only for buckets that are supposed to
    # have one (P3/P4/ExpiredManualReview). P1/P2 never get a ticket, so
    # there's nothing to self-heal there.
    if not jira_key and bucket in JIRA_TICKET_BUCKETS and bucket in SEVERITY_MAP:
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

        # A secret escalating INTO a Jira-ticket bucket (P3/P4) for the
        # first time needs a ticket created now, even if it started life
        # as a Teams-only P1/P2 secret with no ticket yet.
        if not jira_key and bucket in JIRA_TICKET_BUCKETS:
            issue = await create_jira_ticket(
                app_name=c["app_name"], app_id=c["app_id"],
                secret_id=c["secret_id"], secret_description=c["secret_desc"],
                expiration_date=c["expiration"], days_remaining=c["days"],
                severity=sev["severity"], priority=sev["priority"],
                extra_note="Escalated from Teams-only tier — ticket created at this stage.",
            )
            jira_key = issue.get("issue_key", "")
            if jira_key:
                result["jira_created"] = True

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

        if bucket in TEAMS_ALERT_BUCKETS:
            text      = _teams_text(sev["severity"], c, jira_key)
            tag_email = teams_tag_email if bucket in TEAMS_TAG_BUCKETS else None
            res_t     = await send_teams_alert(text, tag_email=tag_email)
            if res_t.get("success"):
                update_fields["AlertStatus"]   = ALERT_STATUS_FOR_BUCKET[bucket]
                update_fields["AlertSentDate"] = today
                result["teams_sent"] = True
            else:
                result["error"] = f"send_teams_alert failed: {res_t}"
        else:
            update_fields["AlertStatus"] = ALERT_STATUS_FOR_BUCKET.get(bucket, "JiraRaised")

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
