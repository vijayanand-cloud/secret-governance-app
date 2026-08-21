"""
decision_engine.py - Secret Monitoring Decision Engine (devsecops-secret-governance-monitor-mcp)
=====================================================================
Changes in this version:
  - Fully dynamic pagination - no hardcoded $top, works for any list size
  - Batch concurrent SharePoint writes (10 in parallel)
  - Batch concurrent Jira ticket creation (5 in parallel)
  - Sequential Teams alerts (one per run, no batching needed)
  - Zero changes needed as list grows - fully self-adapting
  - OWNER-EMAIL → OWNER-EMAILS (comma-separated) for multi-owner support
    owner_email param renamed to owner_emails (list[str]) - KV value parsed
    at call site in main.py; any-of-list match against AppOwners column.
 
  - BUCKET SCHEME (CORRECTED - see fix note below):
      P1  0-3 days   CRITICAL     Jira ticket + Teams alert, WITH tagging
      P2  4-7 days   CRITICAL     Jira ticket + Teams alert, WITHOUT tagging
      P3  8-30 days  WARNING      Jira ticket + Teams alert
      P4  31-60 days INFORMATION  Jira ticket only (no Teams)
      P5  61+ days   -            Safe - logged only, no SharePoint row, no
                                   alert, no ticket
 
  - FIX (this version): P1/P2 WERE INCORRECTLY EXCLUDED FROM JIRA TICKETS.
    A prior version of this file had JIRA_TICKET_BUCKETS = {"P3", "P4",
    "ExpiredManualReview"} - meaning a P1 (0-3 day, most urgent) or P2
    (4-7 day) secret got a Teams alert but NO Jira ticket at all, even
    though the actual requirement is that every bucket except P5 gets a
    ticket. This was confirmed in production: a secret with 4 days
    remaining (P2) sent a correctly-worded CRITICAL Teams alert but
    JiraTicketKey stayed permanently blank, because P2 was never in the
    set that create_jira_ticket gets called for at all - not a timing
    bug, not a stale value, the code simply never attempted it for that
    bucket. JIRA_TICKET_BUCKETS now includes P1 and P2. The _teams_text
    action-required copy for P1/P2 is also corrected - it previously said
    "no manual rotation is needed yet" / implied no ticket existed, which
    is no longer accurate now that P1/P2 always carry one.
 
  - TEAMS TAGGING: P1 alerts @mention a specific person, whose email is
    read from Key Vault (TEAMS-TAG-EMAIL). Adaptive Card mention entities
    are resolved by email/UPN via the msteams entity format.
 
  - SECRET VALIDITY PERIOD FROM KEY VAULT: the number of months a newly
    rotated secret stays valid for is read from Key Vault in
    runbook_rotation.py's create_azure_secret() call - a DIFFERENT file,
    noted here since it was discussed together with the bucket changes.
 
  - FILTER: OWNER-EMAILS list-matching → DevSecOpsOwnership non-blank.
    Monitoring gates on DevSecOpsOwnership being non-blank, both for existing
    SharePoint rows and for brand-new secrets (checked via whether ANY
    existing row for that app_id already has DevSecOpsOwnership filled in).
    owner_emails/owner_email are still accepted as parameters for
    backwards compatibility but are IGNORED by default - set
    manual_owners_only=False at the call site in main.py to fall back to
    the old AppOwners/OWNER-EMAILS behavior.
 
  - P5 LANDS IN SecretAlertRegistry (matches runbook_discovery.py's v10.2
    one-time change): P5 rows get ExpiryBucket/ExpiryNotice/ExpirationDate
    refreshed every run (so a later transition into P4 is detected
    correctly) but still get no alert and no ticket.
 
  - DevSecOpsOwnership APP-WIDE PROPAGATION: app ownership is a property of
    the App Registration, not of any one secret. If a human fills in
    DevSecOpsOwnership on just ONE secret's row, every OTHER row for that
    same app_id is automatically backfilled with the same value on the
    next monitoring run. Runs BEFORE the ownership filter so a sibling row
    backfilled this run is treated as actionable in the SAME run.
 
  - LITERAL P1/P2/P3/P4 JIRA PRIORITIES (explicit client requirement):
    SEVERITY_MAP's priority field for P1-P4 is the literal bucket name
    ("P1"/"P2"/"P3"/"P4"), not Jira's default Highest/High/Medium/Low
    scheme. REQUIRES priorities named exactly "P1"/"P2"/"P3"/"P4" to
    already exist in the Jira project's priority scheme - if they don't,
    ticket creation fails with a 400 from Jira's API. ExpiredManualReview
    is unchanged (still "Highest") - it is not one of the four buckets
    this requirement covers.
 
  - BLOCKED / AWAITING REPORTER - PAUSED, NOT TERMINAL: matches the two
    statuses main.py's jira-status-update endpoint can set. A row in
    either state is skipped by monitoring's normal escalation/alert logic
    (same treatment as the true terminal statuses) but still gets
    ExpiryNotice/LastChecked refreshed each run, and resumes normal
    monitoring once the Jira ticket moves to a different status.
 
  - BUCKET RENUMBERING TO FOUR BUCKETS (this version): the previous
    five-bucket scheme (P1=0-3, P2=4-7, P3=8-30, P4=31-60, P5=61+ safe)
    is replaced with four buckets. P1 and P2 are merged into one bucket,
    P1, covering 0-7 days total - the tagging-vs-plain-alert distinction
    that used to be the P1/P2 boundary is now an internal decision made
    by should_tag_p1(), based on the actual day count, not a separate
    bucket. P2=8-30, P3=31-60, P4=61+ safe. Jira priority names already
    existed as P1 through P4 in the Jira project, so no new priorities
    needed creating - only the day ranges each name maps to have moved.
    Fixed alongside this: Phase 3 (brand-new secrets in the safe bucket)
    previously only logged to console with NO SharePoint write at all,
    inconsistent with how an ALREADY-EXISTING row in that same bucket was
    treated (which did get written/refreshed). Both paths now write
    consistently.
"""
 
from __future__ import annotations
 
import asyncio
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any, Callable, Awaitable
 
# ─────────────────────────────────────────────────────────────────────────────
# BATCH SETTINGS 1 tune here if throttling occurs
# ─────────────────────────────────────────────────────────────────────────────
 
SP_WRITE_BATCH    = 10   # SharePoint writes in parallel
JIRA_CREATE_BATCH = 5    # Jira ticket creations in parallel
BATCH_PAUSE       = 0.5  # seconds between batches 1 avoids throttling
 
# ─────────────────────────────────────────────────────────────────────────────
# US EASTERN TIME, matches runbook_discovery.py's _format_datetime_est /
# _now_est_string exactly, so LastChecked and every other "as of now" field
# carry the same timezone and format no matter which of discovery, monitoring,
# or rotation wrote them most recently. Auto-handles EST/EDT transitions.
# ─────────────────────────────────────────────────────────────────────────────
 
_EASTERN_TZ = ZoneInfo("America/New_York")
 
def _format_datetime_est(dt: datetime) -> str:
    """12-hour EST/EDT clock string, no ISO letters. Example: "2026-07-22 07:50:53 AM"."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    eastern_dt = dt.astimezone(_EASTERN_TZ)
    return eastern_dt.strftime("%Y-%m-%d %I:%M:%S %p")
 
def _now_est_string() -> str:
    """Current moment, formatted per _format_datetime_est, used for
    LastChecked, AlertSentDate, RotationDetectedDate, JiraTicketCreatedDate."""
    return _format_datetime_est(datetime.now(timezone.utc))
 
# ─────────────────────────────────────────────────────────────────────────────
# BUCKET CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────
 
def classify_bucket(days: int) -> str:
    """
    P1  0-7 days   CRITICAL     (Jira ticket + Teams alert. 0-3 days ALSO tags a
                                  specific person; 4-7 days is a plain Teams alert
                                  with no tag. Both are still bucket P1.)
    P2  8-30 days  WARNING      (Jira ticket + Teams alert)
    P3  31-60 days INFORMATION  (Jira ticket only, no Teams alert)
    P4  61+ days   SAFE         (logged only, no alert, no ticket, no rotation)
 
    NOTE (renumbering): this replaces an earlier five-bucket scheme
    (P1=0-3, P2=4-7, P3=8-30, P4=31-60, P5=61+). P1 and P2 have been merged
    into a single P1 covering 0-7 days 1 the tagging-vs-plain-alert split
    that used to be the P1/P2 boundary is now an internal decision WITHIN
    P1, made by should_tag_p1() below, not a separate bucket. Every bucket
    name below P1 has shifted down by one number: old P3 is now P2, old P4
    is now P3, old P5 (safe) is now P4. Jira priority names in SEVERITY_MAP
    already exist as P1 through P4 in the Jira project, so no new priority
    names need to be created for this change, only the day ranges they map
    to have moved.
    """
    if days >= 61:       return "P4"
    if 31 <= days <= 60: return "P3"
    if 8  <= days <= 30: return "P2"
    if 0  <= days <= 7:  return "P1"
    if -7 <= days <= -1: return "ExpiredManualReview"
    return "Ignore"
 
def should_tag_p1(days: int) -> bool:
    """
    Within bucket P1 (0-7 days), only the more urgent half, 0-3 days, tags a
    specific person in the Teams alert. 4-7 days still sends a Teams alert
    and still raises a Jira ticket, exactly like 0-3 days does, it just does
    not tag anyone. This is a decision based on the raw day count, not on
    bucket membership, since both halves share the same bucket name P1.
    """
    return 0 <= days <= 3
 
# ─────────────────────────────────────────────────────────────────────────────
# STATE MAPS
# ─────────────────────────────────────────────────────────────────────────────
 
TERMINAL_STATUSES    = {"Rotated", "Ignored", "Resolved"}
# PAUSED, not permanently terminal. A row here is expected to resume normal
# monitoring once its Jira ticket moves to a different status (the
# jira-status-update endpoint in main.py is what moves it OUT of this state
# again, same mechanism that put it here). Distinct from TERMINAL_STATUSES:
# terminal rows are done forever; paused rows are just quiet for now.
PAUSED_STATUSES       = {"Blocked", "AwaitingReporter"}
MONITOR_SKIP_STATUSES = TERMINAL_STATUSES | PAUSED_STATUSES | {"RotatedPendingDeployment"}
CLOSED_NAMES         = {"done", "closed", "resolved"}
 
# Stage numbers determine escalation direction 1 higher stage always wins
# when comparing against a row's current status, so a secret can only ever
# escalate (never silently de-escalate back to a lower-urgency status).
# P1 (0-7 days) is the highest/most urgent stage.
BUCKET_STAGE = {"P3": 1, "P2": 2, "P1": 3, "ExpiredManualReview": 4}
STATUS_STAGE = {
    "JiraRaised": 1, "TeamsAlerted": 2,
    "Escalated": 3, "CriticalTagged": 4,
    "Expired": 5, "ExpiredManualReview": 5,
}
 
# What AlertStatus gets set to when a bucket's action succeeds.
# P1 covers BOTH the tagged (0-3 day) and untagged (4-7 day) cases 1 which
# one actually happened is decided at the point AlertStatus is set, using
# should_tag_p1() against the secret's actual day count, not hardcoded here.
ALERT_STATUS_FOR_BUCKET = {
    "P3": "JiraRaised",       # Jira ticket only
    "P2": "TeamsAlerted",     # Teams + Jira 1 TeamsAlerted covers both since
                              # both actions happen together for P2
    "P1": "Escalated",        # Teams alert (untagged, 4-7 days) + Jira ticket 1
                              # overridden to CriticalTagged below when the
                              # secret is actually in the 0-3 day tagged half
    "ExpiredManualReview": "ExpiredManualReview",
}
ALERT_STATUS_P1_TAGGED = "CriticalTagged"  # used instead of ALERT_STATUS_FOR_BUCKET["P1"]
                                            # specifically when should_tag_p1() is True
 
SEVERITY_MAP = {
    # Priority is the LITERAL bucket name ("P1"/"P2"/"P3"/"P4"), not Jira's
    # default Highest/High/Medium/Low scheme 1 explicit client requirement.
    # REQUIRES priorities named exactly "P1", "P2", "P3", "P4" to already
    # exist in the Jira project's priority scheme 1 if they don't exist
    # yet, ticket creation will fail with a 400 from Jira's API rather than
    # silently falling back to a default. These four priority NAMES are
    # unchanged by the bucket renumbering 1 only the day ranges that map to
    # each name have moved, so nothing needs to change in Jira itself.
    "P3": {"severity": "INFORMATION", "priority": "P3"},
    "P2": {"severity": "WARNING",     "priority": "P2"},
    "P1": {"severity": "CRITICAL",    "priority": "P1"},
    # ExpiredManualReview's priority is now the literal "P1" too, same tier
    # as the most urgent active bucket, since an already-expired secret is
    # at least as urgent as one about to expire. This is the ONLY change
    # for ExpiredManualReview 1 severity stays "EXPIRED" (distinct wording
    # in the ticket body/Teams text), AlertStatus stays "ExpiredManualReview"
    # (never becomes P1 in SharePoint), and it is still never auto rotated.
    "ExpiredManualReview": {"severity": "EXPIRED", "priority": "P1"},
}
 
TEAMS_HEADERS = {
    "WARNING":  "⚠️ WARNING",
    "CRITICAL": "🚨 CRITICAL",
    "EXPIRED":  "⛔ EXPIRED - MANUAL REVIEW REQUIRED",
}
 
# Which buckets get a Teams alert at all. P3 (Jira-only) and
# ExpiredManualReview (ticket-only, handled separately) do NOT send Teams
# alerts. Whether a P1 alert specifically tags someone is now a per-secret
# decision, see should_tag_p1() above, not a separate bucket membership
# check the way TEAMS_TAG_BUCKETS used to work.
TEAMS_ALERT_BUCKETS       = {"P1", "P2"}
 
# Every bucket except P4 (safe) raises/maintains a Jira ticket.
JIRA_TICKET_BUCKETS       = {"P1", "P2", "P3", "ExpiredManualReview"}
 
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
    elif bucket in ("P1", "P2", "P3"):
        # FIX: previously P1/P2 said "no manual rotation needed yet" and
        # implied no ticket existed 1 no longer accurate now that P1/P2
        # always carry a Jira ticket, same as P3. All three Teams-alert
        # buckets now share the same accurate copy: a ticket exists (or
        # will, by the time this alert is read) for tracking.
        action_req = "This secret is scheduled for AUTO-ROTATION. A Jira ticket has also been raised for tracking."
    else:
        action_req = "Rotate this secret and update all dependent services."
    return (
        f"{header} - Azure Secret Expiry Alert\n"
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
        f"ESCALATION - Secret for {c['app_name']} (Secret ID: {c['secret_id']}) "
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
        app_id        = app.get("appId")
        app_object_id = app.get("id")   # Graph's /applications/{id}/owners needs
                                          # the OBJECT id, not appId (client id) -
                                          # fetch_app_owners() below requires this
        app_name    = app.get("displayName") or "Unknown"
        creds       = app.get("passwordCredentials") or []
        # Carries the tenant this app was actually fetched from (main.py's
        # fetch_azure_secrets() scans multiple tenants and tags each app
        # with _sourceTenantId, matching runbook_discovery.py's own
        # pattern). Falls back to "" if somehow absent, so a caller that
        # doesn't set this doesn't crash 1 write_sharepoint_row's own
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
                "app_id":        app_id,
                "app_object_id": app_object_id,
                "app_name":    app_name,
                "secret_id":   cred.get("keyId"),
                "secret_desc": cred.get("displayName") or "N/A",
                "expiration":  _format_datetime_est(exp),  # EST 12hr string, matches discovery
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
# BACKUP ROTATION
# ─────────────────────────────────────────────────────────────────────────────

# Mirrors main.py's own backup_list_row_fields()/_SP_SYSTEM_FIELDS exactly -
# kept here too since this file builds the rows being backed up and main.py
# is the actual Graph HTTP boundary, same reasoning as
# _build_teams_mention_payload being duplicated between these two files.
_SP_SYSTEM_FIELDS = {
    "id", "ContentType", "Modified", "Created", "AuthorLookupId", "EditorLookupId",
    "_UIVersionString", "Attachments", "Edit", "LinkTitleNoMenu", "LinkTitle",
    "ItemChildCount", "FolderChildCount", "AppEditorLookupId", "AppAuthorLookupId", "_ComplianceFlags",
    "_ComplianceTag", "_ComplianceTagWrittenTime", "_ComplianceTagUserId",
    "_CommentCount", "_LikeCount", "_DisplayName", "OData__UIVersionString",
}

def backup_list_row_fields(source_fields: dict) -> dict:
    """Strips SharePoint system/read-only fields, keeps everything else as-is."""
    return {k: v for k, v in source_fields.items() if k not in _SP_SYSTEM_FIELDS}

async def _rotate_backup_list(
    list_label: str,
    current_items: list[dict],
    backup_list_id: str,
    get_list_state,
    create_list_row,
    delete_list_row,
    upload_backup_to_storage,   # None if Storage isn't configured - treated as "not present", not a failure
    summary: dict,
) -> bool:
    """
    Snapshots current_items (the live current state of a source list, e.g.
    SecretAlertRegistry or IgnoredSecretRegistry) into backup_list_id.

    Ordering is deliberately archive-then-write-then-delete-old, per an
    explicit requirement: the previous backup is NEVER deleted before the
    new one is safely in place.

      1. Read whatever's currently in the backup list.
      2. If it's non-empty AND a Storage upload function is configured,
         archive it there first. A Storage upload that's configured but
         actually FAILS aborts the whole run - this is a real failure of
         something expected to work, not a "not configured" case.
         If Storage genuinely isn't configured (upload_backup_to_storage is
         None), that old content is simply not archived - not an error.
      3. Write a fresh snapshot of current_items into the backup list as NEW
         items, without touching the old ones yet. If this fails partway,
         delete the new items already created (revert to exactly how the
         backup list looked before this run touched it) and abort - nothing
         downstream runs this cycle.
      4. Only once the new snapshot is fully and successfully written are the
         OLD backup-list rows deleted. A failure here is logged but NOT
         fatal - the data-safety goal (archived old + new snapshot present)
         is already met; stray old rows are a lesser problem worth fixing by
         hand, not worth aborting the run over.

    Returns True if the run should proceed, False if it should abort.
    """
    if not backup_list_id:
        print(f"[INFO] Backup rotation ({list_label}): no backup list configured - skipped.")
        return True

    try:
        existing_backup = await get_list_state(backup_list_id)
    except Exception as e:
        summary["errors"].append(
            f"Backup rotation ({list_label}): failed to read existing backup list - aborting run: {e}")
        return False

    old_items = existing_backup.get("items", [])

    if old_items:
        if upload_backup_to_storage is not None:
            blob_name = f"{list_label}_{_now_est_string().replace(' ', '_').replace(':', '-')}.csv"
            archive_result = await upload_backup_to_storage(blob_name, old_items)
            if not archive_result.get("success"):
                summary["errors"].append(
                    f"Backup rotation ({list_label}): archiving previous backup to Storage failed - "
                    f"aborting run without touching anything: {archive_result.get('error')}")
                return False
            print(f"[INFO] Backup rotation ({list_label}): archived {len(old_items)} previous "
                  f"backup row(s) to Storage as {blob_name}")
        else:
            print(f"[INFO] Backup rotation ({list_label}): Storage not configured - previous "
                  f"{len(old_items)} backup row(s) will be discarded (not archived) once the "
                  f"new snapshot is written.")

    # FIX (this version): was a plain sequential loop - 1327 rows meant 1327
    # sequential HTTP round-trips, taking minutes. Since /run's background
    # task has no active inbound HTTP request while this runs, Container
    # Apps' scale-to-zero could kill the replica mid-loop, silently dropping
    # the rest of the backup. Batched the same way every other bulk write in
    # this file already is.
    async def _create_one(row: dict):
        f = row.get("fields", {})
        secret_id = f.get("SecretID")
        app_name  = f.get("AppName")
        try:
            fields = backup_list_row_fields(f)
            created = await create_list_row(backup_list_id, fields)
            return {"item_id": created["item_id"], "error": None}
        except Exception as e:
            # Row identity captured here, not just the error string - create_list_row
            # already logs Graph's own error text plus SecretID/AppName/AlertStatus,
            # but that line alone doesn't say which of possibly many concurrent
            # failures it corresponds to without this.
            print(f"[ERROR] Backup rotation ({list_label}): row failed - "
                  f"SecretID={secret_id!r} AppName={app_name!r}: {e}")
            return {"item_id": None, "error": str(e), "secret_id": secret_id, "app_name": app_name}

    create_tasks   = [_create_one(row) for row in current_items]
    create_results = await _run_batched(create_tasks, SP_WRITE_BATCH)

    new_item_ids: list[str] = []
    failed_rows: list[dict] = []
    for res in create_results:
        if isinstance(res, Exception):
            failed_rows.append({"secret_id": None, "app_name": None, "error": str(res)})
            continue
        if res.get("error"):
            failed_rows.append({"secret_id": res.get("secret_id"), "app_name": res.get("app_name"),
                                "error": res["error"]})
            continue
        new_item_ids.append(res["item_id"])

    if failed_rows:
        # NOTE: _run_batched() runs every batch regardless of earlier failures -
        # "X/Y succeeded" is a final tally, not an early-stop point, so this no
        # longer implies the run halted partway through. failed_rows can hold
        # more than one row with more than one distinct error; the summary
        # surfaces the first one for a quick read, the full list goes to the
        # log for complete diagnosis without needing another run to reproduce it.
        first = failed_rows[0]
        summary["errors"].append(
            f"Backup rotation ({list_label}): snapshot write failed - "
            f"{len(new_item_ids)}/{len(current_items)} rows succeeded, "
            f"{len(failed_rows)} failed, reverting. First failure: "
            f"SecretID={first['secret_id']!r} AppName={first['app_name']!r}: {first['error']}")
        print(f"[ERROR] Backup rotation ({list_label}): {len(failed_rows)} row(s) failed: {failed_rows}")

        async def _delete_one_revert(item_id: str):
            try:
                await delete_list_row(backup_list_id, item_id)
                return None
            except Exception as e:
                return str(e)

        revert_tasks   = [_delete_one_revert(iid) for iid in new_item_ids]
        revert_results = await _run_batched(revert_tasks, SP_WRITE_BATCH)
        for err in revert_results:
            if isinstance(err, Exception):
                summary["errors"].append(f"Backup rotation ({list_label}): revert cleanup failed - may need manual cleanup: {err}")
            elif err:
                summary["errors"].append(f"Backup rotation ({list_label}): revert cleanup failed - may need manual cleanup: {err}")
        return False

    async def _delete_one_old(item: dict):
        try:
            await delete_list_row(backup_list_id, item["id"])
            return None
        except Exception as e:
            return f"Backup rotation ({list_label}): failed to delete old backup row {item.get('id')} (non-fatal): {e}"

    old_delete_tasks   = [_delete_one_old(item) for item in old_items]
    old_delete_results = await _run_batched(old_delete_tasks, SP_WRITE_BATCH)
    for err in old_delete_results:
        if isinstance(err, Exception):
            summary["errors"].append(f"Backup rotation ({list_label}): failed to delete an old backup row (non-fatal): {err}")
        elif err:
            summary["errors"].append(err)

    print(f"[INFO] Backup rotation ({list_label}): wrote {len(new_item_ids)} fresh row(s) "
          f"to backup list, removed {len(old_items)} old row(s).")
    return True

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
    move_secret_to_ignored: Callable[..., Awaitable[dict]] | None = None,  # -8-day abandoned-secret move
    create_ignored_row:     Callable[[dict], Awaitable[dict]] | None = None,  # NEW - brand-new secret
                                                         # already 8+ days expired -> straight to
                                                         # IgnoredSecretRegistry, no master-list row at all
    get_product_service_principal: Callable[[str], Awaitable[str | None]] | None = None,
                                                         # NEW 1 looks up a Key Vault secret literally
                                                         # named after ProductName and returns its value
                                                         # (a service principal name), or None if no such
                                                         # secret exists. See the ProductName lookup step
                                                         # below for how this is used.
    owner_emails:           list[str] | None = None,   # DEPRECATED 1 see manual_owners_only below
    owner_email:            str = "",                  # DEPRECATED 1 see manual_owners_only below
    fetch_app_owners:       Callable[[str, str], Awaitable[str]] | None = None,  # (app_object_id, tenant_id)
                                                         # -> comma-separated owner emails/names, live from
                                                         # Entra. FIX (this version): now actually wired up -
                                                         # previously accepted but never passed from main.py's
                                                         # call site, so AppOwners was unconditionally blank.
    get_owned_app_ids:      Callable[[], Awaitable[set]] | None = None,     # legacy 1 not used
    teams_tag_email:        str = "",                  # person to @mention on P1 alerts (from KV)
    manual_owners_only:     bool = True,                # filter is "does DevSecOpsOwnership have
                                                         # anything in it", not an owner-email match
                                                         # against AppOwners. owner_emails/owner_email
                                                         # are IGNORED when this is True (the default)
                                                         # 1 kept as parameters only so main.py doesn't
                                                         # need to change its call site signature
                                                         # immediately. Set False to restore the old
                                                         # AppOwners/OWNER_EMAILS matching.
    # NEW - pre-run backup rotation. All optional/independently gated: a
    # missing backup_list_id skips that list's backup entirely; a missing
    # upload_backup_to_storage skips archival but still rotates the
    # SharePoint-side backup list. See _rotate_backup_list() below.
    get_ignored_sharepoint_state: Callable[[], Awaitable[dict]] | None = None,
    move_secret_from_ignored:  Callable[..., Awaitable[dict]] | None = None,  # NEW - Feature 2 manual restore trigger
    backup_list_id:            str = "",
    ignored_backup_list_id:    str = "",
    get_list_state:             Callable[[str], Awaitable[dict]] | None = None,
    create_list_row:            Callable[[str, dict], Awaitable[dict]] | None = None,
    delete_list_row:            Callable[[str, str], Awaitable[dict]] | None = None,
    upload_backup_to_storage:   Callable[[str, list], Awaitable[dict]] | None = None,
) -> dict:
    now   = datetime.now(timezone.utc)
    today = _now_est_string()  # full EST timestamp, matches runbook_discovery.py
 
    summary: dict[str, Any] = {
        "runDate": today,
        "secretsScanned": 0,
        "totalsByBucket":  {b: 0 for b in ["P4", "P3", "P2", "P1", "ExpiredManualReview", "Ignore"]},
        "p4LoggedOnly":    0,   # P4 secrets (61+ days, safe) 1 logged only, no SharePoint entry
        "skippedNotOwned": 0,   # secrets skipped 1 app not owned by owner_email
        "newJiraTickets":  0,
        "newTeamsAlerts":  0,
        "jiraComments":    0,
        "sharepointCreated": 0,
        "sharepointUpdated": 0,
        "manualOwnersPropagated": 0,   # sibling rows backfilled with an app-wide DevSecOpsOwnership value
        "productLookupsApplied": 0,    # NEW 1 DevSecOpsOwnership set/overwritten from a ProductName lookup
        "productLookupsNotFound": 0,   # NEW 1 ProductName was filled in, but no matching KV secret exists
        "lineageMatchesFound": 0,      # NEW 1 new secrets that matched a parent row's NewSecretKeyId
        "movedToIgnored": 0,           # abandoned secrets (-8+ days, no ticket or Canceled) moved to IgnoredSecretRegistry
        "newlyIgnored": 0,             # NEW - brand-new secrets already 8+ days expired, written straight to IgnoredSecretRegistry
        "alreadyIgnoredSkipped": 0,    # FIX - secrets already sitting in IgnoredSecretRegistry, correctly recognized and not re-added
        "skippedAlreadyInIgnoredList": 0,  # NEW - secrets in ANY bucket (not just Ignore) already sitting in
                                            # IgnoredSecretRegistry via a Canceled ticket or manual override,
                                            # recognized before ticket/row creation instead of only within the
                                            # Ignore-bucket-specific check above
        "manuallyIgnored":  0,   # NEW - rows manually set to AlertStatus=Ignored on the master list, moved to IgnoredSecretRegistry
        "manuallyRestored": 0,   # NEW - IgnoredSecretRegistry rows manually un-Ignored, moved back to the master list
        "masterListBackedUp": False,   # NEW - SecretAlertRegistry successfully snapshotted before this run touched it
        "ignoredListBackedUp": False,  # NEW - IgnoredSecretRegistry successfully snapshotted before this run touched it
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

    # ── Backup rotation - BEFORE anything else touches either list ───────────
    # Must run here, before the ProductName-lookup/propagation steps just
    # below (which already write to the master list) - backing up after
    # those would snapshot already-modified data, defeating the point.
    if get_list_state is not None and create_list_row is not None and delete_list_row is not None:
        ok = await _rotate_backup_list(
            "SecretAlertRegistry", sp_data.get("items", []), backup_list_id,
            get_list_state, create_list_row, delete_list_row, upload_backup_to_storage, summary,
        )
        summary["masterListBackedUp"] = ok
        if not ok:
            summary["errors"].append("Monitoring run ABORTED - master list backup failed before any real work started.")
            return summary

        if ignored_backup_list_id and get_ignored_sharepoint_state is not None:
            try:
                ignored_data_for_backup = await get_ignored_sharepoint_state()
            except Exception as e:
                summary["errors"].append(f"Monitoring run ABORTED - could not read IgnoredSecretRegistry for backup: {e}")
                return summary
            ok = await _rotate_backup_list(
                "IgnoredSecretRegistry", ignored_data_for_backup.get("items", []), ignored_backup_list_id,
                get_list_state, create_list_row, delete_list_row, upload_backup_to_storage, summary,
            )
            summary["ignoredListBackedUp"] = ok
            if not ok:
                summary["errors"].append("Monitoring run ABORTED - ignored list backup failed before any real work started.")
                return summary
    else:
        print("[INFO] Backup rotation: get_list_state/create_list_row/delete_list_row not wired up - skipping backup entirely.")

    # ── NEW - FEATURE 2: Ignored -> master-list restore loop ─────────────────
    # Runs early - right after backup rotation, before sp_index is built and
    # before candidates are split into new_secrets/existing_secrets (both
    # still based on the sp_data snapshot fetched above). A human can change
    # IgnoredSecretRegistry's AlertStatus column to anything OTHER than
    # "Ignored" to signal "put this back". Blank/missing AlertStatus is
    # deliberately NOT treated as a restore signal - it only means the row
    # predates this column, or is a freshly-Ignored row correctly stamped
    # "Ignored" by one of the move-to-Ignored call sites (FEATURE 3).
    #
    # Restored rows land in SecretAlertRegistry with AlertStatus reset to
    # "Discovered" so the NEXT run picks them up fresh (correct bucket,
    # ticket status, etc. - none of Ignored's stale state carries over).
    # Deliberately does NOT try to fully re-evaluate the row THIS run -
    # sp_data/sp_index (built below) were already snapshotted before this
    # loop ran, so a restored row is invisible to this run's new-vs-existing
    # split. Its SecretID is added to restored_secret_ids and explicitly
    # excluded from new_secrets after the real split block below, so this
    # run doesn't ALSO try to create a duplicate "new secret" row for
    # something this loop just created in the master list.
    restored_secret_ids: set[str] = set()
    if move_secret_from_ignored is not None and get_ignored_sharepoint_state is not None:
        try:
            ignored_state_for_restore = await get_ignored_sharepoint_state()
        except Exception as e:
            summary["errors"].append(f"Could not read IgnoredSecretRegistry for restore check: {e}")
            ignored_state_for_restore = {"items": []}

        for item in ignored_state_for_restore.get("items", []):
            f_ignored = item.get("fields", {})
            ignored_alert_status = (f_ignored.get("AlertStatus") or "").strip()
            # Blank (pre-existing rows, or the column not added yet) is NOT
            # a restore signal - only an explicit non-"Ignored" value is.
            if not ignored_alert_status or ignored_alert_status == "Ignored":
                continue

            secret_id = f_ignored.get("SecretID", "")
            master_fields = {
                "Title":             f_ignored.get("Title", ""),
                "AppName":           f_ignored.get("AppName", ""),
                "SecretID":          secret_id,
                "SecretDescription": f_ignored.get("SecretDescription", ""),
                "ExpirationDate":    f_ignored.get("ExpirationDate", ""),
                "AlertStatus":       "Discovered",
                "ExpiryNotice":      (f"Restored from IgnoredSecretRegistry - AlertStatus manually "
                                      f"changed to '{ignored_alert_status}'"),
                "LastChecked":       today,
                "JiraTicketKey":     f_ignored.get("JiraTicketKey", ""),
                "TenantID":          f_ignored.get("TenantID", ""),
            }
            move_result = await move_secret_from_ignored(
                item.get("id"), master_fields,
                f"AlertStatus manually changed to '{ignored_alert_status}' in IgnoredSecretRegistry")
            if move_result.get("success"):
                summary["manuallyRestored"] += 1
                if secret_id:
                    restored_secret_ids.add(secret_id)
            else:
                summary["errors"].append(
                    f"move_secret_from_ignored (manual restore) failed for SecretID={secret_id}: "
                    f"{move_result.get('error')}")

    # ── ProductName lookup, BEFORE propagation and BEFORE filtering ───────────
    # A row can have ProductName filled in instead of DevSecOpsOwnership being
    # typed in directly. If it is, look up a Key Vault secret literally named
    # after that product (e.g. a secret called "ProductA") and use its value,
    # a service principal name, as DevSecOpsOwnership for this row. This ALWAYS
    # overwrites whatever is currently in DevSecOpsOwnership for that row 1 a
    # deliberate choice, ProductName is meant to be the team's single source
    # of truth going forward, so it always wins over a value someone may have
    # typed in directly the old way. Runs before the propagation step below,
    # so a value written here can still be propagated to sibling rows for the
    # same app in the same run.
    if get_product_service_principal is not None:
        product_lookup_ops: list[tuple[str, dict]] = []
        seen_products: dict[str, str | None] = {}  # cache 1 avoid repeat KV reads for the same product
 
        for item in sp_data.get("items", []):
            f       = item.get("fields", {})
            item_id = item.get("id")
            product = (f.get("ProductName") or "").strip()
            if not product:
                continue
 
            if product not in seen_products:
                try:
                    seen_products[product] = await get_product_service_principal(product)
                except Exception as e:
                    summary["errors"].append(f"ProductName lookup failed for {product!r}: {e}")
                    seen_products[product] = None
 
            service_principal = seen_products[product]
            if service_principal:
                product_lookup_ops.append((item_id, {"DevSecOpsOwnership": service_principal}))
                # Update in-memory too, so propagation and filtering below see
                # this immediately rather than the stale value from before.
                f["DevSecOpsOwnership"] = service_principal
            else:
                summary["productLookupsNotFound"] += 1
                log_msg = (f"[INFO] ProductName {product!r} has no matching Key Vault secret 1 "
                          f"DevSecOpsOwnership left as-is for this row")
                print(log_msg)
 
        if product_lookup_ops:
            print(f"[INFO] Applying ProductName lookups to {len(product_lookup_ops)} row(s)")
            product_tasks   = [write_sharepoint_row(iid, flds) for iid, flds in product_lookup_ops]
            product_results = await _run_batched(product_tasks, SP_WRITE_BATCH)
            product_ok = sum(1 for r in product_results if not isinstance(r, Exception))
            summary["productLookupsApplied"] = product_ok
            for r in product_results:
                if isinstance(r, Exception):
                    summary["errors"].append(f"ProductName lookup write failed: {r}")
 
    # ── Propagate DevSecOpsOwnership app-wide, BEFORE filtering ──────────────────
    # App ownership is a property of the APP REGISTRATION, not of any one
    # secret 1 every secret under the same app belongs to the same app. If a
    # human fills in DevSecOpsOwnership on just ONE secret's row, every OTHER
    # row for that same app_id should get the same value. This runs BEFORE
    # the ownership filter below so a sibling row that gets backfilled THIS
    # run is correctly treated as actionable in the SAME run, not left
    # waiting for a second run to notice the propagated value.
    app_manual_owners_original: dict[str, str] = {}
    for item in sp_data.get("items", []):
        f      = item.get("fields", {})
        app_id = f.get("Title", "")
        manual = (f.get("DevSecOpsOwnership") or "").strip()
        if app_id and manual and app_id not in app_manual_owners_original:
            app_manual_owners_original[app_id] = manual
 
    propagate_ops: list[tuple[str, dict]] = []   # (item_id, fields) pairs
    for item in sp_data.get("items", []):
        f       = item.get("fields", {})
        app_id  = f.get("Title", "")
        item_id = item.get("id")
        current = (f.get("DevSecOpsOwnership") or "").strip()
        best    = app_manual_owners_original.get(app_id, "")
        if best and not current:
            propagate_ops.append((item_id, {"DevSecOpsOwnership": best}))
            # Update the IN-MEMORY copy too, so every check further down this
            # same run (filtering, sp_app_owners, sp_index) sees the
            # propagated value immediately rather than the stale blank one.
            f["DevSecOpsOwnership"] = best
 
    if propagate_ops:
        print(f"[INFO] Propagating DevSecOpsOwnership to {len(propagate_ops)} sibling row(s) "
              f"across {len(app_manual_owners_original)} app(s) with an owner set")
        propagate_tasks = [write_sharepoint_row(iid, flds) for iid, flds in propagate_ops]
        propagate_results = await _run_batched(propagate_tasks, SP_WRITE_BATCH)
        propagate_ok = sum(1 for r in propagate_results if not isinstance(r, Exception))
        summary["manualOwnersPropagated"] = propagate_ok
        for r in propagate_results:
            if isinstance(r, Exception):
                summary["errors"].append(f"DevSecOpsOwnership propagation failed: {r}")
    else:
        summary["manualOwnersPropagated"] = 0
 
    # ── Build SharePoint index ────────────────────────────────────────────────
    # Monitoring only processes rows where DevSecOpsOwnership is non-blank 1
    # this is a deliberate opt-in gate, not the old "does AppOwners match
    # one of a fixed OWNER_EMAILS list from Key Vault" check. DevSecOpsOwnership
    # is admin-filled per app (see runbook_discovery.py 1 it is the one
    # column discovery itself never writes to), so a row only becomes
    # actionable once a human has explicitly marked that app for
    # monitoring/rotation. owner_emails/owner_email are ignored entirely
    # when manual_owners_only is True (the default). Thanks to the
    # propagation step just above, a sibling row backfilled THIS run is
    # already reflected in sp_data's in-memory fields by the time this
    # filter runs.
    if manual_owners_only:
        effective_owners: list[str] = []   # unused in this mode, kept for the old branch below
    elif owner_emails:
        effective_owners = [e.strip().lower() for e in owner_emails if e.strip()]
    elif owner_email:
        effective_owners = [owner_email.strip().lower()]
    else:
        effective_owners = []   # no filter 1 process all rows
 
    # FIX: sp_index's only job is answering "does a row already exist for this
    # secret", it must include EVERY row, owned or not. It previously excluded
    # any row whose DevSecOpsOwnership/AppOwners didn't pass the filter below,
    # which meant an existing row for an app with no owner set was invisible
    # to this lookup and looked "new" on every run. For P1-P3 that mistake was
    # harmless, actionable_new has its own separate ownership check
    # (_is_owned_new/sp_app_owners) that blocks a row from ever being created.
    # P4 has no equivalent check on its create path (see Phase 3 below), so an
    # unowned app that only ever has P4 secrets got a duplicate row created
    # every single run, forever, since sp_index could never see its existing
    # row to match against. The ownership check now only affects the
    # skippedNotOwned count below, not whether a row goes into the index.
    sp_index: dict[str, dict] = {}
    skipped_not_owned = 0
    for item in sp_data.get("items", []):
        f = item.get("fields", {})
 
        if manual_owners_only:
            if not (f.get("DevSecOpsOwnership") or "").strip():
                skipped_not_owned += 1
        elif effective_owners:
            app_owners = (f.get("AppOwners") or "").lower()
            # Row passes if ANY of the owner emails appears in AppOwners
            if not any(email in app_owners for email in effective_owners):
                skipped_not_owned += 1
 
        secret_id = f.get("SecretID")
        if secret_id:
            sp_index[secret_id] = item
 
    summary["skippedNotOwned"] = skipped_not_owned
    if skipped_not_owned:
        if manual_owners_only:
            print(f"[INFO] Skipped {skipped_not_owned} rows 1 DevSecOpsOwnership is blank")
        else:
            print(f"[INFO] Skipped {skipped_not_owned} rows 1 not owned by any of: {effective_owners}")
 
    # ── Build candidates ──────────────────────────────────────────────────────
    candidates, build_errors = _build_candidates(azure_data.get("applications", []), now)
    summary["errors"].extend(build_errors)
    summary["secretsScanned"] = len(candidates)
 
    for c in candidates:
        summary["totalsByBucket"][c["bucket"]] += 1

    # NEW - per-tenant breakdown: unique apps and total secrets scanned per
    # tenant, so a multi-tenant run's summary can be checked against a manual
    # count for each tenant separately, not just the combined total.
    tenant_apps: dict[str, set[str]] = {}
    tenant_secret_counts: dict[str, int] = {}
    for c in candidates:
        t = c.get("tenant_id") or "(unknown)"
        tenant_apps.setdefault(t, set()).add(c["app_id"])
        tenant_secret_counts[t] = tenant_secret_counts.get(t, 0) + 1
    summary["tenantBreakdown"] = {
        t: {"apps": len(tenant_apps[t]), "secrets": tenant_secret_counts[t]}
        for t in tenant_secret_counts
    }

    # ── Fetch AppOwners from Entra, once per unique app (not per secret) ──────
    # FIX (this version): AppOwners was always blank - fetch_app_owners() was
    # a real, working Graph call, but was never passed through from main.py's
    # call site, and nothing ever set a candidate's "app_owners" key. Wired up
    # here: one Graph call per unique (tenant, app object id) pair - a given
    # app can have several secrets/candidates in the same run, and there is
    # no reason to look its owners up more than once - batched the same way
    # every other Graph/SharePoint call in this file already is.
    if fetch_app_owners is not None:
        unique_apps: dict[tuple[str, str], None] = {}
        for c in candidates:
            key = (c.get("tenant_id", ""), c.get("app_object_id", ""))
            if key[1] and key not in unique_apps:
                unique_apps[key] = None

        async def _fetch_owner(key: tuple[str, str]):
            tenant_id, app_object_id = key
            try:
                owners = await fetch_app_owners(app_object_id, tenant_id)
                return key, owners
            except Exception as e:
                return key, ""

        owner_tasks   = [_fetch_owner(key) for key in unique_apps]
        owner_results = await _run_batched(owner_tasks, SP_WRITE_BATCH)
        owner_cache: dict[tuple[str, str], str] = {}
        for res in owner_results:
            if isinstance(res, Exception):
                summary["errors"].append(f"fetch_app_owners batch error: {res}")
                continue
            key, owners = res
            owner_cache[key] = owners

        for c in candidates:
            key = (c.get("tenant_id", ""), c.get("app_object_id", ""))
            c["app_owners"] = owner_cache.get(key, "")
    else:
        for c in candidates:
            c["app_owners"] = ""

    # -- Split into new vs existing ---------------------------------------------
    new_secrets      = []
    existing_secrets = []

    for c in candidates:
        existing = sp_index.get(c["secret_id"])  # SecretID alone, already globally unique
        if existing is None:
            new_secrets.append(c)
        else:
            existing_secrets.append((c, existing))

    # ── Split into new vs existing ────────────────────────────────────────────
    new_secrets      = []
    existing_secrets = []

    for c in candidates:
        existing = sp_index.get(c["secret_id"])  # SecretID alone, already globally unique
        if existing is None:
            new_secrets.append(c)
        else:
            existing_secrets.append((c, existing))

    # NEW - FEATURE 2 cont'd: exclude secrets that were JUST restored above
    # from new_secrets this run - see the FEATURE 2 comment near the top of
    # this function for why. Picked up as a normal "existing" row next run.
    if restored_secret_ids:
        new_secrets = [c for c in new_secrets if c["secret_id"] not in restored_secret_ids]

    # NEW - skip re-creating a ticket/row for a secret that's already sitting
    # in IgnoredSecretRegistry (via a Canceled ticket, or the manual
    # AlertStatus=Ignored trigger on the master list) but isn't actually 8+
    # days expired. Without this, such a secret has no row in sp_index (it
    # only ever lived in SecretAlertRegistry, and was physically moved out),
    # so on the very next run it looks indistinguishable from a genuinely
    # brand-new secret - it gets classified into whatever active bucket its
    # real expiration date lands in, and Phase 1/2 raise a fresh Jira ticket
    # for it, silently undoing the human decision that put it in Ignored in
    # the first place. Deliberately checked here, before the bucket split,
    # so it covers every bucket - the existing alreadyIgnoredSkipped check
    # further below only ever covered secrets landing in the Ignore bucket
    # itself, not this case. A separate, independent read from Feature 2's
    # own fetch above (not reused - that fetch is gated on
    # move_secret_from_ignored being wired too, and this check should still
    # run even if restore capability isn't configured).
    if get_ignored_sharepoint_state is not None and new_secrets:
        try:
            ignored_state_for_dedup = await get_ignored_sharepoint_state()
            ignored_secret_ids = {
                item.get("fields", {}).get("SecretID", "")
                for item in ignored_state_for_dedup.get("items", [])
                if item.get("fields", {}).get("SecretID")
            }
        except Exception as e:
            summary["errors"].append(
                f"Could not read IgnoredSecretRegistry to de-duplicate new secrets already "
                f"tracked there - proceeding without this de-duplication this run: {e}")
            ignored_secret_ids = set()

        if ignored_secret_ids:
            before_count = len(new_secrets)
            new_secrets = [c for c in new_secrets if c["secret_id"] not in ignored_secret_ids]
            summary["skippedAlreadyInIgnoredList"] = before_count - len(new_secrets)

    # ── Lineage tracking 1 same secret, new version after rotation ───────────
    # When a secret rotates, rotation creates a brand-new Entra secret (new
    # SecretID) and records that new ID in the OLD row's NewSecretKeyId
    # column. The team fills TeamName, ProductName, and
    # ProductTeamsKeyVaultName in BY HAND only once, the first time an app is
    # onboarded 1 every year after that, when the new secret shows up here
    # as a "new" secret with no row of its own yet, this checks whether its
    # ID matches some EXISTING row's NewSecretKeyId. If it does, that
    # existing row is this secret's parent, and its three team/product
    # columns are copied onto the brand-new secret automatically, so nobody
    # has to retype them every rotation cycle. The parent row's own
    # NewSecretKeyId is left untouched afterward 1 kept as history, not
    # cleared.
    #
    # This map is keyed by NewSecretKeyId (the value rotation wrote), so a
    # brand-new secret's ID can be looked up directly against it in O(1)
    # rather than scanning every row per new secret.
    lineage_by_new_secret_id: dict[str, dict] = {}
    for item in sp_data.get("items", []):
        f = item.get("fields", {})
        new_id = (f.get("NewSecretKeyId") or "").strip()
        if new_id and new_id not in lineage_by_new_secret_id:
            lineage_by_new_secret_id[new_id] = {
                "TeamName":                f.get("TeamName", ""),
                "ProductName":              f.get("ProductName", ""),
                "ProductTeamsKeyVaultName":  f.get("ProductTeamsKeyVaultName", ""),
            }
 
    lineage_matches_found = 0
    for c in new_secrets:
        parent_fields = lineage_by_new_secret_id.get(c["secret_id"])
        if parent_fields:
            c["lineage_fields"] = parent_fields
            lineage_matches_found += 1
            print(f"[INFO] Lineage match - secret {c['secret_id']} for {c['app_name']} matches a "
                 f"parent row's NewSecretKeyId, copying TeamName/ProductName/"
                 f"ProductTeamsKeyVaultName onto the new row")
    summary["lineageMatchesFound"] = lineage_matches_found

    # -- PHASE 1: Create Jira tickets for new secrets (batched) ------------------
    # Every bucket except P4/Ignore raises/maintains a Jira ticket now -
    # see JIRA_TICKET_BUCKETS and the module docstring FIX note.
    #
    # FIX (this version): ownership is no longer a gate on ticket/alert
    # creation, for new OR existing secrets. Previously a new secret was
    # only actionable if its app already had DevSecOpsOwnership set on some
    # existing row (_is_owned_new(), removed here), and the existing-secret
    # path had an equivalent is_owned gate (removed from
    # _handle_existing_secret() below). Explicit client requirement: tickets
    # and Teams alerts should fire purely based on severity/bucket, not
    # ownership. DevSecOpsOwnership still exists as a column and still gets
    # set via sync.py/ProductName - it's just no longer a precondition for
    # raising an alert. P4 and Ignore still never get a ticket/alert, since
    # that's bucket-based, unrelated to ownership.
    actionable_new = [
        c for c in new_secrets
        if c["bucket"] not in ("P4", "Ignore")
    ]

 
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
 
    # Teams-only new secrets never get a jira_key here 1 with the fix, this
    # list will normally be empty (only P5/Ignore are excluded from
    # JIRA_TICKET_BUCKETS, and both are already excluded from actionable_new
    # entirely) 1 kept for structural safety in case JIRA_TICKET_BUCKETS is
    # ever narrowed again in the future.
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
            "ObjectID":           c.get("app_object_id", ""),
        }
        # Stamp the ACTUAL tenant this app was scanned from, not just
        # whatever write_sharepoint_row's own GRAPH_TENANT_ID fallback would
        # use. Only set if _build_candidates actually carried a tenant_id
        # through 1 an empty string here would overwrite write_sharepoint_
        # row's fallback with nothing, so we only include these keys when
        # there's a real value.
        if c.get("tenant_id"):
            fields["TenantID"]   = c["tenant_id"]
        if jira_key:
            fields["JiraTicketCreatedDate"] = today
 
        # If this secret's ID matched a parent row's NewSecretKeyId (see the
        # lineage tracking step above), carry over the team/product columns
        # so the team doesn't have to retype them on every rotation cycle.
        lineage = c.get("lineage_fields")
        if lineage:
            fields["TeamName"]               = lineage["TeamName"]
            fields["ProductName"]            = lineage["ProductName"]
            fields["ProductTeamsKeyVaultName"] = lineage["ProductTeamsKeyVaultName"]
 
        teams_sent = False
        if bucket in TEAMS_ALERT_BUCKETS:
            try:
                text        = _teams_text(sev["severity"], c, jira_key)
                # Whether to tag someone is now a day-count decision WITHIN
                # bucket P1 (0-3 tags, 4-7 does not), not a bucket-membership
                # check 1 both halves are bucket P1, see should_tag_p1().
                tag_this    = bucket == "P1" and should_tag_p1(c["days"])
                tag_email   = teams_tag_email if tag_this else None
                result      = await send_teams_alert(text, tag_email=tag_email)
                resolved_status = ALERT_STATUS_P1_TAGGED if tag_this else ALERT_STATUS_FOR_BUCKET.get(bucket, "JiraRaised")
                if result.get("success"):
                    fields["AlertStatus"]   = resolved_status
                    fields["AlertSentDate"] = today
                    teams_sent = True
                else:
                    fields["AlertStatus"] = resolved_status
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
 
    # -- PHASE 3: Quiet writes for new secrets that get NO ticket/alert yet --
    # Unifies three cases that all get the same treatment - a plain row with
    # AlertStatus=Discovered, no Jira ticket, no Teams alert:
    #
    #   - P4 (61+ days, safe) - never gets a ticket/alert, regardless of
    #     ownership. Same as before this change.
    #
    #   - Ignore (8+ days expired) and brand new to monitoring - FIX (this
    #     version): previously silently dropped entirely, not written
    #     anywhere, not even to IgnoredSecretRegistry. Written here as a
    #     plain Discovered row instead. The very next run's
    #     _handle_existing_secret() Ignore-branch (already correct, handles
    #     the -8-day abandonment check via move_secret_to_ignored) picks it
    #     up from there once it's no longer "new" - same one-run delay every
    #     other bucket already goes through before it becomes actionable.
    #
    #   - P1/P2/P3/ExpiredManualReview whose app has no DevSecOpsOwnership
    #     set yet - FIX (this version): previously silently dropped
    #     entirely (see the old skippedNotOwned counter this replaced).
    #     Written here as a plain Discovered row instead, matching
    #     runbook_discovery.py's own behavior exactly: EVERY secret gets a
    #     row the first time it's seen, a human fills in ownership
    #     afterward (directly or via ProductName + the sync script), and
    #     only THEN does a later monitoring run raise the ticket/alert for
    #     it. This is what lets monitoring's first run against an empty
    #     list act as a full discovery pass instead of only ever creating
    # FIX: only P4 needs the quiet treatment now - P1/P2/P3/EMR always go to
    # actionable_new above regardless of ownership (see the FIX note there),
    # and Ignore is handled separately by Phase 3a below.
    quiet_new = [c for c in new_secrets if c["bucket"] == "P4"]
    if quiet_new:
        summary["p4LoggedOnly"] += len([c for c in quiet_new if c["bucket"] == "P4"])
        print(f"[INFO] {len(quiet_new)} new secret(s) written with AlertStatus=Discovered, "
              f"no ticket/alert yet (P4, or app not yet owned)")

        async def _write_quiet_new(c: dict):
            fields = {
                "Title":             c["app_id"],
                "AppName":           c["app_name"],
                "SecretID":          c["secret_id"],
                "SecretDescription": c["secret_desc"],
                "ExpirationDate":    c["expiration"],
                "ExpiryBucket":      c["bucket"],
                "ExpiryNotice":      _expiry_notice(c["days"]),
                "LastChecked":       today,
                "AlertStatus":       "Discovered",
                "AppOwners":         c.get("app_owners", ""),
                "ObjectID":          c.get("app_object_id", ""),
            }
            if c.get("tenant_id"):
                fields["TenantID"]   = c["tenant_id"]
            # Same lineage carry-over as the ticket/alert path above, so a
            # quietly-written row still gets TeamName/ProductName/
            # ProductTeamsKeyVaultName copied over if it matched a parent
            # row's NewSecretKeyId.
            lineage = c.get("lineage_fields")
            if lineage:
                fields["TeamName"]               = lineage["TeamName"]
                fields["ProductName"]            = lineage["ProductName"]
                fields["ProductTeamsKeyVaultName"] = lineage["ProductTeamsKeyVaultName"]
            try:
                await write_sharepoint_row(None, fields)
                return {"error": None}
            except Exception as e:
                return {"error": f"Quiet new-secret SP write failed for {c['app_id']}: {e}"}

        quiet_tasks   = [_write_quiet_new(c) for c in quiet_new]
        quiet_results = await _run_batched(quiet_tasks, SP_WRITE_BATCH)
        for res in quiet_results:
            if isinstance(res, Exception):
                summary["errors"].append(f"Quiet new-secret batch error: {res}")
            elif res.get("error"):
                summary["errors"].append(res["error"])
            else:
                summary["sharepointCreated"] += 1

    # -- PHASE 3a: Ignore-bucket secrets brand new to monitoring --------------
    # FIX (this version): a secret that's already 8+ days expired AND has
    # never been seen by monitoring before now goes STRAIGHT to
    # IgnoredSecretRegistry, matching runbook_discovery.py's original
    # behavior exactly - it never gets a row in the master list at all, not
    # even a Discovered one. Previously (the quiet_new fix, one version ago)
    # these landed in the master list as Discovered and only got swept into
    # IgnoredSecretRegistry on the FOLLOWING run once recognized as
    # "existing". This removes that one-run delay for the Ignore case
    # specifically, since there's nothing to wait on ownership for here -
    # Ignore-bucket secrets never get a ticket/alert regardless of ownership,
    # so there is no reason to hold them in the master list even briefly.
    #
    # Falls back to the old quiet-write-to-master-list behavior if
    # create_ignored_row wasn't supplied by the caller (main.py), or if the
    # write to IgnoredSecretRegistry fails for a given secret - the secret is
    # still tracked somewhere either way, never silently dropped.
    #
    # FIX (this version): "new" here only means "not found in sp_index", and
    # sp_index is built exclusively from SecretAlertRegistry (the master
    # list) - it was never cross-checked against IgnoredSecretRegistry. A
    # secret already sitting in IgnoredSecretRegistry is, by definition,
    # absent from the master list, so every single run it kept looking
    # "new" again here and got a FRESH row created in IgnoredSecretRegistry
    # via create_ignored_row() - one extra duplicate row per run, forever,
    # for every secret already tracked there. Fetching the current ignored
    # SecretIDs and filtering them out before writing closes that gap.
    already_ignored_secret_ids: set[str] = set()
    if get_ignored_sharepoint_state is not None:
        try:
            ignored_state_now = await get_ignored_sharepoint_state()
            already_ignored_secret_ids = {
                item.get("fields", {}).get("SecretID", "")
                for item in ignored_state_now.get("items", [])
            }
        except Exception as e:
            summary["errors"].append(
                f"Could not read IgnoredSecretRegistry to de-duplicate new Ignore-bucket "
                f"secrets - proceeding without de-duplication this run: {e}")

    all_ignore_new = [c for c in new_secrets if c["bucket"] == "Ignore"]
    ignore_new = [c for c in all_ignore_new if c["secret_id"] not in already_ignored_secret_ids]
    summary["alreadyIgnoredSkipped"] = len(all_ignore_new) - len(ignore_new)
    if ignore_new:
        print(f"[INFO] {len(ignore_new)} new secret(s) already 8+ days expired - "
              f"writing straight to IgnoredSecretRegistry")

        async def _write_ignore_new(c: dict):
            ignored_fields = {
                "Title":             c["app_id"],
                "AppName":           c["app_name"],
                "SecretID":          c["secret_id"],
                "SecretDescription": c["secret_desc"],
                "ExpirationDate":    c["expiration"],
                "DaysExpired":       abs(c["days"]),
                "TenantID":          c.get("tenant_id", ""),
                "LoggedDate":        today,
                "IgnoreReason":      "Expired8Plus",
                "AlertStatus":       "Ignored",
            }
            if create_ignored_row is not None:
                try:
                    result = await create_ignored_row(ignored_fields)
                    if result.get("success"):
                        return {"error": None, "ignored": True}
                    # Fall through to the master-list fallback below on failure.
                except Exception as e:
                    summary["errors"].append(
                        f"create_ignored_row failed for {c['app_id']} - "
                        f"falling back to a Discovered row in the master list: {e}"
                    )

            # Fallback: create_ignored_row unavailable or failed - write a
            # plain Discovered row in the master list instead, same as any
            # other bucket, so the secret is never silently dropped.
            fallback_fields = {
                "Title":             c["app_id"],
                "AppName":           c["app_name"],
                "SecretID":          c["secret_id"],
                "SecretDescription": c["secret_desc"],
                "ExpirationDate":    c["expiration"],
                "ExpiryBucket":      c["bucket"],
                "ExpiryNotice":      _expiry_notice(c["days"]),
                "LastChecked":       today,
                "AlertStatus":       "Discovered",
                "AppOwners":         c.get("app_owners", ""),
                "ObjectID":          c.get("app_object_id", ""),
            }
            if c.get("tenant_id"):
                fallback_fields["TenantID"] = c["tenant_id"]
            try:
                await write_sharepoint_row(None, fallback_fields)
                return {"error": None, "ignored": False}
            except Exception as e:
                return {"error": f"Ignore new-secret fallback SP write failed for {c['app_id']}: {e}",
                        "ignored": False}

        ignore_tasks   = [_write_ignore_new(c) for c in ignore_new]
        ignore_results = await _run_batched(ignore_tasks, SP_WRITE_BATCH)
        for res in ignore_results:
            if isinstance(res, Exception):
                summary["errors"].append(f"Ignore new-secret batch error: {res}")
            elif res.get("error"):
                summary["errors"].append(res["error"])
            elif res.get("ignored"):
                summary["newlyIgnored"] += 1
            else:
                summary["sharepointCreated"] += 1

 
    # ── PHASE 4: Handle existing secrets (batched) ────────────────────────────
    async def _process_existing(c: dict, existing: dict):
        try:
            # FIX (this version): ownership gate removed - see the FIX note
            # above actionable_new for the full reasoning. Tickets/alerts for
            # existing rows now fire purely based on bucket, same as new
            # secrets.
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
            if res.get("manually_ignored"): summary["manuallyIgnored"]      += 1
 

    # NEW - print a per-tenant breakdown at the end of every run, same spirit
    # as runbook_discovery.py's own reconciliation-totals summary, so this is
    # visible in Container App logs regardless of whether monitoring was
    # triggered via the LangChain agent or called directly.
    print("=" * 60)
    print("MONITORING RUN - PER-TENANT BREAKDOWN")
    print("=" * 60)
    for tenant_id, counts in summary["tenantBreakdown"].items():
        print(f"  Tenant {tenant_id}: {counts['apps']} app(s), {counts['secrets']} secret(s)")
    print(f"  TOTAL: {len(tenant_apps)} tenant(s) scanned, "
          f"{sum(v['apps'] for v in summary['tenantBreakdown'].values())} app(s), "
          f"{summary['secretsScanned']} secret(s)")
    print("=" * 60)
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

    # NEW - FEATURE 1: manual master-list -> Ignored trigger. A human can set
    # AlertStatus="Ignored" directly on a SecretAlertRegistry row (as opposed
    # to this happening automatically via the -8-day abandonment check
    # below). Previously this silently no-op'd: "Ignored" is a member of
    # MONITOR_SKIP_STATUSES, so the check just below unconditionally
    # returned without ever moving the row - the exact bug this closes.
    # This check MUST run before the MONITOR_SKIP_STATUSES check. Fires
    # regardless of bucket/day-count - a human's explicit AlertStatus edit
    # overrides the normal 8-day-abandonment gating entirely.
    if alert_status == "Ignored" and move_secret_to_ignored is not None:
        ignored_fields = {
            "Title":             c["app_id"],
            "AppName":           c["app_name"],
            "SecretID":          c["secret_id"],
            "SecretDescription": c["secret_desc"],
            "ExpirationDate":    c["expiration"],
            "DaysExpired":       abs(c["days"]),
            "TenantID":          c.get("tenant_id", ""),
            "LoggedDate":        today,
            "IgnoreReason":      "ManuallySetIgnored - AlertStatus set to Ignored directly on master list row",
            "JiraTicketKey":     jira_key,
            "AlertStatus":       "Ignored",
        }
        move_result = await move_secret_to_ignored(
            item_id, ignored_fields, "AlertStatus manually set to Ignored")
        if move_result.get("success"):
            result["moved_to_ignored"]  = True
            result["manually_ignored"]  = True
            result["sp_updated"]        = True
        else:
            result["error"] = (f"move_secret_to_ignored (manual trigger) failed for "
                               f"AppID={c['app_id']} SecretID={c['secret_id']}: "
                               f"{move_result.get('error')}")
        return result

    if alert_status in MONITOR_SKIP_STATUSES:
        # RotatedPendingDeployment and the PAUSED_STATUSES (Blocked,
        # AwaitingReporter) still get their ExpiryNotice/LastChecked
        # refreshed each run 1 so the row doesn't look abandoned/stale in
        # SharePoint 1 but get NO alert, ticket, or escalation activity.
        # True TERMINAL_STATUSES (Rotated/Ignored/Resolved) get nothing at
        # all, since there's nothing left to keep current on a closed row.
        if alert_status == "RotatedPendingDeployment" or alert_status in PAUSED_STATUSES:
            paused_fields = {"ExpiryNotice": notice, "LastChecked": today}
            if c.get("tenant_id"):
                paused_fields["TenantID"] = c["tenant_id"]
            paused_fields["AppOwners"] = c.get("app_owners", "")
            paused_fields["ObjectID"] = c.get("app_object_id", "")
            await write_sharepoint_row(item_id, paused_fields)
            result["sp_updated"] = True
        return result
 
    if bucket == "P4":
        # P4 rows (61+ days, safe) still get ExpiryBucket/ExpiryNotice/
        # ExpirationDate refreshed every run 1 so a LATER transition into
        # P3 (31-60 days, once the secret has aged) is detected correctly
        # by the stage comparison below 1 but get no alert and no ticket,
        # same as always.
        update_fields = {
            "LastChecked":     today,
            "ExpiryNotice":    notice,
            "ExpiryBucket":    bucket,
            "ExpirationDate":  c["expiration"],
        }
        # Re-stamp the correct tenant on every touch, self-healing a blank or
        # wrong TenantID back to what this run's Entra scan actually found for
        # this app, rather than falling through to write_sharepoint_row's own
        # GRAPH_TENANT_ID (home-tenant) fallback whenever this key is omitted.
        if c.get("tenant_id"):
            update_fields["TenantID"] = c["tenant_id"]
        # Re-stamp AppOwners on every touch too, unconditionally (unlike
        # TenantID above) - an empty owner list from Entra is real, current
        # data, not a gap to protect a previous value from.
        update_fields["AppOwners"] = c.get("app_owners", "")
        update_fields["ObjectID"] = c.get("app_object_id", "")
        await write_sharepoint_row(item_id, update_fields)
        result["sp_updated"] = True
        return result

    if bucket == "Ignore":
        # The -8-DAY ABANDONMENT CHECK. A secret crossing into "Ignore"
        # (8+ days past expiry) is NOT automatically moved to
        # IgnoredSecretRegistry purely on day count 1 that would risk
        # yanking a secret someone is actively rotating right now out of
        # view. The actual decision is based on whether there's still a
        # live, open Jira ticket for it:
        #
        #   - No JiraTicketKey at all           → genuinely abandoned, MOVE
        #   - Ticket status is Canceled          → explicitly abandoned, MOVE
        #   - Ticket status is Done/Resolved     → shouldn't still be here if
        #                                          the Jira→SharePoint sync
        #                                          worked (should already be
        #                                          Rotated) 1 flag as a
        #                                          possible sync-gap anomaly,
        #                                          do NOT move, stays visible
        #   - Ticket is In Progress/To Do/
        #     Blocked/Awaiting Reporter          → someone is actively
        #                                          engaged 1 do NOT move,
        #                                          stays visible, marked
        #                                          clearly as overdue-but-active
        #   - Any other/unrecognized status       → fail SAFE, do NOT move,
        #                                          log for manual review
        #
        # If move_secret_to_ignored wasn't provided by the caller (main.py),
        # this whole check is skipped and Ignore rows just get the same
        # plain refresh P5 gets 1 same as before this feature existed.
        if move_secret_to_ignored is None:
            update_fields = {
                "LastChecked":     today,
                "ExpiryNotice":    notice,
                "ExpiryBucket":    bucket,
                "ExpirationDate":  c["expiration"],
            }
            # Re-stamp the correct tenant on every touch, self-healing a blank or
            # wrong TenantID back to what this run's Entra scan actually found for
            # this app, rather than falling through to write_sharepoint_row's own
            # GRAPH_TENANT_ID (home-tenant) fallback whenever this key is omitted.
            if c.get("tenant_id"):
                update_fields["TenantID"] = c["tenant_id"]
            # Re-stamp AppOwners on every touch too, unconditionally (unlike
            # TenantID above) - an empty owner list from Entra is real, current
            # data, not a gap to protect a previous value from.
            update_fields["AppOwners"] = c.get("app_owners", "")
            update_fields["ObjectID"] = c.get("app_object_id", "")
            await write_sharepoint_row(item_id, update_fields)
            result["sp_updated"] = True
            return result
 
        if not jira_key:
            move_reason = "no ticket - never actioned"
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
                # This shouldn't normally happen 1 a Done/Resolved ticket
                # should already have flipped this row to AlertStatus=Rotated
                # via the jira-status-update sync. Finding one still sitting
                # here past -8 days suggests that sync didn't fire for this
                # ticket. Do NOT move it 1 flag it clearly instead so it gets
                # investigated rather than silently disappearing into Ignored
                # while still technically unrotated in SharePoint's eyes.
                should_move = False
                sync_gap_fields = {
                    "LastChecked":  today,
                    "ExpiryNotice": (f"⚠ SYNC GAP 1 Jira ticket {jira_key} is "
                                    f"'{jira_status_for_note}' but this row was never "
                                    f"marked Rotated. Check the Jira automation rule."),
                }
                if c.get("tenant_id"):
                    sync_gap_fields["TenantID"] = c["tenant_id"]
                sync_gap_fields["AppOwners"] = c.get("app_owners", "")
                sync_gap_fields["ObjectID"] = c.get("app_object_id", "")
                await write_sharepoint_row(item_id, sync_gap_fields)
                result["sp_updated"] = True
                return result
            else:
                # In Progress / To Do / Blocked / Awaiting Reporter / anything
                # else recognized-but-active 1 someone is engaged, or the
                # status is simply not one of the abandonment signals. Fail
                # safe: do not move. AlertStatus becomes OverdueManualReview 1
                # visible in the master list, distinct from ExpiredManualReview
                # (which covers -1 to -7 days), never auto rotated, same as
                # ExpiredManualReview, since a human already has an open
                # ticket on this and automated rotation risks colliding with
                # whatever they're already doing manually. A human decides
                # from here, not the runbook.
                should_move = False
 
        if not should_move:
            overdue_fields = {
                "LastChecked":   today,
                "AlertStatus":   "OverdueManualReview",
                "ExpiryNotice":  (f"OVERDUE {abs(c['days'])} days - ticket "
                                 f"{jira_key or '(none)'} still "
                                 f"'{jira_status_for_note}', not auto-ignored, "
                                 f"not auto-rotated, human review required"),
            }
            if c.get("tenant_id"):
                overdue_fields["TenantID"] = c["tenant_id"]
            overdue_fields["AppOwners"] = c.get("app_owners", "")
            overdue_fields["ObjectID"] = c.get("app_object_id", "")
            await write_sharepoint_row(item_id, overdue_fields)
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
            "LoggedDate":        today,
            "IgnoreReason":      f"Expired8Plus - {move_reason}",
            # NEW - preserves the ticket link so the jira-status-update
            # webhook can find this row again in IgnoredSecretRegistry if
            # the ticket is later reopened. Requires a JiraTicketKey column
            # to exist on IgnoredSecretRegistry - blank if this row never
            # had a ticket to begin with (the "no ticket at all" abandonment
            # case), which is correct, there's nothing to look up for those.
            "JiraTicketKey":     jira_key,
            "AlertStatus":       "Ignored",
        }
        move_result = await move_secret_to_ignored(item_id, ignored_fields, move_reason)
        if move_result.get("success"):
            result["moved_to_ignored"] = True
            result["sp_updated"] = True
        else:
            result["error"] = (f"move_secret_to_ignored failed for AppID={c['app_id']} "
                               f"SecretID={c['secret_id']}: {move_result.get('error')}")
        return result

    # FIX (this version): the unowned-row quiet-refresh gate that used to sit
    # here has been removed - ownership no longer blocks self-heal/escalation
    # for existing rows. See the FIX note above actionable_new for the full
    # reasoning (explicit requirement: tickets/alerts fire on severity alone).

    # Self-heal missing Jira ticket 1 now applies to EVERY bucket that
    # should have one: P1, P2, P3, P4, ExpiredManualReview. Previously this
    # only fired for P3/P4/ExpiredManualReview, matching the old (wrong)
    # JIRA_TICKET_BUCKETS 1 now that P1/P2 are included, a P1/P2 row that
    # somehow lost/never got its ticket is self-healed here too.
    if not jira_key and bucket in JIRA_TICKET_BUCKETS and bucket in SEVERITY_MAP:
        sev   = SEVERITY_MAP[bucket]
        issue = await create_jira_ticket(
            app_name=c["app_name"], app_id=c["app_id"],
            secret_id=c["secret_id"], secret_description=c["secret_desc"],
            expiration_date=c["expiration"], days_remaining=c["days"],
            severity=sev["severity"], priority=sev["priority"],
            extra_note="Self-healed - previous ticket reference was missing.",
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
        closed_ticket_fields = {"ExpiryNotice": notice, "LastChecked": today}
        if c.get("tenant_id"):
            closed_ticket_fields["TenantID"] = c["tenant_id"]
        closed_ticket_fields["AppOwners"] = c.get("app_owners", "")
        closed_ticket_fields["ObjectID"] = c.get("app_object_id", "")
        await write_sharepoint_row(item_id, closed_ticket_fields)
        result["sp_updated"] = True
        return result
 
    current_stage  = BUCKET_STAGE.get(bucket)
    existing_stage = STATUS_STAGE.get(alert_status, 0)
 
    if current_stage is not None and current_stage > existing_stage:
        sev = SEVERITY_MAP[bucket]
 
        # A secret escalating into ANY ticket-eligible bucket (now including
        # P1/P2) for the first time needs a ticket created now, even if it
        # somehow reached this point with no ticket yet.
        if not jira_key and bucket in JIRA_TICKET_BUCKETS:
            issue = await create_jira_ticket(
                app_name=c["app_name"], app_id=c["app_id"],
                secret_id=c["secret_id"], secret_description=c["secret_desc"],
                expiration_date=c["expiration"], days_remaining=c["days"],
                severity=sev["severity"], priority=sev["priority"],
                extra_note="Escalated - ticket created at this stage.",
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
        # Re-stamp the correct tenant on every touch, self-healing a blank or
        # wrong TenantID back to what this run's Entra scan actually found for
        # this app, rather than falling through to write_sharepoint_row's own
        # GRAPH_TENANT_ID (home-tenant) fallback whenever this key is omitted.
        if c.get("tenant_id"):
            update_fields["TenantID"] = c["tenant_id"]
        # Re-stamp AppOwners on every touch too, unconditionally (unlike
        # TenantID above) - an empty owner list from Entra is real, current
        # data, not a gap to protect a previous value from.
        update_fields["AppOwners"] = c.get("app_owners", "")
        update_fields["ObjectID"] = c.get("app_object_id", "")
        if jira_key:
            update_fields["JiraTicketKey"] = jira_key
            if "JiraTicketCreatedDate" not in f:
                update_fields["JiraTicketCreatedDate"] = today
 
        if bucket in TEAMS_ALERT_BUCKETS:
            text        = _teams_text(sev["severity"], c, jira_key)
            tag_this    = bucket == "P1" and should_tag_p1(c["days"])
            tag_email   = teams_tag_email if tag_this else None
            res_t       = await send_teams_alert(text, tag_email=tag_email)
            resolved_status = ALERT_STATUS_P1_TAGGED if tag_this else ALERT_STATUS_FOR_BUCKET.get(bucket, "JiraRaised")
            if res_t.get("success"):
                update_fields["AlertStatus"]   = resolved_status
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
        # Re-stamp the correct tenant on every touch, self-healing a blank or
        # wrong TenantID back to what this run's Entra scan actually found for
        # this app, rather than falling through to write_sharepoint_row's own
        # GRAPH_TENANT_ID (home-tenant) fallback whenever this key is omitted.
        if c.get("tenant_id"):
            update_fields["TenantID"] = c["tenant_id"]
        # Re-stamp AppOwners on every touch too, unconditionally (unlike
        # TenantID above) - an empty owner list from Entra is real, current
        # data, not a gap to protect a previous value from.
        update_fields["AppOwners"] = c.get("app_owners", "")
        update_fields["ObjectID"] = c.get("app_object_id", "")
        if jira_key:
            update_fields["JiraTicketKey"] = jira_key
        await write_sharepoint_row(item_id, update_fields)
        result["sp_updated"] = True
 
    return result