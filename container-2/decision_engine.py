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

  - BUCKET SCHEME (CORRECTED — see fix note below):
      P1  0-3 days   CRITICAL     Jira ticket + Teams alert, WITH tagging
      P2  4-7 days   CRITICAL     Jira ticket + Teams alert, WITHOUT tagging
      P3  8-30 days  WARNING      Jira ticket + Teams alert
      P4  31-60 days INFORMATION  Jira ticket only (no Teams)
      P5  61+ days   -            Safe — logged only, no SharePoint row, no
                                   alert, no ticket

  - FIX (this version): P1/P2 WERE INCORRECTLY EXCLUDED FROM JIRA TICKETS.
    A prior version of this file had JIRA_TICKET_BUCKETS = {"P3", "P4",
    "ExpiredManualReview"} — meaning a P1 (0-3 day, most urgent) or P2
    (4-7 day) secret got a Teams alert but NO Jira ticket at all, even
    though the actual requirement is that every bucket except P5 gets a
    ticket. This was confirmed in production: a secret with 4 days
    remaining (P2) sent a correctly-worded CRITICAL Teams alert but
    JiraTicketKey stayed permanently blank, because P2 was never in the
    set that create_jira_ticket gets called for at all — not a timing
    bug, not a stale value, the code simply never attempted it for that
    bucket. JIRA_TICKET_BUCKETS now includes P1 and P2. The _teams_text
    action-required copy for P1/P2 is also corrected — it previously said
    "no manual rotation is needed yet" / implied no ticket existed, which
    is no longer accurate now that P1/P2 always carry one.

  - TEAMS TAGGING: P1 alerts @mention a specific person, whose email is
    read from Key Vault (TEAMS-TAG-EMAIL). Adaptive Card mention entities
    are resolved by email/UPN via the msteams entity format.

  - SECRET VALIDITY PERIOD FROM KEY VAULT: the number of months a newly
    rotated secret stays valid for is read from Key Vault in
    runbook_rotation.py's create_azure_secret() call — a DIFFERENT file,
    noted here since it was discussed together with the bucket changes.

  - FILTER: OWNER-EMAILS list-matching → ManualAppOwners non-blank.
    Monitoring gates on ManualAppOwners being non-blank, both for existing
    SharePoint rows and for brand-new secrets (checked via whether ANY
    existing row for that app_id already has ManualAppOwners filled in).
    owner_emails/owner_email are still accepted as parameters for
    backwards compatibility but are IGNORED by default — set
    manual_owners_only=False at the call site in main.py to fall back to
    the old AppOwners/OWNER-EMAILS behavior.

  - P5 LANDS IN SecretAlertRegistry (matches runbook_discovery.py's v10.2
    one-time change): P5 rows get ExpiryBucket/ExpiryNotice/ExpirationDate
    refreshed every run (so a later transition into P4 is detected
    correctly) but still get no alert and no ticket.

  - MANUALAPPOWNERS APP-WIDE PROPAGATION: app ownership is a property of
    the App Registration, not of any one secret. If a human fills in
    ManualAppOwners on just ONE secret's row, every OTHER row for that
    same app_id is automatically backfilled with the same value on the
    next monitoring run. Runs BEFORE the ownership filter so a sibling row
    backfilled this run is treated as actionable in the SAME run.

  - LITERAL P1/P2/P3/P4 JIRA PRIORITIES (explicit client requirement):
    SEVERITY_MAP's priority field for P1-P4 is the literal bucket name
    ("P1"/"P2"/"P3"/"P4"), not Jira's default Highest/High/Medium/Low
    scheme. REQUIRES priorities named exactly "P1"/"P2"/"P3"/"P4" to
    already exist in the Jira project's priority scheme — if they don't,
    ticket creation fails with a 400 from Jira's API. ExpiredManualReview
    is unchanged (still "Highest") — it is not one of the four buckets
    this requirement covers.

  - BLOCKED / AWAITING REPORTER — PAUSED, NOT TERMINAL: matches the two
    statuses main.py's jira-status-update endpoint can set. A row in
    either state is skipped by monitoring's normal escalation/alert logic
    (same treatment as the true terminal statuses) but still gets
    ExpiryNotice/LastChecked refreshed each run, and resumes normal
    monitoring once the Jira ticket moves to a different status.

  - BUCKET RENUMBERING TO FOUR BUCKETS (this version): the previous
    five-bucket scheme (P1=0-3, P2=4-7, P3=8-30, P4=31-60, P5=61+ safe)
    is replaced with four buckets. P1 and P2 are merged into one bucket,
    P1, covering 0-7 days total — the tagging-vs-plain-alert distinction
    that used to be the P1/P2 boundary is now an internal decision made
    by should_tag_p1(), based on the actual day count, not a separate
    bucket. P2=8-30, P3=31-60, P4=61+ safe. Jira priority names already
    existed as P1 through P4 in the Jira project, so no new priorities
    needed creating — only the day ranges each name maps to have moved.
    Fixed alongside this: Phase 3 (brand-new secrets in the safe bucket)
    previously only logged to console with NO SharePoint write at all,
    inconsistent with how an ALREADY-EXISTING row in that same bucket was
    treated (which did get written/refreshed). Both paths now write
    consistently.
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
    P1  0-7 days   CRITICAL     (Jira ticket + Teams alert. 0-3 days ALSO tags a
                                  specific person; 4-7 days is a plain Teams alert
                                  with no tag. Both are still bucket P1.)
    P2  8-30 days  WARNING      (Jira ticket + Teams alert)
    P3  31-60 days INFORMATION  (Jira ticket only, no Teams alert)
    P4  61+ days   SAFE         (logged only, no alert, no ticket, no rotation)

    NOTE (renumbering): this replaces an earlier five-bucket scheme
    (P1=0-3, P2=4-7, P3=8-30, P4=31-60, P5=61+). P1 and P2 have been merged
    into a single P1 covering 0-7 days — the tagging-vs-plain-alert split
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

# Stage numbers determine escalation direction — higher stage always wins
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
# P1 covers BOTH the tagged (0-3 day) and untagged (4-7 day) cases — which
# one actually happened is decided at the point AlertStatus is set, using
# should_tag_p1() against the secret's actual day count, not hardcoded here.
ALERT_STATUS_FOR_BUCKET = {
    "P3": "JiraRaised",       # Jira ticket only
    "P2": "TeamsAlerted",     # Teams + Jira — TeamsAlerted covers both since
                              # both actions happen together for P2
    "P1": "Escalated",        # Teams alert (untagged, 4-7 days) + Jira ticket —
                              # overridden to CriticalTagged below when the
                              # secret is actually in the 0-3 day tagged half
    "ExpiredManualReview": "ExpiredManualReview",
}
ALERT_STATUS_P1_TAGGED = "CriticalTagged"  # used instead of ALERT_STATUS_FOR_BUCKET["P1"]
                                            # specifically when should_tag_p1() is True

SEVERITY_MAP = {
    # Priority is the LITERAL bucket name ("P1"/"P2"/"P3"/"P4"), not Jira's
    # default Highest/High/Medium/Low scheme — explicit client requirement.
    # REQUIRES priorities named exactly "P1", "P2", "P3", "P4" to already
    # exist in the Jira project's priority scheme — if they don't exist
    # yet, ticket creation will fail with a 400 from Jira's API rather than
    # silently falling back to a default. These four priority NAMES are
    # unchanged by the bucket renumbering — only the day ranges that map to
    # each name have moved, so nothing needs to change in Jira itself.
    "P3": {"severity": "INFORMATION", "priority": "P3"},
    "P2": {"severity": "WARNING",     "priority": "P2"},
    "P1": {"severity": "CRITICAL",    "priority": "P1"},
    # ExpiredManualReview's priority is now the literal "P1" too, same tier
    # as the most urgent active bucket, since an already-expired secret is
    # at least as urgent as one about to expire. This is the ONLY change
    # for ExpiredManualReview — severity stays "EXPIRED" (distinct wording
    # in the ticket body/Teams text), AlertStatus stays "ExpiredManualReview"
    # (never becomes P1 in SharePoint), and it is still never auto rotated.
    "ExpiredManualReview": {"severity": "EXPIRED", "priority": "P1"},
}

TEAMS_HEADERS = {
    "WARNING":  "⚠️ WARNING",
    "CRITICAL": "🚨 CRITICAL",
    "EXPIRED":  "⛔ EXPIRED — MANUAL REVIEW REQUIRED",
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
        # implied no ticket existed — no longer accurate now that P1/P2
        # always carry a Jira ticket, same as P3. All three Teams-alert
        # buckets now share the same accurate copy: a ticket exists (or
        # will, by the time this alert is read) for tracking.
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
        # Carries the tenant this app was actually fetched from (main.py's
        # fetch_azure_secrets() scans multiple tenants and tags each app
        # with _sourceTenantId, matching runbook_discovery.py's own
        # pattern). Falls back to "" if somehow absent, so a caller that
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
    move_secret_to_ignored: Callable[..., Awaitable[dict]] | None = None,  # -8-day abandoned-secret move
    get_product_service_principal: Callable[[str], Awaitable[str | None]] | None = None,
                                                         # NEW — looks up a Key Vault secret literally
                                                         # named after ProductName and returns its value
                                                         # (a service principal name), or None if no such
                                                         # secret exists. See the ProductName lookup step
                                                         # below for how this is used.
    owner_emails:           list[str] | None = None,   # DEPRECATED — see manual_owners_only below
    owner_email:            str = "",                  # DEPRECATED — see manual_owners_only below
    fetch_app_owners:       Callable[[str], Awaitable[str]] | None = None,  # legacy — not used
    get_owned_app_ids:      Callable[[], Awaitable[set]] | None = None,     # legacy — not used
    teams_tag_email:        str = "",                  # person to @mention on P1 alerts (from KV)
    manual_owners_only:     bool = True,                # filter is "does ManualAppOwners have
                                                         # anything in it", not an owner-email match
                                                         # against AppOwners. owner_emails/owner_email
                                                         # are IGNORED when this is True (the default)
                                                         # — kept as parameters only so main.py doesn't
                                                         # need to change its call site signature
                                                         # immediately. Set False to restore the old
                                                         # AppOwners/OWNER_EMAILS matching.
) -> dict:
    now   = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    summary: dict[str, Any] = {
        "runDate": today,
        "secretsScanned": 0,
        "totalsByBucket":  {b: 0 for b in ["P4", "P3", "P2", "P1", "ExpiredManualReview", "Ignore"]},
        "p4LoggedOnly":    0,   # P4 secrets (61+ days, safe) — logged only, no SharePoint entry
        "skippedNotOwned": 0,   # secrets skipped — app not owned by owner_email
        "newJiraTickets":  0,
        "newTeamsAlerts":  0,
        "jiraComments":    0,
        "sharepointCreated": 0,
        "sharepointUpdated": 0,
        "manualOwnersPropagated": 0,   # sibling rows backfilled with an app-wide ManualAppOwners value
        "productLookupsApplied": 0,    # NEW — ManualAppOwners set/overwritten from a ProductName lookup
        "productLookupsNotFound": 0,   # NEW — ProductName was filled in, but no matching KV secret exists
        "lineageMatchesFound": 0,      # NEW — new secrets that matched a parent row's NewSecretKeyId
        "movedToIgnored": 0,           # abandoned secrets (-8+ days, no ticket or Canceled) moved to IgnoredSecretRegistry
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

    # ── ProductName lookup, BEFORE propagation and BEFORE filtering ───────────
    # A row can have ProductName filled in instead of ManualAppOwners being
    # typed in directly. If it is, look up a Key Vault secret literally named
    # after that product (e.g. a secret called "ProductA") and use its value,
    # a service principal name, as ManualAppOwners for this row. This ALWAYS
    # overwrites whatever is currently in ManualAppOwners for that row — a
    # deliberate choice, ProductName is meant to be the team's single source
    # of truth going forward, so it always wins over a value someone may have
    # typed in directly the old way. Runs before the propagation step below,
    # so a value written here can still be propagated to sibling rows for the
    # same app in the same run.
    if get_product_service_principal is not None:
        product_lookup_ops: list[tuple[str, dict]] = []
        seen_products: dict[str, str | None] = {}  # cache — avoid repeat KV reads for the same product

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
                product_lookup_ops.append((item_id, {"ManualAppOwners": service_principal}))
                # Update in-memory too, so propagation and filtering below see
                # this immediately rather than the stale value from before.
                f["ManualAppOwners"] = service_principal
            else:
                summary["productLookupsNotFound"] += 1
                log_msg = (f"[INFO] ProductName {product!r} has no matching Key Vault secret — "
                          f"ManualAppOwners left as-is for this row")
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

    # ── Propagate ManualAppOwners app-wide, BEFORE filtering ──────────────────
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
    # Monitoring only processes rows where ManualAppOwners is non-blank —
    # this is a deliberate opt-in gate, not the old "does AppOwners match
    # one of a fixed OWNER_EMAILS list from Key Vault" check. ManualAppOwners
    # is admin-filled per app (see runbook_discovery.py — it is the one
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
    # Keyed off ManualAppOwners now, not AppOwners — see the FILTER note
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

    # ── Lineage tracking — same secret, new version after rotation ───────────
    # When a secret rotates, rotation creates a brand-new Entra secret (new
    # SecretID) and records that new ID in the OLD row's NewSecretKeyId
    # column. The team fills TeamName, ProductName, and
    # ProductTeamkeyVaultName in BY HAND only once, the first time an app is
    # onboarded — every year after that, when the new secret shows up here
    # as a "new" secret with no row of its own yet, this checks whether its
    # ID matches some EXISTING row's NewSecretKeyId. If it does, that
    # existing row is this secret's parent, and its three team/product
    # columns are copied onto the brand-new secret automatically, so nobody
    # has to retype them every rotation cycle. The parent row's own
    # NewSecretKeyId is left untouched afterward — kept as history, not
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
                "ProductTeamkeyVaultName":  f.get("ProductTeamkeyVaultName", ""),
            }

    lineage_matches_found = 0
    for c in new_secrets:
        parent_fields = lineage_by_new_secret_id.get(c["secret_id"])
        if parent_fields:
            c["lineage_fields"] = parent_fields
            lineage_matches_found += 1
            print(f"[INFO] Lineage match — secret {c['secret_id']} for {c['app_name']} matches a "
                 f"parent row's NewSecretKeyId, copying TeamName/ProductName/"
                 f"ProductTeamkeyVaultName onto the new row")
    summary["lineageMatchesFound"] = lineage_matches_found

    # ── PHASE 1: Create Jira tickets for new secrets (batched) ───────────────
    # Every bucket except P5/Ignore raises/maintains a Jira ticket now —
    # see JIRA_TICKET_BUCKETS and the module docstring FIX note.
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
        if c["bucket"] not in ("P4", "Ignore") and _is_owned_new(c)
    ]
    skipped_new_not_owned = len([
        c for c in new_secrets
        if c["bucket"] not in ("P4", "Ignore") and not _is_owned_new(c)
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

    # Teams-only new secrets never get a jira_key here — with the fix, this
    # list will normally be empty (only P5/Ignore are excluded from
    # JIRA_TICKET_BUCKETS, and both are already excluded from actionable_new
    # entirely) — kept for structural safety in case JIRA_TICKET_BUCKETS is
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
        }
        # Stamp the ACTUAL tenant this app was scanned from, not just
        # whatever write_sharepoint_row's own GRAPH_TENANT_ID fallback would
        # use. Only set if _build_candidates actually carried a tenant_id
        # through — an empty string here would overwrite write_sharepoint_
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
            fields["ProductTeamkeyVaultName"] = lineage["ProductTeamkeyVaultName"]

        teams_sent = False
        if bucket in TEAMS_ALERT_BUCKETS:
            try:
                text        = _teams_text(sev["severity"], c, jira_key)
                # Whether to tag someone is now a day-count decision WITHIN
                # bucket P1 (0-3 tags, 4-7 does not), not a bucket-membership
                # check — both halves are bucket P1, see should_tag_p1().
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

    # ── PHASE 3: Handle P4 new secrets (61+ days, safe) — written to SharePoint,
    #            no alert, no ticket ────────────────────────────────────────────
    # NOTE: this bucket still gets a SharePoint row, matching the
    # existing-secret handler's own P4 branch below and the module docstring.
    # An earlier version of this phase only logged these to the console with
    # NO SharePoint write at all, which was inconsistent with how an
    # ALREADY-EXISTING P4 row is treated once it exists — fixed here so a
    # brand new P4 secret and an existing P4 secret are written the same way.
    p4_new = [c for c in new_secrets if c["bucket"] == "P4"]
    if p4_new:
        summary["p4LoggedOnly"] += len(p4_new)
        print(f"[INFO] P4 secrets (61+ days safe): {len(p4_new)} found — writing to SharePoint, no alert or ticket")

        async def _write_p4_new(c: dict):
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
            }
            if c.get("tenant_id"):
                fields["TenantID"]   = c["tenant_id"]
            try:
                await write_sharepoint_row(None, fields)
                return {"error": None}
            except Exception as e:
                return {"error": f"P4 new-secret SP write failed for {c['app_id']}: {e}"}

        p4_tasks   = [_write_p4_new(c) for c in p4_new]
        p4_results = await _run_batched(p4_tasks, SP_WRITE_BATCH)
        for res in p4_results:
            if isinstance(res, Exception):
                summary["errors"].append(f"P4 new-secret batch error: {res}")
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
        # RotatedPendingDeployment and the PAUSED_STATUSES (Blocked,
        # AwaitingReporter) still get their ExpiryNotice/LastChecked
        # refreshed each run — so the row doesn't look abandoned/stale in
        # SharePoint — but get NO alert, ticket, or escalation activity.
        # True TERMINAL_STATUSES (Rotated/Ignored/Resolved) get nothing at
        # all, since there's nothing left to keep current on a closed row.
        if alert_status == "RotatedPendingDeployment" or alert_status in PAUSED_STATUSES:
            await write_sharepoint_row(item_id, {"ExpiryNotice": notice, "LastChecked": today})
            result["sp_updated"] = True
        return result

    if bucket == "P4":
        # P4 rows (61+ days, safe) still get ExpiryBucket/ExpiryNotice/
        # ExpirationDate refreshed every run — so a LATER transition into
        # P3 (31-60 days, once the secret has aged) is detected correctly
        # by the stage comparison below — but get no alert and no ticket,
        # same as always.
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
        # The -8-DAY ABANDONMENT CHECK. A secret crossing into "Ignore"
        # (8+ days past expiry) is NOT automatically moved to
        # IgnoredSecretRegistry purely on day count — that would risk
        # yanking a secret someone is actively rotating right now out of
        # view. The actual decision is based on whether there's still a
        # live, open Jira ticket for it:
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
                # safe: do not move. AlertStatus becomes OverdueManualReview —
                # visible in the master list, distinct from ExpiredManualReview
                # (which covers -1 to -7 days), never auto rotated, same as
                # ExpiredManualReview, since a human already has an open
                # ticket on this and automated rotation risks colliding with
                # whatever they're already doing manually. A human decides
                # from here, not the runbook.
                should_move = False

        if not should_move:
            await write_sharepoint_row(item_id, {
                "LastChecked":   today,
                "AlertStatus":   "OverdueManualReview",
                "ExpiryNotice":  (f"OVERDUE {abs(c['days'])} days — ticket "
                                 f"{jira_key or '(none)'} still "
                                 f"'{jira_status_for_note}', not auto-ignored, "
                                 f"not auto-rotated, human review required"),
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

    # Self-heal missing Jira ticket — now applies to EVERY bucket that
    # should have one: P1, P2, P3, P4, ExpiredManualReview. Previously this
    # only fired for P3/P4/ExpiredManualReview, matching the old (wrong)
    # JIRA_TICKET_BUCKETS — now that P1/P2 are included, a P1/P2 row that
    # somehow lost/never got its ticket is self-healed here too.
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

        # A secret escalating into ANY ticket-eligible bucket (now including
        # P1/P2) for the first time needs a ticket created now, even if it
        # somehow reached this point with no ticket yet.
        if not jira_key and bucket in JIRA_TICKET_BUCKETS:
            issue = await create_jira_ticket(
                app_name=c["app_name"], app_id=c["app_id"],
                secret_id=c["secret_id"], secret_description=c["secret_desc"],
                expiration_date=c["expiration"], days_remaining=c["days"],
                severity=sev["severity"], priority=sev["priority"],
                extra_note="Escalated — ticket created at this stage.",
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
        if jira_key:
            update_fields["JiraTicketKey"] = jira_key
        await write_sharepoint_row(item_id, update_fields)
        result["sp_updated"] = True

    return result
