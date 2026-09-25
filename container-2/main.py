"""
Azure Entra Secret Monitoring — REST API (Replaces FastMCP)
"""
from __future__ import annotations
 
import base64 as _b64
import csv
import io
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional
 
import httpx
from azure.identity import ManagedIdentityCredential, ClientAssertionCredential
from azure.keyvault.secrets import SecretClient
from fastapi import FastAPI
from pydantic import BaseModel
 
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("monitor-api")
 
# ── Key Vault ─────────────────────────────────────────────────────────────────
KV_URL         = os.environ["KEY_VAULT_URL"]
UAMI_CLIENT_ID = os.environ["UAMI_CLIENT_ID"]
_credential    = ManagedIdentityCredential(client_id=UAMI_CLIENT_ID)
_kv            = SecretClient(vault_url=KV_URL, credential=_credential)
 
def _kv_get(n: str) -> str:
    return _kv.get_secret(n).value
 
async def get_product_service_principal(product_name: str) -> str | None:
    """
    Looks up a Key Vault secret literally named after product_name (e.g. a
    secret called "ProductA") and returns its value, a service principal
    name, or None if no such secret exists in this vault.
 
    This is how the ProductName column in SharePoint gets translated into a
    ManualAppOwners value automatically — the team maintains one Key Vault
    secret per product they support, secret name is the product name, secret
    value is that product's service principal. Adding a new product later is
    just creating one more secret, no code change needed.
 
    A missing secret is NOT an error — Key Vault's SDK raises an exception
    for "secret not found", which is expected and normal here whenever
    ProductName contains a typo or a product that hasn't been registered yet.
    That case returns None rather than propagating the exception, so one
    unrecognized product name in one row doesn't fail the whole monitoring run.
    """
    try:
        return _kv.get_secret(product_name).value
    except Exception as e:
        log.info("get_product_service_principal: no Key Vault secret found for "
                 "product %r (or lookup failed): %s", product_name, e)
        return None
 
GRAPH_TENANT_ID    = _kv_get("GRAPH-TENANT-ID")
GRAPH_TENANT_NAME  = _kv_get("GRAPH-TENANT-NAME")  # from KV — no Directory.Read.All needed
# OWNER-EMAILS supports multiple owners — comma-separated in KV
# Falls back to empty list if secret not set (processes all rows)
try:
    _owner_emails_raw = _kv_get("OWNER-EMAILS").strip()
except Exception:
    try:
        # backwards compat — read old OWNER-EMAIL single-value secret
        _owner_emails_raw = _kv_get("OWNER-EMAIL").strip()
    except Exception:
        _owner_emails_raw = ""
 
OWNER_EMAILS = [e.strip() for e in _owner_emails_raw.split(",") if e.strip()]
log.info("Legacy OWNER_EMAILS loaded (currently IGNORED — decision_engine.py "
         "defaults to manual_owners_only=True, filtering on ManualAppOwners "
         "instead): %s", OWNER_EMAILS)
 
# TEAMS-TAG-EMAIL — NEW. The person @mentioned on P1 (0-3 day) Teams alerts.
# decision_engine.py has accepted a teams_tag_email parameter to
# run_secret_monitoring() since the P1/P2 bucket split was introduced, but
# nothing here was actually reading the KV secret or passing it through —
# so P1 alerts were firing without a tag despite the mechanism existing.
# This fixes that wiring. Falls back to empty string (no tag) if not set,
# so a missing secret degrades gracefully rather than breaking the run.
try:
    TEAMS_TAG_EMAIL = _kv_get("TEAMS-TAG-EMAIL").strip()
except Exception:
    TEAMS_TAG_EMAIL = ""
    log.warning("TEAMS-TAG-EMAIL not set in Key Vault — P1 alerts will NOT "
                "tag anyone until this secret is configured.")
log.info("Teams tag target for P1 alerts: %s", TEAMS_TAG_EMAIL or "(none configured)")
 
JIRA_BASE_URL      = _kv_get("JIRA-BASE-URL")
JIRA_API_TOKEN      = _kv_get("JIRA-API-TOKEN")
JIRA_USER_EMAIL     = _kv_get("JIRA-USER-EMAIL")
TEAMS_WEBHOOK_URL   = _kv_get("TEAMS-WEBHOOK-URL").strip()
SHAREPOINT_SITE_ID  = _kv_get("SHAREPOINT-SITE-ID")
SHAREPOINT_LIST_ID  = _kv_get("SHAREPOINT-LIST-ID")
 
# SHAREPOINT-IGNORED-LIST-ID — NEW. Needed for the -8-day "no action taken"
# check: a secret that's genuinely abandoned (no ticket, or ticket
# Canceled) at -8+ days gets MOVED from SecretAlertRegistry into
# IgnoredSecretRegistry, matching the same list runbook_discovery.py
# already writes to for its own Expired8Plus/Ignore bucket. Falls back to
# empty string (with a warning) rather than crashing the whole container if
# not yet provisioned — the move-to-Ignored feature is simply skipped
# (secrets stay in SecretAlertRegistry, logged as normal Ignore-bucket rows)
# until this is configured.
try:
    SHAREPOINT_IGNORED_LIST_ID = _kv_get("SHAREPOINT-IGNORED-LIST-ID")
except Exception as exc:
    SHAREPOINT_IGNORED_LIST_ID = ""
    log.warning("SHAREPOINT-IGNORED-LIST-ID not set — abandoned secrets (no ticket or "
                "Canceled, past -8 days) will NOT be moved to IgnoredSecretRegistry: %s", exc)

# BACKUP LISTS — NEW. Before each monitoring run touches SecretAlertRegistry
# or IgnoredSecretRegistry, their current state is snapshotted into these
# dedicated backup lists (SharePoint has no built-in point-in-time backup for
# a list). Falls back to "" (backup skipped, logged) rather than crashing the
# container if not yet provisioned.
try:
    SHAREPOINT_BACKUP_LIST_ID = _kv_get("SHAREPOINT-BACKUP-LIST-ID")
except Exception as exc:
    SHAREPOINT_BACKUP_LIST_ID = ""
    log.warning("SHAREPOINT-BACKUP-LIST-ID not set — SecretAlertRegistry will NOT "
                "be backed up before each run: %s", exc)
try:
    SHAREPOINT_IGNORED_BACKUP_LIST_ID = _kv_get("SHAREPOINT-IGNORED-BACKUP-LIST-ID")
except Exception as exc:
    SHAREPOINT_IGNORED_BACKUP_LIST_ID = ""
    log.warning("SHAREPOINT-IGNORED-BACKUP-LIST-ID not set — IgnoredSecretRegistry "
                "will NOT be backed up before each run: %s", exc)

# BACKUP-STORAGE-ACCOUNT-URL — NEW, DELIBERATELY OPTIONAL. Blob endpoint for
# archiving the PREVIOUS backup-list snapshot before it's overwritten by a
# fresh one each run. If not set, the rolling SharePoint-side backup still
# works (the old snapshot is just discarded instead of archived) rather than
# blocking monitoring entirely on a Storage Account that may not exist yet -
# see decision_engine.py's _rotate_backup_list() for the exact behavior.
try:
    BACKUP_STORAGE_ACCOUNT_URL = _kv_get("BACKUP-STORAGE-ACCOUNT-URL").strip().rstrip("/")
except Exception:
    BACKUP_STORAGE_ACCOUNT_URL = ""
    log.warning("BACKUP-STORAGE-ACCOUNT-URL not set — the previous backup-list "
                "snapshot will be discarded each run instead of archived to "
                "Storage. Only the SharePoint-side rolling backup will run.")
BACKUP_CONTAINER_NAME = "secret-governance-backups"

try:
    JIRA_PROJECT_KEY = _kv_get("JIRA-PROJECT-KEY").strip()
except Exception:
    JIRA_PROJECT_KEY = "CSD"
try:
    JIRA_EPIC_KEY = _kv_get("JIRA-EPIC-KEY").strip()
except Exception:
    JIRA_EPIC_KEY = ""
try:
    JIRA_ISSUE_TYPE = _kv_get("JIRA-ISSUE-TYPE").strip()
except Exception:
    JIRA_ISSUE_TYPE = "Email request"

# Set this to your Jira custom description field ID (e.g. "customfield_10258")
# if your Jira project uses a custom field instead of the built-in system description.
# Set to None for standard projects using the built-in system description field.
JIRA_DESCRIPTION_CUSTOM_FIELD_ID = "customfield_10258"

log.info(f"Config loaded. Project: {JIRA_PROJECT_KEY} | Epic: {JIRA_EPIC_KEY}")
 
# ── Helpers ───────────────────────────────────────────────────────────────────
# Federated credential — UAMI asserts identity → App Registration → Graph token
#
# FIX #1 (matches runbook_discovery.py's v7 fix — this file never got it until now):
# Previously this file used ONE credential, scoped to CROSS_TENANT_TENANT_ID, for
# EVERY Graph call — both scanning App Registrations AND reading/writing
# SharePoint. That's fine only as long as CROSS_TENANT_TENANT_ID happens to be
# the same tenant SharePoint lives in. The moment CROSS_TENANT_TENANT_ID is
# pointed at a genuinely different tenant (to scan THAT tenant's App
# Registrations, as this project's multi-tenant discovery setup does), every
# SharePoint call in this file also got scoped to that tenant — which may not
# even have a SharePoint license, producing exactly the error this file was
# hitting: {"code":"BadRequest","message":"Tenant does not have a SPO license."}
#
# FIX #2 (matches runbook_discovery.py's v8 fix — this file never got this one
# either): CROSS-TENANT-TENANT-ID in Key Vault was actually set to BOTH tenant
# IDs, comma-joined ("70afdd80-...,c721d616-...") — the same format
# runbook_discovery.py's PLURAL CROSS-TENANT-TENANT-IDS secret uses. But this
# file was reading it as a SINGULAR value and passing the whole malformed
# comma-joined string directly to ClientAssertionCredential(tenant_id=...).
# That credential doesn't validate tenant_id at construction time — it just
# interpolates it into the token endpoint URL
# (https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token), and Entra
# happened to still resolve a request against a malformed multi-value path —
# incidental tolerance, NOT documented or guaranteed behavior, and there was no
# way to know which tenant it actually authenticated against without checking
# the resulting data's TenantID field by hand.
#
# Fix: read CROSS-TENANT-TENANT-IDS (plural, comma-separated) with the same
# fallback-to-singular pattern discovery uses, build ONE federated credential
# PER TENANT (a ClientAssertionCredential is bound to a single tenant_id at
# construction), and loop over all of them when scanning for apps/owners —
# see fetch_azure_secrets_all_tenants() and fetch_app_owners() below.
CROSS_TENANT_APP_ID = _kv_get("CROSS-TENANT-APP-ID")
 
try:
    _tenant_ids_raw = _kv_get("CROSS-TENANT-TENANT-IDS")
except Exception:
    _tenant_ids_raw = _kv_get("CROSS-TENANT-TENANT-ID")
    log.info("CROSS-TENANT-TENANT-IDS not set — falling back to singular "
             "CROSS-TENANT-TENANT-ID for backwards compatibility.")
 
CROSS_TENANT_TENANT_IDS = [t.strip() for t in _tenant_ids_raw.split(",") if t.strip()]
log.info("Configured to scan %d tenant(s): %s", len(CROSS_TENANT_TENANT_IDS), CROSS_TENANT_TENANT_IDS)
 
# HOME_TENANT_ID — the tenant where SharePoint actually lives. Falls back to
# GRAPH_TENANT_ID if not set, matching runbook_discovery.py's same pattern —
# GRAPH_TENANT_ID has always been treated as the home/primary tenant.
try:
    HOME_TENANT_ID = _kv_get("HOME-TENANT-ID")
except Exception:
    HOME_TENANT_ID = GRAPH_TENANT_ID
    log.info("HOME-TENANT-ID not set — falling back to GRAPH-TENANT-ID (%s) "
             "as the home tenant for SharePoint operations.", GRAPH_TENANT_ID)
 
_uami_credential = ManagedIdentityCredential(client_id=UAMI_CLIENT_ID)
 
def _get_uami_assertion() -> str:
    """Returns a short-lived UAMI token used as assertion for federated auth."""
    token = _uami_credential.get_token("api://AzureADTokenExchange")
    return token.token
 
# One federated credential PER TENANT being scanned — a ClientAssertionCredential
# is bound to a single tenant_id at construction, so multi-tenant support means
# building one of these per tenant, not reusing a single instance. Matches
# runbook_discovery.py's _graph_credentials_by_tenant exactly.
_graph_credentials_by_tenant: dict[str, ClientAssertionCredential] = {
    tenant_id: ClientAssertionCredential(
        tenant_id = tenant_id,
        client_id = CROSS_TENANT_APP_ID,
        func      = _get_uami_assertion,
    )
    for tenant_id in CROSS_TENANT_TENANT_IDS
}
 
# Credential for SharePoint (get_sharepoint_state, write_sharepoint_row) —
# ALWAYS scoped to HOME_TENANT_ID, independent of whichever tenant is
# currently being scanned for App Registrations.
_sp_graph_credential = ClientAssertionCredential(
    tenant_id = HOME_TENANT_ID,
    client_id = CROSS_TENANT_APP_ID,
    func      = _get_uami_assertion,
)
 
async def _graph_token_for_tenant(tenant_id: str) -> str:
    """Get Graph API token for ENTRA SCANNING, for a SPECIFIC tenant. Use
    this for fetch_azure_secrets/fetch_app_owners ONLY, never for SharePoint."""
    credential = _graph_credentials_by_tenant[tenant_id]
    token = credential.get_token("https://graph.microsoft.com/.default")
    return token.token
 
async def _sp_graph_token() -> str:
    """Get Graph API token for SHAREPOINT via federated credential — ALWAYS
    home tenant. Use this for get_sharepoint_state/write_sharepoint_row."""
    token = _sp_graph_credential.get_token("https://graph.microsoft.com/.default")
    return token.token
 
async def get_tenant_name() -> str:
    """Returns tenant name from Key Vault — no Graph API call, no extra permissions needed."""
    return GRAPH_TENANT_NAME
 
def _jira_auth() -> str:
    return "Basic " + _b64.b64encode(f"{JIRA_USER_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
 
# ── Tool Implementations ──────────────────────────────────────────────────────
async def fetch_azure_secrets() -> dict:
    """
    Fetches ALL App Registrations across ALL configured tenants
    (CROSS_TENANT_TENANT_IDS), not just one — see the FIX #2 note above the
    credential setup for why this was previously silently limited to a single
    tenant despite Key Vault holding both tenant IDs.
 
    Each app dict gets a '_sourceTenantId' key added, matching
    runbook_discovery.py's fetch_all_applications_all_tenants() exactly —
    fetch_app_owners() needs this to look up owners in the SAME tenant the
    app actually lives in, not necessarily the first/home tenant.
 
    A failure fetching ONE tenant is logged and that tenant contributes zero
    apps, but other tenants still get scanned — same reliability reasoning
    as discovery: a temporary issue with one tenant (revoked consent,
    expired trust) shouldn't block monitoring for every other tenant.
    """
    all_apps: list[dict] = []
    tenant_errors: list[str] = []
 
    for tenant_id in CROSS_TENANT_TENANT_IDS:
        try:
            headers = {"Authorization": f"Bearer {await _graph_token_for_tenant(tenant_id)}"}
            url = "https://graph.microsoft.com/v1.0/applications?$select=id,displayName,appId,passwordCredentials"
            tenant_apps = []
            async with httpx.AsyncClient() as c:
                while url:
                    r = await c.get(url, headers=headers, timeout=30)
                    r.raise_for_status()
                    b = r.json()
                    tenant_apps.extend(b.get("value", []))
                    url = b.get("@odata.nextLink")
            for app in tenant_apps:
                app["_sourceTenantId"] = tenant_id
            all_apps.extend(tenant_apps)
            log.info("Fetched %d App Registrations from tenant %s", len(tenant_apps), tenant_id)
        except Exception as e:
            tenant_errors.append(f"Tenant {tenant_id}: fetch_azure_secrets failed: {e}")
            log.error("Failed to fetch applications from tenant %s: %s", tenant_id, e)
 
    if tenant_errors:
        log.warning("fetch_azure_secrets completed with %d tenant error(s): %s",
                    len(tenant_errors), tenant_errors)
 
    return {"applications": all_apps, "count": len(all_apps), "tenantErrors": tenant_errors}
 
async def fetch_app_owners(app_id: str, tenant_id: str) -> str:
    """
    Fetches owners of an App Registration from Entra ID, scoped to the
    SPECIFIC tenant this app lives in — tenant_id is now REQUIRED (was
    previously implicit/always-the-one-configured-tenant before multi-tenant
    support). Returns a comma-separated string of owner names.
 
    Owner types:
      - User          → stored as displayName (falls back to UPN/email only
                         if Entra has no display name for that user)
      - Service Principal → stored as displayName: automation-pipeline
      - No owners     → returns empty string (admin fills manually in SharePoint)
    """
    headers = {"Authorization": f"Bearer {await _graph_token_for_tenant(tenant_id)}"}
    url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/owners"
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(url, headers=headers, timeout=15)
            if not r.is_success:
                return ""
            owners = r.json().get("value", [])
 
        owner_list = []
        for owner in owners:
            odata_type = owner.get("@odata.type", "")
            if "user" in odata_type.lower():
                # User owner — display name first (client requirement: names,
                # not emails), fall back to UPN/email only if Entra genuinely
                # has no display name for this user.
                name = owner.get("displayName") or owner.get("userPrincipalName") or owner.get("mail", "")
                if name:
                    owner_list.append(name)
            elif "servicePrincipal" in odata_type:
                # Service Principal owner — use display name
                name = owner.get("displayName", "")
                if name:
                    owner_list.append(name)
 
        return ", ".join(owner_list)
    except Exception as e:
        log.warning("fetch_app_owners failed for %s: %s", app_id, e)
        return ""
 
async def get_sharepoint_state() -> dict:
    headers = {"Authorization": f"Bearer {await _sp_graph_token()}"}
    url = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{SHAREPOINT_LIST_ID}/items?$expand=fields"
    items = []
    async with httpx.AsyncClient() as c:
        while url:
            r = await c.get(url, headers=headers, timeout=30)
            if not r.is_success:
                # LOG THE ACTUAL GRAPH ERROR BODY before raising — httpx's own
                # request-logging middleware only prints method/URL/status
                # ("400 Bad Request"), never the response body, and
                # raise_for_status() discards it too. Graph's error body
                # almost always names the specific problem (bad OData query,
                # token/consent issue, malformed filter, etc.) — without this,
                # every failure here looks identical regardless of cause.
                log.error("get_sharepoint_state Graph error [%s] for %s: %s",
                          r.status_code, url, r.text[:2000])
            r.raise_for_status()
            b = r.json()
            items.extend(b.get("value", []))
            url = b.get("@odata.nextLink")
    return {"items": items, "count": len(items)}
 
async def write_sharepoint_row(item_id: str | None, fields: dict[str, str]) -> dict:
    # FIX: no more 10-char truncation here. LastChecked, AlertSentDate,
    # RotationDetectedDate, and JiraTicketCreatedDate now arrive as full EST
    # timestamps from decision_engine.py's _now_est_string() (matching
    # runbook_discovery.py's format exactly), and ExpirationDate arrives
    # pre-formatted via _format_datetime_est() in _build_candidates(). Slicing
    # any of these to 10 characters destroys the time-of-day/AM-PM portion
    # right back down to a bare date, undoing the EST-timestamp work at the
    # last possible step. Nothing passed into this function needs date-only
    # truncation anymore.
    # CHANGED: only default TenantID to the home tenant if the caller hasn't
    # already set it. decision_engine.py now stamps the ACTUAL tenant a
    # given app was scanned from (see _build_candidates' tenant_id field) —
    # unconditionally overwriting here would silently discard that and
    # mislabel every row as the home tenant, defeating the whole point of
    # multi-tenant scanning. (TenantName was removed — the column no longer
    # exists in SharePoint.)
    if not fields.get("TenantID"):
        fields["TenantID"] = GRAPH_TENANT_ID
    headers = {"Authorization": f"Bearer {await _sp_graph_token()}", "Content-Type": "application/json"}
    base = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{SHAREPOINT_LIST_ID}/items"
    async with httpx.AsyncClient() as c:
        if item_id is None:
            r = await c.post(base, headers=headers, content=json.dumps({"fields": fields}), timeout=20)
            if not r.is_success:
                log.error("write_sharepoint_row: create failed (%s) fields=%r body=%s",
                          r.status_code, fields, r.text)
            r.raise_for_status()
            return {"action": "created", "item_id": r.json().get("id"), "fields": fields}
        else:
            r = await c.patch(f"{base}/{item_id}", headers=headers, content=json.dumps({"fields": fields}), timeout=20)
            if not r.is_success:
                log.error("write_sharepoint_row: update failed (%s) item_id=%s fields=%r body=%s",
                          r.status_code, item_id, fields, r.text)
            r.raise_for_status()
            return {"action": "updated", "item_id": item_id, "fields": fields}
 
async def delete_sharepoint_row(item_id: str) -> dict:
    """
    Deletes one row from SecretAlertRegistry. Used ONLY by
    move_secret_to_ignored() below — this is a genuinely destructive
    operation, so it is never exposed as its own general-purpose endpoint
    the way write_sharepoint_row is.
    """
    headers = {"Authorization": f"Bearer {await _sp_graph_token()}"}
    url = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{SHAREPOINT_LIST_ID}/items/{item_id}"
    async with httpx.AsyncClient() as c:
        r = await c.delete(url, headers=headers, timeout=20)
        if r.status_code not in (204, 404):
            r.raise_for_status()
        return {"action": "deleted", "item_id": item_id, "status": r.status_code}
 
async def move_secret_to_ignored(item_id: str, fields: dict[str, str], reason: str) -> dict:
    """
    NEW — moves one row OUT of SecretAlertRegistry and INTO
    IgnoredSecretRegistry, for the -8-day "no action taken" check in
    decision_engine.py. This is a genuine move: create in the Ignored list
    first, THEN delete from the active list — never the other way around,
    so a failure partway through leaves the row duplicated (visible, safe
    to fix by hand) rather than the row vanishing from both lists entirely.
 
    fields should already be shaped to match IgnoredSecretRegistry's own
    schema (Title, AppName, SecretID, SecretDescription, ExpirationDate,
    DaysExpired, TenantID, LoggedDate, IgnoreReason) — see
    decision_engine.py's caller for how these are built.
 
    If SHAREPOINT_IGNORED_LIST_ID isn't configured, this is a no-op that
    returns success=False rather than raising — the caller decides what to
    do (typically: leave the row in SecretAlertRegistry rather than lose it).
    """
    if not SHAREPOINT_IGNORED_LIST_ID:
        return {"success": False, "error": "SHAREPOINT-IGNORED-LIST-ID not configured"}
 
    headers = {"Authorization": f"Bearer {await _sp_graph_token()}", "Content-Type": "application/json"}
    ignored_base = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{SHAREPOINT_IGNORED_LIST_ID}/items"
 
    fields = dict(fields)
    if not fields.get("TenantID"):
        fields["TenantID"] = GRAPH_TENANT_ID
 
    async with httpx.AsyncClient() as c:
        try:
            create_resp = await c.post(ignored_base, headers=headers, content=json.dumps({"fields": fields}), timeout=20)
            create_resp.raise_for_status()
        except Exception as e:
            return {"success": False, "error": f"create in IgnoredSecretRegistry failed: {e}"}
 
    try:
        await delete_sharepoint_row(item_id)
    except Exception as e:
        # The row now exists in BOTH lists — not ideal, but far safer than
        # the alternative (deleted from the active list, creation failed,
        # row now exists in NEITHER list). Log clearly so it's findable.
        log.error("move_secret_to_ignored: created in IgnoredSecretRegistry but FAILED to "
                  "delete original SecretAlertRegistry row %s — row now exists in BOTH "
                  "lists, needs manual cleanup: %s", item_id, e)
        return {"success": True, "warning": f"row exists in both lists — delete of {item_id} failed: {e}"}
 
    log.info("move_secret_to_ignored: moved item %s to IgnoredSecretRegistry (%s)", item_id, reason)
    return {"success": True}
 
async def create_ignored_row(fields: dict[str, str]) -> dict:
    """
    NEW - creates a fresh row directly in IgnoredSecretRegistry, for a secret
    that's brand new to monitoring AND already 8+ days expired. Unlike
    move_secret_to_ignored, there is no delete step here - the secret never
    had a SecretAlertRegistry row to begin with, so there's nothing to move
    it away from. This matches how runbook_discovery.py has always handled a
    freshly-discovered Ignore-bucket secret: straight into IgnoredSecretRegistry,
    never via the master list first.

    fields should already be shaped to match IgnoredSecretRegistry's own
    schema (Title, AppName, SecretID, SecretDescription, ExpirationDate,
    DaysExpired, TenantID, LoggedDate, IgnoreReason) - same shape
    move_secret_to_ignored expects.

    If SHAREPOINT_IGNORED_LIST_ID isn't configured, this is a no-op that
    returns success=False rather than raising - the caller decides what to
    do (typically: fall back to writing a plain Discovered row in the master
    list instead, so the secret is still tracked somewhere).
    """
    if not SHAREPOINT_IGNORED_LIST_ID:
        return {"success": False, "error": "SHAREPOINT-IGNORED-LIST-ID not configured"}

    headers = {"Authorization": f"Bearer {await _sp_graph_token()}", "Content-Type": "application/json"}
    ignored_base = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{SHAREPOINT_IGNORED_LIST_ID}/items"

    fields = dict(fields)
    if not fields.get("TenantID"):
        fields["TenantID"] = GRAPH_TENANT_ID

    async with httpx.AsyncClient() as c:
        try:
            r = await c.post(ignored_base, headers=headers, content=json.dumps({"fields": fields}), timeout=20)
            r.raise_for_status()
        except Exception as e:
            return {"success": False, "error": f"create in IgnoredSecretRegistry failed: {e}"}

    return {"success": True, "item_id": r.json().get("id")}

async def get_ignored_sharepoint_state() -> dict:
    """
    NEW - mirrors get_sharepoint_state() but reads IgnoredSecretRegistry
    instead of the master list. Needed so /tools/jira-status-update can look
    a ticket up in IgnoredSecretRegistry when it isn't found in the master
    list - i.e. the secret was already moved to Ignored (ticket canceled, or
    the -8-day abandonment check), and the ticket has now been reopened.

    Returns an empty result (not an error) if SHAREPOINT_IGNORED_LIST_ID
    isn't configured.
    """
    if not SHAREPOINT_IGNORED_LIST_ID:
        return {"items": [], "count": 0}

    headers = {"Authorization": f"Bearer {await _sp_graph_token()}"}
    url = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{SHAREPOINT_IGNORED_LIST_ID}/items?$expand=fields"
    items = []
    async with httpx.AsyncClient() as c:
        while url:
            r = await c.get(url, headers=headers, timeout=30)
            if not r.is_success:
                log.error("get_ignored_sharepoint_state Graph error [%s] for %s: %s",
                          r.status_code, url, r.text[:2000])
            r.raise_for_status()
            b = r.json()
            items.extend(b.get("value", []))
            url = b.get("@odata.nextLink")
    return {"items": items, "count": len(items)}

# ─────────────────────────────────────────────────────────────────────────────
# BACKUP / ARCHIVE — NEW. Generic helpers for the pre-run backup feature: both
# SecretAlertRegistry and IgnoredSecretRegistry get snapshotted into their own
# backup list before monitoring touches anything, and whatever was already IN
# that backup list gets archived to a Storage Account first if one is
# configured. See decision_engine.py's _rotate_backup_list() for the actual
# ordering/revert logic that calls these.
# ─────────────────────────────────────────────────────────────────────────────

# Graph fields that are system/read-only - never send these back on a create,
# SharePoint rejects or silently ignores most of them anyway. Filtering these
# OUT (rather than allowlisting business columns IN) means this works against
# any list's current schema without needing to know its exact columns ahead
# of time - new columns added to the source list later get backed up
# automatically, no code change needed here.
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

async def get_list_state(list_id: str) -> dict:
    """
    Generic reader, parameterized by list ID - same shape as
    get_sharepoint_state()/get_ignored_sharepoint_state(), used so the backup
    rotation logic can read/write EITHER backup list with one function
    instead of two near-duplicates.
    """
    if not list_id:
        return {"items": [], "count": 0}
    headers = {"Authorization": f"Bearer {await _sp_graph_token()}"}
    url = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{list_id}/items?$expand=fields"
    items = []
    async with httpx.AsyncClient() as c:
        while url:
            r = await c.get(url, headers=headers, timeout=30)
            if not r.is_success:
                log.error("get_list_state Graph error [%s] for list %s: %s",
                          r.status_code, list_id, r.text[:2000])
            r.raise_for_status()
            b = r.json()
            items.extend(b.get("value", []))
            url = b.get("@odata.nextLink")
    return {"items": items, "count": len(items)}

async def create_list_row(list_id: str, fields: dict) -> dict:
    headers = {"Authorization": f"Bearer {await _sp_graph_token()}", "Content-Type": "application/json"}
    url = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{list_id}/items"
    async with httpx.AsyncClient() as c:
        r = await c.post(url, headers=headers, content=json.dumps({"fields": fields}), timeout=20)
        if not r.is_success:
            # Row identity included so a failure is diagnosable from this one log
            # line alone - without it, a batch failure only tells you the status
            # code and Graph's error text, not which row triggered it.
            log.error("create_list_row Graph error [%s] for list %s (SecretID=%s, "
                      "AppName=%s, AlertStatus=%s): %s",
                      r.status_code, list_id, fields.get("SecretID"), fields.get("AppName"),
                      fields.get("AlertStatus"), r.text[:2000])
        r.raise_for_status()
        return {"item_id": r.json().get("id")}

async def delete_list_row(list_id: str, item_id: str) -> dict:
    headers = {"Authorization": f"Bearer {await _sp_graph_token()}"}
    url = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{list_id}/items/{item_id}"
    async with httpx.AsyncClient() as c:
        r = await c.delete(url, headers=headers, timeout=20)
        if r.status_code not in (204, 404):
            log.error("delete_list_row Graph error [%s] for list %s item %s: %s",
                      r.status_code, list_id, item_id, r.text[:2000])
            r.raise_for_status()
        return {"deleted": True}

async def _storage_token() -> str:
    """
    Token for the Storage Blob REST API - a DIFFERENT resource audience than
    Graph, so this cannot reuse _sp_graph_token()/_graph_token_for_tenant()
    even though it's the same underlying managed identity (_credential).
    """
    token = _credential.get_token("https://storage.azure.com/.default")
    return token.token

def _items_to_csv(items: list[dict]) -> bytes:
    """
    Flattens Graph list items down to just their `fields` dict (the actual
    SharePoint column values - id/createdDateTime/parentReference/etc. from
    the Graph envelope aren't useful in a CSV export) and serializes as CSV,
    one row per item. Columns are the union of every field name seen across
    all items, in first-seen order, so a row missing a given column just
    gets an empty cell rather than the whole export failing.
    """
    rows = [item.get("fields", {}) for item in items]
    fieldnames: list[str] = []
    seen = set()
    for row in rows:
        for k in row.keys():
            if k not in seen:
                seen.add(k)
                fieldnames.append(k)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue().encode("utf-8")

async def upload_backup_to_storage(blob_name: str, items: list[dict]) -> dict:
    """
    Uploads a CSV snapshot (a backup list's full item set, captured right
    before it gets overwritten by a newer one) to the dedicated backup
    Storage Account. A no-op returning skipped=True if
    BACKUP_STORAGE_ACCOUNT_URL isn't configured - the caller treats that as
    "storage not present" and falls back to a simpler delete-old/write-new
    flow with no archival, rather than failing the whole run over it.
    """
    if not BACKUP_STORAGE_ACCOUNT_URL:
        return {"success": False, "skipped": True, "error": "BACKUP_STORAGE_ACCOUNT_URL not configured"}

    body = _items_to_csv(items)
    url = f"{BACKUP_STORAGE_ACCOUNT_URL}/{BACKUP_CONTAINER_NAME}/{blob_name}"
    headers = {
        "Authorization": f"Bearer {await _storage_token()}",
        "x-ms-version": "2021-08-06",
        "x-ms-blob-type": "BlockBlob",
        "Content-Type": "text/csv",
        "Content-Length": str(len(body)),
    }
    try:
        async with httpx.AsyncClient() as c:
            r = await c.put(url, headers=headers, content=body, timeout=60)
            if not r.is_success:
                return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:300]}"}
        return {"success": True, "blob_name": blob_name}
    except Exception as e:
        return {"success": False, "error": str(e)}

def _days_expired_from_expiration(expiration_str: str) -> int:
    """Best-effort parse of the EST-formatted ExpirationDate string back into
    a days-expired count, for rebuilding IgnoredSecretRegistry's DaysExpired
    field when moving a row there. Falls back to 0 on any parse failure -
    this is informational only, never blocks the actual move."""
    try:
        exp = datetime.strptime(expiration_str, "%Y-%m-%d %I:%M:%S %p")
        return abs((datetime.now() - exp).days)
    except Exception:
        return 0

async def move_secret_from_ignored(item_id: str, fields: dict[str, str], reason: str) -> dict:
    """
    NEW - the reverse of move_secret_to_ignored: moves one row OUT of
    IgnoredSecretRegistry and back INTO the master SecretAlertRegistry list,
    for when a ticket that was Canceled (and moved to Ignored) gets reopened
    (To Do / In Progress / etc.) in Jira.

    Same safety ordering as move_secret_to_ignored: create in the master
    list FIRST, then delete from IgnoredSecretRegistry - a failure partway
    through leaves the row duplicated (visible, safe to fix by hand) rather
    than the row vanishing from both lists entirely.

    fields should already be shaped to match the master list's schema
    (Title, AppName, SecretID, SecretDescription, ExpirationDate,
    AlertStatus, ExpiryNotice, LastChecked, JiraTicketKey, TenantID).
    """
    headers = {"Authorization": f"Bearer {await _sp_graph_token()}", "Content-Type": "application/json"}
    master_base = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{SHAREPOINT_LIST_ID}/items"

    fields = dict(fields)
    if not fields.get("TenantID"):
        fields["TenantID"] = GRAPH_TENANT_ID

    async with httpx.AsyncClient() as c:
        try:
            create_resp = await c.post(master_base, headers=headers, content=json.dumps({"fields": fields}), timeout=20)
            create_resp.raise_for_status()
        except Exception as e:
            return {"success": False, "error": f"create in master list failed: {e}"}

    ignored_delete_url = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{SHAREPOINT_IGNORED_LIST_ID}/items/{item_id}"
    try:
        async with httpx.AsyncClient() as c:
            r = await c.delete(ignored_delete_url, headers=headers, timeout=20)
            if r.status_code not in (204, 404):
                r.raise_for_status()
    except Exception as e:
        log.error("move_secret_from_ignored: created in master list but FAILED to "
                  "delete original IgnoredSecretRegistry row %s — row now exists in BOTH "
                  "lists, needs manual cleanup: %s", item_id, e)
        return {"success": True, "warning": f"row exists in both lists — delete of {item_id} failed: {e}"}

    log.info("move_secret_from_ignored: moved item %s back to master list (%s)", item_id, reason)
    return {"success": True}

async def create_jira_ticket(app_name: str, app_id: str, secret_id: str, secret_description: str, expiration_date: str, days_remaining: int, severity: str = "WARNING", priority: str = "High", extra_note: str = "") -> dict:
    days_text = f"EXPIRED {abs(days_remaining)} days ago" if days_remaining < 0 else f"{days_remaining} days remaining"
    summary_line = f"[{severity}] Azure Secret Expiry - {app_name}"
    text = (f"App Registration Name: {app_name}\nApp ID: {app_id}\nSecret ID: {secret_id}\nSecret Description: {secret_description}\nSeverity: {severity}\n")
    if extra_note: text += f"\nNote: {extra_note}"
    payload = {"fields": {"project": {"key": JIRA_PROJECT_KEY}, "summary": summary_line, "description": text, "issuetype": {"name": JIRA_ISSUE_TYPE}, "priority": {"name": priority}, "labels": ["azure-secret", "rotation-required"], "duedate": expiration_date[:10]}}
    if JIRA_DESCRIPTION_CUSTOM_FIELD_ID:
        payload["fields"][JIRA_DESCRIPTION_CUSTOM_FIELD_ID] = text
    if JIRA_EPIC_KEY and JIRA_EPIC_KEY != "CSD-123": payload["fields"]["parent"] = {"key": JIRA_EPIC_KEY}
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{JIRA_BASE_URL}/rest/api/2/issue", headers={"Authorization": _jira_auth(), "Content-Type": "application/json"}, content=json.dumps(payload), timeout=20)
        if not r.is_success:
            log.error("create_jira_ticket failed [%s] for app_id=%s: %s", r.status_code, app_id, r.text[:500])
        r.raise_for_status()
        return {"issue_key": r.json()["key"]}
 
async def get_jira_issue(issue_key: str) -> dict:
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{JIRA_BASE_URL}/rest/api/2/issue/{issue_key}?fields=status,summary", headers={"Authorization": _jira_auth(), "Accept": "application/json"}, timeout=15)
        if r.status_code == 404: return {"issue_key": issue_key, "status": "NotFound", "summary": ""}
        r.raise_for_status()
        b = r.json()
    return {"issue_key": issue_key, "status": b.get("fields", {}).get("status", {}).get("name", "Unknown"), "summary": b.get("fields", {}).get("summary", "")}
 
async def add_jira_comment(issue_key: str, comment_text: str) -> dict:
    payload = {"body": comment_text}
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{JIRA_BASE_URL}/rest/api/2/issue/{issue_key}/comment", headers={"Authorization": _jira_auth(), "Content-Type": "application/json"}, content=json.dumps(payload), timeout=15)
        r.raise_for_status()
    return {"issue_key": issue_key, "comment_id": r.json().get("id", "")}
 
def _build_teams_mention_payload(alert_text: str, tag_email: str | None) -> dict:
    """
    Mirrors decision_engine.py's own _build_teams_mention_payload — kept here
    too since send_teams_alert is the actual HTTP boundary that posts to the
    Teams webhook, and needs to build the same msteams mention entity shape.
    If tag_email is empty/None, this degrades to a plain TextBlock with no
    mention — the same behavior as before this change, for every bucket that
    isn't P1.
    """
    body_items = [{"type": "TextBlock", "text": alert_text, "wrap": True}]
    msteams_entities = []
 
    if tag_email:
        mention_text = f"<at>{tag_email}</at>"
        body_items.append({"type": "TextBlock", "text": f"Attention: {mention_text}", "wrap": True})
        msteams_entities.append({
            "type": "mention",
            "text": mention_text,
            "mentioned": {"id": tag_email, "name": tag_email},
        })
 
    card_content: dict[str, Any] = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": body_items,
    }
    if msteams_entities:
        card_content["msteams"] = {"entities": msteams_entities}
 
    return {"attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card_content}]}
 
async def send_teams_alert(alert_text: str, tag_email: str | None = None) -> dict:
    """
    UPDATED — now accepts tag_email, matching decision_engine.py's call
    signature: send_teams_alert(text, tag_email=tag_email). Previously this
    function ignored any tag entirely and always sent a plain TextBlock —
    so even though decision_engine.py already computed tag_email for P1
    alerts and passed it through, nothing here actually used it, and no
    P1 alert ever tagged anyone. This was the missing half of the wiring;
    the other half (reading TEAMS-TAG-EMAIL from Key Vault, passing it into
    run_secret_monitoring) is done at the bottom of this file.
    """
    payload = _build_teams_mention_payload(alert_text, tag_email)
    async with httpx.AsyncClient() as c:
        try:
            r = await c.post(TEAMS_WEBHOOK_URL, content=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=20)
            if r.status_code in (200, 202): return {"success": True}
            return {"success": False, "note": r.text[:300]}
        except Exception as e:
            return {"success": False, "note": str(e)}
 
# ── FastAPI Endpoints ─────────────────────────────────────────────────────────
from decision_engine import run_secret_monitoring as _run_secret_monitoring
 
app = FastAPI(title="Azure Secret Monitor API")
 
@app.get("/health")
async def health(): return {"status": "ok", "server": "AzureSecretMonitor-API"}
 
@app.post("/tools/fetch_azure_secrets")
async def api_fetch_azure_secrets(): return await fetch_azure_secrets()
 
@app.post("/tools/get_sharepoint_state")
async def api_get_sharepoint_state(): return await get_sharepoint_state()
 
class WriteSPReq(BaseModel):
    item_id: Optional[str] = None
    fields: dict
@app.post("/tools/write_sharepoint_row")
async def api_write_sharepoint_row(req: WriteSPReq): return await write_sharepoint_row(req.item_id, req.fields)
 
class JiraReq(BaseModel):
    app_name: str
    app_id: str
    secret_id: str
    secret_description: str
    expiration_date: str
    days_remaining: int
    severity: str = "WARNING"
    priority: str = "High"
    extra_note: str = ""
@app.post("/tools/create_jira_ticket")
async def api_create_jira_ticket(req: JiraReq): return await create_jira_ticket(**req.dict())
 
class GetJiraReq(BaseModel): issue_key: str
@app.post("/tools/get_jira_issue")
async def api_get_jira_issue(req: GetJiraReq): return await get_jira_issue(req.issue_key)
 
class CommentReq(BaseModel):
    issue_key: str
    comment_text: str
@app.post("/tools/add_jira_comment")
async def api_add_jira_comment(req: CommentReq): return await add_jira_comment(req.issue_key, req.comment_text)
 
class TeamsReq(BaseModel):
    alert_text: str
    tag_email: Optional[str] = None
@app.post("/tools/send_teams_alert")
async def api_send_teams_alert(req: TeamsReq): return await send_teams_alert(req.alert_text, req.tag_email)
 
@app.post("/tools/run_secret_monitoring")
async def api_run_monitoring():
    return await _run_secret_monitoring(
        fetch_azure_secrets           = fetch_azure_secrets,
        get_sharepoint_state          = get_sharepoint_state,
        write_sharepoint_row          = write_sharepoint_row,
        create_jira_ticket            = create_jira_ticket,
        get_jira_issue                = get_jira_issue,
        add_jira_comment              = add_jira_comment,
        send_teams_alert              = send_teams_alert,
        move_secret_to_ignored        = move_secret_to_ignored,
        move_secret_from_ignored      = move_secret_from_ignored,  # NEW — Feature 2: Ignored -> master restore trigger
        create_ignored_row            = create_ignored_row,  # NEW — brand-new secret already 8+ days expired, straight to IgnoredSecretRegistry
        get_product_service_principal = get_product_service_principal,  # NEW — ProductName -> ManualAppOwners lookup
        fetch_app_owners              = fetch_app_owners,   # NEW — wires up real AppOwners population from Entra (was previously dead)
        owner_emails                  = OWNER_EMAILS,       # IGNORED by default — see manual_owners_only in decision_engine.py
        teams_tag_email               = TEAMS_TAG_EMAIL,    # person @mentioned on P1 alerts, from KV TEAMS-TAG-EMAIL
        # NEW — pre-run backup rotation, see decision_engine.py's _rotate_backup_list()
        get_ignored_sharepoint_state  = get_ignored_sharepoint_state,
        backup_list_id                = SHAREPOINT_BACKUP_LIST_ID,
        ignored_backup_list_id        = SHAREPOINT_IGNORED_BACKUP_LIST_ID,
        get_list_state                = get_list_state,
        create_list_row                = create_list_row,
        delete_list_row                = delete_list_row,
        upload_backup_to_storage      = (upload_backup_to_storage if BACKUP_STORAGE_ACCOUNT_URL else None),
    )
 
class JiraCloseReq(BaseModel):
    jira_key: str
    today: str
 
@app.post("/tools/update_on_jira_close")
async def api_update_on_jira_close(req: JiraCloseReq):
    """
    Called directly when a Jira ticket is closed — no AI needed.
    Finds SharePoint rows with matching JiraTicketKey and marks them as Rotated.
    """
    sp_data = await get_sharepoint_state()
    today   = req.today
    updated = 0
 
    for item in sp_data.get("items", []):
        f = item.get("fields", {})
        if f.get("JiraTicketKey") == req.jira_key:
            await write_sharepoint_row(item["id"], {
                "AlertStatus":          "Rotated",
                "RotationDetectedDate": today,
                "ExpiryNotice":         "Rotated — Completed",
                "LastChecked":          today,
            })
            updated += 1
            log.info("Marked Rotated: item=%s jira=%s", item["id"], req.jira_key)
 
    log.info("update_on_jira_close: %s rows updated for %s", updated, req.jira_key)
    return {"updated": updated, "jira_key": req.jira_key}
 
# An Azure AD passwordCredential keyId is always a GUID - anything else typed
# into Jira's NewSecretKeyId field is a typo, not a real secret ID. Checked
# before either write site below ever puts a value into SharePoint.
_AZURE_SECRET_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

class JiraStatusUpdateReq(BaseModel):
    jira_key:  str
    to_status: str   # Jira destination status name, exact text from the workflow
    today:     str
    # Populated from the Jira issue's custom fields (see automation rule body
    # below). Backfilled into the matching SharePoint row on In Progress AND
    # Resolved (a "second check" at Resolve), only when that row's own
    # column is empty — never overwrites an existing value. Unless
    # overwrite=True, see below.
    team_name:           Optional[str] = None
    product_name:        Optional[str] = None
    devsecops_ownership: Optional[str] = None  # DEPRECATED — DevSecOpsOwnership was
                                                # removed from Jira; ownership is now
                                                # resolved via sync.py's ProductName ->
                                                # Key Vault lookup instead. Left as an
                                                # accepted-but-unused field rather than
                                                # removed, since nothing currently sends it.
    # NEW — added for the To Do -> In Progress workflow gate.
    product_teams_key_vault_name: Optional[str] = None
    new_secret_vault_name:        Optional[str] = None
    new_secret_key_id:            Optional[str] = None
    new_secret_present:           Optional[str] = None  # "Yes"/"No" from Jira's NewSecretPresent field
    # NEW — comments field paired with Jira's NewSecretUpdatedReferenceInventoryPresent
    # Yes/No gate (Jira-only, not sent here — same pattern as new_secret_present
    # above). Syncs to SharePoint's NewSecretUpdatedReferenceInventory column only.
    new_secret_updated_reference_inventory: Optional[str] = None
    # NEW — set True by a separate "field value changed" Jira automation rule
    # (not the status-transition rule above), fired when an engineer edits
    # TeamName/ProductName/ProductTeamsKeyVaultName/NewSecretVaultName/
    # NewSecretKeyId directly, with no status transition involved. Unlike the
    # status-transition path, this OVERWRITES the SharePoint column
    # unconditionally rather than only filling blanks — explicit client
    # requirement: an engineer correcting a field after the fact should see
    # that correction actually take effect. The Jira-side rule's own
    # condition already restricts this to non-Resolved tickets; status is
    # re-checked server-side too, defensively, before honoring this flag.
    overwrite: bool = False

@app.post("/tools/jira-status-update")
async def api_jira_status_update(req: JiraStatusUpdateReq):
    """
    Unified endpoint — handles ALL Jira ticket transitions in one rule.
    Called by a single Jira automation rule covering every status in the
    client's actual "Incident workflow": To Do, In Progress, Done, Canceled,
    Blocked, Awaiting Reporter: Needs more information.
 
    FIX (this version): previously only 6 status name variants across 2
    buckets were recognized (roughly matching Resolved/Done/Closed and In
    Progress/To Do/Reopened/Open) — anything else, including "Canceled",
    "Blocked", or "Awaiting Reporter...", fell into the unhandled else
    branch and did NOTHING to SharePoint. This is very likely the cause of
    the client's reported issue ("changing status from Done to In Progress
    isn't updating SharePoint") IF the Jira automation rule's trigger was
    only configured to fire on a subset of these statuses rather than all
    six — a rule watching only "Resolved" would never fire on a ticket
    that's actually sitting in "Done" being moved to "In Progress", since
    the FROM status never matched the trigger at all. See the automation
    rule setup below — it must watch ALL SIX destination statuses, not a
    subset, for this endpoint to ever be called on every real transition.
 
    Jira automation rule setup (Project Settings -> Automation -> new rule):
      Trigger : Work item transitioned
        To status : TO DO, IN PROGRESS, DONE, CANCELED, BLOCKED,
                     AWAITING REPORTER: NEEDS MORE INFORMATION
                     (ALL SIX - do not scope this down to a subset, or
                     transitions into an unwatched status will silently
                     never call this endpoint at all)
      Action  : Send web request
        Method : POST
        URL    : https://<container-1-fqdn>/jira-status-update
                 (Container 1's proxy route - see that file's docstring for
                 why this goes through Container 1 rather than straight to
                 this endpoint: ingress only exposes one port at a time, and
                 Container 1's port is the one that also needs to stay
                 reachable for the scheduled /run trigger)
        Body   : {
                   "jira_key":                     "{{issue.key}}",
                   "to_status":                    "{{issue.status.name}}",
                   "today":                        "{{now.jiraDate}}",
                   "team_name":                    "{{issue.customfield_10185.value}}",
                   "product_name":                 "{{issue.customfield_10186.value}}",
                   "product_teams_key_vault_name": "{{issue.customfield_10190.value}}",
                   "new_secret_vault_name":        "{{issue.customfield_10189}}",
                   "new_secret_key_id":            "{{issue.customfield_10188}}",
                   "new_secret_present":           "{{issue.customfield_10191.value}}",
                   "new_secret_updated_reference_inventory": "{{issue.customfield_10224}}"
                 }
        NOTE: {{now.format('yyyy-MM-dd')}} (single-quoted arg) has been seen
        to fail with "Unable to render smart values" in some Jira
        environments, which silently kills the whole request before it's
        ever sent - {{now.jiraDate}} is the confirmed-working equivalent.
        NOTE: to_status uses {{issue.status.name}}, NOT {{destinationStatus.name}}
        - the latter looks like the more "correct" smart value for a
        transition trigger and is what Atlassian's own docs typically show,
        but it does not reliably resolve in this rule's automation builder;
        it arrived as an empty string on every real transition tested,
        confirmed via raw request logging in this endpoint, while every
        {{issue.*}} value in the same body resolved correctly every time.
        Since a rule's actions run AFTER its transition has completed,
        {{issue.status.name}} already reflects the new status by request
        time, and it's the one proven reliable here.
        NOTE: customfield_10185/10186/10187/10188/10189/10190 are KAN
        project field IDs (TeamName/ProductName/NewSecretPresent/
        NewSecretKeyId/NewSecretVaultName/ProductTeamsKeyVaultName
        respectively) - these IDs change every time a field is deleted and
        recreated (Jira never reuses a customfield_NNNNN number), so check
        them against the project's current field list before trusting any
        past version of this docstring. The old DevSecOpsOwnership field
        (customfield_10112 in an earlier iteration) was removed entirely
        and is deliberately NOT sent anymore. Sent on both In Progress and
        Resolved so the backfill below can run at either transition -
        harmless no-ops on every other transition since the backfill logic
        only reads them when status is In Progress/Done/Resolved.
        NOTE: TeamName/ProductName/ProductTeamsKeyVaultName/NewSecretPresent
        are select-list (dropdown) fields - Jira's API returns those as an
        object ({id, value, self}), not a plain string, so the smart value
        needs ".value" appended (e.g. {{issue.customfield_10185.value}}) or
        the field arrives empty even though the ticket has one selected.
        NewSecretVaultName/NewSecretKeyId are plain free-text fields and
        must NOT get ".value" - they're already a string.
        NOTE: there is also a customfield_10187 (NewSecretKeyIDPresent) and
        customfield_10191 (NewSecretPresent) on this issue type - Jira-only
        Yes/No gates deciding whether NewSecretKeyId/NewSecretVaultName are
        required, enforced entirely by Jira Automation rules. NewSecretPresent
        (10191) IS sent above as "new_secret_present" (used for the intake
        acknowledgment comment below - it answers "is a new secret already
        present in the vault", not "is a key ID present", so it must read
        10191, not 10187 - a stale-ID bug caught and fixed here after the
        NewSecretKeyIDPresent/NewSecretPresent field split).
        NewSecretKeyIDPresent (10187) is not sent since the backend has no
        use for it.
        NOTE: customfield_10224 (NewSecretUpdatedReferenceInventory, a
        paragraph/free-text field) and customfield_10225
        (NewSecretUpdatedReferenceInventoryPresent, its Yes/No gate) were
        added later. Only 10224 is sent here - same pattern as
        NewSecretPresent/NewSecretVaultName: the gate stays Jira-only, only
        the actual value syncs to SharePoint (into a column of the same
        name, NewSecretUpdatedReferenceInventory - comments only, no
        "Present" column exists in SharePoint by design).

    SharePoint AlertStatus mapping:
      Done                                        -> Rotated
      Canceled                                     -> row MOVED to IgnoredSecretRegistry (see below)
      In Progress / To Do                          -> JiraRaised (reopened - monitoring resumes)
      Blocked                                      -> Blocked (visible in SharePoint, distinct from JiraRaised)
      Awaiting Reporter: Needs more information     -> AwaitingReporter (visible in SharePoint,
                                                       distinct from Blocked)
    Every one of the six real statuses now maps to SOMETHING - there is no
    remaining "falls through, does nothing" case for a status that's part
    of the actual configured workflow. An entirely unrecognized status name
    (a future workflow change, a typo in the automation rule) still logs
    and no-ops rather than guessing, which is the correct behavior for a
    status this endpoint has never been told about.

    FIX (this version) - TWO-WAY sync with IgnoredSecretRegistry:
    Previously "Canceled" just set AlertStatus="Ignored" on the row IN
    PLACE in the master list. Since "Ignored" is a terminal status,
    monitoring would then skip that row forever - it never actually moved
    to IgnoredSecretRegistry the way the -8-day abandonment check does for
    the same conceptual outcome. Now:
      - Canceled  -> the row is physically MOVED to IgnoredSecretRegistry
        (create there, delete from the master list), same move_secret_to_
        ignored() function the abandonment check already uses.
      - Any other status, when the ticket ISN'T found in the master list ->
        IgnoredSecretRegistry is checked too. If found there, the row is
        moved BACK to the master list with the appropriate AlertStatus,
        since a non-Canceled transition means the ticket is active again.
    This requires a JiraTicketKey column on IgnoredSecretRegistry (added
    for this - see decision_engine.py's Ignore-branch, which now also
    stamps it). Rows moved to IgnoredSecretRegistry BEFORE this column
    existed have no JiraTicketKey recorded and can't be found by the
    reverse lookup even if their ticket is later reopened - only rows
    ignored from this point forward are covered.
    """
    log.info(
        "jira-status-update: RAW request received: jira_key=%r to_status=%r today=%r "
        "team_name=%r product_name=%r product_teams_key_vault_name=%r "
        "new_secret_vault_name=%r new_secret_key_id=%r new_secret_present=%r "
        "new_secret_updated_reference_inventory=%r",
        req.jira_key, req.to_status, req.today, req.team_name, req.product_name,
        req.product_teams_key_vault_name, req.new_secret_vault_name,
        req.new_secret_key_id, req.new_secret_present,
        req.new_secret_updated_reference_inventory,
    )
    today  = req.today
    status = req.to_status.strip().lower()

    # Determine what AlertStatus to set based on Jira transition. Matched
    # against the client's ACTUAL 6-status "Incident workflow" (see the
    # module docstring for the workflow diagram this was verified against).
    DONE_STATUSES        = {"done", "resolved"}   # "resolved" added — the live KAN
                                                    # Incident workflow's actual terminal
                                                    # status is "Resolved", not "Done"
    CANCELED_STATUSES     = {"canceled", "cancelled"}   # accept both spellings
    REOPEN_STATUSES       = {"in progress", "to do", "reopened", "open"}
    BLOCKED_STATUSES      = {"blocked"}
    AWAITING_STATUSES     = {
        "awaiting reporter: needs more information",
        "awaiting reporter",   # in case Jira truncates/aliases the full name
        "waiting for customer",  # KAN project's actual live status name for
                                  # this same "waiting on reporter/customer
                                  # for info" concept — different wording,
                                  # same AlertStatus outcome
    }

    if status in DONE_STATUSES:
        new_alert_status  = "Rotated"
        new_expiry_notice = "Rotated - Completed"
        extra_fields      = {"RotationDetectedDate": today}
    elif status in CANCELED_STATUSES:
        new_alert_status  = "Ignored"
        new_expiry_notice = f"Jira ticket {req.jira_key} canceled - no longer tracked"
        extra_fields      = {}
    elif status in REOPEN_STATUSES:
        new_alert_status  = "JiraRaised"
        new_expiry_notice = f"Jira ticket {req.jira_key} reopened - monitoring resumed"
        extra_fields      = {}
    elif status in BLOCKED_STATUSES:
        new_alert_status  = "Blocked"
        new_expiry_notice = f"Jira ticket {req.jira_key} is blocked"
        extra_fields      = {}
    elif status in AWAITING_STATUSES:
        new_alert_status  = "AwaitingReporter"
        new_expiry_notice = f"Jira ticket {req.jira_key} awaiting reporter - needs more information"
        extra_fields      = {}
    else:
        log.info("jira-status-update: unhandled status '%s' for %s - no SP update "
                 "(this status is not part of the 6 recognized workflow states - "
                 "check for a typo in the Jira automation rule, or a workflow change "
                 "this endpoint hasn't been updated for)",
                 req.to_status, req.jira_key)
        return {"updated": 0, "jira_key": req.jira_key,
                "note": f"Status '{req.to_status}' not mapped - no action taken"}

    # NEW - immediate acknowledgment when the engineer marks a secret NOT
    # already present (NewSecretPresent = No) at ticket intake. Fires once,
    # right at the In Progress transition, rather than waiting until actual
    # rotation happens (which could be a long time later, once the secret
    # nears its threshold days) - the engineer gets confirmation their input
    # was received immediately instead of silence until much later.
    if status == "in progress" and (req.new_secret_present or "").strip().lower() == "no":
        try:
            await add_jira_comment(
                req.jira_key,
                "✅ Noted — this secret is scheduled for automatic rotation. "
                "No manual action is needed; the rotation runbook will "
                "generate a new secret once it's due and update this ticket "
                "and SharePoint automatically.",
            )
        except Exception as e:
            log.warning("jira-status-update: failed to add NewSecretPresent=No "
                        "acknowledgment comment for %s: %s", req.jira_key, e)

    # -- Step 1: search the master list first, same as before -----------------
    sp_data = await get_sharepoint_state()
    master_matches = [item for item in sp_data.get("items", [])
                       if item.get("fields", {}).get("JiraTicketKey") == req.jira_key]

    updated  = 0
    moved_to_ignored   = 0
    moved_from_ignored = 0

    if master_matches:
        for item in master_matches:
            f = item.get("fields", {})
            if status in CANCELED_STATUSES:
                # Physically move to IgnoredSecretRegistry instead of just
                # tagging AlertStatus="Ignored" in place - see the FIX note
                # in the docstring above for why.
                ignored_fields = {
                    "Title":             f.get("Title", ""),
                    "AppName":           f.get("AppName", ""),
                    "SecretID":          f.get("SecretID", ""),
                    "SecretDescription": f.get("SecretDescription", ""),
                    "ExpirationDate":    f.get("ExpirationDate", ""),
                    "DaysExpired":       _days_expired_from_expiration(f.get("ExpirationDate", "")),
                    "TenantID":          f.get("TenantID", ""),
                    "LoggedDate":        today,
                    "IgnoreReason":      f"Jira ticket {req.jira_key} canceled",
                    "JiraTicketKey":     req.jira_key,
                    "AlertStatus":       "Ignored",
                }
                move_result = await move_secret_to_ignored(
                    item["id"], ignored_fields, f"Jira ticket {req.jira_key} canceled")
                if move_result.get("success"):
                    updated += 1
                    moved_to_ignored += 1
                    log.info("jira-status-update: item=%s jira=%s -> moved to IgnoredSecretRegistry",
                             item["id"], req.jira_key)
            else:
                fields = {
                    "AlertStatus":  new_alert_status,
                    "ExpiryNotice": new_expiry_notice,
                    "LastChecked":  today,
                    **extra_fields,
                }
                if req.overwrite and status not in DONE_STATUSES:
                    # NEW - explicit field-edit sync, fired by a separate
                    # "field value changed" Jira automation rule rather than
                    # the status-transition rule. Unlike the fill-blanks
                    # backfill below, this OVERWRITES the SharePoint column
                    # unconditionally whenever Jira carries a non-empty
                    # value for it - an engineer correcting a field after
                    # the fact must see that correction actually take
                    # effect. Deliberately allowed for ANY non-Resolved
                    # status (To Do, In Progress, Waiting for Customer), not
                    # just In Progress - the Jira-side rule's own condition
                    # already restricts this to non-Resolved tickets, and
                    # "status not in DONE_STATUSES" re-checks that here too,
                    # defensively, in case that condition is ever removed or
                    # misconfigured on the Jira side.
                    #
                    # This can overwrite a value rotation itself already
                    # wrote (NewSecretVaultName/NewSecretKeyId) - by explicit
                    # client instruction, engineers are expected to make all
                    # corrections before rotation runs, not after.
                    if req.team_name:
                        fields["TeamName"] = req.team_name
                    if req.product_name:
                        fields["ProductName"] = req.product_name
                    if req.product_teams_key_vault_name:
                        fields["ProductTeamsKeyVaultName"] = req.product_teams_key_vault_name
                    if req.new_secret_vault_name:
                        fields["NewSecretVaultName"] = req.new_secret_vault_name
                    if req.new_secret_key_id is not None:
                        candidate = req.new_secret_key_id.strip()
                        if not candidate:
                            # Explicit clear - engineer blanked the field back
                            # out in Jira, so blank it in SharePoint too.
                            fields["NewSecretKeyId"] = ""
                        elif _AZURE_SECRET_ID_RE.match(candidate):
                            fields["NewSecretKeyId"] = candidate
                        else:
                            log.warning(
                                "jira-status-update: new_secret_key_id %r for %s is not a "
                                "valid Azure secret ID (expected "
                                "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) - not writing to SharePoint",
                                candidate, req.jira_key,
                            )
                    if req.new_secret_updated_reference_inventory:
                        # SharePoint truncated this column's internal REST name
                        # to "NewSecretUpdatedReferenceInvento" (missing "ry")
                        # at creation time - the display name in the UI is the
                        # full "NewSecretUpdatedReferenceInventory", but Graph's
                        # fields PATCH requires the actual internal name.
                        fields["NewSecretUpdatedReferenceInvento"] = req.new_secret_updated_reference_inventory
                elif status in DONE_STATUSES or status in REOPEN_STATUSES:
                    # Backfill only — never overwrites a value someone already
                    # set in SharePoint. Fires on BOTH In Progress and
                    # Resolved now (Resolved acts as a "second check" per
                    # explicit client requirement, since a field cleared
                    # after In Progress would otherwise never get re-synced).
                    # devsecops_ownership is never actually sent anymore
                    # (DevSecOpsOwnership was removed from Jira) so this
                    # branch is a permanent no-op for it, harmlessly.
                    if not f.get("TeamName") and req.team_name:
                        fields["TeamName"] = req.team_name
                    if not f.get("ProductName") and req.product_name:
                        fields["ProductName"] = req.product_name
                    if not f.get("DevSecOpsOwnership") and req.devsecops_ownership:
                        fields["DevSecOpsOwnership"] = req.devsecops_ownership
                    if not f.get("ProductTeamsKeyVaultName") and req.product_teams_key_vault_name:
                        fields["ProductTeamsKeyVaultName"] = req.product_teams_key_vault_name
                    if not f.get("NewSecretVaultName") and req.new_secret_vault_name:
                        fields["NewSecretVaultName"] = req.new_secret_vault_name
                    if not f.get("NewSecretKeyId") and req.new_secret_key_id:
                        candidate = req.new_secret_key_id.strip()
                        if _AZURE_SECRET_ID_RE.match(candidate):
                            fields["NewSecretKeyId"] = candidate
                        else:
                            log.warning(
                                "jira-status-update: new_secret_key_id %r for %s is not a "
                                "valid Azure secret ID (expected "
                                "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) - not backfilling into SharePoint",
                                candidate, req.jira_key,
                            )
                    if not f.get("NewSecretUpdatedReferenceInvento") and req.new_secret_updated_reference_inventory:
                        # See the NOTE above the overwrite branch's equivalent
                        # line - "NewSecretUpdatedReferenceInvento" (no "ry")
                        # is the real internal column name, truncated by
                        # SharePoint at creation time.
                        fields["NewSecretUpdatedReferenceInvento"] = req.new_secret_updated_reference_inventory
                    # NOTE: new_secret_present is deliberately NOT written to
                    # SharePoint - there's no column for it. It only exists
                    # to trigger the "scheduled for autorotation" Jira
                    # comment above. The rotation runbook infers the same
                    # Yes/No distinction by checking whether NewSecretKeyId
                    # (backfilled just above, when the engineer typed one in)
                    # is already non-empty - no separate column needed.
                await write_sharepoint_row(item["id"], fields)
                updated += 1
                log.info("jira-status-update: item=%s jira=%s -> AlertStatus=%s",
                         item["id"], req.jira_key, new_alert_status)

    # -- Step 2: not found in the master list, and not a Canceled transition -
    #            check IgnoredSecretRegistry too, in case this ticket was
    #            previously canceled (moved there) and is now reopened. -----
    elif status not in CANCELED_STATUSES:
        ignored_data = await get_ignored_sharepoint_state()
        ignored_matches = [item for item in ignored_data.get("items", [])
                            if item.get("fields", {}).get("JiraTicketKey") == req.jira_key]
        for item in ignored_matches:
            f = item.get("fields", {})
            master_fields = {
                "Title":             f.get("Title", ""),
                "AppName":           f.get("AppName", ""),
                "SecretID":          f.get("SecretID", ""),
                "SecretDescription": f.get("SecretDescription", ""),
                "ExpirationDate":    f.get("ExpirationDate", ""),
                "TenantID":          f.get("TenantID", ""),
                "JiraTicketKey":     req.jira_key,
                "AlertStatus":       new_alert_status,
                "ExpiryNotice":      new_expiry_notice,
                "LastChecked":       today,
                **extra_fields,
            }
            move_result = await move_secret_from_ignored(
                item["id"], master_fields,
                f"Jira ticket {req.jira_key} reopened ({req.to_status})")
            if move_result.get("success"):
                updated += 1
                moved_from_ignored += 1
                log.info("jira-status-update: item=%s jira=%s -> moved back to master list, AlertStatus=%s",
                         item["id"], req.jira_key, new_alert_status)

    log.info("jira-status-update: %s row(s) updated for %s (-> %s) "
             "[movedToIgnored=%s, movedFromIgnored=%s]",
             updated, req.jira_key, new_alert_status, moved_to_ignored, moved_from_ignored)
    return {
        "updated":           updated,
        "jira_key":          req.jira_key,
        "to_status":         req.to_status,
        "alert_status":      new_alert_status,
        "movedToIgnored":    moved_to_ignored,
        "movedFromIgnored":  moved_from_ignored,
    }
 
# Keep old endpoints for backwards compatibility
class JiraCloseReqLegacy(BaseModel):
    jira_key: str
    today: str
 
class JiraReopenReq(BaseModel):
    jira_key: str
    today: str
 
@app.post("/tools/update_on_jira_reopen")
async def api_update_on_jira_reopen(req: JiraReopenReq):
    """Legacy endpoint — use /tools/jira-status-update instead."""
    return await api_jira_status_update(
        JiraStatusUpdateReq(
            jira_key=req.jira_key,
            to_status="In Progress",
            today=req.today,
        )
    )
 
log.info("REST API Server ready — GET /health | POST /tools/*")
 
 
