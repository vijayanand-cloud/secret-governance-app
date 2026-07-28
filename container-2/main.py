"""
Azure Entra Secret Monitoring — REST API (Replaces FastMCP)
"""
from __future__ import annotations

import base64 as _b64
import json
import logging
import os
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
# e.g. "vijayanand@x.com, john@x.com, priya@x.com"
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

try:
    JIRA_PROJECT_KEY = _kv_get("JIRA-PROJECT-KEY").strip()
except Exception:
    JIRA_PROJECT_KEY = "KAN"
try:
    JIRA_EPIC_KEY = _kv_get("JIRA-EPIC-KEY").strip()
except Exception:
    JIRA_EPIC_KEY = ""
try:
    JIRA_ISSUE_TYPE = _kv_get("JIRA-ISSUE-TYPE").strip()
except Exception:
    JIRA_ISSUE_TYPE = "Incident"

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
    support). Returns a comma-separated string of owner emails/names.

    Owner types:
      - User          → stored as UPN (email): vijay@contoso.com
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
                # User owner — use their email (UPN)
                upn = owner.get("userPrincipalName") or owner.get("mail") or owner.get("displayName", "")
                if upn:
                    owner_list.append(upn)
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
    for col in {"LastChecked", "AlertSentDate", "RotationDetectedDate", "ExpirationDate", "JiraTicketCreatedDate"}:
        if col in fields and fields[col]: fields[col] = str(fields[col])[:10]
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
            r.raise_for_status()
            return {"action": "created", "item_id": r.json().get("id"), "fields": fields}
        else:
            r = await c.patch(f"{base}/{item_id}", headers=headers, content=json.dumps({"fields": fields}), timeout=20)
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

async def create_jira_ticket(app_name: str, app_id: str, secret_id: str, secret_description: str, expiration_date: str, days_remaining: int, severity: str = "WARNING", priority: str = "High", extra_note: str = "") -> dict:
    days_text = f"EXPIRED {abs(days_remaining)} days ago" if days_remaining < 0 else f"{days_remaining} days remaining"
    summary_line = f"[{severity}] Azure Secret Expiry - {app_name} - {days_text}"
    text = (f"App Registration Name: {app_name}\nApp ID: {app_id}\nSecret ID: {secret_id}\nSecret Description: {secret_description}\nExpiration: {expiration_date}\nDays Remaining: {days_text}\nSeverity: {severity}\n")
    if extra_note: text += f"\nNote: {extra_note}"
    payload = {"fields": {"project": {"key": JIRA_PROJECT_KEY}, "summary": summary_line, "description": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]}, "issuetype": {"name": JIRA_ISSUE_TYPE}, "priority": {"name": priority}, "labels": ["azure-secret", "rotation-required"]}}
    if JIRA_EPIC_KEY and JIRA_EPIC_KEY != "KAN-123": payload["fields"]["parent"] = {"key": JIRA_EPIC_KEY}
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{JIRA_BASE_URL}/rest/api/3/issue", headers={"Authorization": _jira_auth(), "Content-Type": "application/json"}, content=json.dumps(payload), timeout=20)
        r.raise_for_status()
        return {"issue_key": r.json()["key"]}

async def get_jira_issue(issue_key: str) -> dict:
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}?fields=status,summary", headers={"Authorization": _jira_auth(), "Accept": "application/json"}, timeout=15)
        if r.status_code == 404: return {"issue_key": issue_key, "status": "NotFound", "summary": ""}
        r.raise_for_status()
        b = r.json()
    return {"issue_key": issue_key, "status": b.get("fields", {}).get("status", {}).get("name", "Unknown"), "summary": b.get("fields", {}).get("summary", "")}

async def add_jira_comment(issue_key: str, comment_text: str) -> dict:
    payload = {"body": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": comment_text}]}]}}
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/comment", headers={"Authorization": _jira_auth(), "Content-Type": "application/json"}, content=json.dumps(payload), timeout=15)
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
        get_product_service_principal = get_product_service_principal,  # NEW — ProductName -> ManualAppOwners lookup
        owner_emails                  = OWNER_EMAILS,       # IGNORED by default — see manual_owners_only in decision_engine.py
        teams_tag_email               = TEAMS_TAG_EMAIL,    # person @mentioned on P1 alerts, from KV TEAMS-TAG-EMAIL
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

class JiraStatusUpdateReq(BaseModel):
    jira_key:  str
    to_status: str   # Jira destination status name, exact text from the workflow
    today:     str

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

    Jira automation rule setup (Project Settings → Automation → new rule):
      Trigger : Work item transitioned
        To status : TO DO, IN PROGRESS, DONE, CANCELED, BLOCKED,
                     AWAITING REPORTER: NEEDS MORE INFORMATION
                     (ALL SIX — do not scope this down to a subset, or
                     transitions into an unwatched status will silently
                     never call this endpoint at all)
      Action  : Send web request
        Method : POST
        URL    : https://<container-2-fqdn>/tools/jira-status-update
        Body   : {
                   "jira_key":  "{{issue.key}}",
                   "to_status": "{{destinationStatus.name}}",
                   "today":     "{{now.format('yyyy-MM-dd')}}"
                 }

    SharePoint AlertStatus mapping:
      Done                                        → Rotated
      Canceled                                     → Ignored (secret no longer being tracked)
      In Progress / To Do                          → JiraRaised (reopened — monitoring resumes)
      Blocked                                      → Blocked (visible in SharePoint, distinct from JiraRaised)
      Awaiting Reporter: Needs more information     → AwaitingReporter (visible in SharePoint,
                                                       distinct from Blocked)
    Every one of the six real statuses now maps to SOMETHING — there is no
    remaining "falls through, does nothing" case for a status that's part
    of the actual configured workflow. An entirely unrecognized status name
    (a future workflow change, a typo in the automation rule) still logs
    and no-ops rather than guessing, which is the correct behavior for a
    status this endpoint has never been told about.
    """
    sp_data   = await get_sharepoint_state()
    today     = req.today
    updated   = 0
    status    = req.to_status.strip().lower()

    # Determine what AlertStatus to set based on Jira transition. Matched
    # against the client's ACTUAL 6-status "Incident workflow" (see the
    # module docstring for the workflow diagram this was verified against).
    DONE_STATUSES        = {"done"}
    CANCELED_STATUSES     = {"canceled", "cancelled"}   # accept both spellings
    REOPEN_STATUSES       = {"in progress", "to do", "reopened", "open"}
    BLOCKED_STATUSES      = {"blocked"}
    AWAITING_STATUSES     = {
        "awaiting reporter: needs more information",
        "awaiting reporter",   # in case Jira truncates/aliases the full name
    }

    if status in DONE_STATUSES:
        new_alert_status  = "Rotated"
        new_expiry_notice = "Rotated — Completed"
        extra_fields      = {"RotationDetectedDate": today}
    elif status in CANCELED_STATUSES:
        new_alert_status  = "Ignored"
        new_expiry_notice = f"Jira ticket {req.jira_key} canceled — no longer tracked"
        extra_fields      = {}
    elif status in REOPEN_STATUSES:
        new_alert_status  = "JiraRaised"
        new_expiry_notice = f"Jira ticket {req.jira_key} reopened — monitoring resumed"
        extra_fields      = {}
    elif status in BLOCKED_STATUSES:
        new_alert_status  = "Blocked"
        new_expiry_notice = f"Jira ticket {req.jira_key} is blocked"
        extra_fields      = {}
    elif status in AWAITING_STATUSES:
        new_alert_status  = "AwaitingReporter"
        new_expiry_notice = f"Jira ticket {req.jira_key} awaiting reporter — needs more information"
        extra_fields      = {}
    else:
        log.info("jira-status-update: unhandled status '%s' for %s — no SP update "
                 "(this status is not part of the 6 recognized workflow states — "
                 "check for a typo in the Jira automation rule, or a workflow change "
                 "this endpoint hasn't been updated for)",
                 req.to_status, req.jira_key)
        return {"updated": 0, "jira_key": req.jira_key,
                "note": f"Status '{req.to_status}' not mapped — no action taken"}

    # Find and update matching SP rows
    for item in sp_data.get("items", []):
        f = item.get("fields", {})
        if f.get("JiraTicketKey") == req.jira_key:
            fields = {
                "AlertStatus":  new_alert_status,
                "ExpiryNotice": new_expiry_notice,
                "LastChecked":  today,
                **extra_fields,
            }
            await write_sharepoint_row(item["id"], fields)
            updated += 1
            log.info("jira-status-update: item=%s jira=%s → AlertStatus=%s",
                     item["id"], req.jira_key, new_alert_status)

    log.info("jira-status-update: %s rows updated for %s (→ %s)",
             updated, req.jira_key, new_alert_status)
    return {
        "updated":      updated,
        "jira_key":     req.jira_key,
        "to_status":    req.to_status,
        "alert_status": new_alert_status,
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
