"""
devsecops-secret-governance-secret-rotation.py - Azure Automation Runbook (v3 - Corrected Bucket Scheme)
================================================================================
Purpose : Run the secret rotation cycle directly - NO AI, NO LangChain
Schedule: Every 7 days, 1 hour after runbook_monitoring.py
Runtime : Python 3.10 (Azure Automation)
 
Changes in v3 (this version):
  1. MULTI-TENANT CREDENTIAL SPLIT (matches devsecops-secret-governance-secret-rotation.py's v7 fix,
     and the same fix applied to main.py/container 2). Two credentials -
     one for Entra scanning (follows whichever tenant is being scanned),
     one for SharePoint (ALWAYS HOME_TENANT_ID).
 
  2. MULTI-TENANT SCANNING - CROSS-TENANT-TENANT-IDS (plural), one
     federated credential per tenant, each app tagged with its source
     tenant.
 
  3. FILTER CHANGED: AppOwners/OWNER-EMAILS → DevSecOpsOwnership non-blank,
     matching decision_engine.py's monitoring filter exactly.
 
  4. CONFIGURABLE SECRET VALIDITY - SECRET-VALIDITY-DAYS from Key Vault,
     default 365, replacing the old hardcoded 12-month calculation.
 
  5. BUCKET SCHEME CORRECTED (NEW in v3) - this file previously had its
     OWN, stale bucket classifier that disagreed with decision_engine.py's
     bucket names AT THE TIME (v3 shipped under the five-bucket scheme:
     P1=0-3, P2=4-7, P3=8-30, P4=31-60, P5=61+ safe). _classify_bucket()
     was brought in line with decision_engine.py's names as of v3.
     ROTATION_ELIGIBLE_BUCKETS at the time was {"P1","P2","P3","P4"} - the
     same 0-60 day range as before, re-expressed under v3's names. P5 was
     never rotation-eligible under that scheme.
 
     SUPERSEDED since v3: decision_engine.py later merged the old P1/P2
     into one P1 (0-7 days) and renumbered everything below it down by
     one - see the ROTATION_ELIGIBLE_BUCKETS definition and
     _classify_bucket() further down in this file for the four-bucket
     names actually in effect now. Under the current names,
     ROTATION_ELIGIBLE_BUCKETS is {"P1","P2","P3"}, and P4 (now the safe,
     61+ day bucket) is never rotation-eligible.
 
  (v1 retained: "Discovered" in ACTIONABLE_STATUSES and the SharePoint
   OData filter.)
 
Required Automation Variables:
  ROTATOR_KV_URL, ROTATION_KV_URL, UAMI_CLIENT_ID
 
Required Key Vault secrets (ROTATOR_KV_URL):
  GRAPH-TENANT-ID, GRAPH-TENANT-NAME, JIRA-BASE-URL, JIRA-API-TOKEN,
  JIRA-USER-EMAIL, SHAREPOINT-SITE-ID, SHAREPOINT-LIST-ID,
  CROSS-TENANT-APP-ID, CROSS-TENANT-TENANT-IDS (or singular fallback),
  HOME-TENANT-ID (falls back to GRAPH-TENANT-ID),
  SECRET-VALIDITY-DAYS (falls back to 365)
"""
 
from __future__ import annotations
 
import base64 as _b64
import json
import logging
import re
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from typing import Any, Callable
 
import automationassets
from azure.identity import ManagedIdentityCredential, ClientAssertionCredential
from azure.keyvault.secrets import SecretClient
 
logging.basicConfig(level=logging.INFO, stream=sys.stdout)
log = logging.getLogger("rotation-runbook")
 
# ─────────────────────────────────────────────────────────────────────────────
# US EASTERN TIME, identical to runbook_discovery.py's and decision_engine.py's
# _format_datetime_est / _now_est_string, so LastChecked and every other "as of
# now" field carry the same timezone and format no matter which of the three
# scripts wrote them most recently. Auto-handles EST/EDT transitions.
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
    LastChecked and RotationDetectedDate."""
    return _format_datetime_est(datetime.now(timezone.utc))
 
# ─────────────────────────────────────────────────────────────────────────────
# AUTOMATION VARIABLES
# ─────────────────────────────────────────────────────────────────────────────
 
def _get_var(name: str) -> str:
    value = automationassets.get_automation_variable(name)
    if not value:
        raise ValueError(f"Automation Variable '{name}' is not set.")
    return str(value).strip()
 
ROTATOR_KV_URL  = _get_var("ROTATOR_KV_URL")
ROTATION_KV_URL = _get_var("ROTATION_KV_URL")
UAMI_CLIENT_ID  = _get_var("UAMI_CLIENT_ID")
 
print(f"[DEBUG] ROTATOR_KV_URL  : {ROTATOR_KV_URL}")
print(f"[DEBUG] ROTATION_KV_URL : {ROTATION_KV_URL}")
print(f"[DEBUG] UAMI_CLIENT_ID  : {UAMI_CLIENT_ID[:8]}...")
 
# ─────────────────────────────────────────────────────────────────────────────
# AZURE CLIENTS
# ─────────────────────────────────────────────────────────────────────────────
 
_credential  = ManagedIdentityCredential(client_id=UAMI_CLIENT_ID)
_config_kv   = SecretClient(vault_url=ROTATOR_KV_URL,  credential=_credential)
_rotation_kv = SecretClient(vault_url=ROTATION_KV_URL, credential=_credential)
 
def _kv_get(name: str) -> str:
    try:
        return _config_kv.get_secret(name).value
    except Exception as exc:
        raise RuntimeError(f"Required KV secret '{name}' could not be loaded: {exc}") from exc
 
log.info("Loading rotation config secrets from Key Vault...")
GRAPH_TENANT_ID    = _kv_get("GRAPH-TENANT-ID")
GRAPH_TENANT_NAME  = _kv_get("GRAPH-TENANT-NAME")
JIRA_BASE_URL      = _kv_get("JIRA-BASE-URL")
JIRA_API_TOKEN     = _kv_get("JIRA-API-TOKEN")
JIRA_USER_EMAIL    = _kv_get("JIRA-USER-EMAIL")
SHAREPOINT_SITE_ID = _kv_get("SHAREPOINT-SITE-ID")
SHAREPOINT_LIST_ID = _kv_get("SHAREPOINT-LIST-ID")
 
try:
    _owner_emails_raw = _kv_get("OWNER-EMAILS").strip()
except Exception:
    try:
        _owner_emails_raw = _kv_get("OWNER-EMAIL").strip()
    except Exception:
        _owner_emails_raw = ""
 
OWNER_EMAILS = [e.strip().lower() for e in _owner_emails_raw.split(",") if e.strip()]
MANUAL_OWNERS_ONLY = True
 
try:
    SECRET_VALIDITY_DAYS = int(_kv_get("SECRET-VALIDITY-DAYS").strip())
except Exception:
    SECRET_VALIDITY_DAYS = 365
    log.info("SECRET-VALIDITY-DAYS not set (or not a valid integer) — "
             "defaulting to %d days for newly rotated secrets.", SECRET_VALIDITY_DAYS)
 
log.info("Config secrets loaded.")
log.info("Owner filter (legacy, logged only — MANUAL_OWNERS_ONLY=%s): %d emails: %s",
         MANUAL_OWNERS_ONLY, len(OWNER_EMAILS), OWNER_EMAILS)
log.info("Secret validity period for new rotations: %d days", SECRET_VALIDITY_DAYS)
 
# ─────────────────────────────────────────────────────────────────────────────
# BATCH SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
 
SP_WRITE_BATCH             = 10
JIRA_COMMENT_BATCH         = 5
BATCH_PAUSE                = 0.5
CLOSED_NAMES               = {"done", "closed", "resolved"}
 
ACTIONABLE_STATUSES        = {
    "Discovered",
    "JiraRaised",
    "TeamsAlerted",
    "Escalated",
    "Expired",
    "ExpiredManualReview",
    # NOTE: OverdueManualReview is DELIBERATELY not in this set. It marks a
    # secret past -8 days expired whose Jira ticket is still open (In
    # Progress/To Do/Blocked/etc) — a human is already engaged, so automated
    # rotation must never fire on it, same reasoning as ExpiredManualReview.
    # Adding it here would make rotation try to act on rows it should leave
    # entirely alone.
}
 
# CORRECTED — matches decision_engine.py's current bucket names, after the
# renumbering that merged the old P1/P2 into one P1 (0-7 days) and shifted
# every bucket below it down by one. P4 is now the SAFE/61+ bucket (it used
# to be P5) and must NEVER be rotation-eligible, same as P5 never was under
# the old scheme.
ROTATION_ELIGIBLE_BUCKETS  = {"P1", "P2", "P3"}
DEFAULT_ROTATION_THRESHOLD = 45
 
# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPER (synchronous urllib — no httpx needed)
# ─────────────────────────────────────────────────────────────────────────────
 
def _http(method: str, url: str, headers: dict, body: dict | None = None,
          timeout: int = 30) -> dict:
    data = json.dumps(body).encode("utf-8") if body else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8")[:300]
        raise RuntimeError(f"HTTP {e.code} {method} {url}: {body_text}") from e
 
def _get(url: str, hdrs: dict, timeout: int = 30) -> dict:
    return _http("GET", url, hdrs, timeout=timeout)
 
def _post(url: str, hdrs: dict, body: dict, timeout: int = 30) -> dict:
    return _http("POST", url, {**hdrs, "Content-Type": "application/json"}, body, timeout)
 
def _patch(url: str, hdrs: dict, body: dict, timeout: int = 30) -> dict:
    return _http("PATCH", url, {**hdrs, "Content-Type": "application/json"}, body, timeout)
 
def _delete(url: str, hdrs: dict, timeout: int = 30):
    req = urllib.request.Request(url, headers=hdrs, method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            pass
    except urllib.error.HTTPError as e:
        if e.code not in (204, 404):
            raise
 
# ─────────────────────────────────────────────────────────────────────────────
# GRAPH TOKEN — TWO CREDENTIALS
# ─────────────────────────────────────────────────────────────────────────────
 
CROSS_TENANT_APP_ID = _kv_get("CROSS-TENANT-APP-ID")
 
try:
    _tenant_ids_raw = _kv_get("CROSS-TENANT-TENANT-IDS")
except Exception:
    _tenant_ids_raw = _kv_get("CROSS-TENANT-TENANT-ID")
    log.info("CROSS-TENANT-TENANT-IDS not set — falling back to singular "
             "CROSS-TENANT-TENANT-ID for backwards compatibility.")
 
CROSS_TENANT_TENANT_IDS = [t.strip() for t in _tenant_ids_raw.split(",") if t.strip()]
log.info("Configured to scan %d tenant(s): %s", len(CROSS_TENANT_TENANT_IDS), CROSS_TENANT_TENANT_IDS)
 
try:
    HOME_TENANT_ID = _kv_get("HOME-TENANT-ID")
except Exception:
    HOME_TENANT_ID = GRAPH_TENANT_ID
    log.info("HOME-TENANT-ID not set — falling back to GRAPH-TENANT-ID (%s) "
             "as the home tenant for SharePoint operations.", GRAPH_TENANT_ID)
 
_uami_credential = ManagedIdentityCredential(client_id=UAMI_CLIENT_ID)
 
def _get_uami_assertion() -> str:
    token = _uami_credential.get_token("api://AzureADTokenExchange")
    return token.token
 
_graph_credentials_by_tenant: dict[str, ClientAssertionCredential] = {
    tenant_id: ClientAssertionCredential(
        tenant_id = tenant_id,
        client_id = CROSS_TENANT_APP_ID,
        func      = _get_uami_assertion,
    )
    for tenant_id in CROSS_TENANT_TENANT_IDS
}
 
_sp_graph_credential = ClientAssertionCredential(
    tenant_id = HOME_TENANT_ID,
    client_id = CROSS_TENANT_APP_ID,
    func      = _get_uami_assertion,
)
 
def _graph_token_for_tenant(tenant_id: str) -> str:
    credential = _graph_credentials_by_tenant[tenant_id]
    token = credential.get_token("https://graph.microsoft.com/.default")
    return token.token
 
def _sp_graph_token() -> str:
    token = _sp_graph_credential.get_token("https://graph.microsoft.com/.default")
    return token.token
 
def _auth_hdrs_for_tenant(tenant_id: str) -> dict:
    return {"Authorization": f"Bearer {_graph_token_for_tenant(tenant_id)}"}
 
def _sp_auth_hdrs() -> dict:
    return {"Authorization": f"Bearer {_sp_graph_token()}"}
 
def _get_tenant_name() -> str:
    return GRAPH_TENANT_NAME
 
def _jira_auth() -> str:
    return "Basic " + _b64.b64encode(f"{JIRA_USER_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
 
def _jira_hdrs() -> dict:
    return {"Authorization": _jira_auth(), "Content-Type": "application/json", "Accept": "application/json"}
 
def _sanitize_kv_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9-]", "-", name)
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    return cleaned[:127]
 
def _classify_bucket(days: int) -> str:
    """
    CORRECTED — matches decision_engine.py's classify_bucket() exactly,
    after the renumbering that merged the old P1 (0-3) and P2 (4-7) into a
    single P1 (0-7), and shifted every bucket below it down by one:
    P1 0-7 days, P2 8-30 days, P3 31-45 days, P4 46+ days (safe).
    """
    if days >= 46:       return "P4"
    if 31 <= days <= 45: return "P3"
    if 8  <= days <= 30: return "P2"
    if 0  <= days <= 7:  return "P1"
    if -7 <= days <= -1: return "ExpiredManualReview"
    return "Ignore"
 
def _days_remaining(expiration_iso: str, now: datetime) -> int | None:
    """
    FIX: ExpirationDate is written by decision_engine.py/discovery.py as an
    EST/EDT 12-hour string via _format_datetime_est(), e.g.
    "2026-08-16 01:57:23 AM" - NOT ISO 8601. datetime.fromisoformat() cannot
    parse that format at all and raised on every single row, silently
    returning None here and skipping every candidate before rotation ever
    got a chance to run - the ISO branch below is now only a fallback for
    any legacy rows still holding an old-format value.
    """
    try:
        exp = datetime.strptime(expiration_iso, "%Y-%m-%d %I:%M:%S %p")
        exp = exp.replace(tzinfo=_EASTERN_TZ)
        return (exp - now).days
    except Exception:
        pass

    try:
        if len(expiration_iso) == 10:
            expiration_iso += "T00:00:00+00:00"
        exp = datetime.fromisoformat(expiration_iso.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return (exp - now).days
    except Exception:
        return None
 
# ─────────────────────────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ─────────────────────────────────────────────────────────────────────────────
 
def fetch_azure_applications() -> dict:
    all_apps: list[dict] = []
    tenant_errors: list[str] = []
 
    for tenant_id in CROSS_TENANT_TENANT_IDS:
        try:
            url = "https://graph.microsoft.com/v1.0/applications?$select=id,displayName,appId,passwordCredentials"
            hdrs = _auth_hdrs_for_tenant(tenant_id)
            tenant_apps: list[dict] = []
            while url:
                b = _get(url, hdrs, timeout=30)
                tenant_apps.extend(b.get("value", []))
                url = b.get("@odata.nextLink")
            for app in tenant_apps:
                app["_sourceTenantId"] = tenant_id
            all_apps.extend(tenant_apps)
            print(f"[DEBUG] fetch_azure_applications: {len(tenant_apps)} apps from tenant {tenant_id}")
        except Exception as e:
            tenant_errors.append(f"Tenant {tenant_id}: fetch_azure_applications failed: {e}")
            log.error("Failed to fetch applications from tenant %s: %s", tenant_id, e)
 
    print(f"[DEBUG] fetch_azure_applications: {len(all_apps)} total apps across "
          f"{len(CROSS_TENANT_TENANT_IDS)} tenant(s)")
    return {"applications": all_apps, "total_apps": len(all_apps), "tenantErrors": tenant_errors}
 
def get_sharepoint_state() -> dict:
    status_filter = " or ".join([
        f"fields/AlertStatus eq '{s}'"
        for s in [
            "Discovered",
            "RotatedPendingDeployment",
            "JiraRaised",
            "TeamsAlerted",
            "Escalated",
            "Expired",
            "ExpiredManualReview",
        ]
    ])
 
    url = (
        f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}"
        f"/lists/{SHAREPOINT_LIST_ID}/items"
        f"?$expand=fields"
        f"&$filter={urllib.parse.quote(status_filter)}"
    )
 
    items: list[dict] = []
    hdrs = _sp_auth_hdrs()
    while url:
        b = _get(url, hdrs, timeout=30)
        items.extend(b.get("value", []))
        url = b.get("@odata.nextLink")
 
    print(f"[DEBUG] get_sharepoint_state (smart filter): {len(items)} actionable rows")
 
    status_counts: dict[str, int] = {}
    for item in items:
        s = item.get("fields", {}).get("AlertStatus", "None")
        status_counts[s] = status_counts.get(s, 0) + 1
    print(f"[DEBUG] AlertStatus distribution: {status_counts}")
 
    return {"items": items, "count": len(items)}
 
# FIX: the old 10-char truncation is gone. LastChecked and RotationDetectedDate
# now arrive as full EST timestamps from _now_est_string() (matching
# runbook_discovery.py's format exactly), slicing them to 10 characters would
# destroy the time portion right back down to a bare date. AlertSentDate and
# ExpirationDate were never actually written by this file's own write calls in
# the first place, so this loop is left empty rather than removed outright, in
# case a future field needs the same date-only treatment later.
_DATE_COLS: set[str] = set()
 
def write_sharepoint_row(item_id: str | None, fields: dict) -> dict:
    for col in _DATE_COLS:
        if col in fields and fields[col]:
            fields[col] = str(fields[col])[:10]
    if not fields.get("TenantID"):
        fields["TenantID"] = GRAPH_TENANT_ID
    base = (f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}"
            f"/lists/{SHAREPOINT_LIST_ID}/items")
    hdrs = _sp_auth_hdrs()
    if item_id is None:
        r = _post(base, hdrs, {"fields": fields}, timeout=20)
        return {"action": "created", "item_id": r.get("id")}
    else:
        _patch(f"{base}/{item_id}", hdrs, {"fields": fields}, timeout=20)
        return {"action": "updated", "item_id": item_id}
 
def create_azure_secret(application_object_id: str, display_name: str,
                        tenant_id: str, days_valid: int = SECRET_VALIDITY_DAYS) -> dict:
    end_date = datetime.now(timezone.utc) + timedelta(days=days_valid)
    payload  = {"passwordCredential": {
        "displayName": display_name,
        "endDateTime": end_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    }}
    url = f"https://graph.microsoft.com/v1.0/applications/{application_object_id}/addPassword"
    hdrs = _auth_hdrs_for_tenant(tenant_id)
    for attempt in range(1, 6):
        try:
            b = _post(url, hdrs, payload, timeout=30)
            log.info("create_azure_secret: new keyId %s (valid %d days)", b.get("keyId"), days_valid)
            return {"success": True, "keyId": b.get("keyId"),
                    "secretText": b.get("secretText"), "endDateTime": b.get("endDateTime")}
        except RuntimeError as e:
            if ("409" in str(e) or "412" in str(e)) and attempt < 5:
                wait = attempt * 5
                log.warning("Concurrency conflict — retry %d/5 in %ds", attempt, wait)
                time.sleep(wait)
                continue
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "Max retries exceeded"}
 
# Cache of SecretClient objects keyed by vault URL, so a product-specific
# override Key Vault only gets one client built for it per run, not one per
# secret rotated into it.
_override_kv_clients: dict[str, SecretClient] = {}
 
def store_rotated_secret(secret_name: str, secret_value: str,
                         override_vault_url: str = "") -> dict:
    """
    Stores a rotated secret's value in Key Vault. By default, uses the
    shared ROTATION_KV_URL every app rotates into. If override_vault_url is
    given (non-empty), meaning the app's SharePoint row had
    ProductTeamsKeyVaultName set, uses that specific vault instead — a
    product team gets its own rotated secrets landing in their own Key
    Vault rather than the shared one.
 
    A client for a given override URL is built once and reused for the rest
    of this run, not rebuilt on every single secret rotated into it.
    """
    try:
        clean_name = _sanitize_kv_name(secret_name)
 
        if override_vault_url:
            if override_vault_url not in _override_kv_clients:
                _override_kv_clients[override_vault_url] = SecretClient(
                    vault_url=override_vault_url, credential=_credential
                )
            target_kv = _override_kv_clients[override_vault_url]
        else:
            target_kv = _rotation_kv
 
        result = target_kv.set_secret(clean_name, secret_value,
                                      content_type="azure-app-registration-secret")
        return {"success": True, "vault_name": clean_name, "vault_url": result.id}
    except Exception as e:
        return {"success": False, "error": str(e)}
 
def get_jira_issue(issue_key: str) -> dict:
    try:
        b = _get(f"{JIRA_BASE_URL}/rest/api/2/issue/{issue_key}?fields=status,summary",
                 _jira_hdrs(), timeout=15)
        return {"issue_key": issue_key,
                "status": b.get("fields", {}).get("status", {}).get("name", "Unknown"),
                "summary": b.get("fields", {}).get("summary", "")}
    except RuntimeError as e:
        if "404" in str(e):
            return {"issue_key": issue_key, "status": "NotFound", "summary": ""}
        raise
 
def add_jira_comment(issue_key: str, comment_text: str) -> dict:
    """
    FIX: /rest/api/2/issue/{key}/comment expects a plain string body, not an
    ADF document object - the ADF wrapper this used to send failed every
    call with HTTP 400 "Comment body is not valid!". Matches main.py's
    (container 2's) add_jira_comment(), which already sends a plain string
    against this same v2 endpoint and works.
    """
    payload = {"body": comment_text}
    b = _post(f"{JIRA_BASE_URL}/rest/api/2/issue/{issue_key}/comment",
              _jira_hdrs(), payload, timeout=15)
    return {"issue_key": issue_key, "comment_id": b.get("id", "")}
 
# ─────────────────────────────────────────────────────────────────────────────
# ROTATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
 
def run_secret_rotation(rotation_threshold_days: int = DEFAULT_ROTATION_THRESHOLD) -> dict:
    now   = datetime.now(timezone.utc)
    today = _now_est_string()  # full EST timestamp, matches runbook_discovery.py
 
    summary: dict[str, Any] = {
        "runDate": today, "rotationThresholdDays": rotation_threshold_days,
        "secretValidityDays": SECRET_VALIDITY_DAYS,
        "tenantsScanned": len(CROSS_TENANT_TENANT_IDS),
        "rowsScanned": 0,
        "rowsSkippedNoManualOwner": 0,
        "rowsSkippedRotated": 0,
        "rotationsCompleted": 0, "newSecretsGenerated": 0,
        "jiraComments": 0, "flaggedForManualReview": 0, "sharepointUpdated": 0,
        "errors": [],
    }
 
    try:
        sp_data = get_sharepoint_state()
    except Exception as e:
        summary["errors"].append(f"get_sharepoint_state failed: {e}")
        return summary
 
    try:
        azure_data = fetch_azure_applications()
        summary["errors"].extend(azure_data.get("tenantErrors", []))
    except Exception as e:
        summary["errors"].append(f"fetch_azure_applications failed: {e}")
        return summary
 
    app_info_by_client_id: dict[str, tuple[str, str]] = {
        app["appId"]: (app["id"], app.get("_sourceTenantId", HOME_TENANT_ID))
        for app in azure_data.get("applications", [])
        if app.get("appId") and app.get("id")
    }
 
    items = sp_data.get("items", [])
    summary["rowsScanned"] = len(items)
 
    # ── PHASE A: Closure check ────────────────────────────────────────────────
    pending = [i for i in items
               if i.get("fields", {}).get("AlertStatus") == "RotatedPendingDeployment"]
    print(f"[DEBUG] Phase A: {len(pending)} RotatedPendingDeployment rows")
 
    for item in pending:
        f        = item.get("fields", {})
        item_id  = item.get("id")
        jira_key = f.get("JiraTicketKey", "")
        try:
            if not jira_key:
                write_sharepoint_row(item_id, {"AlertStatus": "JiraClosed-Unverified",
                                               "LastChecked": today})
                summary["flaggedForManualReview"] += 1
                summary["sharepointUpdated"] += 1
                continue
            issue       = get_jira_issue(jira_key)
            status_name = (issue.get("status") or "").strip().lower()
            if status_name in CLOSED_NAMES:
                write_sharepoint_row(item_id, {"AlertStatus": "Rotated",
                    "RotationDetectedDate": today, "ExpiryNotice": "Rotated — Completed",
                    "LastChecked": today})
                summary["rotationsCompleted"] += 1
                summary["sharepointUpdated"]  += 1
            else:
                write_sharepoint_row(item_id, {"LastChecked": today})
                summary["sharepointUpdated"] += 1
        except Exception as e:
            summary["errors"].append(f"Phase A error SecretID={f.get('SecretID')}: {e}")
 
    # ── PHASE B: Proactive rotation ───────────────────────────────────────────
    # NOTE: NewSecretVaultName is now filled in BY THE TEAM, by hand, before
    # any rotation has ever happened — it holds the exact vault entry name
    # their application already expects, since many apps hardcode a secret
    # name and can't easily be changed. This means NewSecretVaultName being
    # present no longer signals "this row was already rotated" the way it
    # used to. AlertStatus == RotatedPendingDeployment is the replacement
    # signal — rotation itself sets that status only after it has actually
    # run for a given cycle, so a row already in that status is correctly
    # skipped here rather than rotated a second time.
    all_candidates = [
        item for item in items
        if item.get("fields", {}).get("AlertStatus") in ACTIONABLE_STATUSES
    ]
 
    candidates = []
    for item in all_candidates:
        f      = item.get("fields", {})
        app_id = f.get("Title", "")
 
        if MANUAL_OWNERS_ONLY:
            manual_owners = (f.get("DevSecOpsOwnership") or "").strip()
            if not manual_owners:
                summary["rowsSkippedNoManualOwner"] += 1
                log.debug("Skipping %s — DevSecOpsOwnership is blank", app_id)
                continue
        else:
            app_owners = (f.get("AppOwners") or "").lower()
            if not app_owners:
                summary["rowsSkippedNoManualOwner"] += 1
                log.debug("Skipping %s — AppOwners is blank", app_id)
                continue
            if OWNER_EMAILS and not any(email in app_owners for email in OWNER_EMAILS):
                summary["rowsSkippedNoManualOwner"] += 1
                log.debug("Skipping %s — not owned by any of %s (owners: %s)",
                          app_id, OWNER_EMAILS, app_owners)
                continue
 
        candidates.append(item)
 
    print(f"[DEBUG] Phase B: {len(all_candidates)} total candidates, {len(candidates)} "
          f"after {'DevSecOpsOwnership' if MANUAL_OWNERS_ONLY else 'AppOwners/OWNER_EMAILS'} filter")
    print(f"[DEBUG] Phase B: {summary['rowsSkippedNoManualOwner']} skipped "
          f"({'DevSecOpsOwnership blank' if MANUAL_OWNERS_ONLY else f'not owned by any of {OWNER_EMAILS}'})")
 
    for item in candidates[:5]:
        f    = item.get("fields", {})
        days = _days_remaining(f.get("ExpirationDate", ""), now)
        bkt  = _classify_bucket(days) if days is not None else "unknown"
        print(f"[DEBUG]   AppID={f.get('Title')} Status={f.get('AlertStatus')} "
              f"Days={days} Bucket={bkt}")
 
    for item in candidates:
        f      = item.get("fields", {})
        days   = _days_remaining(f.get("ExpirationDate", ""), now)
        if days is None:
            continue
        bucket = _classify_bucket(days)
        if bucket not in ROTATION_ELIGIBLE_BUCKETS:
            continue
        if days > rotation_threshold_days:
            continue
 
        item_id  = item.get("id")
        app_id   = f.get("Title")
        app_name = f.get("AppName", "Unknown")
        jira_key = f.get("JiraTicketKey", "")
 
        if not jira_key:
            summary["errors"].append(f"AppID={app_id}: no JiraTicketKey, cannot rotate")
            continue
 
        # NOTE: rows with AlertStatus == RotatedPendingDeployment are already
        # excluded at the all_candidates stage above (that status is not in
        # ACTIONABLE_STATUSES), so no separate "already rotated" check is
        # needed here — a row reaching this point genuinely has not been
        # rotated yet this cycle.
 
        try:
            issue       = get_jira_issue(jira_key)
            status_name = (issue.get("status") or "").strip().lower()
            if status_name in CLOSED_NAMES:
                write_sharepoint_row(item_id, {"AlertStatus": "JiraClosed-Unverified",
                                               "LastChecked": today})
                summary["flaggedForManualReview"] += 1
                summary["sharepointUpdated"] += 1
                continue

            # NEW - a non-blank NewSecretKeyId at this point means the
            # engineer already created the new secret manually (generation
            # AND storage, both outside this runbook) and typed its
            # NewSecretKeyId into Jira (NewSecretPresent = Yes there) -
            # synced into this row's NewSecretKeyId column by the
            # jira-status-update endpoint on In Progress. No separate
            # NewSecretPresent column exists in SharePoint - this reuses the
            # existing NewSecretKeyId column as the signal instead. Skip
            # create_azure_secret()/store_rotated_secret() entirely here -
            # calling them anyway would generate a SECOND, conflicting
            # secret alongside the one the engineer already made.
            manually_provided_key_id = (f.get("NewSecretKeyId") or "").strip()
            if manually_provided_key_id:
                write_sharepoint_row(item_id, {
                    "AlertStatus":  "RotatedPendingDeployment",
                    "ExpiryNotice": f"Secret manually provided by engineer - pending deployment ({jira_key})",
                    "LastChecked":  today,
                })
                summary["sharepointUpdated"] += 1
                try:
                    add_jira_comment(
                        jira_key,
                        f"🔐 MANUAL SECRET RECORDED — {today}\n"
                        f"NewSecretPresent was marked Yes, so no secret was auto-generated. "
                        f"The manually-provided secret (NewSecretKeyId: "
                        f"{manually_provided_key_id}) has been recorded "
                        f"for {app_name} (App ID: {app_id}).\n\n"
                        f"Next steps:\n"
                        f"1. Confirm the secret is deployed to all dependent services\n"
                        f"2. Confirm authentication works\n"
                        f"3. Close this ticket to mark as Rotated in SharePoint."
                    )
                    summary["jiraComments"] += 1
                except Exception as e:
                    summary["errors"].append(f"Jira comment failed for {jira_key}: {e}")
                continue

            app_info = app_info_by_client_id.get(app_id)
            if not app_info:
                summary["errors"].append(f"AppID={app_id}: not found in Azure snapshot")
                continue
            object_id, app_tenant_id = app_info
 
            print(f"[DEBUG] Rotating: {app_name} ({app_id}) jira={jira_key} days={days} "
                  f"tenant={app_tenant_id} validity={SECRET_VALIDITY_DAYS}d")
            new_secret = create_azure_secret(
                application_object_id=object_id,
                display_name=f"AutoRotated-{jira_key}-{today}",
                tenant_id=app_tenant_id)
            if not new_secret.get("success"):
                summary["errors"].append(f"AppID={app_id}: create_azure_secret failed: {new_secret}")
                continue
            summary["newSecretsGenerated"] += 1
 
            # ProductTeamsKeyVaultName lets a specific product's team override
            # where their rotated secret gets stored, instead of the shared
            # ROTATION_KV_URL every app uses by default. Blank means "use the
            # shared vault" — this is the normal case for most rows. Every
            # Key Vault in this environment follows the same
            # https://<name>.vault.azure.net/ pattern, so the full URL is
            # derived directly from whatever short name is in the column,
            # rather than looked up against a separately maintained list.
            raw_vault_key = (f.get("ProductTeamsKeyVaultName") or "").strip()
            override_vault_url = f"https://{raw_vault_key.lower()}.vault.azure.net/" if raw_vault_key else ""
 
            # SECRET NAMING — this is what makes "same name, new version every
            # rotation" actually work, since Key Vault's own set_secret() call
            # automatically creates a NEW VERSION under an existing name, or
            # creates fresh if the name doesn't exist yet, with no special
            # versioning logic needed here at all.
            #
            # If NewSecretVaultName is already filled in (by the team, or by
            # a PRIOR rotation cycle having written one back — see below),
            # use that EXACT name every time. This is what lets an
            # application's hardcoded config, which points at one fixed
            # secret name, keep working release after release without ever
            # needing to change.
            #
            # If NewSecretVaultName is genuinely blank (brand-new app, never
            # rotated before, team hasn't assigned a fixed name), generate
            # one: "ProductName-TeamName-AppDisplayName", so the Entra secret
            # description, the SharePoint NewSecretVaultName value, and the
            # actual Key Vault secret name all end up identical. This
            # generated name is then WRITTEN BACK into NewSecretVaultName on
            # this same row (below), so every rotation AFTER this first one
            # finds it already filled in and reuses it as a new version,
            # rather than generating a fresh name every single cycle forever.
            existing_vault_name = (f.get("NewSecretVaultName") or "").strip()
            generated_name_this_run = None
 
            if existing_vault_name:
                secret_name_to_use = existing_vault_name
            else:
                product_name = (f.get("ProductName") or "").strip()
                team_name    = (f.get("TeamName") or "").strip()
                # Falls back to whatever piece is actually available rather
                # than failing outright if ProductName or TeamName is blank
                # too — an app can still be rotated even if the team hasn't
                # filled in every one of these three columns yet, it just
                # gets a less complete generated name.
                name_parts = [p for p in (product_name, team_name, app_name) if p]
                secret_name_to_use = "-".join(name_parts) if name_parts else f"{app_name}-{jira_key}"
                generated_name_this_run = secret_name_to_use
 
            vault_result = store_rotated_secret(
                secret_name=secret_name_to_use,
                secret_value=new_secret["secretText"],
                override_vault_url=override_vault_url)
            if not vault_result.get("success"):
                summary["errors"].append(f"AppID={app_id}: store_rotated_secret failed: {vault_result}")
                continue
 
            vault_name = vault_result["vault_name"]
 
            try:
                comment = (
                    f"🔐 AUTO-ROTATION — {today}\n"
                    f"A new client secret has been generated for {app_name} (App ID: {app_id}).\n"
                    f"New credential keyId: {new_secret['keyId']}\n"
                    f"New credential expiry: {new_secret['endDateTime']}\n"
                    f"Stored in Key Vault under: {vault_name}\n\n"
                    f"Next steps:\n"
                    f"1. Retrieve the value from Key Vault ({vault_name})\n"
                    f"2. Deploy to all dependent services\n"
                    f"3. Confirm authentication works\n"
                    f"4. Close this ticket to mark as Rotated in SharePoint."
                )
                add_jira_comment(jira_key, comment)
                summary["jiraComments"] += 1
            except Exception as e:
                summary["errors"].append(f"Jira comment failed for {jira_key}: {e}")
 
            write_sharepoint_row(item_id, {
                "AlertStatus":        "RotatedPendingDeployment",
                "NewSecretKeyId":     new_secret["keyId"],
                "NewSecretVaultName": vault_name,
                "ExpiryNotice":       f"New secret ready — pending deployment ({jira_key})",
                "LastChecked":        today,
                "TenantID":           app_tenant_id,
            })
            summary["sharepointUpdated"] += 1
 
            time.sleep(5)
 
        except Exception as e:
            summary["errors"].append(f"Phase B error AppID={f.get('Title')}: {e}")
 
    return summary
 
# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
 
def main():
    started = datetime.now(timezone.utc).isoformat()
    log.info("Rotation Runbook v3 started at %s (multi-tenant credential split, "
             "DevSecOpsOwnership filter, configurable SECRET-VALIDITY-DAYS, "
             "bucket scheme corrected to match decision_engine.py)", started)
 
    summary = run_secret_rotation(rotation_threshold_days=45)
 
    print("=" * 60)
    print("ROTATION RUNBOOK v3 — SUMMARY")
    print("=" * 60)
    print(f"  Run Date                 : {summary.get('runDate')}")
    print(f"  Threshold (days)         : {summary.get('rotationThresholdDays')}")
    print(f"  Secret Validity (days)   : {summary.get('secretValidityDays')}")
    print(f"  Tenants Scanned          : {summary.get('tenantsScanned')} ({', '.join(CROSS_TENANT_TENANT_IDS)})")
    print(f"  SharePoint Rows Scanned  : {summary.get('rowsScanned')}")
    print(f"  Skipped (DevSecOpsOwnership blank): {summary.get('rowsSkippedNoManualOwner')}")
    print(f"  Skipped (already rotated): {summary.get('rowsSkippedRotated')}")
    print(f"  New Secrets Generated    : {summary.get('newSecretsGenerated')}")
    print(f"  Rotations Completed      : {summary.get('rotationsCompleted')}")
    print(f"  Jira Comments Added      : {summary.get('jiraComments')}")
    print(f"  Flagged for Manual Rev.  : {summary.get('flaggedForManualReview')}")
    print(f"  SharePoint Updated       : {summary.get('sharepointUpdated')}")
 
    errors = summary.get("errors", [])
    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for err in errors:
            print(f"    - {err}")
        sys.exit(1)
    else:
        print("\n  No errors.")
 
main()