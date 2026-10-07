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
from typing import Any, Callable, Optional
 
try:
    import automationassets
except ImportError:
    automationassets = None

import os
from azure.identity import ManagedIdentityCredential, ClientAssertionCredential, DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
log = logging.getLogger("rotation-runbook")

try:
    from decision_engine import (
        DEFAULT_BYPASS_JIRA_PATTERNS,
        DEFAULT_PATTERN_BYPASS_TENANTS,
        matches_bypass_jira_pattern,
        should_bypass_jira_for_secret,
    )
except ImportError:
    DEFAULT_BYPASS_JIRA_PATTERNS = ["*.select*", "practice-plus-*", "*-partner-*", "*-internal-*", "svc-automation-*", "temp-*"]
    DEFAULT_PATTERN_BYPASS_TENANTS = ["c721d616-dcf3-4510-9c3e-548bc6c1f628"]

    def matches_bypass_jira_pattern(display_name: str, patterns: list[str] | None = None) -> bool:
        import fnmatch
        if not display_name:
            return False
        patterns = patterns or DEFAULT_BYPASS_JIRA_PATTERNS
        dn = display_name.lower().strip()
        return any(fnmatch.fnmatch(dn, p.lower().strip()) for p in patterns)

    def should_bypass_jira_for_secret(
        c: dict,
        patterns: list[str] | None = None,
        target_tenants: list[str] | None = None
    ) -> bool:
        if not isinstance(c, dict):
            return False
        tenant_id = (
            c.get("tenant_id")
            or c.get("TenantID")
            or c.get("_sourceTenantId")
            or c.get("tenantId")
            or ""
        ).strip().lower()
        target_tenants = [t.lower() for t in (target_tenants or DEFAULT_PATTERN_BYPASS_TENANTS)]
        if not tenant_id or tenant_id not in target_tenants:
            return False
        display_name = (
            c.get("secret_desc")
            or c.get("secret_display_name")
            or c.get("display_name")
            or c.get("SecretDescription")
            or c.get("AppName")
            or ""
        )
        return matches_bypass_jira_pattern(display_name, patterns)

# ─────────────────────────────────────────────────────────────────────────────
# 1PASSWORD INTEGRATION (embedded for zero external dependencies)
# ─────────────────────────────────────────────────────────────────────────────
import asyncio
import sys, os

ONEPASSWORD_SDK_AVAILABLE = False
_op_import_error = None
OnePasswordClient = None
OnePasswordItemCategory = None
OnePasswordItemCreateParams = None
OnePasswordItemField = None
OnePasswordItemFieldType = None
OnePasswordItemShareDuration = None
OnePasswordItemShareParams = None

def _ensure_onepassword_loaded(config_kv=None) -> bool:
    global ONEPASSWORD_SDK_AVAILABLE, _op_import_error
    global OnePasswordClient, OnePasswordItemCategory, OnePasswordItemCreateParams
    global OnePasswordItemField, OnePasswordItemFieldType, OnePasswordItemShareDuration, OnePasswordItemShareParams

    if ONEPASSWORD_SDK_AVAILABLE and OnePasswordClient is not None:
        return True

    # 1. Try direct import (e.g. if installed in local env or mounted by runner)
    try:
        from onepassword import (
            Client, ItemCategory, ItemCreateParams, ItemField,
            ItemFieldType, ItemShareDuration, ItemShareParams,
        )
        OnePasswordClient = Client
        OnePasswordItemCategory = ItemCategory
        OnePasswordItemCreateParams = ItemCreateParams
        OnePasswordItemField = ItemField
        OnePasswordItemFieldType = ItemFieldType
        OnePasswordItemShareDuration = ItemShareDuration
        OnePasswordItemShareParams = ItemShareParams
        ONEPASSWORD_SDK_AVAILABLE = True
        log.info("1Password Python SDK loaded directly.")
        return True
    except Exception as e1:
        _op_import_error = str(e1)

    # 2. Extract self-contained bundle for Linux (Azure Automation sandbox)
    target_dir = "/tmp/onepassword_bundle" if sys.platform.startswith("linux") else os.path.join(os.environ.get("TEMP", "C:/temp"), "onepassword_bundle")
    if not os.path.exists(os.path.join(target_dir, "onepassword")):
        bundle_url = ""
        if config_kv:
            try:
                bundle_url = config_kv.get_secret("ONEPASSWORD-BUNDLE-URL").value.strip()
            except Exception:
                pass
        if not bundle_url:
            bundle_url = "https://stsecgovbackup01.blob.core.windows.net/secret-governance-backups/onepassword_bundle_linux_x86_64.zip?se=2031-01-01T00%3A00%3A00Z&sp=r&sv=2026-04-06&sr=b&sig=PzwjJotlDlvHqaXLOgAQcxqFfPYISh4KMdmiKhpkHE0%3D"

        try:
            import zipfile, io, urllib.request
            log.info("Downloading 1Password bundle for Azure Automation Linux sandbox from blob storage...")
            req = urllib.request.Request(bundle_url, headers={"User-Agent": "AzureSecretGov/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                zip_bytes = resp.read()
            os.makedirs(target_dir, exist_ok=True)
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                z.extractall(target_dir)
            log.info("Successfully extracted 1Password bundle to %s (%d files)", target_dir, len(os.listdir(target_dir)))
        except Exception as dl_err:
            log.warning("Could not download 1Password bundle: %s", dl_err)
            _op_import_error = str(dl_err)
            return False

    if target_dir not in sys.path:
        sys.path.insert(0, target_dir)

    try:
        from onepassword import (
            Client, ItemCategory, ItemCreateParams, ItemField,
            ItemFieldType, ItemShareDuration, ItemShareParams,
        )
        OnePasswordClient = Client
        OnePasswordItemCategory = ItemCategory
        OnePasswordItemCreateParams = ItemCreateParams
        OnePasswordItemField = ItemField
        OnePasswordItemFieldType = ItemFieldType
        OnePasswordItemShareDuration = ItemShareDuration
        OnePasswordItemShareParams = ItemShareParams
        ONEPASSWORD_SDK_AVAILABLE = True
        _op_import_error = None
        log.info("1Password Python SDK loaded successfully from bundle.")
        return True
    except Exception as e2:
        ONEPASSWORD_SDK_AVAILABLE = False
        _op_import_error = str(e2)
        log.warning("Failed to import onepassword from %s: %s", target_dir, e2)
        return False

# Attempt immediate load if pre-installed
_ensure_onepassword_loaded()



def _determine_share_duration(expiry_dt: Optional[datetime]) -> Any:
    if not ONEPASSWORD_SDK_AVAILABLE or OnePasswordItemShareDuration is None:
        return "ThirtyDays"
    if not expiry_dt:
        return OnePasswordItemShareDuration.THIRTYDAYS
    now = datetime.now(timezone.utc)
    if expiry_dt.tzinfo is None:
        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
    days = (expiry_dt - now).days
    if days >= 30:
        return OnePasswordItemShareDuration.THIRTYDAYS
    elif days >= 14:
        return OnePasswordItemShareDuration.FOURTEENDAYS
    elif days >= 7:
        return OnePasswordItemShareDuration.SEVENDAYS
    elif days >= 1:
        return OnePasswordItemShareDuration.ONEDAY
    else:
        return OnePasswordItemShareDuration.ONEHOUR


def _parse_expiry(expiry_val: Any) -> Optional[datetime]:
    if isinstance(expiry_val, datetime):
        return expiry_val if expiry_val.tzinfo else expiry_val.replace(tzinfo=timezone.utc)
    if not expiry_val or not isinstance(expiry_val, str):
        return None
    raw = expiry_val.strip()
    try:
        if len(raw) == 10:
            raw += "T00:00:00+00:00"
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


async def _push_secret_to_1password_and_share_async(
    app_name: str,
    app_id: str,
    secret_name: str,
    secret_value: str,
    expiry_date: Any,
    tenant_id: str,
    service_account_token: str,
    vault_id: str,
    one_time_only: bool = False,
) -> dict[str, Any]:
    if not ONEPASSWORD_SDK_AVAILABLE:
        _ensure_onepassword_loaded()
    if not ONEPASSWORD_SDK_AVAILABLE:
        return {
            "success": False,
            "item_id": None,
            "vault_id": vault_id,
            "share_link": "",
            "duration": "None",
            "error": f"onepassword package could not be loaded: {_op_import_error}",
        }
    if not service_account_token:
        return {
            "success": False,
            "item_id": None,
            "vault_id": vault_id,
            "share_link": "",
            "duration": "None",
            "error": "ONEPASSWORD-SERVICE-ACCOUNT-TOKEN is missing or blank",
        }
    if not vault_id:
        return {
            "success": False,
            "item_id": None,
            "vault_id": "",
            "share_link": "",
            "duration": "None",
            "error": "ONEPASSWORD-VAULT-ID is missing or blank",
        }

    try:
        client = await OnePasswordClient.authenticate(
            auth=service_account_token,
            integration_name="AzureSecretGov",
            integration_version="v1.0.0",
        )
    except Exception as exc:
        log.error("Failed to authenticate 1Password client: %s", exc)
        return {
            "success": False,
            "item_id": None,
            "vault_id": vault_id,
            "share_link": "",
            "duration": "None",
            "error": f"1Password authentication error: {exc}",
        }

    parsed_expiry = _parse_expiry(expiry_date)
    duration = _determine_share_duration(parsed_expiry)
    duration_str = duration.value if hasattr(duration, "value") else str(duration)
    expiry_str = parsed_expiry.isoformat() if parsed_expiry else str(expiry_date)

    item_title = f"{app_name} - {secret_name}"
    fields = [
        OnePasswordItemField(
            id="password",
            title="Credential Secret",
            value=secret_value,
            field_type=OnePasswordItemFieldType.CONCEALED,
        ),
        OnePasswordItemField(
            id="app_id",
            title="App Client ID",
            value=app_id,
            field_type=OnePasswordItemFieldType.TEXT,
        ),
        OnePasswordItemField(
            id="tenant_id",
            title="Tenant ID",
            value=tenant_id,
            field_type=OnePasswordItemFieldType.TEXT,
        ),
        OnePasswordItemField(
            id="expiry",
            title="Secret Expiry",
            value=expiry_str,
            field_type=OnePasswordItemFieldType.TEXT,
        ),
    ]

    try:
        item = await client.items.create(
            OnePasswordItemCreateParams(
                title=item_title,
                category=OnePasswordItemCategory.PASSWORD,
                vault_id=vault_id,
                fields=fields,
                notes=(
                    f"Rotated by Azure Secret Governance\n"
                    f"App Name: {app_name}\n"
                    f"App ID: {app_id}\n"
                    f"Tenant: {tenant_id}\n"
                    f"Expiry: {expiry_str}"
                ),
            )
        )
        log.info("Created 1Password item '%s' (id: %s) in vault %s", item_title, item.id, vault_id)
    except Exception as exc:
        log.error("Failed to create item in 1Password vault %s: %s", vault_id, exc)
        return {
            "success": False,
            "item_id": None,
            "vault_id": vault_id,
            "share_link": "",
            "duration": duration_str,
            "error": f"1Password item creation failed: {exc}",
        }

    share_link = ""
    share_error = None
    try:
        policy = await client.items.shares.get_account_policy(vault_id, item.id)
        share_link = await client.items.shares.create(
            item=item,
            policy=policy,
            params=OnePasswordItemShareParams(
                expire_after=duration,
                one_time_only=one_time_only,
            ),
        )
        log.info("Generated 1Password share link for '%s': %s (duration: %s)", item_title, share_link, duration_str)
    except Exception as exc:
        share_error = str(exc)
        log.warning("Secret '%s' saved in 1Password vault %s, but share link generation failed: %s", item_title, vault_id, exc)

    return {
        "success": True,
        "item_id": item.id,
        "vault_id": vault_id,
        "share_link": share_link,
        "duration": duration_str,
        "error": share_error,
    }


def push_secret_to_1password_and_share(
    app_name: str,
    app_id: str,
    secret_name: str,
    secret_value: str,
    expiry_date: Any,
    tenant_id: str,
    service_account_token: str,
    vault_id: str,
    one_time_only: bool = False,
) -> dict[str, Any]:
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    if loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(
                asyncio.run,
                _push_secret_to_1password_and_share_async(
                    app_name=app_name,
                    app_id=app_id,
                    secret_name=secret_name,
                    secret_value=secret_value,
                    expiry_date=expiry_date,
                    tenant_id=tenant_id,
                    service_account_token=service_account_token,
                    vault_id=vault_id,
                    one_time_only=one_time_only,
                ),
            ).result()
    else:
        return loop.run_until_complete(
            _push_secret_to_1password_and_share_async(
                app_name=app_name,
                app_id=app_id,
                secret_name=secret_name,
                secret_value=secret_value,
                expiry_date=expiry_date,
                tenant_id=tenant_id,
                service_account_token=service_account_token,
                vault_id=vault_id,
                one_time_only=one_time_only,
            )
        )

 
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
    if automationassets:
        try:
            value = automationassets.get_automation_variable(name)
            if value:
                return str(value).strip()
        except Exception:
            pass
    env_val = os.environ.get(name)
    if env_val:
        return env_val.strip()
    defaults = {
        "ROTATOR_KV_URL":  "https://kv-secret-monitor-0103.vault.azure.net/",
        "ROTATION_KV_URL": "https://kv-secret-monitor-0103.vault.azure.net/",
        "UAMI_CLIENT_ID":  "62e92cfa-e089-4be7-ab87-d1a196bbfa8a",
    }
    if name in defaults:
        return defaults[name]
    raise ValueError(f"Automation Variable '{name}' is not set.")
 
ROTATOR_KV_URL  = _get_var("ROTATOR_KV_URL")
ROTATION_KV_URL = _get_var("ROTATION_KV_URL")
UAMI_CLIENT_ID  = _get_var("UAMI_CLIENT_ID")
 
print(f"[DEBUG] ROTATOR_KV_URL  : {ROTATOR_KV_URL}")
print(f"[DEBUG] ROTATION_KV_URL : {ROTATION_KV_URL}")
print(f"[DEBUG] UAMI_CLIENT_ID  : {UAMI_CLIENT_ID[:8]}...")
print(f"[DEBUG] ONEPASSWORD_SDK_AVAILABLE: {ONEPASSWORD_SDK_AVAILABLE} (error: {_op_import_error})")
 
# ─────────────────────────────────────────────────────────────────────────────
# AZURE CLIENTS
# ─────────────────────────────────────────────────────────────────────────────
 
try:
    _credential  = ManagedIdentityCredential(client_id=UAMI_CLIENT_ID)
    _config_kv   = SecretClient(vault_url=ROTATOR_KV_URL,  credential=_credential)
    _rotation_kv = SecretClient(vault_url=ROTATION_KV_URL, credential=_credential)
    _config_kv.get_secret("GRAPH-TENANT-ID")
except Exception:
    _credential  = DefaultAzureCredential()
    _config_kv   = SecretClient(vault_url=ROTATOR_KV_URL,  credential=_credential)
    _rotation_kv = SecretClient(vault_url=ROTATION_KV_URL, credential=_credential)
 
def _kv_get(name: str) -> str:
    try:
        return _config_kv.get_secret(name).value
    except Exception as exc:
        raise RuntimeError(f"Required KV secret '{name}' could not be loaded: {exc}") from exc

_ensure_onepassword_loaded(_config_kv)
print(f"[DEBUG] ONEPASSWORD_SDK_AVAILABLE after bootstrap: {ONEPASSWORD_SDK_AVAILABLE} (error: {_op_import_error})")

log.info("Loading rotation config secrets from Key Vault...")
GRAPH_TENANT_ID    = _kv_get("GRAPH-TENANT-ID")
GRAPH_TENANT_NAME  = _kv_get("GRAPH-TENANT-NAME")
JIRA_BASE_URL      = _kv_get("JIRA-BASE-URL")
JIRA_API_TOKEN     = _kv_get("JIRA-API-TOKEN")
JIRA_USER_EMAIL    = _kv_get("JIRA-USER-EMAIL")
SHAREPOINT_SITE_ID = _kv_get("SHAREPOINT-SITE-ID")
SHAREPOINT_LIST_ID = _kv_get("SHAREPOINT-LIST-ID")

try:
    ONEPASSWORD_SERVICE_ACCOUNT_TOKEN = _kv_get("ONEPASSWORD-SERVICE-ACCOUNT-TOKEN").strip()
except Exception:
    ONEPASSWORD_SERVICE_ACCOUNT_TOKEN = os.environ.get("ONEPASSWORD_SERVICE_ACCOUNT_TOKEN", "")

try:
    ONEPASSWORD_VAULT_ID = _kv_get("ONEPASSWORD-VAULT-ID").strip()
except Exception:
    ONEPASSWORD_VAULT_ID = os.environ.get("ONEPASSWORD_VAULT_ID", "zpauibuhj6qp3yc2pif2wfzliq")
 
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
    "CriticalTagged",
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
    target_statuses = ACTIONABLE_STATUSES | {"RotatedPendingDeployment", "JiraClosed-Unverified"}

    url = (
        f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}"
        f"/lists/{SHAREPOINT_LIST_ID}/items"
        f"?$expand=fields&$select=id,fields&$top=999"
    )

    items: list[dict] = []
    hdrs = _sp_auth_hdrs()
    hdrs["Prefer"] = "HonorNonIndexedQueriesWarningMayFailRandomly"
    while url:
        b = _get(url, hdrs, timeout=30)
        for row in b.get("value", []):
            st = row.get("fields", {}).get("AlertStatus")
            if st in target_statuses:
                items.append(row)
        url = b.get("@odata.nextLink")

    print(f"[DEBUG] get_sharepoint_state: {len(items)} actionable rows")

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
        "onePasswordItemsCreated": 0, "onePasswordShareLinksGenerated": 0,
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
               if i.get("fields", {}).get("AlertStatus") in ("RotatedPendingDeployment", "JiraClosed-Unverified")]
    print(f"[DEBUG] Phase A: {len(pending)} RotatedPendingDeployment rows")
 
    for item in pending:
        f        = item.get("fields", {})
        item_id  = item.get("id")
        jira_key = f.get("JiraTicketKey", "")
        try:
            # Backfill 1Password share link ONLY for pattern-matching bypass apps (Tenant 2)
            existing_op_link = (f.get("OnePasswordShareLink") or "").strip()
            is_bypass = should_bypass_jira_for_secret({
                "TenantID": f.get("TenantID"),
                "tenant_id": f.get("TenantID"),
                "SecretDescription": f.get("SecretDescription"),
                "AppName": f.get("AppName"),
            })
            if is_bypass and not existing_op_link and push_secret_to_1password_and_share and ONEPASSWORD_SERVICE_ACCOUNT_TOKEN:
                vault_entry_name = (f.get("NewSecretVaultName") or "").strip()
                if vault_entry_name:
                    print(f"[DEBUG] Backfill checking vault entry: {vault_entry_name}")
                    try:
                        kv_sec = _rotation_kv.get_secret(vault_entry_name)
                        if kv_sec and kv_sec.value:
                            op_res = push_secret_to_1password_and_share(
                                app_name=f.get("AppName", "Unknown"),
                                app_id=f.get("Title", ""),
                                secret_name=vault_entry_name,
                                secret_value=kv_sec.value,
                                expiry_date=f.get("ExpirationDate"),
                                tenant_id=f.get("TenantID") or HOME_TENANT_ID,
                                service_account_token=ONEPASSWORD_SERVICE_ACCOUNT_TOKEN,
                                vault_id=ONEPASSWORD_VAULT_ID,
                            )
                            if not op_res.get("success"):
                                print(f"[DEBUG] 1Password push error for {vault_entry_name}: {op_res.get('error')}")
                            if op_res.get("success") and op_res.get("share_link"):
                                op_link = op_res["share_link"]
                                f["OnePasswordShareLink"] = op_link
                                write_sharepoint_row(item_id, {"OnePasswordShareLink": op_link, "LastChecked": today})
                                summary["onePasswordItemsCreated"] += 1
                                summary["onePasswordShareLinksGenerated"] += 1
                                summary["sharepointUpdated"] += 1
                                log.info("Populated missing 1Password share link for %s: %s", vault_entry_name, op_link)
                    except Exception as op_backfill_err:
                        log.warning("Could not backfill 1Password link for %s: %s", vault_entry_name, op_backfill_err)
            if not jira_key:
                if is_bypass:
                    # Jira-bypassed secret in Second Tenant pending team deployment via 1Password
                    write_sharepoint_row(item_id, {"LastChecked": today})
                    summary["sharepointUpdated"] += 1
                    continue
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

        app_info = app_info_by_client_id.get(app_id)
        if not app_info:
            summary["errors"].append(f"AppID={app_id}: not found in Azure snapshot")
            continue
        object_id, app_tenant_id = app_info

        # Determine if secret bypasses Jira (e.g. Second Tenant pattern-matching secrets)
        is_bypass = should_bypass_jira_for_secret({
            "TenantID": f.get("TenantID") or app_tenant_id,
            "tenant_id": f.get("TenantID") or app_tenant_id,
            "SecretDescription": f.get("SecretDescription") or "",
            "AppName": app_name,
        })

        if not jira_key and not is_bypass:
            summary["errors"].append(f"AppID={app_id}: no JiraTicketKey, cannot rotate")
            continue

        # NOTE: rows with AlertStatus == RotatedPendingDeployment are already
        # excluded at the all_candidates stage above (that status is not in
        # ACTIONABLE_STATUSES), so no separate "already rotated" check is
        # needed here — a row reaching this point genuinely has not been
        # rotated yet this cycle.

        try:
            if jira_key:
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
                # jira-status-update endpoint on In Progress.
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

            display_label = f"AutoRotated-{jira_key}-{today}" if jira_key else f"AutoRotated-PatternBypass-{today}"
            print(f"[DEBUG] Rotating: {app_name} ({app_id}) jira={jira_key} is_bypass={is_bypass} days={days} "
                  f"tenant={app_tenant_id} validity={SECRET_VALIDITY_DAYS}d")
            new_secret = create_azure_secret(
                application_object_id=object_id,
                display_name=display_label,
                tenant_id=app_tenant_id)
            if not new_secret.get("success"):
                summary["errors"].append(f"AppID={app_id}: create_azure_secret failed: {new_secret}")
                continue
            summary["newSecretsGenerated"] += 1

            # ProductTeamsKeyVaultName lets a specific product's team override
            # where their rotated secret gets stored, instead of the shared
            # ROTATION_KV_URL every app uses by default.
            raw_vault_key = (f.get("ProductTeamsKeyVaultName") or "").strip()
            override_vault_url = f"https://{raw_vault_key.lower()}.vault.azure.net/" if raw_vault_key else ""

            existing_vault_name = (f.get("NewSecretVaultName") or "").strip()
            if existing_vault_name:
                secret_name_to_use = existing_vault_name
            else:
                product_name = (f.get("ProductName") or "").strip()
                team_name    = (f.get("TeamName") or "").strip()
                secret_desc  = (f.get("SecretDescription") or "").strip()
                secret_id_short = (f.get("SecretID") or "").strip()[:8]
                suffix = jira_key if jira_key else (secret_desc or secret_id_short or "Rotated")
                name_parts = [p for p in (product_name, team_name, app_name, suffix) if p]
                secret_name_to_use = "-".join(name_parts) if name_parts else f"{app_name}-{suffix}"

            secret_name_to_use = _sanitize_kv_name(secret_name_to_use)

            vault_result = store_rotated_secret(
                secret_name=secret_name_to_use,
                secret_value=new_secret["secretText"],
                override_vault_url=override_vault_url)
            if not vault_result.get("success"):
                summary["errors"].append(f"AppID={app_id}: store_rotated_secret failed: {vault_result}")
                continue

            vault_name = vault_result["vault_name"]

            # Store in 1Password and generate secure share link ONLY for pattern-matching bypass apps (Tenant 2)
            onepassword_share_link = ""
            if is_bypass and push_secret_to_1password_and_share and ONEPASSWORD_SERVICE_ACCOUNT_TOKEN:
                try:
                    op_res = push_secret_to_1password_and_share(
                        app_name=app_name,
                        app_id=app_id,
                        secret_name=vault_name,
                        secret_value=new_secret["secretText"],
                        expiry_date=new_secret.get("endDateTime"),
                        tenant_id=app_tenant_id,
                        service_account_token=ONEPASSWORD_SERVICE_ACCOUNT_TOKEN,
                        vault_id=ONEPASSWORD_VAULT_ID,
                    )
                    if op_res.get("success"):
                        onepassword_share_link = op_res.get("share_link") or ""
                        summary["onePasswordItemsCreated"] = summary.get("onePasswordItemsCreated", 0) + 1
                        if onepassword_share_link:
                            summary["onePasswordShareLinksGenerated"] = summary.get("onePasswordShareLinksGenerated", 0) + 1
                            log.info("1Password share link generated for %s: %s", app_name, onepassword_share_link)
                    else:
                        summary["errors"].append(f"AppID={app_id}: 1Password push failed: {op_res.get('error')}")
                except Exception as op_err:
                    log.warning("1Password integration error for AppID=%s: %s", app_id, op_err)
                    summary["errors"].append(f"AppID={app_id}: 1Password exception: {op_err}")

            if jira_key:
                try:
                    op_share_note = f"\n1Password Share Link (valid 30 days): {onepassword_share_link}" if onepassword_share_link else ""
                    comment = (
                        f"🔐 AUTO-ROTATION — {today}\n"
                        f"A new client secret has been generated for {app_name} (App ID: {app_id}).\n"
                        f"New credential keyId: {new_secret['keyId']}\n"
                        f"New credential expiry: {new_secret['endDateTime']}\n"
                        f"Stored in Key Vault under: {vault_name}"
                        f"{op_share_note}\n\n"
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

            expiry_notice = (
                f"New secret ready — pending deployment ({jira_key})"
                if jira_key
                else "New secret ready — pending deployment (1Password link generated)"
            )
            sp_row_data = {
                "AlertStatus":        "RotatedPendingDeployment",
                "NewSecretKeyId":     new_secret["keyId"],
                "NewSecretVaultName": vault_name,
                "ExpiryNotice":       expiry_notice,
                "LastChecked":        today,
                "TenantID":           app_tenant_id,
            }
            if onepassword_share_link:
                sp_row_data["OnePasswordShareLink"] = onepassword_share_link

            write_sharepoint_row(item_id, sp_row_data)
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
    print(f"  1Password Items Created  : {summary.get('onePasswordItemsCreated')}")
    print(f"  1Password Share Links    : {summary.get('onePasswordShareLinksGenerated')}")
 
    errors = summary.get("errors", [])
    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for err in errors:
            print(f"    - {err}")
        sys.exit(1)
    else:
        print("\n  No errors.")
 
if __name__ == "__main__":
    main()
