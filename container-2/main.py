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
from azure.identity import ManagedIdentityCredential
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

GRAPH_TENANT_ID    = _kv_get("GRAPH-TENANT-ID")
GRAPH_TENANT_NAME  = _kv_get("GRAPH-TENANT-NAME")  # from KV — no Directory.Read.All needed
JIRA_BASE_URL      = _kv_get("JIRA-BASE-URL")
JIRA_API_TOKEN      = _kv_get("JIRA-API-TOKEN")
JIRA_USER_EMAIL     = _kv_get("JIRA-USER-EMAIL")
TEAMS_WEBHOOK_URL   = _kv_get("TEAMS-WEBHOOK-URL").strip()
SHAREPOINT_SITE_ID  = _kv_get("SHAREPOINT-SITE-ID")
SHAREPOINT_LIST_ID  = _kv_get("SHAREPOINT-LIST-ID")

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
# UAMI handles Graph auth — no client secret needed
from azure.identity import ManagedIdentityCredential as _MIC
_graph_credential = _MIC(client_id=UAMI_CLIENT_ID)

async def _graph_token() -> str:
    """Get Graph API token using UAMI — no client secret required."""
    token = _graph_credential.get_token("https://graph.microsoft.com/.default")
    return token.token

async def get_tenant_name() -> str:
    """Returns tenant name from Key Vault — no Graph API call, no extra permissions needed."""
    return GRAPH_TENANT_NAME

def _jira_auth() -> str:
    return "Basic " + _b64.b64encode(f"{JIRA_USER_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()

# ── Tool Implementations ──────────────────────────────────────────────────────
async def fetch_azure_secrets() -> dict:
    headers = {"Authorization": f"Bearer {await _graph_token()}"}
    url = "https://graph.microsoft.com/v1.0/applications?$select=displayName,appId,passwordCredentials"
    apps = []
    async with httpx.AsyncClient() as c:
        while url:
            r = await c.get(url, headers=headers, timeout=30)
            r.raise_for_status()
            b = r.json()
            apps.extend(b.get("value", []))
            url = b.get("@odata.nextLink")
    return {"applications": apps, "count": len(apps)}

async def get_sharepoint_state() -> dict:
    headers = {"Authorization": f"Bearer {await _graph_token()}"}
    url = f"https://graph.microsoft.com/v1.0/sites/{SHAREPOINT_SITE_ID}/lists/{SHAREPOINT_LIST_ID}/items?$expand=fields"
    items = []
    async with httpx.AsyncClient() as c:
        while url:
            r = await c.get(url, headers=headers, timeout=30)
            r.raise_for_status()
            b = r.json()
            items.extend(b.get("value", []))
            url = b.get("@odata.nextLink")
    return {"items": items, "count": len(items)}

async def write_sharepoint_row(item_id: str | None, fields: dict[str, str]) -> dict:
    for col in {"LastChecked", "AlertSentDate", "RotationDetectedDate", "ExpirationDate", "JiraTicketCreatedDate"}:
        if col in fields and fields[col]: fields[col] = str(fields[col])[:10]
    fields["TenantID"] = GRAPH_TENANT_ID
    fields["TenantName"] = await get_tenant_name()
    headers = {"Authorization": f"Bearer {await _graph_token()}", "Content-Type": "application/json"}
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

async def send_teams_alert(alert_text: str) -> dict:
    payload = {"attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4", "body": [{"type": "TextBlock", "text": alert_text, "wrap": True}]}}]}
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

class TeamsReq(BaseModel): alert_text: str
@app.post("/tools/send_teams_alert")
async def api_send_teams_alert(req: TeamsReq): return await send_teams_alert(req.alert_text)

@app.post("/tools/run_secret_monitoring")
async def api_run_monitoring():
    return await _run_secret_monitoring(fetch_azure_secrets, get_sharepoint_state, write_sharepoint_row, create_jira_ticket, get_jira_issue, add_jira_comment, send_teams_alert)

log.info("REST API Server ready — GET /health | POST /tools/*")