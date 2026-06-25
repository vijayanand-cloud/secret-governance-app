"""
Azure Secret Governance — LangChain Agent  (Container 1)
=========================================================
Endpoints:
  GET  /health   — liveness probe
  POST /run      — trigger a governance cycle (called by Automation Runbook)
  POST /chat     — conversational endpoint with per-session memory

Container 2 is now a plain FastAPI REST API (not MCP).
LangChain tools are defined here as @tool functions that call Container 2's
/tools/* endpoints over HTTP on localhost:8001.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import httpx
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from langchain_openai import AzureChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.chat_history import BaseChatMessageHistory, InMemoryChatMessageHistory
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.tools import tool

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("secret-agent")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

KV_URL          = os.environ["KEY_VAULT_URL"]
UAMI_CLIENT_ID  = os.environ["UAMI_CLIENT_ID"]
MONITOR_API_URL = os.environ.get("MONITOR_API_URL", "http://localhost:8001")

_credential = ManagedIdentityCredential(client_id=UAMI_CLIENT_ID)
_kv         = SecretClient(vault_url=KV_URL, credential=_credential)

def _kv_get(name: str) -> str:
    try:
        return _kv.get_secret(name).value
    except Exception as exc:
        raise RuntimeError(f"Required Key Vault secret '{name}' could not be loaded: {exc}") from exc

log.info("Loading Azure OpenAI config from Key Vault...")
AOAI_ENDPOINT   = _kv_get("AZURE-OPENAI-ENDPOINT")
AOAI_API_KEY    = _kv_get("AZURE-OPENAI-API-KEY")
AOAI_DEPLOYMENT = _kv_get("AZURE-OPENAI-DEPLOYMENT-NAME")
log.info("Azure OpenAI config loaded. Deployment: %s", AOAI_DEPLOYMENT)

# ─────────────────────────────────────────────────────────────────────────────
# HTTP CLIENT — talks to Container 2 REST API
# ─────────────────────────────────────────────────────────────────────────────

async def _call_monitor(endpoint: str, payload: dict | None = None) -> dict:
    """POST to a Container 2 /tools/* endpoint and return the JSON response."""
    url = f"{MONITOR_API_URL}/tools/{endpoint}"
    async with httpx.AsyncClient(timeout=300) as c:
        r = await c.post(url, json=payload or {})
        r.raise_for_status()
        return r.json()

# ─────────────────────────────────────────────────────────────────────────────
# LANGCHAIN TOOLS — thin wrappers around Container 2 REST endpoints
# ─────────────────────────────────────────────────────────────────────────────

@tool
async def run_secret_monitoring() -> dict:
    """Runs the complete Azure secret expiry monitoring cycle: scans all App Registrations,
    classifies expiry buckets, raises Jira tickets, sends Teams alerts, and updates SharePoint."""
    return await _call_monitor("run_secret_monitoring")

@tool
async def fetch_azure_secrets() -> dict:
    """Fetches all Azure App Registrations and their client secrets from Entra ID."""
    return await _call_monitor("fetch_azure_secrets")

@tool
async def get_sharepoint_state() -> dict:
    """Reads all items from the SecretAlertRegistry SharePoint list."""
    return await _call_monitor("get_sharepoint_state")

@tool
async def get_jira_issue(issue_key: str) -> dict:
    """Returns the current status and summary of a Jira issue by its key (e.g. KAN-96)."""
    return await _call_monitor("get_jira_issue", {"issue_key": issue_key})

@tool
async def add_jira_comment(issue_key: str, comment_text: str) -> dict:
    """Adds a comment to an existing Jira issue."""
    return await _call_monitor("add_jira_comment", {"issue_key": issue_key, "comment_text": comment_text})

@tool
async def send_teams_alert(alert_text: str) -> dict:
    """Posts an Adaptive Card alert message to the Teams webhook channel."""
    return await _call_monitor("send_teams_alert", {"alert_text": alert_text})

@tool
async def write_sharepoint_row(item_id: Optional[str], fields: dict) -> dict:
    """Creates or updates a row in the SecretAlertRegistry SharePoint list."""
    return await _call_monitor("write_sharepoint_row", {"item_id": item_id, "fields": fields})

@tool
async def create_jira_ticket(
    app_name: str, app_id: str, secret_id: str, secret_description: str,
    expiration_date: str, days_remaining: int,
    severity: str = "WARNING", priority: str = "High", extra_note: str = ""
) -> dict:
    """Creates a Jira incident ticket for a secret expiry event."""
    return await _call_monitor("create_jira_ticket", {
        "app_name": app_name, "app_id": app_id, "secret_id": secret_id,
        "secret_description": secret_description, "expiration_date": expiration_date,
        "days_remaining": days_remaining, "severity": severity,
        "priority": priority, "extra_note": extra_note,
    })

TOOLS = [
    run_secret_monitoring,
    fetch_azure_secrets,
    get_sharepoint_state,
    get_jira_issue,
    add_jira_comment,
    send_teams_alert,
    write_sharepoint_row,
    create_jira_ticket,
]

# ─────────────────────────────────────────────────────────────────────────────
# MEMORY
# ─────────────────────────────────────────────────────────────────────────────

_chat_histories: dict[str, BaseChatMessageHistory] = {}

def get_session_history(session_id: str) -> BaseChatMessageHistory:
    if session_id not in _chat_histories:
        _chat_histories[session_id] = InMemoryChatMessageHistory()
    return _chat_histories[session_id]

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are the Azure Secret Governance Agent.

You have access to tools that interact with Azure Entra ID, SharePoint, Jira, and Teams:
- run_secret_monitoring    — runs the full weekly monitoring cycle (use this for scheduled runs)
- fetch_azure_secrets      — fetch all App Registrations and their secrets from Entra ID
- get_sharepoint_state     — read all rows from the SecretAlertRegistry SharePoint list
- get_jira_issue           — get the current status of a specific Jira ticket
- add_jira_comment         — add a comment to a Jira ticket
- send_teams_alert         — post an alert to the Teams channel
- write_sharepoint_row     — create or update a SharePoint row
- create_jira_ticket       — raise a new Jira incident ticket

Guidelines:
- For a full monitoring cycle, call run_secret_monitoring().
- For specific questions ("What is the status of KAN-96?", "Show secrets for App X"),
  use the targeted individual tools rather than the full cycle.
- Rotation is handled automatically by a separate Azure Automation Runbook — inform
  users of this if they ask about rotation.
- Always respond in clear, well-formatted Markdown with ticket keys, dates, and counts.
"""

DEFAULT_INSTRUCTION = (
    "Run the weekly secret monitoring check. "
    "Summarise everything: secrets scanned, new Jira tickets raised, "
    "Teams alerts sent, SharePoint rows created or updated, and any errors."
)

# ─────────────────────────────────────────────────────────────────────────────
# AGENT FACTORY
# ─────────────────────────────────────────────────────────────────────────────

_agent_with_history: RunnableWithMessageHistory | None = None

def build_agent() -> RunnableWithMessageHistory:
    log.info("Building LangChain agent with %d tools", len(TOOLS))
    llm = AzureChatOpenAI(
        azure_endpoint=AOAI_ENDPOINT,
        api_key=AOAI_API_KEY,
        azure_deployment=AOAI_DEPLOYMENT,
        api_version="2024-10-21",
        temperature=0,
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])
    agent    = create_tool_calling_agent(llm, TOOLS, prompt)
    executor = AgentExecutor(agent=agent, tools=TOOLS, verbose=True, max_iterations=15)
    return RunnableWithMessageHistory(
        executor,
        get_session_history,
        input_messages_key="input",
        history_messages_key="chat_history",
    )

async def _get_agent() -> RunnableWithMessageHistory:
    global _agent_with_history
    if _agent_with_history is None:
        _agent_with_history = build_agent()
    return _agent_with_history

# ─────────────────────────────────────────────────────────────────────────────
# GOVERNANCE CYCLE
# ─────────────────────────────────────────────────────────────────────────────

async def run_governance_cycle(instruction: str = DEFAULT_INSTRUCTION) -> dict:
    agent   = await _get_agent()
    started = datetime.now(timezone.utc)
    try:
        result = await agent.ainvoke(
            {"input": instruction},
            config={"configurable": {"session_id": "runbook_trigger"}},
        )
        return {
            "success":   True,
            "startedAt": started.isoformat(),
            "summary":   result.get("output", ""),
        }
    except Exception as e:
        log.exception("Governance cycle failed")
        return {"success": False, "startedAt": started.isoformat(), "error": str(e)}

# ─────────────────────────────────────────────────────────────────────────────
# FASTAPI APP
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _agent_with_history
    _agent_with_history = build_agent()
    log.info("Agent ready. Monitor API: %s", MONITOR_API_URL)
    yield

app = FastAPI(title="Azure Secret Governance Agent", lifespan=lifespan)

class RunRequest(BaseModel):
    instruction: str | None = None

class ChatRequest(BaseModel):
    message: str
    session_id: str = "default_user_session"

@app.get("/health")
async def health():
    return {"status": "ok", "server": "AzureSecretGovernanceAgent", "deployment": AOAI_DEPLOYMENT}

@app.post("/run")
async def run(req: RunRequest):
    """Trigger a monitoring governance cycle. Called by the Azure Automation Runbook."""
    return await run_governance_cycle(req.instruction or DEFAULT_INSTRUCTION)

@app.post("/chat")
async def chat(req: ChatRequest):
    """Conversational endpoint with per-session memory. Ready for Teams bot or web UI."""
    agent = await _get_agent()
    try:
        result = await agent.ainvoke(
            {"input": req.message},
            config={"configurable": {"session_id": req.session_id}},
        )
        return {"session_id": req.session_id, "response": result["output"]}
    except Exception as e:
        log.exception("Chat request failed for session %s", req.session_id)
        raise HTTPException(status_code=500, detail=str(e))
