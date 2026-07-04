"""
teams_bot.py — Microsoft Teams Bot for Azure Secret Governance
==============================================================
Standalone module — import into main.py to enable Teams bot.
To disable: comment out the import in main.py.

How it works:
  1. Azure Bot Service receives message from Teams channel
  2. Posts to /teams-webhook on this container
  3. LangChain agent processes the question
  4. Reply sent back to Teams via Bot Framework API

Setup:
  - Azure Bot Service created and Teams channel enabled
  - BOT-APP-ID, BOT-APP-SECRET, BOT-TENANT-ID stored in Key Vault
  - Bot manifest uploaded to Teams org app catalog
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Request, Response

log = logging.getLogger("teams-bot")

# ─────────────────────────────────────────────────────────────────────────────
# ROUTER — mounted into main FastAPI app
# ─────────────────────────────────────────────────────────────────────────────

router = APIRouter(tags=["Teams Bot"])

# ─────────────────────────────────────────────────────────────────────────────
# BOT CREDENTIALS — injected from main.py after KV load
# ─────────────────────────────────────────────────────────────────────────────

_bot_app_id     = ""
_bot_app_secret = ""
_bot_tenant_id  = ""
_get_agent_fn   = None   # injected from main.py

def configure(bot_app_id: str, bot_app_secret: str,
              bot_tenant_id: str, get_agent_fn) -> None:
    """
    Called from main.py after Key Vault secrets are loaded.
    Injects credentials and the agent factory function.
    """
    global _bot_app_id, _bot_app_secret, _bot_tenant_id, _get_agent_fn
    _bot_app_id     = bot_app_id
    _bot_app_secret = bot_app_secret
    _bot_tenant_id  = bot_tenant_id
    _get_agent_fn   = get_agent_fn
    log.info("Teams bot configured. App ID: %s", bot_app_id[:8] + "...")

# ─────────────────────────────────────────────────────────────────────────────
# BOT FRAMEWORK TOKEN
# ─────────────────────────────────────────────────────────────────────────────

async def _get_bot_token() -> str:
    """Get Bot Framework access token to send replies back to Teams."""
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"https://login.microsoftonline.com/{_bot_tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type":    "client_credentials",
                "client_id":     _bot_app_id,
                "client_secret": _bot_app_secret,
                "scope":         "https://api.botframework.com/.default",
            },
            timeout=15,
        )
        r.raise_for_status()
        return r.json()["access_token"]

# ─────────────────────────────────────────────────────────────────────────────
# SEND REPLY TO TEAMS
# ─────────────────────────────────────────────────────────────────────────────

async def _send_reply(service_url: str, conversation_id: str,
                      activity_id: str, text: str) -> None:
    """Send a reply message back to the Teams channel."""
    try:
        token = await _get_bot_token()
        url   = f"{service_url}v3/conversations/{conversation_id}/activities/{activity_id}"
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(url,
                json={
                    "type":       "message",
                    "text":       text,
                    "textFormat": "markdown",
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            r.raise_for_status()
            log.info("Reply sent to Teams conversation %s", conversation_id[:20])
    except Exception as e:
        log.exception("Failed to send Teams reply: %s", e)

# ─────────────────────────────────────────────────────────────────────────────
# COMMAND SHORTCUTS
# ─────────────────────────────────────────────────────────────────────────────

QUICK_COMMANDS = {
    "status":   "Give me a brief summary of current secret expiry status — how many P1, P2, P3, and how many rotated.",
    "critical": "Show me all P1 critical secrets expiring within 7 days from the SecretAlertRegistry SharePoint list.",
    "expiring": "Show me all secrets expiring within the next 30 days.",
    "pending":  "Show me all secrets with AlertStatus = RotatedPendingDeployment — these are rotated but waiting for deployment.",
    "help":     (
        "List all available commands for this bot:\n"
        "- **status** — summary of all secret statuses\n"
        "- **critical** — P1 secrets expiring within 7 days\n"
        "- **expiring** — secrets expiring this month\n"
        "- **pending** — secrets pending deployment\n"
        "- You can also ask natural language questions like:\n"
        "  'What is the status of KAN-1442?'\n"
        "  'How many secrets expire this week?'\n"
        "  'Show me all secrets for App X'"
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS MESSAGE AND REPLY
# ─────────────────────────────────────────────────────────────────────────────

async def _process_and_reply(
    text: str, from_id: str, conversation_id: str,
    service_url: str, activity_id: str,
) -> None:
    """Process a Teams message through LangChain and send reply."""
    # Map quick commands to full instructions
    instruction = QUICK_COMMANDS.get(text.lower().strip(), text)

    try:
        agent  = await _get_agent_fn()
        result = await agent.ainvoke(
            {"input": instruction},
            config={"configurable": {
                "session_id": f"teams_{from_id}_{conversation_id[:20]}"
            }},
        )
        reply = result.get("output", "Sorry, I could not process your request.")
    except Exception as e:
        log.exception("Teams agent error: %s", e)
        reply = (
            f"⚠️ Sorry, I encountered an error processing your request.\n\n"
            f"Error: `{str(e)[:200]}`\n\n"
            f"Please try again or check the container logs."
        )

    await _send_reply(service_url, conversation_id, activity_id, reply)

# ─────────────────────────────────────────────────────────────────────────────
# TEAMS WEBHOOK ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/teams-webhook")
async def teams_webhook(request: Request):
    """
    Receives messages from Microsoft Teams via Azure Bot Service.
    Processes through LangChain agent and replies back to Teams.

    Jira Automation setup:
      Azure Bot Service → Channels → Microsoft Teams → Enable
      Messaging endpoint: https://<fqdn>/teams-webhook

    To disable Teams bot:
      Comment out 'from teams_bot import ...' in main.py
    """
    try:
        body = await request.json()
    except Exception:
        return Response(status_code=200)

    activity_type   = body.get("type", "")
    text            = (body.get("text") or "").strip()
    service_url     = body.get("serviceUrl", "")
    conversation_id = body.get("conversation", {}).get("id", "")
    activity_id     = body.get("id", "")
    from_name       = body.get("from", {}).get("name", "User")
    from_id         = body.get("from", {}).get("id", "unknown")

    log.info("Teams activity from %s: type=%s", from_name, activity_type)

    # Handle bot added to channel — send welcome message
    if activity_type == "conversationUpdate":
        members_added = body.get("membersAdded", [])
        bot_id = _bot_app_id
        for member in members_added:
            if member.get("id", "").startswith(bot_id):
                welcome = (
                    "👋 Hello! I'm the **Azure Secret Governance Bot**.\n\n"
                    "I can help you monitor Azure App Registration secret expiry.\n\n"
                    "**Quick commands:**\n"
                    "- `status` — overall summary\n"
                    "- `critical` — P1 secrets expiring within 7 days\n"
                    "- `expiring` — secrets expiring this month\n"
                    "- `pending` — secrets pending deployment\n"
                    "- `help` — show all commands\n\n"
                    "You can also ask me anything in natural language! 🔐"
                )
                asyncio.create_task(
                    _send_reply(service_url, conversation_id, activity_id, welcome)
                )
        return Response(status_code=200)

    # Only process text messages
    if activity_type != "message" or not text:
        return Response(status_code=200)

    # Remove bot @mention from text
    clean_text = re.sub(r"<at>.*?</at>", "", text).strip()
    if not clean_text:
        return Response(status_code=200)

    log.info("Teams message from %s: %s", from_name, clean_text[:100])

    # Process async — return 200 immediately so Teams doesn't timeout
    asyncio.create_task(
        _process_and_reply(clean_text, from_id, conversation_id, service_url, activity_id)
    )

    return Response(status_code=200)
