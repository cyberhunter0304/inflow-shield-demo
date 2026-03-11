"""
Conversation Routes
-------------------
All conversation data is read from MongoDB ONLY.

GET  /api/conversations                     — paginated list with filters
GET  /api/conversations/{conversation_id}   — single conversation by ID
GET  /api/conversations/bot/{bot_id}        — all conversations for a bot
GET  /api/conversations/thread/{thread_id}  — all messages in a thread
GET  /api/conversations/message/{message_id} — single message by messageId
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status

from datetime_utils import now
from mongodb_storage import fetch_conversations

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/conversations", tags=["Conversations"])


@router.get("")
async def list_conversations(
    bot_id:      Optional[str] = Query(None, description="Filter by bot ID"),
    thread_id:   Optional[str] = Query(None, description="Filter by thread ID"),
    role:        Optional[str] = Query(None, description="Filter by from.role (e.g. 'user')"),
    unprocessed: bool          = Query(False, description="Only return unprocessed messages"),
    skip:        int           = Query(0, ge=0),
    limit:       int           = Query(50, ge=1, le=500),
):
    """Fetch conversations from MongoDB with optional filters and pagination."""
    result = fetch_conversations(
        bot_id           = bot_id,
        thread_id        = thread_id,
        role             = role,
        only_unprocessed = unprocessed,
        skip             = skip,
        limit            = limit,
    )
    return {"success": True, **result}


@router.get("/bot/{bot_id}")
async def get_bot_conversations(
    bot_id:    str,
    thread_id: Optional[str] = Query(None),
    skip:      int            = Query(0, ge=0),
    limit:     int            = Query(50, ge=1, le=500),
):
    """Fetch all conversations for a specific bot, optionally filtered by thread."""
    result = fetch_conversations(bot_id=bot_id, thread_id=thread_id, skip=skip, limit=limit)
    return {"success": True, "bot_id": bot_id, **result}


@router.get("/thread/{thread_id}")
async def get_thread_conversations(
    thread_id: str,
    skip:  int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    """Fetch all messages belonging to a thread."""
    result = fetch_conversations(thread_id=thread_id, skip=skip, limit=limit)
    return {"success": True, "thread_id": thread_id, **result}


@router.get("/message/{message_id}")
async def get_message(message_id: str):
    """Fetch a single message document by messageId."""
    result = fetch_conversations(message_id=message_id, limit=1)
    docs = result.get("conversations", [])
    if not docs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Message '{message_id}' not found",
        )
    return {"success": True, "message": docs[0], "timestamp": now()}


@router.get("/{conversation_id}")
async def get_conversation(conversation_id: str):
    """Fetch a single conversation document by conversationId."""
    result = fetch_conversations(conversation_id=conversation_id, limit=1)
    docs = result.get("conversations", [])
    if not docs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation '{conversation_id}' not found",
        )
    return {"success": True, "conversation": docs[0], "timestamp": now()}
