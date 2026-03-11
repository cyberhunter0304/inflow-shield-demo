"""
MongoDB Storage Module
======================
Handles ALL MongoDB read/write operations.

Responsibilities
----------------
- Connect / disconnect MongoDB
- save_conversation()       — write one message doc to the conversations collection
- fetch_conversations()     — THE single shared helper for ALL conversation reads
- insert_test_message()     — write a test-chat message so the monitor picks it up
- get_unprocessed_conversations() / mark_conversation_processed()  — batch helpers
- get_processing_stats()    — stats for the batch endpoints

Security-log operations (load / save / delete / list) now write to
LOCAL JSON FILES via storage.py, NOT MongoDB.  Do NOT add MongoDB security-log
writes here.
"""

import logging
import time
from typing import Dict, List, Optional, Any

from bson import ObjectId
from pymongo import MongoClient, DESCENDING, ASCENDING
from pymongo.errors import ServerSelectionTimeoutError

from config import (
    MONGODB_URI,
    MONGODB_DATABASE,
    MONGODB_CONVERSATIONS_COLLECTION,
)
from datetime_utils import now

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global connection state
# ---------------------------------------------------------------------------

_client: Optional[MongoClient] = None
_db = None


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def connect_mongodb() -> bool:
    """Initialise the shared MongoDB connection. Returns True on success."""
    global _client, _db
    try:
        _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        _client.admin.command("ping")
        _db = _client[MONGODB_DATABASE]
        logger.info(f"✅ Connected to MongoDB — database: {MONGODB_DATABASE}")
    except ServerSelectionTimeoutError:
        logger.error(f"❌ Could not reach MongoDB at {MONGODB_URI}")
        return False
    except Exception as exc:
        logger.error(f"❌ MongoDB connection error: {exc}")
        return False

    # Index setup is best-effort — a failure here must NOT prevent the server
    # from starting.  All index errors are logged as warnings, not exceptions.
    try:
        _create_indexes()
    except Exception as exc:
        logger.warning(f"⚠️  Index setup failed (non-fatal): {exc}")

    return True


def close_mongodb() -> None:
    """Close the shared MongoDB connection."""
    global _client
    if _client:
        _client.close()
        logger.info("MongoDB connection closed")


def get_mongodb():
    """Return the shared database instance, reconnecting if necessary."""
    global _db
    if _db is None:
        connect_mongodb()
    return _db


def _drop_index_if_exists(col, name: str) -> None:
    """Drop an index by name, ignoring errors if it doesn't exist."""
    try:
        col.drop_index(name)
        logger.info(f"Dropped stale index: {name}")
    except Exception as e:
        logger.debug(f"Could not drop {name} (may not exist): {e}")


def _create_indexes() -> None:
    """
    Create necessary indexes — fully idempotent, never raises on boot.

    Strategy: always drop an index before (re)creating it with different
    options.  MongoDB raises IndexKeySpecsConflict (code 86) if you try to
    create an index with the same name but different options, so we drop first.

    Desired final state
    -------------------
    conversationId  — non-unique, sparse (multiple messages share one conv ID)
    messageId       — unique, sparse     (one doc per message)
    botId           — non-unique
    threadId        — non-unique
    createdAt       — non-unique descending
    processed       — non-unique
    """
    if _db is None:
        return

    col = _db[MONGODB_CONVERSATIONS_COLLECTION]

    try:
        existing_indexes = list(col.list_indexes())
        existing = {idx["name"]: idx for idx in existing_indexes}
    except Exception as e:
        logger.warning(f"Could not list indexes: {e}")
        return

    # ── Drop ALL stale / mismatched indexes so we can recreate cleanly ────────

    # Legacy snake_case index (old schema)
    if "conversation_id_1" in existing:
        _drop_index_if_exists(col, "conversation_id_1")

    # conversationId was previously unique — must NOT be unique
    if "conversationId_1" in existing:
        if existing["conversationId_1"].get("unique"):
            _drop_index_if_exists(col, "conversationId_1")

    # messageId was previously non-unique — must be unique
    # MongoDB rejects re-creating with different options under the same name,
    # so always drop it and let create_index rebuild it correctly.
    if "messageId_1" in existing:
        existing_is_unique = existing["messageId_1"].get("unique", False)
        if not existing_is_unique:
            # Old non-unique version — drop so we can recreate as unique
            _drop_index_if_exists(col, "messageId_1")
        # If already unique+sparse: leave it, create_index is a no-op

    # ── Recreate indexes with correct options ─────────────────────────────────
    index_specs = [
        # (keys_or_field, kwargs)
        ("conversationId",              {}),                             # lookup, NOT unique
        ("messageId",                   {"unique": True, "sparse": True}),
        ("botId",                       {}),
        ("threadId",                    {}),
        ([("createdAt", DESCENDING)],   {}),
        ("processed",                   {}),
    ]

    for keys, kwargs in index_specs:
        try:
            col.create_index(keys, **kwargs)
        except Exception as e:
            # Log but never let an index error crash the whole startup
            logger.warning(f"Index creation skipped ({keys}): {e}")

    logger.info("✅ MongoDB indexes ensured")


# ---------------------------------------------------------------------------
# ════════════════════════════════════════════════════════════════════════════
#  COMMON CONVERSATION FETCH HELPER  ← every endpoint must use this
# ════════════════════════════════════════════════════════════════════════════
# ---------------------------------------------------------------------------

def fetch_conversations(
    *,
    bot_id: Optional[str] = None,
    thread_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
    message_id: Optional[str] = None,
    role: Optional[str] = None,
    only_unprocessed: bool = False,
    skip: int = 0,
    limit: int = 100,
    sort_by: str = "createdAt",
    sort_order: int = DESCENDING,
    projection: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    THE single gateway for reading conversations from MongoDB.

    Every API endpoint and service that needs conversation data MUST call
    this function — never query the collection directly elsewhere.

    Parameters
    ----------
    bot_id            : Filter to a specific bot.
    thread_id         : Filter to a specific thread.
    conversation_id   : Filter to a specific conversation ID.
    message_id        : Filter to a specific message ID.
    role              : Filter by ``from.role`` field  (e.g. ``"user"``).
    only_unprocessed  : When True only return docs where ``processed != True``.
    skip              : Pagination offset.
    limit             : Maximum number of documents to return (0 = no limit).
    sort_by           : Field to sort by (default ``createdAt``).
    sort_order        : ``DESCENDING`` (default) or ``ASCENDING``.
    projection        : MongoDB projection dict. ``_id`` is always stringified.

    Returns
    -------
    {
        "conversations": [...],   # list of document dicts (_id → str)
        "total":         int,     # total matching docs (before skip/limit)
        "skip":          int,
        "limit":         int,
        "timestamp":     str,
    }
    """
    db = get_mongodb()
    if db is None:
        logger.error("fetch_conversations: MongoDB not connected")
        return {"conversations": [], "total": 0, "skip": skip, "limit": limit, "timestamp": now()}

    collection = db[MONGODB_CONVERSATIONS_COLLECTION]

    # ── Build filter ────────────────────────────────────────────────────────
    flt: Dict[str, Any] = {}

    if bot_id:
        flt["botId"] = bot_id
    if thread_id:
        flt["threadId"] = thread_id
    if conversation_id:
        flt["conversationId"] = conversation_id
    if message_id:
        flt["messageId"] = message_id
    if role:
        flt["from.role"] = role
    if only_unprocessed:
        flt["processed"] = {"$ne": True}

    # ── Count (before pagination) ────────────────────────────────────────────
    total = collection.count_documents(flt)

    # ── Query ───────────────────────────────────────────────────────────────
    cursor = collection.find(flt, projection or {})
    cursor = cursor.sort(sort_by, sort_order)
    if skip:
        cursor = cursor.skip(skip)
    if limit:
        cursor = cursor.limit(limit)

    # ── Serialise ───────────────────────────────────────────────────────────
    conversations = []
    for doc in cursor:
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
        conversations.append(doc)

    return {
        "conversations": conversations,
        "total": total,
        "skip": skip,
        "limit": limit,
        "timestamp": now(),
    }


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def save_conversation(conversation_data: dict) -> bool:
    """
    Insert a validated conversation document into MongoDB.

    The document must contain at minimum:
        conversationId, botId, threadId, userId, model, activity, validation

    Returns True on success.
    """
    db = get_mongodb()
    if db is None:
        logger.error("save_conversation: MongoDB not connected")
        return False

    collection = db[MONGODB_CONVERSATIONS_COLLECTION]

    # Validate required top-level fields
    required = ["conversationId", "botId", "userId", "threadId", "model", "activity", "validation"]
    missing = [f for f in required if not conversation_data.get(f)]
    if missing:
        logger.warning(f"save_conversation: missing fields {missing}")
        return False

    # Validate activity sub-fields
    activity = conversation_data.get("activity", {})
    if not isinstance(activity, dict) or not all(k in activity for k in ("role", "text", "timestamp")):
        logger.warning("save_conversation: malformed activity field")
        return False

    # Validate validation sub-fields
    validation = conversation_data.get("validation", {})
    if not isinstance(validation, dict):
        logger.warning("save_conversation: validation must be a dict")
        return False

    required_val = ["prompt", "is_safe", "blocked", "risk_level", "detections", "metrics", "timestamp"]
    missing_val = [f for f in required_val if f not in validation]
    if missing_val:
        logger.warning(f"save_conversation: validation missing fields {missing_val}")
        return False

    # Normalise
    doc = {
        "conversationId": str(conversation_data["conversationId"]),
        "botId":          str(conversation_data["botId"]),
        "userId":         str(conversation_data["userId"]),
        "threadId":       str(conversation_data["threadId"]),
        "model":          str(conversation_data["model"]),
        "activity": {
            "role":      activity.get("role", "user"),
            "text":      str(activity.get("text", "")),
            "timestamp": activity.get("timestamp", now()),
        },
        "validation": {
            "prompt":        str(validation.get("prompt", "")),
            "prompt_length": len(validation.get("prompt", "")),
            "is_safe":       bool(validation.get("is_safe", False)),
            "blocked":       bool(validation.get("blocked", False)),
            "risk_level":    str(validation.get("risk_level", "UNKNOWN")),
            "detections":    validation.get("detections", {}),
            "metrics":       validation.get("metrics", {}),
            "timestamp":     validation.get("timestamp", now()),
        },
        "processed": conversation_data.get("processed", False),
        "createdAt": conversation_data.get("createdAt", now()),
        "updatedAt": now(),
    }

    # Optional fields
    if conversation_data.get("messageId"):
        doc["messageId"] = str(conversation_data["messageId"])
    if conversation_data.get("source"):
        doc["source"] = str(conversation_data["source"])
    if validation.get("block_reason"):
        doc["validation"]["block_reason"] = str(validation["block_reason"])
    if validation.get("llm_response"):
        doc["validation"]["llm_response"] = str(validation["llm_response"])
    if conversation_data.get("security_log_id"):
        doc["security_log_id"] = str(conversation_data["security_log_id"])

    doc.pop("_id", None)

    try:
        collection.insert_one(doc)
        logger.debug(f"Saved conversation {doc['conversationId']}")
        return True
    except Exception as exc:
        logger.error(f"save_conversation error: {exc}")
        return False


def insert_test_message(
    bot_id: str,
    thread_id: str,
    conversation_id: str,
    message_id: str,
    text: str,
    user_id: str = "test_user",
) -> bool:
    """
    Insert a raw message document into the conversations collection in the
    exact shape the realtime monitor expects.

    The monitor's Change Stream will pick this up, scan it, and write
    the result to security_logs/{bot_id}.json automatically.

    This is the ONLY write path for the /api/test-chat endpoint.
    No validation happens here — validation is the monitor's job.
    """
    db = get_mongodb()
    if db is None:
        logger.error("insert_test_message: MongoDB not connected")
        return False

    collection = db[MONGODB_CONVERSATIONS_COLLECTION]

    doc = {
        "messageId":      message_id,
        "botId":          bot_id,
        "threadId":       thread_id,
        "conversationId": conversation_id,
        "userId":         user_id,
        "from": {
            "role": "user",
            "id":   user_id,
        },
        "activity": {
            "role":      "user",
            "text":      text,
            "timestamp": now(),
        },
        "processed": False,
        "source":    "test_chat",
        "createdAt": now(),
        "updatedAt": now(),
    }

    try:
        collection.insert_one(doc)
        logger.info(f"insert_test_message: inserted {message_id} for bot {bot_id}")
        return True
    except Exception as exc:
        logger.error(f"insert_test_message error: {exc}")
        return False


# ---------------------------------------------------------------------------
# Batch processing helpers (used by /api/batch/* endpoints)
# ---------------------------------------------------------------------------

def get_unprocessed_conversations(limit: int = 1) -> List[Dict[str, Any]]:
    """
    Return up to *limit* documents where ``processed != True``.
    Uses fetch_conversations() internally.
    """
    result = fetch_conversations(only_unprocessed=True, limit=limit, sort_order=ASCENDING)
    return result["conversations"]


def mark_conversation_processed(message_or_conv_id: str, security_log_id: str = None) -> bool:
    """
    Mark a message document as processed=True in MongoDB.

    Accepts any of:
    - A 24-char hex ObjectId string  → matches _id
    - A messageId string             → matches messageId  (backfill uses this)
    - A conversationId string        → matches conversationId  (legacy callers)

    messageId is tried first so the backfill works correctly.
    """
    db = get_mongodb()
    if db is None:
        return False

    collection = db[MONGODB_CONVERSATIONS_COLLECTION]
    update_fields = {"processed": True, "processed_at": now()}
    if security_log_id:
        update_fields["security_log_id"] = security_log_id

    id_str = str(message_or_conv_id)

    # Determine filter — try _id (24-char hex), then messageId, then conversationId
    if len(id_str) == 24:
        try:
            flt: Dict[str, Any] = {"_id": ObjectId(id_str)}
        except Exception:
            flt = {"messageId": id_str}
    elif id_str.startswith("msg_"):
        flt = {"messageId": id_str}
    else:
        flt = {"conversationId": id_str}

    try:
        result = collection.update_one(flt, {"$set": update_fields})
        if result.modified_count > 0:
            logger.debug(f"mark_conversation_processed: marked {id_str!r}")
            return True
        logger.warning(f"mark_conversation_processed: no document matched for {id_str!r}")
        return False
    except Exception as exc:
        logger.error(f"mark_conversation_processed error: {exc}")
        return False


def get_processing_stats() -> Dict[str, Any]:
    """Return counts of total / processed / pending conversations."""
    db = get_mongodb()
    if db is None:
        return {"error": "MongoDB not connected"}

    collection = db[MONGODB_CONVERSATIONS_COLLECTION]
    try:
        total     = collection.count_documents({})
        processed = collection.count_documents({"processed": True})
        pending   = total - processed
        return {
            "total_conversations":     total,
            "processed_conversations": processed,
            "pending_conversations":   pending,
            "processing_percentage":   round(processed / total * 100, 2) if total else 0,
        }
    except Exception as exc:
        logger.error(f"get_processing_stats error: {exc}")
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Legacy shims — kept so nothing else in the codebase breaks while migrating
# ---------------------------------------------------------------------------

def build_conversation(
    bot_id: str,
    prompt: str,
    model: str,
    is_safe: bool,
    blocked: bool,
    risk_level: str,
    detections: dict,
    metrics: dict,
    llm_response: Optional[str] = None,
    block_reason: Optional[str] = None,
    scan_results: Optional[Any] = None,
    request_timestamp: Optional[str] = None,
) -> dict:
    """
    Build a standardised conversation dict ready for save_conversation().

    Kept for backward compatibility — new code should build the dict inline.
    """
    timestamp  = request_timestamp or now()
    bot_parts  = bot_id.split("_")
    user_id    = f"user_{bot_parts[1]}"   if len(bot_parts) > 1 else f"user_{bot_id}"
    thread_id  = f"thread_{bot_parts[1]}" if len(bot_parts) > 1 else f"thread_{bot_id}"

    conversation = {
        "conversationId": f"conv_{bot_id}_{int(time.time() * 1000)}",
        "botId":    bot_id,
        "userId":   user_id,
        "threadId": thread_id,
        "model":    model,
        "activity": {
            "role":      "user",
            "text":      prompt,
            "timestamp": timestamp,
        },
        "validation": {
            "prompt":        prompt,
            "prompt_length": len(prompt),
            "is_safe":       is_safe,
            "blocked":       blocked,
            "risk_level":    risk_level,
            "detections":    detections,
            "metrics":       metrics,
            "timestamp":     timestamp,
        },
        "processed": False,
    }

    if blocked and not is_safe:
        conversation["validation"]["block_reason"] = block_reason or (
            scan_results.message if scan_results else "Security threat detected"
        )
    if not blocked and is_safe and llm_response:
        conversation["validation"]["llm_response"] = llm_response

    return conversation