"""
Admin Routes
------------
GET  /api/admin/diagnose   — show why unprocessed docs are being skipped
POST /api/admin/fix-indexes — drop and recreate MongoDB indexes
"""

import logging

from fastapi import APIRouter, HTTPException
from pymongo import ASCENDING, DESCENDING

from config import MONGODB_CONVERSATIONS_COLLECTION
from datetime_utils import now
from mongodb_storage import get_mongodb
from realtime_monitor import get_monitor

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin", tags=["Admin"])


@router.get("/diagnose")
async def diagnose_unprocessed():
    """
    🔍 Show exactly why unprocessed docs are being skipped.
    Run this when backfill shows 0/N scanned.
    """
    db = get_mongodb()
    if db is None:
        raise HTTPException(status_code=503, detail="MongoDB not connected")

    col  = db[MONGODB_CONVERSATIONS_COLLECTION]
    docs = list(col.find({"processed": {"$ne": True}}).limit(20))

    results = []
    monitor = get_monitor()
    for doc in docs:
        report = monitor.diagnose_document(doc)
        results.append({
            "messageId":      doc.get("messageId"),
            "botId":          doc.get("botId"),
            "threadId":       doc.get("threadId"),
            "conversationId": doc.get("conversationId"),
            "from_role":      doc.get("from", {}).get("role"),
            "processed":      doc.get("processed"),
            "text_preview":   (doc.get("activity", {}).get("text") or "")[:60],
            "verdict":        report.get("verdict"),
            "checks":         report.get("checks"),
        })

    return {
        "total_unprocessed": len(docs),
        "results":           results,
        "timestamp":         now(),
    }


@router.post("/fix-indexes")
async def fix_indexes():
    """
    🔧 Drop and recreate all MongoDB indexes cleanly.
    Run once if you see IndexKeySpecsConflict errors on startup.
    """
    db = get_mongodb()
    if db is None:
        raise HTTPException(status_code=503, detail="MongoDB not connected")

    col     = db[MONGODB_CONVERSATIONS_COLLECTION]
    dropped = []
    errors  = []

    # Drop every index except the immutable _id index
    try:
        existing = [idx["name"] for idx in col.list_indexes() if idx["name"] != "_id_"]
        for name in existing:
            try:
                col.drop_index(name)
                dropped.append(name)
                logger.info(f"[fix-indexes] Dropped: {name}")
            except Exception as e:
                errors.append({"index": name, "error": str(e)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not list indexes: {e}")

    # Recreate the correct set
    created = []
    specs = [
        ("conversationId", {}),
        ("messageId",      {"unique": True, "sparse": True}),
        ("botId",          {}),
        ("threadId",       {}),
        ([("createdAt", DESCENDING)], {}),
        ("processed",      {}),
    ]
    for keys, kwargs in specs:
        try:
            col.create_index(keys, **kwargs)
            created.append(str(keys))
        except Exception as e:
            errors.append({"index": str(keys), "error": str(e)})

    return {
        "success":   len(errors) == 0,
        "dropped":   dropped,
        "created":   created,
        "errors":    errors,
        "message":   (
            "Indexes fixed. Restart the server to apply backfill."
            if not errors else "Some errors occurred — see 'errors' field."
        ),
        "timestamp": now(),
    }
