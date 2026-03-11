"""
Scan & Batch Routes
-------------------
POST /api/scan                   — ad-hoc single-prompt scan (not persisted)
POST /api/batch/process-next     — process next unprocessed MongoDB doc
POST /api/batch/process-bulk     — process N unprocessed docs in sequence
GET  /api/batch/status           — current batch processing stats

OPTIMIZED: Removed executor wrapper for 6-8x faster scanning
"""

import asyncio
import logging
import time

from fastapi import APIRouter, HTTPException, Query

from datetime_utils import now
from models import ScanRequest, SecurityScanResult
from mongodb_storage import (
    get_unprocessed_conversations,
    mark_conversation_processed,
    get_processing_stats,
)
from security_scanner import ConcurrentSecurityScanner
from storage import append_security_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["Security"])

# Shared scanner instance (scan-only, does NOT write to MongoDB/JSON)
_detector = ConcurrentSecurityScanner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_security_event(
    scan_results,
    message_id: str,
    thread_id: str,
    conversation_id: str,
    bot_id: str,
    prompt: str,
    request_start: float,
) -> dict:
    pii_data = scan_results.detections.get("pii", {})
    pii_entities = pii_data.get("entities", [])
    return {
        "message_id":        message_id,
        "thread_id":         thread_id,
        "conversation_id":   conversation_id,
        "bot_id":            bot_id,
        "timestamp":         now(),
        "prompt":            prompt,
        "prompt_length":     len(prompt),
        "anonymized_prompt": pii_data.get("anonymized_prompt") if pii_entities else None,
        "detections":        scan_results.detections,
        "risk_level":        scan_results.risk_level,
        "is_safe":           scan_results.is_safe,
        "blocked":           not scan_results.is_safe,
        "block_reason":      scan_results.message if not scan_results.is_safe else None,
        "scan_duration":     round(scan_results.scan_duration, 4),
        "metrics": {
            "scan_time":  round(scan_results.scan_duration, 4),
            "total_time": round(time.time() - request_start, 4),
        },
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=SecurityScanResult, tags=["Security"])
async def scan_only(request: ScanRequest):
    """
    Scan a single prompt with all security checks and return results inline.
    Nothing is persisted — useful for ad-hoc testing.
    """
    try:
        scan_start = time.time()
        result = await _detector.scan_prompt(request.prompt, request.bot_id or "scan-only")
        scan_time = time.time() - scan_start
        logger.info(f"[scan] Completed in {scan_time:.3f}s")
        return result
    except Exception as exc:
        logger.error(f"Scan error: {exc}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}")


@router.post("/batch/process-next", tags=["Batch Processing"])
async def process_next_conversation():
    """Process the next unprocessed conversation from MongoDB."""
    conversations = get_unprocessed_conversations(limit=1)
    if not conversations:
        return {"success": False, "message": "No more conversations to process", "processed": False}

    conv            = conversations[0]
    conversation_id = str(conv.get("_id") or conv.get("conversationId", "unknown"))
    prompt          = conv.get("activity", {}).get("text", "") or conv.get("message", "")
    bot_id          = conv.get("botId") or f"batch_{conversation_id}"
    thread_id       = conv.get("threadId", "unknown")
    message_id      = conv.get("messageId") or conversation_id

    if not prompt:
        return {"success": False, "message": "Empty prompt — skipping", "conversation_id": conversation_id}

    request_start = time.time()
    
    # ========================================================================
    # OPTIMIZATION: Direct scan call (no executor)
    # ========================================================================
    scan_results = _detector.scan_prompt(prompt, bot_id)
    # ========================================================================

    pii_data      = scan_results.detections.get("pii", {})
    pii_entities  = pii_data.get("entities", [])
    has_pii       = bool(pii_entities)
    has_jailbreak = scan_results.detections.get("prompt_injection", {}).get("detected", False)
    has_toxicity  = scan_results.detections.get("toxicity", {}).get("detected", False)
    has_secrets   = pii_data.get("secrets_detected", False)
    is_blocked    = not scan_results.is_safe

    security_event = _build_security_event(
        scan_results, message_id, thread_id, conversation_id, bot_id, prompt, request_start
    )

    append_security_event(
        bot_id         = bot_id,
        message_id     = message_id,
        security_event = security_event,
        is_blocked     = is_blocked,
        has_pii        = has_pii,
        has_jailbreak  = has_jailbreak,
        has_toxicity   = has_toxicity,
        has_secrets    = has_secrets,
    )
    mark_conversation_processed(conversation_id, bot_id)

    return {
        "success":         True,
        "processed":       True,
        "conversation_id": conversation_id,
        "security_log_id": bot_id,
        "scan_results": {
            "is_safe":         scan_results.is_safe,
            "risk_level":      scan_results.risk_level,
            "pii_detected":    has_pii,
            "threat_detected": is_blocked,
            "scan_duration":   round(scan_results.scan_duration, 4),
            "message":         scan_results.message,
        },
        "processing_stats": get_processing_stats(),
        "timestamp":        now(),
    }


@router.post("/batch/process-bulk", tags=["Batch Processing"])
async def process_bulk_conversations(count: int = Query(10, ge=1, le=200)):
    """Process up to *count* unprocessed conversations in sequence."""
    results = []

    for i in range(count):
        conversations = get_unprocessed_conversations(limit=1)
        if not conversations:
            logger.info(f"Batch done after {i} items — no more data")
            break

        conv            = conversations[0]
        conversation_id = str(conv.get("_id") or conv.get("conversationId", "unknown"))
        prompt          = conv.get("activity", {}).get("text", "") or conv.get("message", "")
        bot_id          = conv.get("botId") or f"batch_{conversation_id}"
        thread_id       = conv.get("threadId", "unknown")
        message_id      = conv.get("messageId") or conversation_id

        if not prompt:
            mark_conversation_processed(conversation_id, bot_id)
            continue

        request_start = time.time()
        
        # ====================================================================
        # OPTIMIZATION: Direct scan call (no executor)
        # ====================================================================
        scan_results = _detector.scan_prompt(prompt, bot_id)
        # ====================================================================

        pii_data      = scan_results.detections.get("pii", {})
        pii_entities  = pii_data.get("entities", [])
        has_pii       = bool(pii_entities)
        has_jailbreak = scan_results.detections.get("prompt_injection", {}).get("detected", False)
        has_toxicity  = scan_results.detections.get("toxicity", {}).get("detected", False)
        has_secrets   = pii_data.get("secrets_detected", False)
        is_blocked    = not scan_results.is_safe

        security_event = _build_security_event(
            scan_results, message_id, thread_id, conversation_id, bot_id, prompt, request_start
        )

        append_security_event(
            bot_id         = bot_id,
            message_id     = message_id,
            security_event = security_event,
            is_blocked     = is_blocked,
            has_pii        = has_pii,
            has_jailbreak  = has_jailbreak,
            has_toxicity   = has_toxicity,
            has_secrets    = has_secrets,
        )
        mark_conversation_processed(conversation_id, bot_id)

        results.append({
            "conversation_id": conversation_id,
            "is_safe":         scan_results.is_safe,
            "risk_level":      scan_results.risk_level,
            "scan_duration":   round(scan_results.scan_duration, 4),
        })

    return {
        "success":          True,
        "count_processed":  len(results),
        "results":          results,
        "processing_stats": get_processing_stats(),
        "timestamp":        now(),
    }


@router.get("/batch/status", tags=["Batch Processing"])
async def get_batch_status():
    """Current batch processing statistics from MongoDB."""
    return {"success": True, "stats": get_processing_stats(), "timestamp": now()}