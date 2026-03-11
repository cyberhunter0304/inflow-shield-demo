"""
Security Log Routes
-------------------
All security / validation data is read from LOCAL JSON files only
(security_logs/{bot_id}.json).  Never mix with MongoDB conversation data.

GET    /api/security-logs                        — all logs (paginated)
GET    /api/security-logs/stats/summary          — aggregate stats
GET    /api/security-logs/search/prompts         — full-text search
GET    /api/security-logs/threats/top            — bots with most threats
GET    /api/security-logs/{bot_id}               — single bot log
GET    /api/security-logs/{bot_id}/summary       — stats for one bot
GET    /api/security-logs/{bot_id}/pii           — PII events for one bot
DELETE /api/security-logs/{bot_id}               — delete a bot log
"""

import json
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status

from config import SECURITY_STORAGE_DIR
from datetime_utils import now

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/security-logs", tags=["Security Logs"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iter_log_files(bot_id: Optional[str] = None):
    """Yield parsed log dicts, skipping hidden files and optionally filtering by bot_id."""
    SECURITY_STORAGE_DIR.mkdir(exist_ok=True)
    for log_file in sorted(SECURITY_STORAGE_DIR.glob("*.json")):
        if log_file.name.startswith("."):
            continue
        try:
            with open(log_file) as f:
                data = json.load(f)
            if bot_id and data.get("bot_id") != bot_id:
                continue
            yield data
        except Exception as exc:
            logger.warning(f"Could not read {log_file}: {exc}")


def _get_log_or_404(bot_id: str) -> dict:
    log_path = SECURITY_STORAGE_DIR / f"{bot_id}.json"
    if not log_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No security log found for bot_id: {bot_id}",
        )
    with open(log_path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Endpoints — ordered from most-specific to least-specific to avoid
# FastAPI routing ambiguity (static segments before {bot_id} catch-all).
# ---------------------------------------------------------------------------

@router.get("/stats/summary")
async def get_security_stats_summary(bot_id: Optional[str] = Query(None)):
    """Aggregate statistics across all local security-log files."""
    totals = {
        "total_bots":      0,
        "total_prompts":   0,
        "total_blocked":   0,
        "total_pii":       0,
        "total_secrets":   0,
        "total_jailbreaks": 0,
        "total_toxicity":  0,
    }
    for data in _iter_log_files(bot_id):
        totals["total_bots"]       += 1
        totals["total_prompts"]    += data.get("total_prompts",       0)
        totals["total_blocked"]    += data.get("blocked_prompts",     0)
        totals["total_pii"]        += data.get("pii_detections",      0)
        totals["total_secrets"]    += data.get("secrets_detections",  0)
        totals["total_jailbreaks"] += data.get("jailbreak_attempts",  0)
        totals["total_toxicity"]   += data.get("toxicity_detections", 0)

    return {**totals, "timestamp": now()}


@router.get("/search/prompts")
async def search_prompts(
    query:  str            = Query(..., min_length=3),
    bot_id: Optional[str] = Query(None),
    limit:  int            = Query(100, ge=1, le=500),
):
    """Full-text search over security-log event prompts."""
    results = []
    q = query.lower()

    for data in _iter_log_files(bot_id):
        if len(results) >= limit:
            break
        for ev in data.get("security_events", []):
            if q in ev.get("prompt", "").lower() or q in (ev.get("anonymized_prompt") or "").lower():
                results.append(ev)
                if len(results) >= limit:
                    break

    return {
        "results":       results[:limit],
        "total_matches": len(results),
        "query":         query,
        "timestamp":     now(),
    }


@router.get("/threats/top")
async def get_top_threatening_bots(
    limit:  int            = Query(10, ge=1, le=100),
    bot_id: Optional[str] = Query(None),
):
    """Return bots with the most threat events."""
    threats = []
    for data in _iter_log_files(bot_id):
        pii   = data.get("pii_detections",      0)
        jb    = data.get("jailbreak_attempts",  0)
        tox   = data.get("toxicity_detections", 0)
        sec   = data.get("secrets_detections",  0)
        total = pii + jb + tox + sec
        if total > 0:
            threats.append({
                "bot_id":              data.get("bot_id"),
                "pii_detections":      pii,
                "jailbreak_attempts":  jb,
                "toxicity_detections": tox,
                "secrets_detections":  sec,
                "total_threats":       total,
            })

    threats.sort(key=lambda x: x["total_threats"], reverse=True)
    return {"results": threats[:limit], "timestamp": now()}


@router.get("")
async def get_all_security_logs(
    bot_id: Optional[str] = Query(None),
    skip:   int           = Query(0, ge=0),
    limit:  int           = Query(100, ge=1, le=1000),
):
    """Read all security logs from the local security_logs/ folder."""
    logs = list(_iter_log_files(bot_id))
    total         = len(logs)
    paginated     = logs[skip: skip + limit]
    total_prompts = sum(lg.get("total_prompts",       0) for lg in logs)
    total_blocked = sum(lg.get("blocked_prompts",     0) for lg in logs)
    total_pii     = sum(lg.get("pii_detections",      0) for lg in logs)
    total_jb      = sum(lg.get("jailbreak_attempts",  0) for lg in logs)
    total_tox     = sum(lg.get("toxicity_detections", 0) for lg in logs)
    total_sec     = sum(lg.get("secrets_detections",  0) for lg in logs)

    return {
        "success":  True,
        "sessions": paginated,
        "total":    total,
        "skip":     skip,
        "limit":    limit,
        "stats": {
            "totalConversations": total,
            "totalPrompts":       total_prompts,
            "totalBlocked":       total_blocked,
            "totalPII":           total_pii,
            "totalJailbreaks":    total_jb,
            "totalToxicity":      total_tox,
            "totalSecrets":       total_sec,
        },
        "timestamp": now(),
    }


@router.get("/{bot_id}/summary")
async def get_bot_security_summary(bot_id: str):
    """Statistics summary for one bot."""
    data = _get_log_or_404(bot_id)
    return {
        "bot_id":       data.get("bot_id"),
        "created_at":   data.get("created_at"),
        "last_updated": data.get("last_updated"),
        "statistics": {
            "total_prompts":       data.get("total_prompts",       0),
            "blocked_prompts":     data.get("blocked_prompts",     0),
            "pii_detections":      data.get("pii_detections",      0),
            "jailbreak_attempts":  data.get("jailbreak_attempts",  0),
            "toxicity_detections": data.get("toxicity_detections", 0),
            "secrets_detections":  data.get("secrets_detections",  0),
            "total_events":        len(data.get("security_events", [])),
        },
    }


@router.get("/{bot_id}/pii")
async def get_bot_pii_events(bot_id: str):
    """Return only PII-flagged events for a bot."""
    data = _get_log_or_404(bot_id)
    pii_events = [
        ev for ev in data.get("security_events", [])
        if ev.get("detections", {}).get("pii", {}).get("detected", False)
    ]
    return {
        "bot_id":              bot_id,
        "pii_detection_count": len(pii_events),
        "pii_events":          pii_events,
    }


@router.get("/{bot_id}")
async def get_bot_security_log(bot_id: str):
    """Read the full security log for a specific bot."""
    data = _get_log_or_404(bot_id)
    return {"success": True, "log": data, "timestamp": now()}


@router.delete("/{bot_id}")
async def delete_bot_security_log(bot_id: str):
    """Delete the local security log for a bot."""
    log_path = SECURITY_STORAGE_DIR / f"{bot_id}.json"
    if not log_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No security log found for bot_id: {bot_id}",
        )
    log_path.unlink()
    return {"success": True, "message": f"Deleted security log for {bot_id}", "timestamp": now()}
