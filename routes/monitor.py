"""
Monitor Routes
--------------
GET  /api/monitor/stream  — SSE stream of real-time scan events
GET  /api/monitor/status  — current monitor statistics
POST /api/monitor/stop    — stop the monitor (admin)
"""

import logging

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from datetime_utils import now
from realtime_monitor import get_monitor

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/monitor", tags=["Real-Time Monitor"])


@router.get("/stream")
async def stream_monitor():
    """
    📡 SSE endpoint — subscribe to receive real-time scan events.

    Frontend usage::

        const es = new EventSource('/api/monitor/stream');
        es.addEventListener('processed', (e) => {
            const data = JSON.parse(e.data);
            // data.message_id, data.is_blocked, data.has_pii, …
        });
        es.addEventListener('stats', (e) => { … });
        es.addEventListener('error', (e) => { … });
    """
    monitor = get_monitor()
    return StreamingResponse(
        monitor.sse_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "Connection":        "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/status")
async def get_monitor_status():
    """Current monitor statistics."""
    monitor = get_monitor()
    return {
        "running":         monitor.running,
        "processed_count": monitor.processed_count,
        "skipped_count":   monitor.skipped_count,
        "error_count":     monitor.error_count,
        "subscribers":     len(monitor._sse_queues),
        "timestamp":       now(),
    }


@router.post("/stop")
async def stop_monitor():
    """Stop the real-time monitor (admin use)."""
    monitor = get_monitor()
    monitor.stop()
    return {
        "success":         True,
        "message":         "Monitor stopped",
        "processed_count": monitor.processed_count,
        "error_count":     monitor.error_count,
        "timestamp":       now(),
    }
