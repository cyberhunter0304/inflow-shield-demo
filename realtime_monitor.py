"""
Real-Time Conversation Monitor with SSE
========================================
Watches MongoDB for newly inserted message documents and processes each one
through security validators, storing results in security_logs/{botId}.json.

HOW IT WORKS:
  - Each MongoDB document = ONE message (user or bot)
  - We only scan messages where from.role == "user"
  - We group results by botId in local JSON files
  - Each event is deduplicated by messageId (no reprocessing)
  - Results are streamed live to the frontend via SSE
  - Resume token is saved after every change so server restarts
    pick up exactly where they left off — no missed messages

HIERARCHY:
  1 bot → many threads (bot-user connection, e.g. WhatsApp number)
        → many conversations (sessions within that connection)
              → many messages (individual user inputs)

FILE OUTPUT:
  security_logs/{botId}.json        <- one file per bot, all threads/convos inside
  security_logs/.resume_token.json  <- saved after every processed change

HOW TO ADAPT FOR A NEW BOT SCHEMA:
  See _extract_message_data() and _get_text() below.
"""
import asyncio
import logging
import json
import time
from typing import AsyncGenerator, Dict, Any, Optional
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, PyMongoError
from pathlib import Path

from config import (
    MONGODB_URI,
    MONGODB_DATABASE,
    MONGODB_CONVERSATIONS_COLLECTION,
    SECURITY_STORAGE_DIR,
)
from security_scanner import ConcurrentSecurityScanner
from storage import append_security_event, is_message_processed
from datetime_utils import now

logger = logging.getLogger(__name__)

# Where we persist the Change Stream resume token between restarts
RESUME_TOKEN_FILE = SECURITY_STORAGE_DIR / ".resume_token.json"


# ============================================================================
# RESUME TOKEN
# ============================================================================

def _save_resume_token(token: Dict) -> None:
    """Persist the Change Stream resume token to disk."""
    try:
        with open(RESUME_TOKEN_FILE, "w") as f:
            json.dump(token, f)
    except Exception as e:
        logger.warning(f"Could not save resume token: {e}")


def _load_resume_token() -> Optional[Dict]:
    """Load the last saved resume token, or None if not present."""
    if not RESUME_TOKEN_FILE.exists():
        return None
    try:
        with open(RESUME_TOKEN_FILE, "r") as f:
            token = json.load(f)
        logger.info("Loaded resume token — will catch up from last position")
        return token
    except Exception as e:
        logger.warning(f"Could not load resume token (starting fresh): {e}")
        return None


# ============================================================================
# MESSAGE EXTRACTION
# ============================================================================

def _extract_message_data(doc: Dict) -> Optional[Dict[str, Any]]:
    """
    Extract the fields we care about from one MongoDB message document.

    Returns a dict with:
        bot_id, thread_id, conversation_id, message_id, role, text, timestamp

    Returns None if the document is missing critical identifiers.

    threadId is OPTIONAL — if missing we fall back to conversationId.
    Only botId + conversationId are truly required.
    """
    bot_id          = doc.get("botId")          or doc.get("bot_id")
    conversation_id = doc.get("conversationId") or doc.get("conversation_id")
    message_id      = doc.get("messageId")      or doc.get("message_id")

    # threadId is optional — fall back to conversationId if not present
    thread_id = (
        doc.get("threadId")
        or doc.get("thread_id")
        or conversation_id   # ← fallback for external bots that don't send threadId
    )

    if not bot_id or not conversation_id:
        present_keys = list(doc.keys())
        logger.warning(
            f"Skipping doc — missing required fields. "
            f"botId={bot_id!r}, conversationId={conversation_id!r}. "
            f"Keys in doc: {present_keys}"
        )
        return None

    from_field = doc.get("from", {})
    role       = from_field.get("role", "").lower()
    text       = _get_text(doc)
    timestamp  = _get_timestamp(doc)

    return {
        "bot_id":          bot_id,
        "thread_id":       thread_id,
        "conversation_id": conversation_id,
        "message_id":      message_id,
        "role":            role,
        "text":            text,
        "timestamp":       timestamp,
    }


def _get_text(doc: Dict) -> str:
    """
    Extract the user-visible text from a message document.

    Priority order:
      1. activity.text                           — standard Bot Framework
      2. activity.channelData.whatsapp.body.text — WhatsApp via channelData
      3. activity.channelData.entry[*]...        — raw WhatsApp webhook payload

    ADD NEW BOT FALLBACKS BELOW THE EXISTING ONES.
    """
    activity = doc.get("activity", {})

    # 1. Standard Bot Framework
    text = activity.get("text") or ""
    if text and text.strip():
        return text.strip()

    # 2. WhatsApp via channelData.whatsapp
    try:
        wa_text = (
            activity.get("channelData", {})
            .get("whatsapp", {})
            .get("body", {})
            .get("text", "")
        )
        if wa_text and wa_text.strip():
            return wa_text.strip()
    except Exception:
        pass

    # 3. Raw WhatsApp webhook payload
    try:
        for entry in activity.get("channelData", {}).get("entry", []):
            for change in entry.get("changes", []):
                for msg in change.get("value", {}).get("messages", []):
                    wa_body = msg.get("text", {}).get("body", "")
                    if wa_body and wa_body.strip():
                        return wa_body.strip()
                    interactive = msg.get("interactive", {})
                    btn_title = (
                        interactive.get("button_reply", {}).get("title")
                        or interactive.get("list_reply", {}).get("title")
                    )
                    if btn_title:
                        return btn_title.strip()
    except Exception:
        pass

    # ADD YOUR BOT FALLBACK HERE:
    # custom_text = doc.get("message", {}).get("content", "")
    # if custom_text:
    #     return custom_text.strip()

    return ""


def _get_timestamp(doc: Dict) -> str:
    """Extract ISO timestamp from document."""
    created_at = doc.get("createdAt")
    if isinstance(created_at, dict):
        return created_at.get("$date", now())
    if isinstance(created_at, str):
        return created_at
    ts = doc.get("activity", {}).get("timestamp")
    if isinstance(ts, dict):
        return ts.get("$date", now())
    if isinstance(ts, str):
        return ts
    return now()


# ============================================================================
# LLM CALLER (sync wrapper — runs in its own thread with a fresh event loop)
# ============================================================================

def _call_llm_sync(
    prompt: str,
    model: str = None,
    has_pii: bool = False,
    message_id: str = "",
) -> Optional[str]:
    """
    Call the LLM synchronously from a non-async context (the monitor's
    process_message method). Runs in a dedicated thread with its own
    event loop to avoid conflicting with the FastAPI event loop.
    """
    import asyncio as _asyncio
    import concurrent.futures
    from llm_client import call_llm

    def run_in_thread():
        loop = _asyncio.new_event_loop()
        _asyncio.set_event_loop(loop)
        try:
            raw = loop.run_until_complete(
                call_llm(prompt, model=model, has_pii=has_pii)
            )
            return raw.get("choices", [{}])[0].get("message", {}).get("content", "")
        finally:
            loop.close()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(run_in_thread)
            response = future.result(timeout=60)
        logger.info(f"[monitor] LLM responded for msg={message_id}")
        return response
    except Exception as e:
        logger.error(f"[monitor] LLM call failed for msg={message_id}: {e}")
        return None


# ============================================================================
# MONITOR
# ============================================================================

class ConversationMonitor:
    """
    Real-time MongoDB -> security scan -> local JSON pipeline.

    Auto-started by FastAPI on server boot via run_forever().
    Resumes from last saved Change Stream position after restarts.
    Broadcasts events to all connected SSE dashboard tabs.
    """

    def __init__(self):
        self.client: Optional[MongoClient] = None
        self.db = None
        self.scanner    = ConcurrentSecurityScanner()
        self.running    = False
        self.processed_count = 0
        self.skipped_count   = 0
        self.error_count     = 0

        # One asyncio.Queue per connected frontend tab
        self._sse_queues: list = []

        SECURITY_STORAGE_DIR.mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # MongoDB connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        try:
            self.client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
            self.client.admin.command("ping")
            self.db = self.client[MONGODB_DATABASE]
            logger.info(f"Monitor connected to MongoDB: {MONGODB_DATABASE}")
            return True
        except ServerSelectionTimeoutError:
            logger.error(f"Cannot reach MongoDB at {MONGODB_URI}")
            return False
        except Exception as e:
            logger.error(f"MongoDB connection error: {e}")
            return False

    def disconnect(self):
        if self.client:
            self.client.close()
            self.client = None
            self.db = None
            logger.info("MongoDB monitor disconnected")

    # ------------------------------------------------------------------
    # SSE fan-out — broadcast to all connected frontend tabs
    # ------------------------------------------------------------------

    def _broadcast(self, event: Dict) -> None:
        """Push an event onto every active SSE subscriber queue."""
        dead = []
        for q in self._sse_queues:
            try:
                q.put_nowait(event)
            except Exception:
                dead.append(q)
        for q in dead:
            if q in self._sse_queues:
                self._sse_queues.remove(q)

    def subscribe(self) -> asyncio.Queue:
        """Register a new SSE subscriber. Returns its queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._sse_queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Remove an SSE subscriber when its connection closes."""
        if q in self._sse_queues:
            self._sse_queues.remove(q)

    # ------------------------------------------------------------------
    # Core: process a single message document
    # ------------------------------------------------------------------

    async def process_message(self, doc: Dict) -> Dict[str, Any]:
        """
        Process one MongoDB message document end-to-end.

        Steps:
          1. Extract fields
          2. Skip non-user / empty / already-processed messages
          3. Run security scan
          4. Atomically append to security_logs/{botId}.json
          5. Return result summary (broadcast as SSE event)
        """
        # 1 — Extract
        msg = _extract_message_data(doc)
        if msg is None:
            return {"success": False, "skipped": True, "reason": "missing_identifiers"}

        bot_id          = msg["bot_id"]
        thread_id       = msg["thread_id"]
        conversation_id = msg["conversation_id"]
        message_id      = msg["message_id"]
        role            = msg["role"]
        text            = msg["text"]
        timestamp       = msg["timestamp"]

        # 2a — Only user messages
        if role != "user":
            self.skipped_count += 1
            logger.info(
                f"Skipping non-user message — role={role!r}, "
                f"message_id={message_id}, bot_id={bot_id}"
            )
            return {"success": True, "skipped": True, "reason": "not_user_message",
                    "role": role, "message_id": message_id, "bot_id": bot_id}

        # 2b — Must have text
        if not text:
            self.skipped_count += 1
            logger.warning(
                f"Skipping user message with no extractable text — "
                f"message_id={message_id}, bot_id={bot_id}. "
                f"Check _get_text() for your document structure."
            )
            return {"success": True, "skipped": True, "reason": "no_text",
                    "message_id": message_id, "bot_id": bot_id}

        # 2c — Deduplication (fast file check before expensive scan)
        if message_id and is_message_processed(bot_id, message_id):
            self.skipped_count += 1
            return {"success": True, "skipped": True, "reason": "already_processed",
                    "message_id": message_id, "bot_id": bot_id}

        # 3 — Security scan
        logger.info(f"Scanning [{bot_id}] conv={conversation_id} msg={message_id}")
        scan_start = time.time()
        try:
            scan_results = await self.scanner.scan_prompt_parallel(text, bot_id)
        except Exception as e:
            logger.error(f"Scanner error for {message_id}: {e}")
            self.error_count += 1
            return {"success": False, "skipped": False, "error": str(e),
                    "message_id": message_id, "bot_id": bot_id}
        scan_duration = round(time.time() - scan_start, 4)

        pii_data      = scan_results.detections.get("pii", {})
        pii_entities  = pii_data.get("entities", [])
        has_pii       = len(pii_entities) > 0
        has_jailbreak = scan_results.detections.get("prompt_injection", {}).get("detected", False)
        has_toxicity  = scan_results.detections.get("toxicity", {}).get("detected", False)
        has_secrets   = pii_data.get("secrets_detected", False)
        is_blocked    = not scan_results.is_safe

        # 4 — Call LLM only if safe (runs in its own thread/event loop)
        llm_response = None
        if not is_blocked:
            prompt_for_llm = (
                pii_data.get("anonymized_prompt") or text if has_pii else text
            )
            llm_response = _call_llm_sync(
                prompt=prompt_for_llm,
                model=doc.get("model") or None,
                has_pii=has_pii,
                message_id=message_id,
            )

        # 5 — Build and save security event
        security_event = {
            "message_id":        message_id,
            "thread_id":         thread_id,
            "conversation_id":   conversation_id,
            "bot_id":            bot_id,
            "timestamp":         timestamp,
            "prompt":            text,
            "prompt_length":     len(text),
            "anonymized_prompt": pii_data.get("anonymized_prompt") if pii_entities else None,
            "llm_response":      llm_response,
            "detections":        scan_results.detections,
            "risk_level":        scan_results.risk_level,
            "is_safe":           scan_results.is_safe,
            "blocked":           is_blocked,
            "block_reason":      scan_results.message if is_blocked else None,
            "scan_duration":     scan_duration,
            "metrics": {
                "scan_time":       scan_duration,
                "scanner_details": scan_results.detections.get("metrics", {}).get("scanner_times", {}),
            },
        }

        appended = append_security_event(
            bot_id=bot_id, message_id=message_id,
            security_event=security_event,
            is_blocked=is_blocked, has_pii=has_pii,
            has_jailbreak=has_jailbreak, has_toxicity=has_toxicity,
            has_secrets=has_secrets,
        )

        if not appended:
            return {"success": True, "skipped": True, "reason": "already_processed_race",
                    "message_id": message_id, "bot_id": bot_id}

        self.processed_count += 1
        logger.info(f"Saved -> security_logs/{bot_id}.json  (msg={message_id})")

        return {
            "success":         True,
            "skipped":         False,
            "bot_id":          bot_id,
            "thread_id":       thread_id,
            "conversation_id": conversation_id,
            "message_id":      message_id,
            "is_blocked":      is_blocked,
            "has_pii":         has_pii,
            "has_jailbreak":   has_jailbreak,
            "has_toxicity":    has_toxicity,
            "has_secrets":     has_secrets,
            "scan_duration":   scan_duration,
            "total_processed": self.processed_count,
            "total_errors":    self.error_count,
        }

    # ------------------------------------------------------------------
    # Background loop — started once by FastAPI on boot
    # ------------------------------------------------------------------

    async def run_forever(self) -> None:
        """
        Polling loop — checks MongoDB every 10 seconds for new user messages.

        MongoDB is READ-ONLY — this loop never writes anything back to it.
        Deduplication is handled entirely by the local security_logs JSON files
        via processed_message_ids (see storage.py → is_message_processed()).

        Only processes messages created AFTER this server started, so existing
        data in the company DB is never touched.
        """
        logger.info("Monitor polling loop started (interval: 10s)")
        POLL_INTERVAL = 10

        # Only look at docs created after this server started
        startup_time = now()
        logger.info(f"[poll] Will only scan messages created after: {startup_time}")

        while True:
            # Ensure DB connection
            if self.db is None:
                if not self.connect():
                    logger.warning("MongoDB not available — retrying in 10 s...")
                    await asyncio.sleep(POLL_INTERVAL)
                    continue

            self.running = True

            try:
                collection = self.db[MONGODB_CONVERSATIONS_COLLECTION]

                # READ ONLY — no processed filter needed, dedup handled by local JSON
                # Only new messages (after server start), only user turns
                all_messages = list(collection.find({
                    "from.role": "user",
                    "createdAt": {"$gte": startup_time},
                }).limit(100))

                # Filter out already-processed messages before logging
                new_messages = []
                for doc in all_messages:
                    msg_id = doc.get("messageId")
                    bot_id = doc.get("botId")
                    if msg_id and bot_id and not is_message_processed(bot_id, msg_id):
                        new_messages.append(doc)

                if new_messages:
                    logger.info(f"[poll] Found {len(new_messages)} new message(s) — checking...")

                for doc in new_messages:
                    try:
                        # process_message() calls is_message_processed() internally
                        # — already-scanned docs are skipped via local JSON dedup,
                        # no MongoDB write needed
                        result = await self.process_message(doc)
                        msg_id = result.get("message_id") or doc.get("messageId")

                        if not result.get("skipped") and result.get("success"):
                            self._broadcast({"event": "processed", "data": {**result, "timestamp": now()}})
                            logger.info(f"[poll] ✅ Scanned and saved: {msg_id}")

                        # No MongoDB writes at all — ever

                    except Exception as exc:
                        logger.error(f"[poll] Error on {doc.get('messageId')}: {exc}")
                        self.error_count += 1

            except PyMongoError as exc:
                logger.error(f"[poll] MongoDB error: {exc} — reconnecting...")
                self.running = False
                self.disconnect()

            except Exception as exc:
                logger.error(f"[poll] Unexpected error: {exc}")

            await asyncio.sleep(POLL_INTERVAL)

    # ------------------------------------------------------------------
    # SSE stream — one per connected frontend tab
    # ------------------------------------------------------------------

    async def sse_stream(self) -> AsyncGenerator[str, None]:
        """
        Async generator consumed by the FastAPI /api/monitor/stream endpoint.
        Each connected dashboard tab gets its own subscription to the same events.
        """
        q = self.subscribe()
        try:
            # Send current status immediately so the frontend knows we're alive
            yield _sse_format("status", {
                "running":         self.running,
                "processed_count": self.processed_count,
                "skipped_count":   self.skipped_count,
                "error_count":     self.error_count,
                "timestamp":       now(),
            })

            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=25)
                    yield _sse_format(event["event"], event["data"])
                except asyncio.TimeoutError:
                    # Keep-alive ping so the browser doesn't close the connection
                    yield ": ping\n\n"
        finally:
            self.unsubscribe(q)

    def stop(self):
        self.running = False
        logger.info("Monitor stop requested")

    def diagnose_document(self, doc_id_or_doc) -> Dict[str, Any]:
        """
        Developer helper: run a document through the full extraction + skip logic
        WITHOUT actually scanning or saving it. Returns a plain dict explaining
        exactly why the document would be accepted or rejected.

        Usage (from a FastAPI route or shell):
            monitor.diagnose_document({"botId": "x", "threadId": "y", ...})
            monitor.diagnose_document("64f1a2b3c4d5e6f7a8b9c0d1")  # MongoDB _id hex string
        """
        if isinstance(doc_id_or_doc, str):
            # Fetch the real doc from MongoDB by _id
            from bson import ObjectId
            if self.db is None:
                self.connect()
            collection = self.db[MONGODB_CONVERSATIONS_COLLECTION]
            doc = collection.find_one({"_id": ObjectId(doc_id_or_doc)})
            if not doc:
                return {"error": f"No document found with _id={doc_id_or_doc}"}
        else:
            doc = doc_id_or_doc

        report = {"doc_keys": list(doc.keys()), "checks": []}

        def check(name, passed, detail=""):
            report["checks"].append({"check": name, "passed": passed, "detail": detail})
            return passed

        msg = _extract_message_data(doc)
        if not check(
            "required_fields (botId/threadId/conversationId)",
            msg is not None,
            f"botId={doc.get('botId')!r}, threadId={doc.get('threadId')!r}, "
            f"conversationId={doc.get('conversationId')!r}",
        ):
            report["verdict"] = "SKIPPED — missing required identifiers"
            return report

        role = msg["role"]
        check("role == 'user'", role == "user", f"actual role={role!r}")

        text = msg["text"]
        check("text is non-empty", bool(text), f"extracted text={text!r}")

        if msg["message_id"]:
            already = is_message_processed(msg["bot_id"], msg["message_id"])
            check("not already processed", not already,
                  f"message_id={msg['message_id']!r}")

        all_passed = all(c["passed"] for c in report["checks"])
        report["verdict"] = "WOULD BE SCANNED ✅" if all_passed else "WOULD BE SKIPPED ❌"
        report["extracted"] = msg
        return report


def _sse_format(event: str, data: Dict) -> str:
    """Format a dict as a valid SSE message string."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ============================================================================
# Singleton
# ============================================================================

_monitor: Optional[ConversationMonitor] = None


def get_monitor() -> ConversationMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ConversationMonitor()
    return _monitor


def shutdown_monitor():
    global _monitor
    if _monitor:
        _monitor.stop()
        _monitor.disconnect()
        _monitor = None