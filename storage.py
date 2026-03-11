"""
Storage Module
Thread-safe file operations for security logs

Structure per file: security_logs/{botId}.json
Each file aggregates ALL messages for that bot across all threads/conversations.
Messages are deduplicated via processed_message_ids.
"""
import json
import threading
from pathlib import Path
from typing import Dict, Any, Optional
from config import SECURITY_STORAGE_DIR
from datetime_utils import now

# Thread-safe file operations lock
file_lock = threading.Lock()


def get_bot_security_file(bot_id: str) -> Path:
    """Get the security log file path for a bot session"""
    return SECURITY_STORAGE_DIR / f"{bot_id}.json"


def _default_security_log(bot_id: str) -> dict:
    """Default empty security log structure"""
    return {
        "bot_id": bot_id,
        "created_at": now(),
        "last_updated": now(),
        "security_events": [],
        "processed_message_ids": [],   # Tracks processed messageIds for deduplication
        "total_prompts": 0,
        "blocked_prompts": 0,
        "pii_detections": 0,
        "jailbreak_attempts": 0,
        "toxicity_detections": 0,
        "secrets_detections": 0,
        # ================================================================
        # 🔧 ADD NEW SCANNER STATISTICS COUNTERS HERE:
        # "banned_topics_detections": 0,
        # "code_detections": 0,
        # "sentiment_issues": 0,
        # ================================================================
    }


def load_bot_security_log(bot_id: str) -> dict:
    """Load security log for a bot session - THREAD SAFE"""
    security_file = get_bot_security_file(bot_id)

    with file_lock:
        if security_file.exists():
            with open(security_file, 'r') as f:
                data = json.load(f)
                # Migrate older files that don't have processed_message_ids
                if "processed_message_ids" not in data:
                    data["processed_message_ids"] = []
                return data
        return _default_security_log(bot_id)


def save_bot_security_log(bot_id: str, security_data: dict):
    """Save security log for a bot session - THREAD SAFE"""
    security_file = get_bot_security_file(bot_id)

    with file_lock:
        with open(security_file, 'w') as f:
            json.dump(security_data, f, indent=2)


def append_security_event(
    bot_id: str,
    message_id: str,
    security_event: dict,
    is_blocked: bool,
    has_pii: bool,
    has_jailbreak: bool,
    has_toxicity: bool,
    has_secrets: bool,
) -> bool:
    """
    Atomically append a single processed message's security event to the bot log.
    Returns True if appended, False if already processed (duplicate).

    This is the ONLY function realtime_monitor should call to write events.
    The entire load → check → append → save is done under one lock to prevent
    race conditions when multiple messages for the same bot arrive simultaneously.
    """
    security_file = get_bot_security_file(bot_id)

    with file_lock:
        # Load existing or create new
        if security_file.exists():
            with open(security_file, 'r') as f:
                log = json.load(f)
            if "processed_message_ids" not in log:
                log["processed_message_ids"] = []
        else:
            log = _default_security_log(bot_id)

        # Deduplication check
        if message_id in log["processed_message_ids"]:
            return False

        # Append the event and mark as processed
        log["security_events"].append(security_event)
        log["processed_message_ids"].append(message_id)

        # Update aggregated counters
        log["total_prompts"] = log.get("total_prompts", 0) + 1
        if is_blocked:
            log["blocked_prompts"] = log.get("blocked_prompts", 0) + 1
        if has_pii:
            log["pii_detections"] = log.get("pii_detections", 0) + 1
        if has_jailbreak:
            log["jailbreak_attempts"] = log.get("jailbreak_attempts", 0) + 1
        if has_toxicity:
            log["toxicity_detections"] = log.get("toxicity_detections", 0) + 1
        if has_secrets:
            log["secrets_detections"] = log.get("secrets_detections", 0) + 1
        # ================================================================
        # 🔧 ADD NEW SCANNER COUNTER UPDATES HERE:
        # if has_banned_topic:
        #     log["banned_topics_detections"] = log.get("banned_topics_detections", 0) + 1
        # ================================================================

        log["last_updated"] = now()

        # Save atomically
        with open(security_file, 'w') as f:
            json.dump(log, f, indent=2)

    return True


def is_message_processed(bot_id: str, message_id: str) -> bool:
    """
    Quick check if a messageId was already processed for this bot.
    Used as an early exit before running expensive security scans.
    """
    security_file = get_bot_security_file(bot_id)

    with file_lock:
        if not security_file.exists():
            return False
        with open(security_file, 'r') as f:
            data = json.load(f)
        return message_id in data.get("processed_message_ids", [])


def delete_bot_security_log(bot_id: str) -> Dict[str, Any]:
    """Delete security log for a bot session - THREAD SAFE"""
    security_file = get_bot_security_file(bot_id)

    with file_lock:
        if security_file.exists():
            security_file.unlink()
            return {"success": True, "message": f"Security log deleted for bot_id: {bot_id}"}
        return {"success": False, "message": f"No security log found for bot_id: {bot_id}"}


def list_all_bot_sessions() -> Dict[str, Any]:
    """List all bot sessions with security logs - THREAD SAFE"""
    security_files = list(SECURITY_STORAGE_DIR.glob("*.json"))
    bot_sessions = []

    with file_lock:
        for security_file in security_files:
            with open(security_file, 'r') as f:
                data = json.load(f)
            bot_sessions.append({
                "bot_id": data.get("bot_id"),
                "created_at": data.get("created_at"),
                "last_updated": data.get("last_updated"),
                "total_prompts": data.get("total_prompts", 0),
                "blocked_prompts": data.get("blocked_prompts", 0),
                "pii_detections": data.get("pii_detections", 0),
                "jailbreak_attempts": data.get("jailbreak_attempts", 0),
                "toxicity_detections": data.get("toxicity_detections", 0),
                "secrets_detections": data.get("secrets_detections", 0),
                # ================================================================
                # 🔧 ADD NEW SCANNER STATISTICS TO LISTING:
                # "banned_topics_detections": data.get("banned_topics_detections", 0),
                # "code_detections": data.get("code_detections", 0),
                # ================================================================
            })

    return {
        "total_sessions": len(bot_sessions),
        "sessions": bot_sessions
    }