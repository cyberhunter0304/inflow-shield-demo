"""
Async Background Task Handler
Truly async file I/O to avoid blocking the response
"""
import asyncio
import json
import logging
from pathlib import Path
from config import SECURITY_STORAGE_DIR
from datetime_utils import now

logger = logging.getLogger(__name__)


async def store_security_event_async(
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
    Truly ASYNC background task for storing security events
    This will NOT block the response
    """
    try:
        # Run file I/O in thread pool (non-blocking)
        loop = asyncio.get_event_loop()
        
        # Define sync work
        def _write_to_file():
            security_file = SECURITY_STORAGE_DIR / f"{bot_id}.json"
            
            # Load existing or create new
            if security_file.exists():
                with open(security_file, 'r') as f:
                    log = json.load(f)
                if "processed_message_ids" not in log:
                    log["processed_message_ids"] = []
            else:
                log = {
                    "bot_id": bot_id,
                    "created_at": now(),
                    "last_updated": now(),
                    "security_events": [],
                    "processed_message_ids": [],
                    "total_prompts": 0,
                    "blocked_prompts": 0,
                    "pii_detections": 0,
                    "jailbreak_attempts": 0,
                    "toxicity_detections": 0,
                    "secrets_detections": 0,
                }
            
            # Check if already processed
            if message_id in log["processed_message_ids"]:
                logger.debug(f"[async-bg] Skipping duplicate: {message_id}")
                return False
            
            # Append event
            log["security_events"].append(security_event)
            log["processed_message_ids"].append(message_id)
            
            # Update counters
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
            
            log["last_updated"] = now()
            
            # Write to file
            with open(security_file, 'w') as f:
                json.dump(log, f, indent=2)
            
            return True
        
        # Execute in thread pool (non-blocking!)
        appended = await loop.run_in_executor(None, _write_to_file)
        
        if appended:
            logger.info(f"[async-bg] ✅ Stored security event: {message_id}")
        else:
            logger.debug(f"[async-bg] Skipped duplicate: {message_id}")
        
        return appended
        
    except Exception as e:
        logger.error(f"[async-bg] Error storing event: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False