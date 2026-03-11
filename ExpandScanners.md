"""
EXAMPLE: Adding a "Secrets Scanner" to the System
==================================================

This file shows EXACTLY what changes you need to make in each file
to add a new scanner (using Secrets detection as an example).

Follow these steps in order:
"""

# ============================================================================
# STEP 1: config.py - Add scanner configuration
# ============================================================================

# BEFORE:
SCANNER_CONFIG = {
    "prompt_injection_threshold": 0.8,
    "toxicity_threshold": 0.5,
    "pii_threshold": 0.5,
    "thread_pool_workers": 20
}

# AFTER:
SCANNER_CONFIG = {
    "prompt_injection_threshold": 0.8,
    "toxicity_threshold": 0.5,
    "pii_threshold": 0.5,
    "secrets_threshold": 0.0,  # ← NEW: Usually 0.0 for binary detection
    "thread_pool_workers": 20
}


# ============================================================================
# STEP 2: security_scanner.py - Import the scanner
# ============================================================================

# BEFORE:
from llm_guard.input_scanners import PromptInjection, Toxicity

# AFTER:
from llm_guard.input_scanners import PromptInjection, Toxicity, Secrets  # ← NEW


# ============================================================================
# STEP 3: security_scanner.py - Initialize the scanner
# ============================================================================

# BEFORE:
prompt_injection_scanner = PromptInjection(threshold=SCANNER_CONFIG["prompt_injection_threshold"])
toxicity_scanner = Toxicity(threshold=SCANNER_CONFIG["toxicity_threshold"])

# AFTER:
prompt_injection_scanner = PromptInjection(threshold=SCANNER_CONFIG["prompt_injection_threshold"])
toxicity_scanner = Toxicity(threshold=SCANNER_CONFIG["toxicity_threshold"])
secrets_scanner = Secrets(redact_mode="all")  # ← NEW


# ============================================================================
# STEP 4: security_scanner.py - Register in ConcurrentSecurityScanner.__init__
# ============================================================================

# BEFORE:
def __init__(self):
    self.scanners = {
        "prompt_injection": prompt_injection_scanner,
        "toxicity": toxicity_scanner
    }

# AFTER:
def __init__(self):
    self.scanners = {
        "prompt_injection": prompt_injection_scanner,
        "toxicity": toxicity_scanner,
        "secrets": secrets_scanner  # ← NEW
    }


# ============================================================================
# STEP 5: security_scanner.py - Add friendly message
# ============================================================================

# BEFORE:
friendly_messages = {
    "Prompt Injection": "I'm sorry, but I cannot process this request. Please rephrase your question in a different way.",
    "Toxicity": "Please ask your question respectfully. I'm here to help when you communicate in a kind manner."
}

# AFTER:
friendly_messages = {
    "Prompt Injection": "I'm sorry, but I cannot process this request. Please rephrase your question in a different way.",
    "Toxicity": "Please ask your question respectfully. I'm here to help when you communicate in a kind manner.",
    "Secrets": "Your message contains sensitive information like API keys or passwords. Please remove them and try again."  # ← NEW
}


# ============================================================================
# STEP 6: storage.py - Initialize counter in load_bot_security_log
# ============================================================================

# BEFORE:
return {
    "bot_id": bot_id, 
    "created_at": datetime.utcnow().isoformat(),
    "security_events": [],
    "total_prompts": 0,
    "blocked_prompts": 0,
    "pii_detections": 0,
    "jailbreak_attempts": 0,
    "toxicity_detections": 0
}

# AFTER:
return {
    "bot_id": bot_id, 
    "created_at": datetime.utcnow().isoformat(),
    "security_events": [],
    "total_prompts": 0,
    "blocked_prompts": 0,
    "pii_detections": 0,
    "jailbreak_attempts": 0,
    "toxicity_detections": 0,
    "secrets_detections": 0  # ← NEW
}


# ============================================================================
# STEP 7: main.py - Track detections in chat endpoint
# ============================================================================

# BEFORE:
if scan_results.detections.get("prompt_injection", {}).get("detected"):
    bot_security_log["jailbreak_attempts"] += 1
if scan_results.detections.get("toxicity", {}).get("detected"):
    bot_security_log["toxicity_detections"] += 1

# AFTER:
if scan_results.detections.get("prompt_injection", {}).get("detected"):
    bot_security_log["jailbreak_attempts"] += 1
if scan_results.detections.get("toxicity", {}).get("detected"):
    bot_security_log["toxicity_detections"] += 1
if scan_results.detections.get("secrets", {}).get("detected"):  # ← NEW
    bot_security_log["secrets_detections"] += 1  # ← NEW


# ============================================================================
# STEP 8: main.py - Add to stats endpoint
# ============================================================================

# BEFORE:
scanners={
    "prompt_injection": {...},
    "toxicity": {...},
    "pii": {...}
}

# AFTER:
scanners={
    "prompt_injection": {...},
    "toxicity": {...},
    "pii": {...},
    "secrets": {  # ← NEW
        "name": "Secrets Scanner",
        "threshold": 0.0,
        "description": "Detects API keys, passwords, and tokens",
        "concurrent_safe": True
    }
}


# ============================================================================
# STEP 9: storage.py - Add to list_all_bot_sessions
# ============================================================================

# BEFORE:
bot_sessions.append({
    "bot_id": data.get("bot_id"),
    "created_at": data.get("created_at"),
    "last_updated": data.get("last_updated"),
    "total_prompts": data.get("total_prompts", 0),
    "blocked_prompts": data.get("blocked_prompts", 0),
    "pii_detections": data.get("pii_detections", 0),
    "jailbreak_attempts": data.get("jailbreak_attempts", 0),
    "toxicity_detections": data.get("toxicity_detections", 0)
})

# AFTER:
bot_sessions.append({
    "bot_id": data.get("bot_id"),
    "created_at": data.get("created_at"),
    "last_updated": data.get("last_updated"),
    "total_prompts": data.get("total_prompts", 0),
    "blocked_prompts": data.get("blocked_prompts", 0),
    "pii_detections": data.get("pii_detections", 0),
    "jailbreak_attempts": data.get("jailbreak_attempts", 0),
    "toxicity_detections": data.get("toxicity_detections", 0),
    "secrets_detections": data.get("secrets_detections", 0)  # ← NEW
})


# ============================================================================
# THAT'S IT! Your new scanner is fully integrated.
# ============================================================================

"""
OTHER AVAILABLE SCANNERS FROM llm_guard.input_scanners:
========================================================

1. BanSubstrings - Block specific words/phrases
   Example: BanSubstrings(substrings=["badword1", "badword2"], case_sensitive=False)

2. BanTopics - Block specific topics
   Example: BanTopics(topics=["violence", "hate"], threshold=0.7)

3. Code - Detect code in prompts
   Example: Code(languages=["python", "javascript"], threshold=0.5)

4. Language - Detect language mismatches
   Example: Language(valid_languages=["en"], threshold=0.5)

5. PromptInjectionV2 - Alternative prompt injection detector
   Example: PromptInjectionV2(threshold=0.8)

6. Regex - Custom regex pattern matching
   Example: Regex(patterns=[r"\b\d{3}-\d{2}-\d{4}\b"], is_blocked=True)

7. Secrets - Detect API keys, passwords, tokens
   Example: Secrets(redact_mode="all")

8. Sentiment - Detect sentiment (positive/negative)
   Example: Sentiment(threshold=0.5)

9. TokenLimit - Limit token count
   Example: TokenLimit(limit=1024, encoding_name="cl100k_base")

For full documentation, visit:
https://llm-guard.com/input_scanners/
"""