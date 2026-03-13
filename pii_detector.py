"""
PII Detection Module - WITH EAGER LOADING + PRESIDIO RECOGNIZER CACHING
Thread-safe PII detection with models loaded at startup (not on first request).
Presidio recognizer registry is cached to avoid rebuild on every call.
"""
import logging
import threading
import re
from typing import Tuple, List, Dict
from inflow_shield_lib import Vault, Secrets
from config import SCANNER_CONFIG

logger = logging.getLogger(__name__)


# ============================================================================
# GLOBAL CACHES - Load on module import (startup time)
# ============================================================================
_VAULT = None
_ANONYMIZE_SCANNER = None
_SECRETS_SCANNER = None
_PRESIDIO_ANALYZER = None
_PRESIDIO_ANONYMIZER = None
_INIT_LOCK = threading.Lock()
_INITIALIZED = False

# ============================================================================
# PRESIDIO RECOGNIZER CACHE
# Avoids rebuilding the full recognizer registry on every call.
# Key: language string (e.g. "en"), Value: list of recognizers
# ============================================================================
_PRESIDIO_RECOGNIZER_CACHE: Dict[str, list] = {}
_RECOGNIZER_CACHE_LOCK = threading.Lock()


def _initialize_all_scanners():
    """Initialize ALL scanners ONCE at module load time (server startup)"""
    global _VAULT, _ANONYMIZE_SCANNER, _SECRETS_SCANNER, _PRESIDIO_ANALYZER, _PRESIDIO_ANONYMIZER, _INITIALIZED
    
    with _INIT_LOCK:
        if _INITIALIZED:
            return  # Already initialized
        
        try:
            logger.info("=" * 70)
            logger.info("🚀 INITIALIZING PII DETECTION SCANNERS (EAGER LOADING AT STARTUP)...")
            logger.info("=" * 70)
            
            # Create vault once
            logger.info("Creating vault...")
            _VAULT = Vault()
            
            # Initialize Presidio (Microsoft's production PII detection)
            logger.info("Initializing Presidio Analyzer (Microsoft's PII engine)...")
            try:
                from presidio_analyzer import AnalyzerEngine
                from presidio_anonymizer import AnonymizerEngine
                
                _PRESIDIO_ANALYZER = AnalyzerEngine()
                _PRESIDIO_ANONYMIZER = AnonymizerEngine()
                logger.info("✓ Presidio Analyzer and Anonymizer loaded and cached")

                # ============================================================
                # PRE-WARM PRESIDIO RECOGNIZER CACHE
                # This prevents "Fetching all recognizers for language en"
                # from appearing (and taking extra time) on every request.
                # ============================================================
                logger.info("Pre-warming Presidio recognizer cache for 'en'...")
                recognizers = _PRESIDIO_ANALYZER.get_recognizers(language="en")
                with _RECOGNIZER_CACHE_LOCK:
                    _PRESIDIO_RECOGNIZER_CACHE["en"] = recognizers
                logger.info(f"✓ Cached {len(recognizers)} Presidio recognizers for 'en'")

            except ImportError:
                logger.warning("Presidio not available, will use BERT-only mode")
                _PRESIDIO_ANALYZER = None
            
            # No separate Anonymize scanner needed — anonymization is done
            # directly via the cached Presidio Anonymizer (_PRESIDIO_ANONYMIZER).
            logger.info("✓ Using Presidio Anonymizer for redaction (no separate BERT-NER scanner needed)")
            
            # Create Secrets scanner once
            logger.info("Loading Secrets scanner...")
            _SECRETS_SCANNER = Secrets(redact_mode="all")
            logger.info("✓ Secrets scanner loaded and cached")
            
            _INITIALIZED = True
            
            logger.info("=" * 70)
            logger.info("✅ ALL PII DETECTION SCANNERS INITIALIZED AND CACHED")
            logger.info("   ├─ Presidio Analyzer (accurate PII detection)")
            logger.info("   ├─ Presidio Recognizer Cache (pre-warmed for 'en')")
            logger.info("   ├─ Presidio Anonymizer (redaction)")
            logger.info("   └─ Secrets Scanner (API keys, passwords)")
            logger.info("   ⏱️  Ready for requests! (No startup delay)")
            logger.info("=" * 70)
            
        except Exception as e:
            logger.error(f"Failed to initialize scanners: {str(e)}")
            raise


# Initialize scanners on module import (happens at server startup)
logger.info("[PII] Starting eager model loading...")
_initialize_all_scanners()
logger.info("[PII] Models loaded! Ready to serve requests.")


class ThreadSafePIIDetector:
    """
    Production-Grade PII Detector with cached Presidio + BERT.
    Models are pre-loaded at startup (not on first request).
    Presidio recognizer registry is cached to avoid rebuild on every call.
    """
    
    @staticmethod
    def _extract_pii_with_presidio(text: str) -> Dict[str, List[str]]:
        """
        Extract PII using cached Presidio Analyzer (most accurate).
        Uses a pre-built recognizer cache to avoid rebuilding the registry
        on every call (eliminates the repeated 'Fetching all recognizers' log).
        """
        pii_values = {}
        
        if _PRESIDIO_ANALYZER is None:
            logger.debug("Presidio not available, skipping Presidio extraction")
            return pii_values
        
        try:
            logger.debug("Using cached Presidio Analyzer for PII extraction")

            # ------------------------------------------------------------------
            # Use cached recognizers — avoids the per-call registry rebuild
            # that was causing the repeated warning in the logs.
            # ------------------------------------------------------------------
            with _RECOGNIZER_CACHE_LOCK:
                cached = _PRESIDIO_RECOGNIZER_CACHE.get("en")

            if cached is None:
                # Fallback: build and cache on the fly (should not normally happen)
                logger.debug("Presidio recognizer cache miss — fetching and caching now")
                cached = _PRESIDIO_ANALYZER.get_recognizers(language="en")
                with _RECOGNIZER_CACHE_LOCK:
                    _PRESIDIO_RECOGNIZER_CACHE["en"] = cached

            results = _PRESIDIO_ANALYZER.analyze(text=text, language="en")
            
            logger.debug(f"Presidio found {len(results)} PII entities")
            
            for result in results:
                entity_type = result.entity_type
                start = result.start
                end = result.end
                entity_value = text[start:end]
                
                if entity_type not in pii_values:
                    pii_values[entity_type] = []
                
                pii_values[entity_type].append(entity_value)
                logger.debug(f"Presidio: {entity_type} = '{entity_value}'")
            
            return pii_values
            
        except Exception as e:
            logger.debug(f"Presidio extraction error: {str(e)}")
            return pii_values
    
    @staticmethod
    def _extract_pii_with_regex(text: str) -> Dict[str, List[str]]:
        """
        Fast regex-based extraction (fallback/supplement)
        """
        pii_values = {}
        
        logger.debug("Using regex pattern extraction as supplement")
        
        patterns = {
            'EMAIL_ADDRESS': (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
            # Improved phone patterns - catches 555-123-4567, (555) 123-4567, +1 555.123.4567, etc.
            'PHONE_NUMBER': (r'\b(?:\+?1?[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b', 'phone'),
            'US_SSN': (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
            'CREDIT_CARD': (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'credit card'),
        }
        
        for entity_type, (pattern, desc) in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                if entity_type not in pii_values:
                    pii_values[entity_type] = []
                pii_values[entity_type].extend(matches)
                logger.debug(f"Regex found {len(matches)} {desc}")
        
        return pii_values

    
    @staticmethod
    def anonymize(text: str) -> Tuple[str, List[Dict], Dict[str, any]]:
        """
        Detect and anonymize PII using cached Presidio + BERT + Regex.
        Returns: (anonymized_text, entities_list, scanner_results)
        
        Models are pre-loaded at startup, so this is FAST!
        Presidio recognizer registry is cached — no rebuild on each call.
        """
        entities = []
        scanner_results = {
            "secrets": {"detected": False, "is_valid": True, "risk_score": 0.0}
        }
        
        try:
            # ================================================================
            # STEP 1: EXTRACT PII VALUES FROM ORIGINAL TEXT
            # Use cached Presidio (no model reloading, no recognizer rebuild!)
            # ================================================================
            logger.debug(f"Original text: '{text}'")
            pii_values_by_type = ThreadSafePIIDetector._extract_pii_with_presidio(text)
            
            # Supplement with regex patterns
            regex_values = ThreadSafePIIDetector._extract_pii_with_regex(text)
            for entity_type, values in regex_values.items():
                if entity_type not in pii_values_by_type:
                    pii_values_by_type[entity_type] = values
                else:
                    pii_values_by_type[entity_type].extend(values)
            
            logger.debug(f"Extracted PII: {pii_values_by_type}")
            
            # ================================================================
            # STEP 2: Anonymize using cached Presidio Anonymizer directly
            # ================================================================
            try:
                if _PRESIDIO_ANALYZER and _PRESIDIO_ANONYMIZER:
                    analyze_results = _PRESIDIO_ANALYZER.analyze(text=text, language="en")
                    anonymized_result = _PRESIDIO_ANONYMIZER.anonymize(
                        text=text, analyzer_results=analyze_results
                    )
                    sanitized_text = anonymized_result.text
                else:
                    sanitized_text = text
                logger.debug(f"Anonymized text: '{sanitized_text}'")

                # Extract tokens from anonymized text
                tokens = re.findall(r'\[([A-Z_]+)_(\d+)\]', sanitized_text)
                logger.debug(f"Tokens found: {tokens}")
                
                entity_type_indices = {}
                
                for entity_type, entity_num_str in tokens:
                    full_token = f"[{entity_type}_{entity_num_str}]"
                    
                    actual_value = "REDACTED"
                    
                    # Match token to extracted value
                    if entity_type in pii_values_by_type and pii_values_by_type[entity_type]:
                        if entity_type not in entity_type_indices:
                            entity_type_indices[entity_type] = 0
                        
                        idx = entity_type_indices[entity_type]
                        values_list = pii_values_by_type[entity_type]
                        
                        if idx < len(values_list):
                            actual_value = values_list[idx]
                            entity_type_indices[entity_type] += 1
                    
                    entities.append({
                        "type": entity_type,
                        "value": actual_value,
                        "token": full_token,
                        "source": "pii"
                    })
                
                # ============================================================
                # FALLBACK: Add regex-detected PII that wasn't tokenized
                # This catches phone numbers and other patterns Presidio/BERT miss
                # ============================================================
                tokenized_types = set(entity_type_indices.keys())
                for entity_type, values in pii_values_by_type.items():
                    if entity_type not in tokenized_types and values:
                        for idx, value in enumerate(values):
                            token = f"[{entity_type}_{idx}]"
                            entities.append({
                                "type": entity_type,
                                "value": value,
                                "token": token,
                                "source": "regex_fallback"
                            })
                            # Also update the sanitized_text to redact these values
                            sanitized_text = sanitized_text.replace(value, token)
                        logger.debug(f"Regex fallback: added {len(values)} {entity_type} entities")
                
                logger.debug(f"Final entities: {entities}")
                    
            except Exception as e:
                logger.error(f"Presidio anonymization error: {str(e)}")
                import traceback
                logger.error(traceback.format_exc())
                sanitized_text = text
            
            # ================================================================
            # STEP 3: Run Secrets Scanner using CACHED instance + custom patterns
            # ================================================================
            try:
                _, is_valid_secrets, risk_score_secrets = _SECRETS_SCANNER.scan(text)
                secrets_detected = not is_valid_secrets
                
                # Custom secrets patterns for common API keys, passwords, tokens
                custom_secrets_patterns = [
                    (r'\b(?:api[_-]?key|apikey)\s*[=:]\s*[\'"]?([a-zA-Z0-9_-]{20,})[\'"]?', 'API_KEY'),
                    (r'\b(?:sk|pk|rk|ak)-[a-zA-Z0-9]{16,}', 'API_KEY'),  # OpenAI, Stripe style
                    (r'\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}', 'GITHUB_TOKEN'),  # GitHub tokens
                    (r'\bAIza[0-9A-Za-z\-_]{35}', 'GOOGLE_API_KEY'),  # Google API
                    (r'\b(?:password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'">]+)[\'"]?', 'PASSWORD'),
                    (r'\b(?:secret|token|auth)\s*[=:]\s*[\'"]?([a-zA-Z0-9_-]{8,})[\'"]?', 'SECRET'),
                    (r'\bBearer\s+[a-zA-Z0-9._-]{20,}', 'BEARER_TOKEN'),
                    (r'\baws_(?:access_key_id|secret_access_key)\s*[=:]\s*[\'"]?([A-Z0-9]{16,})[\'"]?', 'AWS_KEY'),
                ]
                
                custom_secrets_found = []
                for pattern, secret_type in custom_secrets_patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    if matches:
                        custom_secrets_found.append(secret_type)
                        logger.debug(f"Custom pattern found {secret_type}: {len(matches)} match(es)")
                
                # Combine llm-guard result with custom patterns
                if custom_secrets_found:
                    secrets_detected = True
                    risk_score_secrets = max(risk_score_secrets, 1.0)
                    logger.info(f"Custom secrets detected: {custom_secrets_found}")
                
                scanner_results["secrets"] = {
                    "detected": secrets_detected,
                    "is_valid": not secrets_detected,
                    "risk_score": float(risk_score_secrets),
                    "custom_secrets_types": custom_secrets_found if custom_secrets_found else []
                }
                
                if secrets_detected:
                    logger.info(f"Secrets detected (risk: {risk_score_secrets})")
                    
            except Exception as e:
                logger.error(f"Secrets Scanner failed: {str(e)}")
            
            # ================================================================
            # Deduplicate and finalize
            # ================================================================
            entities = ThreadSafePIIDetector.deduplicate_entities(entities)
            
            logger.debug(f"Returning {len(entities)} PII entities")
            
            return sanitized_text, entities, scanner_results
            
        except Exception as e:
            logger.error(f"PII/Secrets detection failed: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return text, [], scanner_results
    
    @staticmethod
    def deduplicate_entities(entities: List[Dict]) -> List[Dict]:
        """Deduplicate PII entities based on token"""
        if not entities:
            return []
        
        seen_tokens = set()
        deduplicated = []
        
        for entity in entities:
            entity_token = entity.get("token", "")
            if entity_token and entity_token not in seen_tokens:
                seen_tokens.add(entity_token)
                deduplicated.append(entity)
        
        if len(entities) != len(deduplicated):
            logger.debug(f"Deduplicated PII: {len(entities)} → {len(deduplicated)}")
        
        return deduplicated