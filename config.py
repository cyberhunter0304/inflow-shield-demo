"""
Configuration Module
Centralized configuration for the Guardrail Cloud Service
"""
import os
from pathlib import Path

# Load .env file automatically — searches current dir and all parent dirs
# so it works whether uvicorn is launched from /backend or the project root.
try:
    from dotenv import load_dotenv, find_dotenv
    _env_file = find_dotenv(usecwd=True)
    if _env_file:
        load_dotenv(_env_file, override=True)
        print(f"[config] Loaded .env from: {_env_file}")
    else:
        print("[config] No .env file found — relying on system environment variables")
except ImportError:
    print("[config] python-dotenv not installed — run: pip install python-dotenv")

# ============================================================================
# MongoDB Configuration
# ============================================================================

MONGODB_URI      = os.getenv("MONGODB_URI")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE")

# Warn loudly at import time if the required env vars are missing
import warnings as _warnings
if not MONGODB_URI:
    _warnings.warn(
        "MONGODB_URI environment variable is not set. "
        "MongoDB features will fail. Add it to your .env file.",
        RuntimeWarning,
        stacklevel=2,
    )
if not MONGODB_DATABASE:
    _warnings.warn(
        "MONGODB_DATABASE environment variable is not set. "
        "MongoDB features will fail. Add it to your .env file.",
        RuntimeWarning,
        stacklevel=2,
    )

# Collection Names — all driven by env vars with sensible defaults
MONGODB_CONVERSATIONS_COLLECTION  = os.getenv("MONGODB_CONVERSATIONS_COLLECTION",  "messages")
MONGODB_SECURITY_LOGS_COLLECTION  = os.getenv("MONGODB_SECURITY_LOGS_COLLECTION",  "security_logs")
MONGODB_THREAD_SUMMARIES_COLLECTION = os.getenv("MONGODB_THREAD_SUMMARIES_COLLECTION", "thread_summaries")

# ============================================================================
# Local Storage Configuration
# ============================================================================

SECURITY_STORAGE_DIR = Path("security_logs")
SECURITY_STORAGE_DIR.mkdir(exist_ok=True)

# ============================================================================
# Azure AI Foundry Configuration (sole LLM provider)
# ============================================================================

AZURE_ENDPOINT          = os.getenv("AZURE_ENDPOINT", "")          # e.g. https://your-resource.openai.azure.com/
AZURE_API_KEY           = os.getenv("AZURE_API_KEY", "")
AZURE_DEPLOYMENT        = os.getenv("AZURE_DEPLOYMENT", "gpt-4-turbo")  # Deployment name in Azure
AZURE_API_VERSION       = os.getenv("AZURE_API_VERSION", "2024-02-01")
AZURE_PROJECT_ID        = os.getenv("AZURE_PROJECT_ID", "")
AZURE_CONNECTION_STRING = os.getenv("AZURE_CONNECTION_STRING", "")

import warnings as _w
if not AZURE_ENDPOINT:
    _w.warn("AZURE_ENDPOINT is not set. LLM calls will fail.", RuntimeWarning, stacklevel=2)
if not AZURE_API_KEY:
    _w.warn("AZURE_API_KEY is not set. LLM calls will fail.", RuntimeWarning, stacklevel=2)

# ============================================================================
# CORS Configuration
# ============================================================================

ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://0.0.0.0:8000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://192.168.68.111:3001",
    "http://192.168.68.111:3000",
    "*"  # Allow all origins for development
]

# ============================================================================
# Scanner Configuration
# ============================================================================

SCANNER_CONFIG = {
    "prompt_injection_threshold": 0.8,
    "toxicity_threshold":         0.5,
    "pii_threshold":              0.5,
    "secrets_threshold":          0.0,   # Binary detection for API keys, passwords, tokens
    "thread_pool_workers":        20,
}

# ============================================================================
# API Configuration
# ============================================================================

API_CONFIG = {
    "title":       "Jailbreak-Protected LLM API - Concurrent",
    "description": "Secure LLM API with comprehensive jailbreak detection - Handles multiple concurrent bots",
    "version":     "2.0.0",
    "docs_url":    "/docs",
    "redoc_url":   "/redoc",
}

# LLM Models (Azure deployment names)
AVAILABLE_MODELS = [
    "gpt-4o-mini",
    "gpt-4o",
    "gpt-4-turbo",
]

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# OpenRouter Configuration (fallback)
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', '')
OPENROUTER_MODEL   = os.getenv('OPENROUTER_MODEL', 'openai/gpt-4o-mini')
