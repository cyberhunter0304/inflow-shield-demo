"""
RAG Loader Module
=================
Loads company knowledge base from inextlabs_rag.txt at startup.
Provides get_rag_context() for LLM system prompts.
"""
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Token cap for RAG context (approximate: 1 token ≈ 4 chars)
MAX_RAG_CHARS = 3200  # ~800 tokens

_rag_context: str = ""
_loaded: bool = False


def _load_rag_file() -> str:
    """Load RAG context from file. Returns empty string on failure."""
    rag_path = Path(__file__).parent / "inextlabs_rag.txt"
    
    if not rag_path.exists():
        logger.warning(f"[rag] File not found: {rag_path} — using empty context")
        return ""
    
    try:
        content = rag_path.read_text(encoding="utf-8").strip()
        
        # Cap at ~800 tokens
        if len(content) > MAX_RAG_CHARS:
            content = content[:MAX_RAG_CHARS].rsplit("\n", 1)[0]
            logger.info(f"[rag] Truncated to {len(content)} chars (~800 tokens)")
        
        logger.info(f"[rag] Loaded {len(content)} chars from {rag_path.name}")
        return content
    except Exception as e:
        logger.error(f"[rag] Failed to load {rag_path}: {e}")
        return ""


def get_rag_context() -> str:
    """
    Get the RAG context string. Loads once at first call.
    Returns empty string if file missing or unreadable.
    """
    global _rag_context, _loaded
    
    if not _loaded:
        _rag_context = _load_rag_file()
        _loaded = True
    
    # DEBUG: Show what RAG returns
    print(f"[DEBUG RAG] get_rag_context() called, returning {len(_rag_context)} chars")
    print(f"[DEBUG RAG] First 100 chars: {_rag_context[:100]!r}")
    
    return _rag_context
