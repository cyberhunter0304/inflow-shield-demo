"""
Data Models Module
Pydantic models for request/response validation
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000, description="User prompt")
    model: str = Field(default="openai/gpt-4o-mini", description="LLM model to use")
    bot_id: str = Field(..., description="Unique bot session ID")
    
    @validator('prompt')
    def validate_prompt(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Prompt must be a non-empty string")
        return v.strip()


class ScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000, description="Prompt to scan")
    bot_id: str = Field(default="scan-only", description="Bot ID for context")
    
    @validator('prompt')
    def validate_prompt(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Prompt must be a non-empty string")
        return v.strip()


class SecurityScanResult(BaseModel):
    is_safe: bool
    detections: Dict[str, Any]
    risk_level: str
    message: str
    timestamp: str
    scan_duration: float
    metrics: Dict[str, Any] = {}
    detected_threats: List[str] = []
    anonymized_prompt: Optional[str] = None


class ChatResponse(BaseModel):
    success: bool
    response: Optional[str] = None
    security_scan: SecurityScanResult
    model: Optional[str] = None
    usage: Optional[Dict[str, Any]] = None
    timestamp: str


class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    message: Optional[str] = None
    security_scan: Optional[SecurityScanResult] = None
    blocked: Optional[bool] = None


class HealthResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    scanners_active: int


class StatsResponse(BaseModel):
    service: str
    version: str
    scanners: Dict[str, Any]
    models_available: List[str]