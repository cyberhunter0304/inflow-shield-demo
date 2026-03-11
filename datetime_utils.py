"""
DateTime Utility Module
Provides timezone-aware datetime functions for consistent timestamps
All timestamps are in UTC format for consistency across the system.
"""
from datetime import datetime, timezone


def get_utc_timestamp() -> str:
    """
    Get current UTC timestamp in ISO format
    
    Returns UTC timezone-aware timestamp in ISO 8601 format
    Example: "2024-01-29T10:00:45.123456+00:00"
    """
    return datetime.now(timezone.utc).isoformat()


def format_timestamp(dt: datetime) -> str:
    """
    Format a datetime object to UTC ISO string
    
    Args:
        dt: datetime object (timezone-aware or naive)
    
    Returns:
        ISO 8601 formatted string in UTC
    """
    if dt.tzinfo is None:
        # If naive datetime, assume it's UTC
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        # Convert to UTC if it has a different timezone
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


# Use this function throughout the application for consistency
# It returns UTC timezone time for global consistency
now = get_utc_timestamp