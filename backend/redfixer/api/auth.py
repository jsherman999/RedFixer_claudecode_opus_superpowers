"""API authentication using API keys."""
from fastapi import Depends, Header, HTTPException, status

from redfixer.config import Settings
from redfixer.api.dependencies import get_settings_dependency


def verify_api_key(
    x_api_key: str = Header(..., description="API key for authentication"),
    settings: Settings = Depends(get_settings_dependency),
) -> str:
    """
    Verify API key from request header.

    This dependency checks the X-API-Key header against the configured
    API key in settings. Raises HTTPException if the key is invalid.

    Args:
        x_api_key: API key from X-API-Key header
        settings: Application settings

    Returns:
        The validated API key

    Raises:
        HTTPException: 401 Unauthorized if API key is invalid
    """
    if x_api_key != settings.api.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return x_api_key
