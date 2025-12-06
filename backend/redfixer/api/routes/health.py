"""Health check and monitoring routes."""
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from redfixer.api.dependencies import get_db_dependency, get_settings_dependency
from redfixer.config import Settings

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check() -> Dict[str, str]:
    """
    Basic health check endpoint.

    Returns:
        Status message indicating the service is running
    """
    return {"status": "healthy", "service": "redfixer"}


@router.get("/ready")
async def readiness_check(
    db: Session = Depends(get_db_dependency),
    settings: Settings = Depends(get_settings_dependency),
) -> Dict[str, Any]:
    """
    Readiness check that verifies critical dependencies.

    Checks:
    - Database connectivity
    - Configuration loaded

    Returns:
        Readiness status with component checks
    """
    checks = {}

    # Check database connectivity
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {str(e)}"

    # Check configuration
    try:
        # Verify critical settings are present
        assert settings.api.host is not None
        assert settings.api.port is not None
        assert settings.database.path is not None
        checks["config"] = "ok"
    except Exception as e:
        checks["config"] = f"error: {str(e)}"

    # Determine overall status
    all_ok = all(status == "ok" for status in checks.values())
    status_code = "ready" if all_ok else "not_ready"

    response = {
        "status": status_code,
        "checks": checks,
    }

    # Return 503 if not ready
    if not all_ok:
        raise HTTPException(status_code=503, detail=response)

    return response


@router.get("/info")
async def info(
    settings: Settings = Depends(get_settings_dependency),
) -> Dict[str, Any]:
    """
    Get service information.

    Returns:
        Service configuration and version information
    """
    return {
        "service": "redfixer",
        "version": "0.1.0",
        "api": {
            "host": settings.api.host,
            "port": settings.api.port,
        },
        "llm": {
            "provider": settings.llm.provider,
        },
        "database": {
            "type": "sqlite",
            "path": str(settings.database.path),
        },
    }
