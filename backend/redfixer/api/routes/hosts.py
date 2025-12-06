"""Host-related API routes."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from redfixer.api.auth import verify_api_key
from redfixer.api.dependencies import get_db_dependency
from redfixer.models.database import ScanHost, Scan
from redfixer.models.schemas import HostResponse

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=List[HostResponse])
async def list_hosts(
    hostname: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db_dependency),
    api_key: str = Depends(verify_api_key),
):
    """
    List scanned hosts with optional filtering.

    Args:
        hostname: Filter by hostname (exact match)
        status: Filter by status (scanning, clean, affected, error)
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return (max 1000)

    Returns:
        List of scan host records
    """
    # Validate limit
    if limit > 1000:
        raise HTTPException(status_code=400, detail="Limit cannot exceed 1000")

    # Build query
    query = db.query(ScanHost)

    # Apply filters
    if hostname:
        query = query.filter(ScanHost.hostname == hostname)

    if status:
        # Validate status value
        valid_statuses = ["scanning", "clean", "affected", "error"]
        if status.lower() not in valid_statuses:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
        query = query.filter(ScanHost.status == status.upper())

    # Order by most recent scans first
    query = query.order_by(desc(ScanHost.scanned_at))

    # Apply pagination
    hosts = query.offset(skip).limit(limit).all()

    return hosts


@router.get("/{hostname}/history", response_model=List[HostResponse])
async def get_host_history(
    hostname: str,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db_dependency),
    api_key: str = Depends(verify_api_key),
):
    """
    Get scan history for a specific host.

    Args:
        hostname: Hostname to get history for
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return (max 1000)

    Returns:
        List of scan host records for the specified hostname
    """
    # Validate limit
    if limit > 1000:
        raise HTTPException(status_code=400, detail="Limit cannot exceed 1000")

    # Query all scans for this hostname
    hosts = (
        db.query(ScanHost)
        .filter(ScanHost.hostname == hostname)
        .order_by(desc(ScanHost.scanned_at))
        .offset(skip)
        .limit(limit)
        .all()
    )

    if not hosts and skip == 0:
        raise HTTPException(
            status_code=404,
            detail=f"No scan history found for hostname: {hostname}"
        )

    return hosts
