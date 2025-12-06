"""Pydantic schemas for API and CLI."""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanStatusEnum(str, Enum):
    """Scan status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class HostStatusEnum(str, Enum):
    """Host status."""
    PENDING = "pending"
    SCANNING = "scanning"
    AFFECTED = "affected"
    CLEAN = "clean"
    ERROR = "error"


class FindingTypeEnum(str, Enum):
    """Finding type."""
    PACKAGE = "package"
    FILE = "file"
    PROCESS = "process"
    HUNT_ARTIFACT = "hunt_artifact"


class SeverityEnum(str, Enum):
    """Severity level."""
    CRITICAL = "critical"
    IMPORTANT = "important"
    MODERATE = "moderate"
    LOW = "low"


# Request Schemas

class ScanAssessRequest(BaseModel):
    """Request to assess hosts for a vulnerability."""
    vuln_id: str = Field(..., description="RHSA or CVE identifier")
    hosts: List[str] = Field(..., description="List of hostnames to scan")
    hunt_mode: bool = Field(default=False, description="Enable LLM-powered hunt mode")


class HostValidateRequest(BaseModel):
    """Request to validate host connectivity."""
    hosts: List[str] = Field(..., description="List of hostnames to validate")


# Response Schemas

class FindingResponse(BaseModel):
    """Scan finding response."""
    id: str
    finding_type: FindingTypeEnum
    name: str
    current_value: str
    expected_value: str
    severity: SeverityEnum
    fix_command: str
    details: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class HostResponse(BaseModel):
    """Host scan result response."""
    id: str
    hostname: str
    status: HostStatusEnum
    error_message: Optional[str] = None
    scanned_at: Optional[datetime] = None
    findings: List[FindingResponse] = []

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    """Scan response."""
    id: str
    vuln_id: str
    vuln_title: str
    hunt_mode: bool
    status: ScanStatusEnum
    created_at: datetime
    completed_at: Optional[datetime] = None
    hosts: List[HostResponse] = []

    class Config:
        from_attributes = True


class ScanListItem(BaseModel):
    """Scan list item (summary without full host details)."""
    id: str
    vuln_id: str
    vuln_title: str
    hunt_mode: bool
    status: ScanStatusEnum
    created_at: datetime
    completed_at: Optional[datetime] = None
    host_count: int
    affected_count: int

    class Config:
        from_attributes = True


class VulnLookupResponse(BaseModel):
    """Vulnerability lookup response."""
    vuln_id: str
    title: str
    severity: SeverityEnum
    description: str
    affected_packages: List[Dict[str, Any]]
    references: List[str]
    published_date: Optional[datetime] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str
