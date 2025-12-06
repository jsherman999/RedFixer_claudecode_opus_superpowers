"""SQLAlchemy database models."""
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


class ScanStatus(str, PyEnum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class HostStatus(str, PyEnum):
    """Host scan status enumeration."""
    PENDING = "pending"
    SCANNING = "scanning"
    AFFECTED = "affected"
    CLEAN = "clean"
    ERROR = "error"


class FindingType(str, PyEnum):
    """Finding type enumeration."""
    PACKAGE = "package"
    FILE = "file"
    PROCESS = "process"
    HUNT_ARTIFACT = "hunt_artifact"


class Severity(str, PyEnum):
    """Vulnerability severity enumeration."""
    CRITICAL = "critical"
    IMPORTANT = "important"
    MODERATE = "moderate"
    LOW = "low"


class Scan(Base):
    """Scan record."""
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vuln_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    vuln_title: Mapped[str] = mapped_column(String(500), nullable=False)
    hunt_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    hosts: Mapped[list["ScanHost"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanHost(Base):
    """Host within a scan."""
    __tablename__ = "scan_hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[HostStatus] = mapped_column(Enum(HostStatus), default=HostStatus.PENDING)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="hosts")
    findings: Mapped[list["ScanFinding"]] = relationship(back_populates="scan_host", cascade="all, delete-orphan")


class ScanFinding(Base):
    """Finding from a host scan."""
    __tablename__ = "scan_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_host_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_hosts.id"), nullable=False)
    finding_type: Mapped[FindingType] = mapped_column(Enum(FindingType), nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    current_value: Mapped[str] = mapped_column(String(500), nullable=False)
    expected_value: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    fix_command: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=True)

    # Relationships
    scan_host: Mapped["ScanHost"] = relationship(back_populates="findings")


class VulnCache(Base):
    """Cached vulnerability data."""
    __tablename__ = "vuln_cache"

    vuln_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
