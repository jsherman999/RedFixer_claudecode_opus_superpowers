# RedFixer Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build RedFixer, a vulnerability assessment and remediation tool for RHEL9 that fetches RHSA/CVE data, scans hosts via SSH, and provides fix recommendations with optional LLM-powered artifact hunting.

**Architecture:** FastAPI backend with three core services (VulnFetcher, HostScanner, HuntEngine), SQLite persistence, React 19 frontend, and Typer CLI sharing Pydantic models.

**Tech Stack:** Python 3.11+, FastAPI, Paramiko, SQLAlchemy, Pydantic, React 19, Vite, Tailwind CSS, shadcn/ui, Typer, Rich

---

## Phase 1: Project Foundation & Configuration

### Task 1.1: Initialize Backend Structure

**Files:**
- Create: `backend/pyproject.toml`
- Create: `backend/redfixer/__init__.py`
- Create: `backend/redfixer/config.py`
- Create: `backend/tests/__init__.py`
- Create: `config/config.example.yaml`

**Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "redfixer"
version = "0.1.0"
description = "Vulnerability assessment and remediation tool for RHEL9"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.30.0",
    "pydantic>=2.8.0",
    "pydantic-settings>=2.4.0",
    "sqlalchemy>=2.0.0",
    "alembic>=1.13.0",
    "httpx>=0.27.0",
    "paramiko>=3.4.0",
    "pyyaml>=6.0",
    "typer>=0.12.0",
    "rich>=13.7.0",
    "jinja2>=3.1.4",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=5.0.0",
    "httpx>=0.27.0",
    "ruff>=0.5.0",
]

[project.scripts]
redfixer = "redfixer.cli.main:app"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W"]
ignore = ["E501"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

**Step 2: Create backend package init**

```python
# backend/redfixer/__init__.py
"""RedFixer - RHEL9 Vulnerability Assessment Tool."""

__version__ = "0.1.0"
```

**Step 3: Create configuration module with Pydantic Settings**

```python
# backend/redfixer/config.py
"""Configuration management using Pydantic Settings."""
from pathlib import Path
from typing import Literal, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class APISettings(BaseSettings):
    """API server settings."""
    host: str = "0.0.0.0"
    port: int = 8000
    api_key: str = Field(default="change-me-in-production")


class SSHSettings(BaseSettings):
    """SSH connection settings."""
    user: str = "root"
    key_path: Path = Path.home() / ".ssh" / "id_rsa"
    timeout: int = 30


class RedHatAPISettings(BaseSettings):
    """Red Hat API credentials (optional)."""
    username: Optional[str] = None
    password: Optional[str] = None


class OllamaSettings(BaseSettings):
    """Ollama LLM settings."""
    endpoint: str = "http://localhost:11434"
    model: str = "llama3.1:8b"


class UAIStudioSettings(BaseSettings):
    """UAI Studio (Azure AI) settings."""
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    model: str = "gpt-4"


class OpenAISettings(BaseSettings):
    """OpenAI API settings."""
    api_key: Optional[str] = None
    model: str = "gpt-4-turbo"


class AnthropicSettings(BaseSettings):
    """Anthropic API settings."""
    api_key: Optional[str] = None
    model: str = "claude-sonnet-4-20250514"


class LLMSettings(BaseSettings):
    """LLM provider configuration."""
    provider: Literal["ollama", "uai_studio", "openai", "anthropic"] = "ollama"
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    uai_studio: UAIStudioSettings = Field(default_factory=UAIStudioSettings)
    openai: OpenAISettings = Field(default_factory=OpenAISettings)
    anthropic: AnthropicSettings = Field(default_factory=AnthropicSettings)


class DatabaseSettings(BaseSettings):
    """Database settings."""
    path: Path = Path.home() / ".redfixer" / "redfixer.db"


class CacheSettings(BaseSettings):
    """Cache settings."""
    vuln_ttl_hours: int = 24


class Settings(BaseSettings):
    """Main application settings."""
    model_config = SettingsConfigDict(
        env_prefix="REDFIXER_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    api: APISettings = Field(default_factory=APISettings)
    ssh: SSHSettings = Field(default_factory=SSHSettings)
    redhat: RedHatAPISettings = Field(default_factory=RedHatAPISettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
```

**Step 4: Create example config file**

```yaml
# config/config.example.yaml
# RedFixer Configuration Example
# Copy to ~/.redfixer/config.yaml or /etc/redfixer/config.yaml

# API Settings
api:
  host: 0.0.0.0
  port: 8000
  api_key: "change-me-in-production"

# SSH Settings
ssh:
  user: root
  key_path: ~/.ssh/id_rsa
  timeout: 30

# Red Hat API (optional, for higher rate limits)
redhat:
  username: null
  password: null

# LLM Configuration
llm:
  provider: ollama  # ollama | uai_studio | openai | anthropic

  ollama:
    endpoint: http://localhost:11434
    model: llama3.1:8b

  uai_studio:
    endpoint: https://uai-studio.yourcompany.com/v1
    api_key: null
    model: gpt-4

  openai:
    api_key: null
    model: gpt-4-turbo

  anthropic:
    api_key: null
    model: claude-sonnet-4-20250514

# Database
database:
  path: ~/.redfixer/redfixer.db

# Cache
cache:
  vuln_ttl_hours: 24
```

**Step 5: Create empty test init**

```python
# backend/tests/__init__.py
"""Test suite for RedFixer."""
```

**Step 6: Verify structure**

Run: `ls -R backend/`

Expected output showing created directories and files

**Step 7: Commit**

```bash
git add backend/ config/
git commit -m "feat: initialize backend structure with configuration

- Add pyproject.toml with FastAPI, Paramiko, SQLAlchemy dependencies
- Add Pydantic Settings-based configuration module
- Add example YAML config file
- Set up project structure

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 1.2: Initialize Database Models

**Files:**
- Create: `backend/redfixer/models/__init__.py`
- Create: `backend/redfixer/models/database.py`
- Create: `backend/redfixer/models/schemas.py`
- Create: `backend/redfixer/db/__init__.py`
- Create: `backend/redfixer/db/session.py`

**Step 1: Create database models with SQLAlchemy**

```python
# backend/redfixer/models/database.py
"""SQLAlchemy database models."""
import uuid
from datetime import datetime
from enum import Enum as PyEnum

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
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationships
    hosts: Mapped[list["ScanHost"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanHost(Base):
    """Host within a scan."""
    __tablename__ = "scan_hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[HostStatus] = mapped_column(Enum(HostStatus), default=HostStatus.PENDING)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

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
```

**Step 2: Create Pydantic schemas for API**

```python
# backend/redfixer/models/schemas.py
"""Pydantic schemas for API and CLI."""
from datetime import datetime
from enum import Enum
from typing import Any

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
    hosts: list[str] = Field(..., description="List of hostnames to scan")
    hunt_mode: bool = Field(default=False, description="Enable LLM-powered hunt mode")


class HostValidateRequest(BaseModel):
    """Request to validate host connectivity."""
    hosts: list[str] = Field(..., description="List of hostnames to validate")


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
    details: dict[str, Any] | None = None

    class Config:
        from_attributes = True


class HostResponse(BaseModel):
    """Host scan result response."""
    id: str
    hostname: str
    status: HostStatusEnum
    error_message: str | None = None
    scanned_at: datetime | None = None
    findings: list[FindingResponse] = []

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
    completed_at: datetime | None = None
    hosts: list[HostResponse] = []

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
    completed_at: datetime | None = None
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
    affected_packages: list[dict[str, Any]]
    references: list[str]
    published_date: datetime | None = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str
```

**Step 3: Create database session management**

```python
# backend/redfixer/db/session.py
"""Database session management."""
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from redfixer.config import get_settings
from redfixer.models.database import Base

settings = get_settings()

# Ensure database directory exists
db_path = Path(settings.database.path)
db_path.parent.mkdir(parents=True, exist_ok=True)

# Create engine
engine = create_engine(
    f"sqlite:///{db_path}",
    connect_args={"check_same_thread": False},
    echo=False,
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    """Get database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

**Step 4: Create module inits**

```python
# backend/redfixer/models/__init__.py
"""Database and schema models."""
from redfixer.models.database import (
    Base,
    FindingType,
    HostStatus,
    Scan,
    ScanFinding,
    ScanHost,
    ScanStatus,
    Severity,
    VulnCache,
)
from redfixer.models.schemas import (
    FindingResponse,
    HostResponse,
    ScanAssessRequest,
    ScanListItem,
    ScanResponse,
    VulnLookupResponse,
)

__all__ = [
    # Database models
    "Base",
    "Scan",
    "ScanHost",
    "ScanFinding",
    "VulnCache",
    # Enums
    "ScanStatus",
    "HostStatus",
    "FindingType",
    "Severity",
    # Schemas
    "ScanAssessRequest",
    "ScanResponse",
    "ScanListItem",
    "HostResponse",
    "FindingResponse",
    "VulnLookupResponse",
]
```

```python
# backend/redfixer/db/__init__.py
"""Database configuration and session management."""
from redfixer.db.session import get_db, init_db

__all__ = ["get_db", "init_db"]
```

**Step 5: Write test to verify models can be created**

```python
# backend/tests/test_models.py
"""Test database models."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from redfixer.models.database import Base, Scan, ScanHost, ScanStatus


@pytest.fixture
def db_session():
    """Create in-memory database session for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


def test_create_scan(db_session: Session):
    """Test creating a scan record."""
    scan = Scan(
        vuln_id="RHSA-2024:1234",
        vuln_title="Test Vulnerability",
        hunt_mode=False,
        status=ScanStatus.PENDING,
    )
    db_session.add(scan)
    db_session.commit()

    assert scan.id is not None
    assert scan.vuln_id == "RHSA-2024:1234"
    assert scan.status == ScanStatus.PENDING


def test_create_scan_with_hosts(db_session: Session):
    """Test creating a scan with hosts."""
    scan = Scan(
        vuln_id="CVE-2024-12345",
        vuln_title="Another Test",
        hunt_mode=True,
    )
    host = ScanHost(hostname="server1.example.com", scan=scan)

    db_session.add(scan)
    db_session.commit()

    assert len(scan.hosts) == 1
    assert scan.hosts[0].hostname == "server1.example.com"
```

**Step 6: Run tests**

Run: `cd backend && pytest tests/test_models.py -v`

Expected: 2 tests PASS

**Step 7: Commit**

```bash
git add backend/
git commit -m "feat: add database models and schemas

- Add SQLAlchemy models for scans, hosts, findings, cache
- Add Pydantic schemas for API requests/responses
- Add database session management with SQLite
- Add tests for model creation

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Phase 2: Core Services - VulnFetcher

### Task 2.1: VulnFetcher Service (Red Hat API Integration)

**Files:**
- Create: `backend/redfixer/services/__init__.py`
- Create: `backend/redfixer/services/vuln_fetcher.py`
- Create: `backend/tests/test_vuln_fetcher.py`

**Step 1: Write failing test for VulnFetcher**

```python
# backend/tests/test_vuln_fetcher.py
"""Test VulnFetcher service."""
import pytest
from datetime import datetime, timedelta

from redfixer.services.vuln_fetcher import VulnFetcher
from redfixer.models.schemas import VulnLookupResponse, SeverityEnum


@pytest.mark.asyncio
async def test_fetch_rhsa():
    """Test fetching RHSA data."""
    fetcher = VulnFetcher()

    # Use a real, old RHSA that should be stable
    result = await fetcher.fetch_vulnerability("RHSA-2023:1234")

    assert result.vuln_id == "RHSA-2023:1234"
    assert result.title is not None
    assert result.severity in SeverityEnum
    assert len(result.affected_packages) > 0


@pytest.mark.asyncio
async def test_fetch_cve():
    """Test fetching CVE data."""
    fetcher = VulnFetcher()

    # Use a real, well-known CVE
    result = await fetcher.fetch_vulnerability("CVE-2021-44228")  # Log4Shell

    assert result.vuln_id == "CVE-2021-44228"
    assert "log4j" in result.title.lower()
    assert result.severity in SeverityEnum


@pytest.mark.asyncio
async def test_cache_prevents_duplicate_calls():
    """Test that cache prevents duplicate API calls."""
    fetcher = VulnFetcher()

    # First call - should hit API
    result1 = await fetcher.fetch_vulnerability("RHSA-2023:1234")

    # Second call - should hit cache
    result2 = await fetcher.fetch_vulnerability("RHSA-2023:1234")

    assert result1.vuln_id == result2.vuln_id
    assert result1.title == result2.title
```

**Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_vuln_fetcher.py -v`

Expected: FAIL with "ModuleNotFoundError: No module named 'redfixer.services.vuln_fetcher'"

**Step 3: Implement VulnFetcher service**

```python
# backend/redfixer/services/vuln_fetcher.py
"""Vulnerability fetcher service for Red Hat APIs."""
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from redfixer.config import get_settings
from redfixer.models.database import VulnCache
from redfixer.models.schemas import SeverityEnum, VulnLookupResponse


class VulnFetcher:
    """Fetches vulnerability data from Red Hat APIs."""

    BASE_URL = "https://access.redhat.com/hydra/rest/securitydata"

    def __init__(self, db: Session | None = None):
        """Initialize VulnFetcher."""
        self.settings = get_settings()
        self.db = db
        self.client = httpx.AsyncClient(timeout=30.0)

    async def fetch_vulnerability(self, vuln_id: str) -> VulnLookupResponse:
        """
        Fetch vulnerability details from Red Hat API.

        Args:
            vuln_id: RHSA or CVE identifier

        Returns:
            VulnLookupResponse with vulnerability details
        """
        # Check cache first
        if self.db:
            cached = self._get_from_cache(vuln_id)
            if cached:
                return cached

        # Determine if RHSA or CVE
        if vuln_id.startswith("RHSA-"):
            data = await self._fetch_rhsa(vuln_id)
        elif vuln_id.startswith("CVE-"):
            data = await self._fetch_cve(vuln_id)
        else:
            raise ValueError(f"Invalid vulnerability ID format: {vuln_id}")

        response = self._parse_vulnerability_data(vuln_id, data)

        # Cache the result
        if self.db:
            self._cache_result(vuln_id, data)

        return response

    async def _fetch_rhsa(self, rhsa_id: str) -> dict[str, Any]:
        """Fetch RHSA data from Red Hat API."""
        url = f"{self.BASE_URL}/cvrf/{rhsa_id}.json"

        auth = None
        if self.settings.redhat.username and self.settings.redhat.password:
            auth = (self.settings.redhat.username, self.settings.redhat.password)

        response = await self.client.get(url, auth=auth)
        response.raise_for_status()
        return response.json()

    async def _fetch_cve(self, cve_id: str) -> dict[str, Any]:
        """Fetch CVE data from Red Hat API."""
        url = f"{self.BASE_URL}/cve/{cve_id}.json"

        auth = None
        if self.settings.redhat.username and self.settings.redhat.password:
            auth = (self.settings.redhat.username, self.settings.redhat.password)

        response = await self.client.get(url, auth=auth)
        response.raise_for_status()
        return response.json()

    def _parse_vulnerability_data(self, vuln_id: str, data: dict[str, Any]) -> VulnLookupResponse:
        """Parse Red Hat API response into VulnLookupResponse."""
        # This is simplified - real implementation would parse complex CVRF/CVE JSON
        # For now, extract basic fields

        if vuln_id.startswith("RHSA-"):
            title = data.get("cvrfdoc", {}).get("document_title", vuln_id)
            severity = self._map_severity(
                data.get("cvrfdoc", {}).get("aggregate_severity", "Moderate")
            )
            description = data.get("cvrfdoc", {}).get("document_notes", [{}])[0].get("note", "")

            # Extract affected packages from vulnerabilities
            affected_packages = []
            for vuln in data.get("cvrfdoc", {}).get("vulnerabilities", []):
                for package in vuln.get("product_statuses", [{}])[0].get("product_ids", []):
                    affected_packages.append({"package": package})

            references = [
                ref.get("url", "")
                for ref in data.get("cvrfdoc", {}).get("document_references", [])
            ]

            published_date = None
            tracking = data.get("cvrfdoc", {}).get("document_tracking", {})
            if "current_release_date" in tracking:
                published_date = datetime.fromisoformat(
                    tracking["current_release_date"].replace("Z", "+00:00")
                )

        else:  # CVE
            title = data.get("name", vuln_id)
            severity = self._map_severity(data.get("threat_severity", "Moderate"))
            description = data.get("details", [""])[0] if data.get("details") else ""

            affected_packages = [
                {"package": pkg} for pkg in data.get("affected_packages", [])
            ]

            references = data.get("references", [])

            published_date = None
            if "public_date" in data:
                published_date = datetime.fromisoformat(
                    data["public_date"].replace("Z", "+00:00")
                )

        return VulnLookupResponse(
            vuln_id=vuln_id,
            title=title,
            severity=severity,
            description=description,
            affected_packages=affected_packages,
            references=references,
            published_date=published_date,
        )

    def _map_severity(self, severity_str: str) -> SeverityEnum:
        """Map Red Hat severity string to SeverityEnum."""
        severity_lower = severity_str.lower()

        if "critical" in severity_lower:
            return SeverityEnum.CRITICAL
        elif "important" in severity_lower or "high" in severity_lower:
            return SeverityEnum.IMPORTANT
        elif "moderate" in severity_lower or "medium" in severity_lower:
            return SeverityEnum.MODERATE
        else:
            return SeverityEnum.LOW

    def _get_from_cache(self, vuln_id: str) -> VulnLookupResponse | None:
        """Get vulnerability from cache if not expired."""
        cached = self.db.query(VulnCache).filter(VulnCache.vuln_id == vuln_id).first()

        if cached and cached.expires_at > datetime.utcnow():
            return self._parse_vulnerability_data(vuln_id, cached.data)

        return None

    def _cache_result(self, vuln_id: str, data: dict[str, Any]) -> None:
        """Cache vulnerability data."""
        expires_at = datetime.utcnow() + timedelta(hours=self.settings.cache.vuln_ttl_hours)

        cached = self.db.query(VulnCache).filter(VulnCache.vuln_id == vuln_id).first()

        if cached:
            cached.data = data
            cached.fetched_at = datetime.utcnow()
            cached.expires_at = expires_at
        else:
            cached = VulnCache(
                vuln_id=vuln_id,
                data=data,
                fetched_at=datetime.utcnow(),
                expires_at=expires_at,
            )
            self.db.add(cached)

        self.db.commit()

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
```

**Step 4: Create services init**

```python
# backend/redfixer/services/__init__.py
"""Core services."""
from redfixer.services.vuln_fetcher import VulnFetcher

__all__ = ["VulnFetcher"]
```

**Step 5: Run tests**

Run: `cd backend && pytest tests/test_vuln_fetcher.py -v`

Expected: Tests may fail if Red Hat API responses differ. Adjust parsing logic as needed.

**Step 6: Commit**

```bash
git add backend/
git commit -m "feat: add VulnFetcher service for Red Hat APIs

- Implement async fetcher for RHSA and CVE data
- Add caching to reduce API calls
- Support optional Red Hat credentials
- Add tests for fetcher

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Phase 3: Core Services - HostScanner

### Task 3.1: HostScanner Service (Paramiko SSH)

**Files:**
- Create: `backend/redfixer/services/host_scanner.py`
- Create: `backend/tests/test_host_scanner.py`

**Step 1: Write failing test for HostScanner**

```python
# backend/tests/test_host_scanner.py
"""Test HostScanner service."""
import pytest
from unittest.mock import Mock, patch, MagicMock

from redfixer.services.host_scanner import HostScanner
from redfixer.models.schemas import SeverityEnum


@pytest.fixture
def mock_ssh_client():
    """Mock Paramiko SSH client."""
    with patch("paramiko.SSHClient") as mock:
        client = MagicMock()
        mock.return_value = client

        # Mock exec_command to return version info
        stdout = MagicMock()
        stdout.read.return_value = b"httpd-2.4.51-1.el9.x86_64\n"
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock())

        yield mock


@pytest.mark.asyncio
async def test_scan_host_affected(mock_ssh_client):
    """Test scanning a host that has vulnerable package."""
    scanner = HostScanner()

    affected_packages = [
        {"package": "httpd", "fixed_version": "2.4.57-1.el9"}
    ]

    result = await scanner.scan_host(
        hostname="testhost.example.com",
        vuln_id="RHSA-2024:1234",
        severity=SeverityEnum.IMPORTANT,
        affected_packages=affected_packages,
    )

    assert result.hostname == "testhost.example.com"
    assert result.is_affected is True
    assert len(result.findings) > 0
    assert result.findings[0].name == "httpd"


@pytest.mark.asyncio
async def test_scan_host_clean(mock_ssh_client):
    """Test scanning a host that is not affected."""
    scanner = HostScanner()

    # Mock installed version is newer than vulnerable version
    mock_ssh_client.return_value.exec_command.return_value = (
        MagicMock(),
        MagicMock(read=lambda: b"httpd-2.4.60-1.el9.x86_64\n"),
        MagicMock()
    )

    affected_packages = [
        {"package": "httpd", "fixed_version": "2.4.57-1.el9"}
    ]

    result = await scanner.scan_host(
        hostname="testhost.example.com",
        vuln_id="RHSA-2024:1234",
        severity=SeverityEnum.IMPORTANT,
        affected_packages=affected_packages,
    )

    assert result.is_affected is False
    assert len(result.findings) == 0
```

**Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_host_scanner.py -v`

Expected: FAIL with "ModuleNotFoundError: No module named 'redfixer.services.host_scanner'"

**Step 3: Implement HostScanner service**

```python
# backend/redfixer/services/host_scanner.py
"""Host scanner service using Paramiko SSH."""
import asyncio
import re
from dataclasses import dataclass
from typing import Any

import paramiko

from redfixer.config import get_settings
from redfixer.models.schemas import FindingTypeEnum, SeverityEnum


@dataclass
class PackageFinding:
    """Package finding from scan."""
    name: str
    current_version: str
    expected_version: str
    severity: SeverityEnum
    fix_command: str


@dataclass
class HostScanResult:
    """Result from scanning a host."""
    hostname: str
    is_affected: bool
    findings: list[PackageFinding]
    error: str | None = None


class HostScanner:
    """Scans hosts via SSH for vulnerable packages."""

    def __init__(self):
        """Initialize HostScanner."""
        self.settings = get_settings()

    async def scan_host(
        self,
        hostname: str,
        vuln_id: str,
        severity: SeverityEnum,
        affected_packages: list[dict[str, Any]],
    ) -> HostScanResult:
        """
        Scan a host for vulnerable packages.

        Args:
            hostname: Target hostname
            vuln_id: RHSA or CVE ID
            severity: Vulnerability severity
            affected_packages: List of affected package specifications

        Returns:
            HostScanResult with findings
        """
        try:
            # Run SSH scan in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self._scan_host_sync,
                hostname,
                vuln_id,
                severity,
                affected_packages,
            )
            return result
        except Exception as e:
            return HostScanResult(
                hostname=hostname,
                is_affected=False,
                findings=[],
                error=str(e),
            )

    def _scan_host_sync(
        self,
        hostname: str,
        vuln_id: str,
        severity: SeverityEnum,
        affected_packages: list[dict[str, Any]],
    ) -> HostScanResult:
        """Synchronous host scan implementation."""
        findings = []

        # Create SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect
            client.connect(
                hostname=hostname,
                username=self.settings.ssh.user,
                key_filename=str(self.settings.ssh.key_path),
                timeout=self.settings.ssh.timeout,
            )

            # Check each affected package
            for pkg_spec in affected_packages:
                package_name = self._extract_package_name(pkg_spec.get("package", ""))
                if not package_name:
                    continue

                # Query installed version
                stdin, stdout, stderr = client.exec_command(f"rpm -q {package_name}")
                output = stdout.read().decode().strip()

                if "not installed" in output.lower():
                    # Package not installed, not affected
                    continue

                # Parse version from rpm output
                installed_version = self._parse_rpm_version(output)
                fixed_version = pkg_spec.get("fixed_version", "")

                if not installed_version or not fixed_version:
                    continue

                # Compare versions
                if self._is_version_vulnerable(installed_version, fixed_version):
                    findings.append(
                        PackageFinding(
                            name=package_name,
                            current_version=installed_version,
                            expected_version=fixed_version,
                            severity=severity,
                            fix_command=f"dnf update {package_name}-{fixed_version}",
                        )
                    )

        finally:
            client.close()

        return HostScanResult(
            hostname=hostname,
            is_affected=len(findings) > 0,
            findings=findings,
        )

    def _extract_package_name(self, package_spec: str) -> str:
        """Extract package name from specification."""
        # Handle various formats: httpd, httpd-2.4.51, etc.
        if not package_spec:
            return ""

        # Take first part before version separator
        parts = re.split(r"[-_]\d", package_spec)
        return parts[0] if parts else package_spec

    def _parse_rpm_version(self, rpm_output: str) -> str:
        """Parse version from rpm -q output."""
        # Format: package-version-release.arch
        # Example: httpd-2.4.51-1.el9.x86_64
        match = re.search(r"-([\d.]+(?:-[\d.]+)?)", rpm_output)
        return match.group(1) if match else ""

    def _is_version_vulnerable(self, installed: str, fixed: str) -> bool:
        """
        Compare versions to determine if installed version is vulnerable.

        Returns True if installed < fixed
        """
        # Simplified version comparison
        # Real implementation should use proper RPM version comparison
        installed_parts = self._version_to_tuple(installed)
        fixed_parts = self._version_to_tuple(fixed)

        return installed_parts < fixed_parts

    def _version_to_tuple(self, version: str) -> tuple[int, ...]:
        """Convert version string to tuple for comparison."""
        # Split on . and - and convert to integers
        parts = re.split(r"[.\-]", version)
        result = []

        for part in parts:
            try:
                result.append(int(part))
            except ValueError:
                # Non-numeric part, skip or use 0
                result.append(0)

        return tuple(result)
```

**Step 4: Update services init**

```python
# backend/redfixer/services/__init__.py
"""Core services."""
from redfixer.services.vuln_fetcher import VulnFetcher
from redfixer.services.host_scanner import HostScanner

__all__ = ["VulnFetcher", "HostScanner"]
```

**Step 5: Run tests**

Run: `cd backend && pytest tests/test_host_scanner.py -v`

Expected: 2 tests PASS

**Step 6: Commit**

```bash
git add backend/
git commit -m "feat: add HostScanner service with Paramiko

- Implement async SSH-based package scanning
- Add RPM version comparison logic
- Generate fix commands
- Add unit tests with mocked SSH

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Phase 4: Core Services - LLM Integration

### Task 4.1: LLM Base Interface

**Files:**
- Create: `backend/redfixer/llm/__init__.py`
- Create: `backend/redfixer/llm/base.py`
- Create: `backend/tests/test_llm_base.py`

**Step 1: Write LLM base interface**

```python
# backend/redfixer/llm/base.py
"""Base LLM interface."""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Response from LLM."""
    content: str
    confidence: float  # 0.0 to 1.0


class BaseLLM(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def generate(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """
        Generate a response from the LLM.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Returns:
            LLMResponse with content and confidence
        """
        pass

    @abstractmethod
    async def close(self):
        """Close any open connections."""
        pass
```

**Step 2: Create test for base interface**

```python
# backend/tests/test_llm_base.py
"""Test LLM base interface."""
import pytest

from redfixer.llm.base import BaseLLM, LLMResponse


class MockLLM(BaseLLM):
    """Mock LLM for testing."""

    async def generate(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Return mock response."""
        return LLMResponse(content=f"Mock response to: {prompt}", confidence=0.95)

    async def close(self):
        """No-op close."""
        pass


@pytest.mark.asyncio
async def test_mock_llm():
    """Test mock LLM implementation."""
    llm = MockLLM()

    response = await llm.generate("Test prompt")

    assert "Test prompt" in response.content
    assert response.confidence > 0.9

    await llm.close()
```

**Step 3: Run test**

Run: `cd backend && pytest tests/test_llm_base.py -v`

Expected: 1 test PASS

**Step 4: Commit**

```bash
git add backend/
git commit -m "feat: add LLM base interface

- Define abstract BaseLLM interface
- Add LLMResponse dataclass
- Add mock implementation for testing

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4.2: Ollama LLM Implementation

**Files:**
- Create: `backend/redfixer/llm/ollama.py`
- Create: `backend/tests/test_llm_ollama.py`

**Step 1: Write Ollama implementation**

```python
# backend/redfixer/llm/ollama.py
"""Ollama LLM provider implementation."""
import httpx

from redfixer.config import OllamaSettings
from redfixer.llm.base import BaseLLM, LLMResponse


class OllamaLLM(BaseLLM):
    """Ollama LLM provider."""

    def __init__(self, settings: OllamaSettings):
        """Initialize Ollama client."""
        self.settings = settings
        self.client = httpx.AsyncClient(timeout=120.0)

    async def generate(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Generate response using Ollama."""
        url = f"{self.settings.endpoint}/api/generate"

        payload = {
            "model": self.settings.model,
            "prompt": prompt,
            "stream": False,
        }

        if system_prompt:
            payload["system"] = system_prompt

        response = await self.client.post(url, json=payload)
        response.raise_for_status()

        data = response.json()
        content = data.get("response", "")

        # Ollama doesn't provide confidence, estimate based on response
        confidence = 0.8 if content else 0.0

        return LLMResponse(content=content, confidence=confidence)

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
```

**Step 2: Write test (requires Ollama running, or mock)**

```python
# backend/tests/test_llm_ollama.py
"""Test Ollama LLM implementation."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from redfixer.config import OllamaSettings
from redfixer.llm.ollama import OllamaLLM


@pytest.mark.asyncio
async def test_ollama_generate():
    """Test Ollama generate with mocked HTTP client."""
    settings = OllamaSettings(
        endpoint="http://localhost:11434",
        model="llama3.1:8b"
    )

    with patch("httpx.AsyncClient") as mock_client_class:
        # Setup mock
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "response": "This is a test response from Ollama"
        }
        mock_client.post = AsyncMock(return_value=mock_response)

        llm = OllamaLLM(settings)

        result = await llm.generate("Test prompt")

        assert result.content == "This is a test response from Ollama"
        assert result.confidence > 0.0

        await llm.close()
```

**Step 3: Run test**

Run: `cd backend && pytest tests/test_llm_ollama.py -v`

Expected: 1 test PASS

**Step 4: Commit**

```bash
git add backend/
git commit -m "feat: add Ollama LLM provider

- Implement OllamaLLM with async HTTP client
- Add generate method with system prompt support
- Add test with mocked HTTP responses

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4.3: LLM Factory and Other Providers

**Files:**
- Create: `backend/redfixer/llm/factory.py`
- Create: `backend/redfixer/llm/openai.py`
- Create: `backend/redfixer/llm/anthropic.py`
- Create: `backend/redfixer/llm/uai_studio.py`

**Step 1: Create OpenAI provider (stub for now)**

```python
# backend/redfixer/llm/openai.py
"""OpenAI LLM provider implementation."""
import httpx

from redfixer.config import OpenAISettings
from redfixer.llm.base import BaseLLM, LLMResponse


class OpenAILLM(BaseLLM):
    """OpenAI LLM provider."""

    def __init__(self, settings: OpenAISettings):
        """Initialize OpenAI client."""
        self.settings = settings
        self.client = httpx.AsyncClient(
            timeout=120.0,
            headers={"Authorization": f"Bearer {settings.api_key}"}
        )

    async def generate(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Generate response using OpenAI."""
        url = "https://api.openai.com/v1/chat/completions"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.settings.model,
            "messages": messages,
        }

        response = await self.client.post(url, json=payload)
        response.raise_for_status()

        data = response.json()
        content = data["choices"][0]["message"]["content"]

        return LLMResponse(content=content, confidence=0.9)

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
```

**Step 2: Create Anthropic provider (stub)**

```python
# backend/redfixer/llm/anthropic.py
"""Anthropic LLM provider implementation."""
import httpx

from redfixer.config import AnthropicSettings
from redfixer.llm.base import BaseLLM, LLMResponse


class AnthropicLLM(BaseLLM):
    """Anthropic LLM provider."""

    def __init__(self, settings: AnthropicSettings):
        """Initialize Anthropic client."""
        self.settings = settings
        self.client = httpx.AsyncClient(
            timeout=120.0,
            headers={
                "x-api-key": settings.api_key,
                "anthropic-version": "2023-06-01"
            }
        )

    async def generate(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Generate response using Anthropic."""
        url = "https://api.anthropic.com/v1/messages"

        payload = {
            "model": self.settings.model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system_prompt:
            payload["system"] = system_prompt

        response = await self.client.post(url, json=payload)
        response.raise_for_status()

        data = response.json()
        content = data["content"][0]["text"]

        return LLMResponse(content=content, confidence=0.9)

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
```

**Step 3: Create UAI Studio provider (generic OpenAI-compatible)**

```python
# backend/redfixer/llm/uai_studio.py
"""UAI Studio (Azure AI) LLM provider implementation."""
import httpx

from redfixer.config import UAIStudioSettings
from redfixer.llm.base import BaseLLM, LLMResponse


class UAIStudioLLM(BaseLLM):
    """UAI Studio LLM provider (Azure AI compatible)."""

    def __init__(self, settings: UAIStudioSettings):
        """Initialize UAI Studio client."""
        self.settings = settings
        self.client = httpx.AsyncClient(
            timeout=120.0,
            headers={"Authorization": f"Bearer {settings.api_key}"}
        )

    async def generate(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Generate response using UAI Studio."""
        # Assumes OpenAI-compatible endpoint
        url = f"{self.settings.endpoint}/chat/completions"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.settings.model,
            "messages": messages,
        }

        response = await self.client.post(url, json=payload)
        response.raise_for_status()

        data = response.json()
        content = data["choices"][0]["message"]["content"]

        return LLMResponse(content=content, confidence=0.9)

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
```

**Step 4: Create LLM factory**

```python
# backend/redfixer/llm/factory.py
"""LLM provider factory."""
from redfixer.config import get_settings
from redfixer.llm.base import BaseLLM
from redfixer.llm.ollama import OllamaLLM
from redfixer.llm.openai import OpenAILLM
from redfixer.llm.anthropic import AnthropicLLM
from redfixer.llm.uai_studio import UAIStudioLLM


def get_llm() -> BaseLLM:
    """
    Get configured LLM provider.

    Returns:
        BaseLLM instance based on configuration
    """
    settings = get_settings()

    if settings.llm.provider == "ollama":
        return OllamaLLM(settings.llm.ollama)
    elif settings.llm.provider == "openai":
        if not settings.llm.openai.api_key:
            raise ValueError("OpenAI API key not configured")
        return OpenAILLM(settings.llm.openai)
    elif settings.llm.provider == "anthropic":
        if not settings.llm.anthropic.api_key:
            raise ValueError("Anthropic API key not configured")
        return AnthropicLLM(settings.llm.anthropic)
    elif settings.llm.provider == "uai_studio":
        if not settings.llm.uai_studio.endpoint:
            raise ValueError("UAI Studio endpoint not configured")
        return UAIStudioLLM(settings.llm.uai_studio)
    else:
        raise ValueError(f"Unknown LLM provider: {settings.llm.provider}")
```

**Step 5: Update llm package init**

```python
# backend/redfixer/llm/__init__.py
"""LLM provider implementations."""
from redfixer.llm.base import BaseLLM, LLMResponse
from redfixer.llm.factory import get_llm

__all__ = ["BaseLLM", "LLMResponse", "get_llm"]
```

**Step 6: Commit**

```bash
git add backend/
git commit -m "feat: add LLM providers and factory

- Add OpenAI, Anthropic, UAI Studio implementations
- Add factory function to get configured provider
- Support multiple LLM backends

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4.4: HuntEngine Service

**Files:**
- Create: `backend/redfixer/services/hunt_engine.py`
- Create: `backend/tests/test_hunt_engine.py`

**Step 1: Write HuntEngine implementation**

```python
# backend/redfixer/services/hunt_engine.py
"""Hunt engine for LLM-powered artifact detection."""
import asyncio
from dataclasses import dataclass

import paramiko

from redfixer.config import get_settings
from redfixer.llm import get_llm
from redfixer.models.schemas import SeverityEnum


@dataclass
class HuntFinding:
    """Finding from hunt mode."""
    artifact_type: str  # log, file, process, network
    location: str
    description: str
    confidence: float
    severity: SeverityEnum


@dataclass
class HuntResult:
    """Result from hunt mode scan."""
    hostname: str
    findings: list[HuntFinding]
    error: str | None = None


class HuntEngine:
    """LLM-powered vulnerability artifact hunting."""

    def __init__(self):
        """Initialize HuntEngine."""
        self.settings = get_settings()
        self.llm = get_llm()

    async def hunt(
        self,
        hostname: str,
        vuln_id: str,
        vuln_description: str,
        severity: SeverityEnum,
    ) -> HuntResult:
        """
        Hunt for exploitation artifacts on a host.

        Args:
            hostname: Target hostname
            vuln_id: Vulnerability ID
            vuln_description: Description of vulnerability
            severity: Vulnerability severity

        Returns:
            HuntResult with discovered artifacts
        """
        try:
            # Step 1: Ask LLM what to look for
            checks = await self._generate_hunt_checks(vuln_id, vuln_description)

            # Step 2: Execute checks on host
            check_results = await self._execute_checks(hostname, checks)

            # Step 3: Ask LLM to analyze results
            findings = await self._analyze_results(
                vuln_id, vuln_description, check_results, severity
            )

            return HuntResult(hostname=hostname, findings=findings)

        except Exception as e:
            return HuntResult(hostname=hostname, findings=[], error=str(e))

    async def _generate_hunt_checks(self, vuln_id: str, description: str) -> list[dict]:
        """Ask LLM to generate hunt checks for this vulnerability."""
        system_prompt = """You are a security analyst expert in finding exploitation artifacts.
Given a vulnerability, suggest specific checks to find indicators of compromise.
Return checks as a JSON array with: type (log/file/process/network), command, and description."""

        user_prompt = f"""Vulnerability: {vuln_id}
Description: {description}

Generate 3-5 specific checks to find exploitation artifacts on a RHEL9 system.
Focus on practical, high-signal checks (log patterns, file presence, processes).

Return JSON array format:
[{{"type": "log", "command": "grep pattern /var/log/file", "description": "What we're looking for"}}]"""

        response = await self.llm.generate(user_prompt, system_prompt)

        # Parse JSON from response (simplified - real impl should be more robust)
        import json
        try:
            checks = json.loads(response.content)
            return checks if isinstance(checks, list) else []
        except json.JSONDecodeError:
            return []

    async def _execute_checks(self, hostname: str, checks: list[dict]) -> list[dict]:
        """Execute hunt checks on target host via SSH."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._execute_checks_sync, hostname, checks
        )

    def _execute_checks_sync(self, hostname: str, checks: list[dict]) -> list[dict]:
        """Synchronously execute checks via SSH."""
        results = []

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=hostname,
                username=self.settings.ssh.user,
                key_filename=str(self.settings.ssh.key_path),
                timeout=self.settings.ssh.timeout,
            )

            for check in checks:
                command = check.get("command", "")
                if not command:
                    continue

                stdin, stdout, stderr = client.exec_command(command)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()

                results.append({
                    "check": check,
                    "output": output,
                    "error": error,
                    "has_results": bool(output and not error),
                })

        finally:
            client.close()

        return results

    async def _analyze_results(
        self,
        vuln_id: str,
        description: str,
        results: list[dict],
        severity: SeverityEnum,
    ) -> list[HuntFinding]:
        """Ask LLM to analyze check results and identify IOCs."""
        system_prompt = """You are a security analyst analyzing system scan results for exploitation indicators.
Provide HIGH/MEDIUM/LOW confidence assessment for each finding.
Return findings as JSON array."""

        results_summary = "\n".join([
            f"Check: {r['check']['description']}\nOutput: {r['output'][:500]}\n"
            for r in results if r['has_results']
        ])

        user_prompt = f"""Vulnerability: {vuln_id}
Description: {description}

Scan Results:
{results_summary}

Analyze these results and identify indicators of compromise.
For each IOC, provide: artifact_type, location, description, confidence (0.0-1.0).

Return JSON array:
[{{"artifact_type": "log", "location": "/path", "description": "What was found", "confidence": 0.8}}]"""

        response = await self.llm.generate(user_prompt, system_prompt)

        # Parse response
        import json
        try:
            iocs = json.loads(response.content)
            if not isinstance(iocs, list):
                return []

            findings = []
            for ioc in iocs:
                findings.append(HuntFinding(
                    artifact_type=ioc.get("artifact_type", "unknown"),
                    location=ioc.get("location", ""),
                    description=ioc.get("description", ""),
                    confidence=float(ioc.get("confidence", 0.5)),
                    severity=severity,
                ))

            return findings

        except (json.JSONDecodeError, ValueError):
            return []

    async def close(self):
        """Close LLM connection."""
        await self.llm.close()
```

**Step 2: Update services init**

```python
# backend/redfixer/services/__init__.py
"""Core services."""
from redfixer.services.vuln_fetcher import VulnFetcher
from redfixer.services.host_scanner import HostScanner
from redfixer.services.hunt_engine import HuntEngine

__all__ = ["VulnFetcher", "HostScanner", "HuntEngine"]
```

**Step 3: Write test**

```python
# backend/tests/test_hunt_engine.py
"""Test HuntEngine service."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from redfixer.services.hunt_engine import HuntEngine
from redfixer.models.schemas import SeverityEnum


@pytest.mark.asyncio
async def test_hunt_engine_basic():
    """Test basic hunt engine flow with mocked LLM and SSH."""
    with patch("redfixer.services.hunt_engine.get_llm") as mock_get_llm:
        with patch("paramiko.SSHClient") as mock_ssh:
            # Mock LLM responses
            mock_llm = MagicMock()
            mock_llm.generate = AsyncMock()

            # First call: generate checks
            mock_llm.generate.side_effect = [
                MagicMock(content='[{"type": "log", "command": "grep test /var/log/messages", "description": "Test check"}]'),
                MagicMock(content='[{"artifact_type": "log", "location": "/var/log/messages", "description": "Found suspicious entry", "confidence": 0.8}]'),
            ]

            mock_get_llm.return_value = mock_llm

            # Mock SSH
            ssh_client = MagicMock()
            mock_ssh.return_value = ssh_client
            ssh_client.exec_command.return_value = (
                MagicMock(),
                MagicMock(read=lambda: b"suspicious log entry"),
                MagicMock(read=lambda: b""),
            )

            engine = HuntEngine()

            result = await engine.hunt(
                hostname="testhost",
                vuln_id="CVE-2024-12345",
                vuln_description="Test vulnerability",
                severity=SeverityEnum.CRITICAL,
            )

            assert result.hostname == "testhost"
            assert len(result.findings) > 0

            await engine.close()
```

**Step 4: Run test**

Run: `cd backend && pytest tests/test_hunt_engine.py -v`

Expected: 1 test PASS

**Step 5: Commit**

```bash
git add backend/
git commit -m "feat: add HuntEngine for LLM-powered artifact detection

- Implement hunt mode with LLM check generation
- Execute checks via SSH on target hosts
- LLM analyzes results for IOCs
- Add tests with mocked LLM and SSH

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Phase 5: FastAPI Backend - API Routes

### Task 5.1: API Dependencies and Middleware

**Files:**
- Create: `backend/redfixer/api/__init__.py`
- Create: `backend/redfixer/api/deps.py`

**Step 1: Create API dependencies**

```python
# backend/redfixer/api/deps.py
"""FastAPI dependencies."""
from typing import Annotated

from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session

from redfixer.config import get_settings
from redfixer.db import get_db

settings = get_settings()


async def verify_api_key(x_api_key: Annotated[str, Header()]) -> str:
    """Verify API key from header."""
    if x_api_key != settings.api.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


# Dependency aliases
DBSession = Annotated[Session, Depends(get_db)]
APIKey = Annotated[str, Depends(verify_api_key)]
```

**Step 2: Create API package init**

```python
# backend/redfixer/api/__init__.py
"""FastAPI application and routes."""
```

**Step 3: Commit**

```bash
git add backend/
git commit -m "feat: add API dependencies and auth

- Add API key verification dependency
- Add database session dependency
- Set up FastAPI deps module

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5.2: Vulnerability Routes

**Files:**
- Create: `backend/redfixer/api/routes/__init__.py`
- Create: `backend/redfixer/api/routes/vuln.py`

**Step 1: Create vulnerability routes**

```python
# backend/redfixer/api/routes/vuln.py
"""Vulnerability lookup routes."""
from fastapi import APIRouter, HTTPException

from redfixer.api.deps import APIKey, DBSession
from redfixer.models.schemas import VulnLookupResponse
from redfixer.services import VulnFetcher

router = APIRouter(prefix="/vuln", tags=["vulnerability"])


@router.get("/lookup/{vuln_id}", response_model=VulnLookupResponse)
async def lookup_vulnerability(
    vuln_id: str,
    db: DBSession,
    api_key: APIKey,
) -> VulnLookupResponse:
    """
    Look up vulnerability details from Red Hat APIs.

    Args:
        vuln_id: RHSA or CVE identifier
        db: Database session
        api_key: API key for authentication

    Returns:
        Vulnerability details
    """
    fetcher = VulnFetcher(db)
    try:
        result = await fetcher.fetch_vulnerability(vuln_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await fetcher.close()


@router.get("/lookup/{vuln_id}/fixes")
async def get_vulnerability_fixes(
    vuln_id: str,
    db: DBSession,
    api_key: APIKey,
):
    """
    Get fix recommendations for a vulnerability.

    This is a simplified endpoint that returns the affected packages
    and their fixed versions from the vulnerability lookup.
    """
    fetcher = VulnFetcher(db)
    try:
        result = await fetcher.fetch_vulnerability(vuln_id)
        return {
            "vuln_id": result.vuln_id,
            "fixes": [
                {
                    "package": pkg.get("package", ""),
                    "fixed_version": pkg.get("fixed_version", ""),
                }
                for pkg in result.affected_packages
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await fetcher.close()
```

**Step 2: Create routes package init**

```python
# backend/redfixer/api/routes/__init__.py
"""API route modules."""
from redfixer.api.routes import vuln

__all__ = ["vuln"]
```

**Step 3: Commit**

```bash
git add backend/
git commit -m "feat: add vulnerability lookup routes

- Add /vuln/lookup/{id} endpoint
- Add /vuln/lookup/{id}/fixes endpoint
- Integrate VulnFetcher service

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5.3: Scan Routes

**Files:**
- Create: `backend/redfixer/api/routes/scan.py`

**Step 1: Create scan routes**

```python
# backend/redfixer/api/routes/scan.py
"""Scan assessment routes."""
import asyncio
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException
from sqlalchemy import func

from redfixer.api.deps import APIKey, DBSession
from redfixer.models.database import (
    Scan,
    ScanFinding,
    ScanHost,
    ScanStatus,
    HostStatus,
    FindingType,
)
from redfixer.models.schemas import (
    ScanAssessRequest,
    ScanResponse,
    ScanListItem,
)
from redfixer.services import VulnFetcher, HostScanner, HuntEngine

router = APIRouter(prefix="/scan", tags=["scan"])


async def run_scan_background(
    scan_id: str,
    vuln_id: str,
    hosts: list[str],
    hunt_mode: bool,
    db_path: str,
):
    """Background task to run scan."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # Create new DB session for background task
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        # Update scan status to running
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = ScanStatus.RUNNING
        db.commit()

        # Fetch vulnerability details
        fetcher = VulnFetcher(db)
        vuln_data = await fetcher.fetch_vulnerability(vuln_id)
        await fetcher.close()

        # Scan each host
        scanner = HostScanner()
        for hostname in hosts:
            scan_host = db.query(ScanHost).filter(
                ScanHost.scan_id == scan_id,
                ScanHost.hostname == hostname
            ).first()

            scan_host.status = HostStatus.SCANNING
            db.commit()

            # Run host scan
            result = await scanner.scan_host(
                hostname=hostname,
                vuln_id=vuln_id,
                severity=vuln_data.severity,
                affected_packages=vuln_data.affected_packages,
            )

            if result.error:
                scan_host.status = HostStatus.ERROR
                scan_host.error_message = result.error
            elif result.is_affected:
                scan_host.status = HostStatus.AFFECTED

                # Store findings
                for finding in result.findings:
                    db_finding = ScanFinding(
                        scan_host_id=scan_host.id,
                        finding_type=FindingType.PACKAGE,
                        name=finding.name,
                        current_value=finding.current_version,
                        expected_value=finding.expected_version,
                        severity=finding.severity,
                        fix_command=finding.fix_command,
                    )
                    db.add(db_finding)
            else:
                scan_host.status = HostStatus.CLEAN

            scan_host.scanned_at = datetime.utcnow()
            db.commit()

            # Run hunt mode if enabled and host is affected
            if hunt_mode and result.is_affected:
                hunt_engine = HuntEngine()
                hunt_result = await hunt_engine.hunt(
                    hostname=hostname,
                    vuln_id=vuln_id,
                    vuln_description=vuln_data.description,
                    severity=vuln_data.severity,
                )
                await hunt_engine.close()

                # Store hunt findings
                for hunt_finding in hunt_result.findings:
                    db_finding = ScanFinding(
                        scan_host_id=scan_host.id,
                        finding_type=FindingType.HUNT_ARTIFACT,
                        name=hunt_finding.artifact_type,
                        current_value=hunt_finding.location,
                        expected_value="clean",
                        severity=hunt_finding.severity,
                        fix_command="Manual investigation required",
                        details={"description": hunt_finding.description, "confidence": hunt_finding.confidence},
                    )
                    db.add(db_finding)
                db.commit()

        # Mark scan complete
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.utcnow()
        db.commit()

    finally:
        db.close()


@router.post("/assess", response_model=ScanResponse)
async def assess_vulnerability(
    request: ScanAssessRequest,
    background_tasks: BackgroundTasks,
    db: DBSession,
    api_key: APIKey,
) -> ScanResponse:
    """
    Initiate vulnerability assessment on hosts.

    This endpoint creates a scan and returns immediately.
    The actual scanning happens in the background.
    """
    # Fetch vulnerability title for display
    fetcher = VulnFetcher(db)
    vuln_data = await fetcher.fetch_vulnerability(request.vuln_id)
    await fetcher.close()

    # Create scan record
    scan = Scan(
        vuln_id=request.vuln_id,
        vuln_title=vuln_data.title,
        hunt_mode=request.hunt_mode,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Create host records
    for hostname in request.hosts:
        scan_host = ScanHost(
            scan_id=scan.id,
            hostname=hostname,
            status=HostStatus.PENDING,
        )
        db.add(scan_host)
    db.commit()

    # Start background scan
    from redfixer.config import get_settings
    settings = get_settings()
    background_tasks.add_task(
        run_scan_background,
        scan.id,
        request.vuln_id,
        request.hosts,
        request.hunt_mode,
        str(settings.database.path),
    )

    # Return scan info
    db.refresh(scan)
    return ScanResponse.model_validate(scan)


@router.get("/assess/{scan_id}", response_model=ScanResponse)
async def get_scan_results(
    scan_id: str,
    db: DBSession,
    api_key: APIKey,
) -> ScanResponse:
    """Get scan results by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse.model_validate(scan)


@router.get("/history", response_model=list[ScanListItem])
async def get_scan_history(
    db: DBSession,
    api_key: APIKey,
    limit: int = 50,
) -> list[ScanListItem]:
    """Get scan history."""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()

    result = []
    for scan in scans:
        host_count = len(scan.hosts)
        affected_count = sum(1 for h in scan.hosts if h.status == HostStatus.AFFECTED)

        result.append(ScanListItem(
            id=scan.id,
            vuln_id=scan.vuln_id,
            vuln_title=scan.vuln_title,
            hunt_mode=scan.hunt_mode,
            status=scan.status,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            host_count=host_count,
            affected_count=affected_count,
        ))

    return result
```

**Step 2: Update routes init**

```python
# backend/redfixer/api/routes/__init__.py
"""API route modules."""
from redfixer.api.routes import vuln, scan

__all__ = ["vuln", "scan"]
```

**Step 3: Commit**

```bash
git add backend/
git commit -m "feat: add scan assessment routes

- Add POST /scan/assess to initiate scans
- Add GET /scan/assess/{id} to get results
- Add GET /scan/history for scan list
- Implement background scanning with asyncio
- Integrate HostScanner and HuntEngine

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5.4: Additional Routes (Hosts, Reports, Health)

**Files:**
- Create: `backend/redfixer/api/routes/hosts.py`
- Create: `backend/redfixer/api/routes/report.py`
- Create: `backend/redfixer/services/report_gen.py`

**Step 1: Create hosts routes**

```python
# backend/redfixer/api/routes/hosts.py
"""Host validation routes."""
import asyncio

import paramiko
from fastapi import APIRouter

from redfixer.api.deps import APIKey
from redfixer.config import get_settings
from redfixer.models.schemas import HostValidateRequest

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.post("/validate")
async def validate_hosts(
    request: HostValidateRequest,
    api_key: APIKey,
):
    """
    Validate SSH connectivity to hosts.

    Returns status for each host.
    """
    settings = get_settings()

    async def check_host(hostname: str) -> dict:
        """Check if host is reachable via SSH."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _check_host_sync, hostname, settings)

    tasks = [check_host(host) for host in request.hosts]
    results = await asyncio.gather(*tasks)

    return {"hosts": results}


def _check_host_sync(hostname: str, settings) -> dict:
    """Synchronously check host connectivity."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=hostname,
            username=settings.ssh.user,
            key_filename=str(settings.ssh.key_path),
            timeout=10,
        )
        client.close()
        return {"hostname": hostname, "status": "reachable"}
    except Exception as e:
        return {"hostname": hostname, "status": "unreachable", "error": str(e)}


@router.post("/upload")
async def upload_hosts_file(
    api_key: APIKey,
    # In real implementation, would accept file upload
    # For now, placeholder
):
    """
    Upload hosts file and parse hostnames.

    TODO: Implement file upload handling
    """
    return {"message": "Not implemented yet"}
```

**Step 2: Create report generation service**

```python
# backend/redfixer/services/report_gen.py
"""Report generation service."""
import csv
import io
import json
from datetime import datetime

from jinja2 import Template
from sqlalchemy.orm import Session

from redfixer.models.database import Scan


class ReportGenerator:
    """Generate reports in various formats."""

    def __init__(self, db: Session):
        """Initialize report generator."""
        self.db = db

    def generate_json(self, scan_id: str) -> str:
        """Generate JSON report."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError("Scan not found")

        data = {
            "scan_id": scan.id,
            "vuln_id": scan.vuln_id,
            "vuln_title": scan.vuln_title,
            "hunt_mode": scan.hunt_mode,
            "status": scan.status.value,
            "created_at": scan.created_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "hosts": [
                {
                    "hostname": host.hostname,
                    "status": host.status.value,
                    "findings": [
                        {
                            "type": f.finding_type.value,
                            "name": f.name,
                            "current": f.current_value,
                            "expected": f.expected_value,
                            "severity": f.severity.value,
                            "fix": f.fix_command,
                        }
                        for f in host.findings
                    ],
                }
                for host in scan.hosts
            ],
        }

        return json.dumps(data, indent=2)

    def generate_csv(self, scan_id: str) -> str:
        """Generate CSV report."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError("Scan not found")

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Hostname", "Status", "Finding Type", "Name",
            "Current Value", "Expected Value", "Severity", "Fix Command"
        ])

        # Data
        for host in scan.hosts:
            for finding in host.findings:
                writer.writerow([
                    host.hostname,
                    host.status.value,
                    finding.finding_type.value,
                    finding.name,
                    finding.current_value,
                    finding.expected_value,
                    finding.severity.value,
                    finding.fix_command,
                ])

        return output.getvalue()

    def generate_html(self, scan_id: str) -> str:
        """Generate HTML report."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError("Scan not found")

        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <title>RedFixer Report - {{ scan.vuln_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #c00; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .critical { color: #c00; font-weight: bold; }
        .important { color: #f80; font-weight: bold; }
        .moderate { color: #fa0; }
        .low { color: #080; }
    </style>
</head>
<body>
    <h1>RedFixer Vulnerability Assessment Report</h1>

    <h2>Summary</h2>
    <p><strong>Vulnerability:</strong> {{ scan.vuln_id }} - {{ scan.vuln_title }}</p>
    <p><strong>Scan ID:</strong> {{ scan.id }}</p>
    <p><strong>Status:</strong> {{ scan.status.value }}</p>
    <p><strong>Created:</strong> {{ scan.created_at }}</p>
    <p><strong>Completed:</strong> {{ scan.completed_at or 'In progress' }}</p>
    <p><strong>Hunt Mode:</strong> {{ 'Enabled' if scan.hunt_mode else 'Disabled' }}</p>

    <h2>Host Results</h2>
    {% for host in scan.hosts %}
    <h3>{{ host.hostname }} - {{ host.status.value }}</h3>
    {% if host.findings %}
    <table>
        <tr>
            <th>Type</th>
            <th>Name</th>
            <th>Current</th>
            <th>Expected</th>
            <th>Severity</th>
            <th>Fix Command</th>
        </tr>
        {% for finding in host.findings %}
        <tr>
            <td>{{ finding.finding_type.value }}</td>
            <td>{{ finding.name }}</td>
            <td>{{ finding.current_value }}</td>
            <td>{{ finding.expected_value }}</td>
            <td class="{{ finding.severity.value }}">{{ finding.severity.value }}</td>
            <td><code>{{ finding.fix_command }}</code></td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <p>No findings.</p>
    {% endif %}
    {% endfor %}

    <hr>
    <p><em>Generated by RedFixer on {{ now }}</em></p>
</body>
</html>
        """)

        return template.render(scan=scan, now=datetime.utcnow())
```

**Step 3: Create report routes**

```python
# backend/redfixer/api/routes/report.py
"""Report generation routes."""
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from redfixer.api.deps import APIKey, DBSession
from redfixer.services.report_gen import ReportGenerator

router = APIRouter(prefix="/report", tags=["report"])


@router.get("/{scan_id}/json")
async def get_json_report(
    scan_id: str,
    db: DBSession,
    api_key: APIKey,
):
    """Get scan results as JSON."""
    try:
        generator = ReportGenerator(db)
        content = generator.generate_json(scan_id)
        return Response(content=content, media_type="application/json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{scan_id}/csv")
async def get_csv_report(
    scan_id: str,
    db: DBSession,
    api_key: APIKey,
):
    """Get scan results as CSV."""
    try:
        generator = ReportGenerator(db)
        content = generator.generate_csv(scan_id)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=redfixer-{scan_id}.csv"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{scan_id}/html")
async def get_html_report(
    scan_id: str,
    db: DBSession,
    api_key: APIKey,
):
    """Get scan results as HTML."""
    try:
        generator = ReportGenerator(db)
        content = generator.generate_html(scan_id)
        return Response(content=content, media_type="text/html")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
```

**Step 4: Update services and routes**

```python
# backend/redfixer/services/__init__.py
"""Core services."""
from redfixer.services.vuln_fetcher import VulnFetcher
from redfixer.services.host_scanner import HostScanner
from redfixer.services.hunt_engine import HuntEngine
from redfixer.services.report_gen import ReportGenerator

__all__ = ["VulnFetcher", "HostScanner", "HuntEngine", "ReportGenerator"]
```

```python
# backend/redfixer/api/routes/__init__.py
"""API route modules."""
from redfixer.api.routes import vuln, scan, hosts, report

__all__ = ["vuln", "scan", "hosts", "report"]
```

**Step 5: Commit**

```bash
git add backend/
git commit -m "feat: add hosts, report routes and report generation

- Add host validation endpoint
- Add report generation service (JSON, CSV, HTML)
- Add report download endpoints
- Support multiple export formats

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5.5: Main FastAPI Application

**Files:**
- Create: `backend/redfixer/main.py`

**Step 1: Create FastAPI app**

```python
# backend/redfixer/main.py
"""FastAPI application entry point."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from redfixer import __version__
from redfixer.api.routes import vuln, scan, hosts, report
from redfixer.config import get_settings
from redfixer.db import init_db
from redfixer.models.schemas import HealthResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager."""
    # Startup
    init_db()
    yield
    # Shutdown
    pass


app = FastAPI(
    title="RedFixer API",
    description="RHEL9 Vulnerability Assessment and Remediation Tool",
    version=__version__,
    lifespan=lifespan,
)

# CORS middleware
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(vuln.router, prefix="/api/v1")
app.include_router(scan.router, prefix="/api/v1")
app.include_router(hosts.router, prefix="/api/v1")
app.include_router(report.router, prefix="/api/v1")


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(status="healthy", version=__version__)


@app.get("/", tags=["root"])
async def root():
    """Root endpoint."""
    return {
        "name": "RedFixer API",
        "version": __version__,
        "docs": "/docs",
    }
```

**Step 2: Test API can start**

Run: `cd backend && python -m uvicorn redfixer.main:app --reload --port 8000`

Expected: Server starts, browse to http://localhost:8000/docs

**Step 3: Stop server and commit**

```bash
git add backend/
git commit -m "feat: add main FastAPI application

- Create FastAPI app with lifespan management
- Register all API routes under /api/v1
- Add CORS middleware
- Add health check and root endpoints
- Initialize database on startup

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Phase 6: CLI Implementation

### Task 6.1: CLI Foundation with Typer

**Files:**
- Create: `backend/redfixer/cli/__init__.py`
- Create: `backend/redfixer/cli/main.py`

**Step 1: Create CLI main**

```python
# backend/redfixer/cli/main.py
"""RedFixer CLI application."""
import typer
from rich.console import Console
from rich.table import Table

from redfixer import __version__

app = typer.Typer(
    name="redfixer",
    help="RHEL9 Vulnerability Assessment and Remediation Tool",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version():
    """Show RedFixer version."""
    console.print(f"RedFixer version {__version__}", style="bold green")


# Subcommands
vuln_app = typer.Typer(help="Vulnerability lookup commands")
scan_app = typer.Typer(help="Scan assessment commands")
hosts_app = typer.Typer(help="Host management commands")
config_app = typer.Typer(help="Configuration commands")

app.add_typer(vuln_app, name="vuln")
app.add_typer(scan_app, name="scan")
app.add_typer(hosts_app, name="hosts")
app.add_typer(config_app, name="config")


@vuln_app.command("lookup")
def vuln_lookup(vuln_id: str):
    """Look up vulnerability details."""
    console.print(f"Looking up {vuln_id}...", style="bold")
    # TODO: Implement API call
    console.print("[red]Not implemented yet[/red]")


@scan_app.command()
def scan(
    vuln: str = typer.Option(..., help="Vulnerability ID (RHSA or CVE)"),
    hosts: str = typer.Option(None, help="Comma-separated hostnames"),
    hosts_file: str = typer.Option(None, help="File containing hostnames"),
    hunt: bool = typer.Option(False, help="Enable hunt mode"),
    output: str = typer.Option("table", help="Output format: table, json, csv"),
):
    """Run vulnerability assessment scan."""
    console.print(f"Scanning for {vuln}...", style="bold")
    # TODO: Implement scanning
    console.print("[red]Not implemented yet[/red]")


@hosts_app.command("validate")
def hosts_validate(hosts: str):
    """Validate SSH connectivity to hosts."""
    console.print("Validating hosts...", style="bold")
    # TODO: Implement validation
    console.print("[red]Not implemented yet[/red]")


@config_app.command("show")
def config_show():
    """Show current configuration."""
    from redfixer.config import get_settings

    settings = get_settings()

    table = Table(title="RedFixer Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("API Host", settings.api.host)
    table.add_row("API Port", str(settings.api.port))
    table.add_row("SSH User", settings.ssh.user)
    table.add_row("SSH Key", str(settings.ssh.key_path))
    table.add_row("LLM Provider", settings.llm.provider)
    table.add_row("Database Path", str(settings.database.path))

    console.print(table)


@config_app.command("set")
def config_set(key: str, value: str):
    """Set configuration value."""
    console.print(f"Setting {key} = {value}", style="bold")
    console.print("[yellow]Configuration setting not implemented[/yellow]")
    console.print("Edit ~/.redfixer/config.yaml manually")


if __name__ == "__main__":
    app()
```

**Step 2: Test CLI**

Run: `cd backend && python -m redfixer.cli.main --help`

Expected: CLI help text displays

Run: `cd backend && python -m redfixer.cli.main config show`

Expected: Configuration table displays

**Step 3: Commit**

```bash
git add backend/
git commit -m "feat: add CLI foundation with Typer

- Create main CLI app with subcommands
- Add vuln, scan, hosts, config commands
- Implement config show command
- Use Rich for styled output
- Add placeholder commands

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6.2: Complete CLI Commands

**Files:**
- Modify: `backend/redfixer/cli/main.py`

**Step 1: Add HTTP client for CLI to call API**

First, update `pyproject.toml` dependencies to ensure `httpx` is available (it already is from earlier).

**Step 2: Implement CLI commands that call the API**

```python
# Modify backend/redfixer/cli/main.py

# Add at top:
import asyncio
import httpx
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add helper function:
def get_api_client() -> httpx.AsyncClient:
    """Get configured API client."""
    from redfixer.config import get_settings
    settings = get_settings()

    return httpx.AsyncClient(
        base_url=f"http://{settings.api.host}:{settings.api.port}/api/v1",
        headers={"X-API-Key": settings.api.api_key},
        timeout=300.0,
    )


# Replace vuln_lookup command:
@vuln_app.command("lookup")
def vuln_lookup(vuln_id: str):
    """Look up vulnerability details."""
    async def _lookup():
        async with get_api_client() as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(description=f"Looking up {vuln_id}...", total=None)

                response = await client.get(f"/vuln/lookup/{vuln_id}")
                response.raise_for_status()
                return response.json()

    try:
        result = asyncio.run(_lookup())

        table = Table(title=f"Vulnerability: {result['vuln_id']}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Title", result["title"])
        table.add_row("Severity", result["severity"])
        table.add_row("Description", result["description"][:200] + "...")
        table.add_row("Affected Packages", str(len(result["affected_packages"])))

        console.print(table)

    except httpx.HTTPError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# Replace scan command:
@scan_app.command()
def scan(
    vuln: str = typer.Option(..., help="Vulnerability ID (RHSA or CVE)"),
    hosts: str = typer.Option(None, help="Comma-separated hostnames"),
    hosts_file: str = typer.Option(None, help="File containing hostnames"),
    hunt: bool = typer.Option(False, help="Enable hunt mode"),
    output: str = typer.Option("table", help="Output format: table, json, csv"),
    report: str = typer.Option(None, help="Generate HTML report to file"),
):
    """Run vulnerability assessment scan."""
    # Parse hosts
    if hosts:
        host_list = [h.strip() for h in hosts.split(",")]
    elif hosts_file:
        host_list = Path(hosts_file).read_text().strip().split("\n")
    else:
        console.print("[red]Error: Must provide --hosts or --hosts-file[/red]")
        raise typer.Exit(1)

    async def _scan():
        async with get_api_client() as client:
            # Start scan
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(description="Initiating scan...", total=None)

                response = await client.post(
                    "/scan/assess",
                    json={"vuln_id": vuln, "hosts": host_list, "hunt_mode": hunt}
                )
                response.raise_for_status()
                scan_data = response.json()
                scan_id = scan_data["id"]

            console.print(f"[green]Scan started: {scan_id}[/green]")
            console.print("Waiting for scan to complete...")

            # Poll for completion
            while True:
                await asyncio.sleep(2)
                response = await client.get(f"/scan/assess/{scan_id}")
                response.raise_for_status()
                scan_data = response.json()

                if scan_data["status"] in ["completed", "failed"]:
                    break

                console.print(".", end="")

            console.print("\n[green]Scan completed![/green]")

            # Get report if requested
            if report:
                response = await client.get(f"/report/{scan_id}/html")
                response.raise_for_status()
                Path(report).write_text(response.text)
                console.print(f"[green]Report saved to {report}[/green]")

            return scan_data

    try:
        result = asyncio.run(_scan())

        if output == "json":
            import json
            console.print_json(json.dumps(result, indent=2))

        elif output == "csv":
            # Print CSV format
            console.print("Hostname,Status,Findings")
            for host in result["hosts"]:
                console.print(f"{host['hostname']},{host['status']},{len(host['findings'])}")

        else:  # table
            table = Table(title=f"Scan Results: {result['vuln_id']}")
            table.add_column("Hostname", style="cyan")
            table.add_column("Status", style="white")
            table.add_column("Findings", style="yellow")

            for host in result["hosts"]:
                status_style = "green" if host["status"] == "clean" else "red"
                table.add_row(
                    host["hostname"],
                    f"[{status_style}]{host['status']}[/{status_style}]",
                    str(len(host["findings"]))
                )

            console.print(table)

            # Show findings details
            for host in result["hosts"]:
                if host["findings"]:
                    console.print(f"\n[bold]Findings for {host['hostname']}:[/bold]")
                    for finding in host["findings"]:
                        console.print(f"  • {finding['name']}: {finding['current_value']} → {finding['expected_value']}")
                        console.print(f"    Fix: [cyan]{finding['fix_command']}[/cyan]")

    except httpx.HTTPError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# Replace hosts_validate:
@hosts_app.command("validate")
def hosts_validate(hosts: str):
    """Validate SSH connectivity to hosts."""
    host_list = [h.strip() for h in hosts.split(",")]

    async def _validate():
        async with get_api_client() as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(description="Validating hosts...", total=None)

                response = await client.post("/hosts/validate", json={"hosts": host_list})
                response.raise_for_status()
                return response.json()

    try:
        result = asyncio.run(_validate())

        table = Table(title="Host Validation Results")
        table.add_column("Hostname", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Error", style="red")

        for host in result["hosts"]:
            status_style = "green" if host["status"] == "reachable" else "red"
            table.add_row(
                host["hostname"],
                f"[{status_style}]{host['status']}[/{status_style}]",
                host.get("error", "")
            )

        console.print(table)

    except httpx.HTTPError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# Add history command:
@scan_app.command("history")
def scan_history(
    limit: int = typer.Option(10, help="Number of scans to show"),
    scan_id: str = typer.Option(None, help="Show specific scan by ID"),
):
    """View scan history."""
    async def _history():
        async with get_api_client() as client:
            if scan_id:
                response = await client.get(f"/scan/assess/{scan_id}")
            else:
                response = await client.get(f"/scan/history?limit={limit}")

            response.raise_for_status()
            return response.json()

    try:
        result = asyncio.run(_history())

        if scan_id:
            # Show detailed scan
            console.print_json(str(result))
        else:
            # Show scan list
            table = Table(title="Scan History")
            table.add_column("Scan ID", style="cyan")
            table.add_column("Vulnerability", style="white")
            table.add_column("Status", style="yellow")
            table.add_column("Hosts", style="white")
            table.add_column("Affected", style="red")
            table.add_column("Created", style="white")

            for scan in result:
                table.add_row(
                    scan["id"][:8] + "...",
                    scan["vuln_id"],
                    scan["status"],
                    str(scan["host_count"]),
                    str(scan["affected_count"]),
                    scan["created_at"][:19],
                )

            console.print(table)

    except httpx.HTTPError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
```

**Step 3: Add serve command to run API**

```python
# Add to backend/redfixer/cli/main.py

@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host to bind to"),
    port: int = typer.Option(8000, help="Port to bind to"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
):
    """Start the RedFixer API server."""
    import uvicorn

    console.print(f"[green]Starting RedFixer API server on {host}:{port}[/green]")

    uvicorn.run(
        "redfixer.main:app",
        host=host,
        port=port,
        reload=reload,
    )
```

**Step 4: Test full CLI**

Run: `cd backend && python -m redfixer.cli.main serve` (in one terminal)

In another terminal:
Run: `cd backend && python -m redfixer.cli.main config show`

**Step 5: Commit**

```bash
git add backend/
git commit -m "feat: complete CLI implementation with API integration

- Implement vuln lookup command
- Implement scan command with polling
- Implement hosts validate command
- Add scan history command
- Add serve command to run API
- Integrate with FastAPI backend via httpx
- Rich output formatting

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Phase 7: Frontend - React Application

### Task 7.1: Initialize React + Vite Project

**Files:**
- Create: `frontend/` directory structure

**Step 1: Initialize Vite React project**

Run:
```bash
cd /Users/jay/cc_projects/redfixer
npm create vite@latest frontend -- --template react-ts
```

**Step 2: Install dependencies**

Run:
```bash
cd frontend
npm install
npm install -D tailwindcss postcss autoprefixer
npm install @tanstack/react-query axios
npm install react-router-dom
npx tailwindcss init -p
```

**Step 3: Configure Tailwind CSS**

```javascript
// frontend/tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
```

**Step 4: Update main CSS**

```css
/* frontend/src/index.css */
@tailwind base;
@tailwind components;
@tailwind utilities;
```

**Step 5: Verify app runs**

Run: `npm run dev`

Expected: Vite dev server starts on port 5173

**Step 6: Commit**

```bash
git add frontend/
git commit -m "feat: initialize React 19 + Vite + Tailwind frontend

- Create Vite project with React 19 and TypeScript
- Install and configure Tailwind CSS
- Add TanStack Query for data fetching
- Add React Router for navigation

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 7.2: API Client and React Query Setup

**Files:**
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/api/types.ts`
- Create: `frontend/src/main.tsx` (update)

**Step 1: Create API types**

```typescript
// frontend/src/api/types.ts
export type SeverityEnum = 'critical' | 'important' | 'moderate' | 'low';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type HostStatus = 'pending' | 'scanning' | 'affected' | 'clean' | 'error';

export interface VulnLookupResponse {
  vuln_id: string;
  title: string;
  severity: SeverityEnum;
  description: string;
  affected_packages: Array<{ package: string }>;
  references: string[];
  published_date: string | null;
}

export interface ScanAssessRequest {
  vuln_id: string;
  hosts: string[];
  hunt_mode: boolean;
}

export interface Finding {
  id: string;
  finding_type: string;
  name: string;
  current_value: string;
  expected_value: string;
  severity: SeverityEnum;
  fix_command: string;
  details?: Record<string, any>;
}

export interface HostResult {
  id: string;
  hostname: string;
  status: HostStatus;
  error_message?: string;
  scanned_at?: string;
  findings: Finding[];
}

export interface ScanResponse {
  id: string;
  vuln_id: string;
  vuln_title: string;
  hunt_mode: boolean;
  status: ScanStatus;
  created_at: string;
  completed_at?: string;
  hosts: HostResult[];
}

export interface ScanListItem {
  id: string;
  vuln_id: string;
  vuln_title: string;
  hunt_mode: boolean;
  status: ScanStatus;
  created_at: string;
  completed_at?: string;
  host_count: number;
  affected_count: number;
}
```

**Step 2: Create API client**

```typescript
// frontend/src/api/client.ts
import axios from 'axios';
import type {
  VulnLookupResponse,
  ScanAssessRequest,
  ScanResponse,
  ScanListItem,
} from './types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
const API_KEY = import.meta.env.VITE_API_KEY || 'change-me-in-production';

const client = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'X-API-Key': API_KEY,
  },
});

export const api = {
  // Vulnerability endpoints
  lookupVuln: async (vulnId: string): Promise<VulnLookupResponse> => {
    const { data } = await client.get(`/vuln/lookup/${vulnId}`);
    return data;
  },

  // Scan endpoints
  createScan: async (request: ScanAssessRequest): Promise<ScanResponse> => {
    const { data } = await client.post('/scan/assess', request);
    return data;
  },

  getScan: async (scanId: string): Promise<ScanResponse> => {
    const { data } = await client.get(`/scan/assess/${scanId}`);
    return data;
  },

  getScanHistory: async (limit = 50): Promise<ScanListItem[]> => {
    const { data } = await client.get('/scan/history', { params: { limit } });
    return data;
  },

  // Report endpoints
  downloadReport: async (scanId: string, format: 'json' | 'csv' | 'html'): Promise<Blob> => {
    const { data } = await client.get(`/report/${scanId}/${format}`, {
      responseType: 'blob',
    });
    return data;
  },
};
```

**Step 3: Set up React Query provider**

```typescript
// frontend/src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App.tsx'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
)
```

**Step 4: Create .env file**

```bash
# frontend/.env
VITE_API_BASE_URL=http://localhost:8000/api/v1
VITE_API_KEY=change-me-in-production
```

**Step 5: Commit**

```bash
git add frontend/
git commit -m "feat: add API client and React Query setup

- Create TypeScript types for API
- Create axios-based API client
- Set up React Query provider
- Add environment variables for config

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Phase 8: Deployment Configuration

### Task 8.1: Containerfile and Deployment Scripts

**Files:**
- Create: `deploy/Containerfile`
- Create: `deploy/podman-compose.yml`
- Create: `deploy/redfixer.service`
- Create: `scripts/dev.sh`
- Create: `Makefile`
- Create: `README.md`

**Step 1: Create Containerfile**

```dockerfile
# deploy/Containerfile
# Multi-stage build for RedFixer

# Stage 1: Build frontend
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Build backend
FROM python:3.11-slim AS backend-builder

WORKDIR /app/backend
COPY backend/pyproject.toml backend/requirements.txt* ./
RUN pip install --no-cache-dir build && \
    pip wheel --no-cache-dir --wheel-dir /wheels .

# Stage 3: Final image
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY --from=backend-builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && \
    rm -rf /wheels

# Copy backend code
COPY backend/redfixer ./redfixer

# Copy frontend build
COPY --from=frontend-builder /app/frontend/dist ./static

# Copy config example
COPY config/config.example.yaml /app/config.example.yaml

# Create data directory
RUN mkdir -p /data

# Set environment
ENV REDFIXER_DATABASE__PATH=/data/redfixer.db
ENV REDFIXER_API__HOST=0.0.0.0
ENV REDFIXER_API__PORT=8000

EXPOSE 8000

# Run server
CMD ["python", "-m", "uvicorn", "redfixer.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Step 2: Create podman-compose file**

```yaml
# deploy/podman-compose.yml
version: '3'

services:
  redfixer:
    build:
      context: ..
      dockerfile: deploy/Containerfile
    ports:
      - "8000:8000"
    volumes:
      - redfixer-data:/data
      - ${HOME}/.ssh:/root/.ssh:ro
      - ${HOME}/.redfixer:/root/.redfixer:ro
    environment:
      - REDFIXER_API__API_KEY=${REDFIXER_API_KEY:-change-me-in-production}
    restart: unless-stopped

  ollama:
    image: docker.io/ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama-data:/root/.ollama
    restart: unless-stopped

volumes:
  redfixer-data:
  ollama-data:
```

**Step 3: Create systemd service**

```ini
# deploy/redfixer.service
[Unit]
Description=RedFixer Vulnerability Assessment Service
After=network.target

[Service]
Type=simple
User=redfixer
Group=redfixer
WorkingDirectory=/opt/redfixer
ExecStart=/opt/redfixer/venv/bin/python -m uvicorn redfixer.main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=10

Environment="REDFIXER_DATABASE__PATH=/var/lib/redfixer/redfixer.db"
Environment="REDFIXER_API__API_KEY=CHANGE_ME_IN_PRODUCTION"

[Install]
WantedBy=multi-user.target
```

**Step 4: Create dev script**

```bash
# scripts/dev.sh
#!/bin/bash
# Development script to run backend and frontend concurrently

set -e

echo "Starting RedFixer in development mode..."

# Start backend in background
cd backend
python -m uvicorn redfixer.main:app --reload --port 8000 &
BACKEND_PID=$!

# Start frontend
cd ../frontend
npm run dev &
FRONTEND_PID=$!

# Trap Ctrl+C to kill both processes
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT

# Wait
wait
```

**Step 5: Create Makefile**

```makefile
# Makefile for RedFixer

.PHONY: help dev install test build clean docker-build docker-run

help:
	@echo "RedFixer Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install       - Install dependencies (backend + frontend)"
	@echo "  dev           - Run development servers"
	@echo "  test          - Run tests"
	@echo "  build         - Build production artifacts"
	@echo "  docker-build  - Build Docker/Podman image"
	@echo "  docker-run    - Run with podman-compose"
	@echo "  clean         - Clean build artifacts"

install:
	@echo "Installing backend dependencies..."
	cd backend && pip install -e ".[dev]"
	@echo "Installing frontend dependencies..."
	cd frontend && npm install

dev:
	@echo "Starting development servers..."
	chmod +x scripts/dev.sh
	./scripts/dev.sh

test:
	@echo "Running backend tests..."
	cd backend && pytest -v
	@echo "Running frontend tests..."
	cd frontend && npm run test

build:
	@echo "Building frontend..."
	cd frontend && npm run build
	@echo "Build complete!"

docker-build:
	@echo "Building container image..."
	podman build -t redfixer:latest -f deploy/Containerfile .

docker-run:
	@echo "Starting with podman-compose..."
	cd deploy && podman-compose up -d

clean:
	@echo "Cleaning build artifacts..."
	rm -rf backend/dist backend/build backend/*.egg-info
	rm -rf frontend/dist frontend/node_modules/.vite
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
```

**Step 6: Create comprehensive README**

```markdown
# RedFixer

RHEL9 Vulnerability Assessment and Remediation Tool

## Features

- **Vulnerability Lookup**: Fetch RHSA and CVE details from Red Hat APIs
- **Host Scanning**: SSH-based assessment of package vulnerabilities
- **Hunt Mode**: LLM-powered artifact detection for exploitation indicators
- **Multiple Interfaces**: Web UI, CLI, and REST API
- **Flexible Deployment**: venv, Podman, or Kubernetes

## Quick Start

### Prerequisites

**For RHEL9/Linux:**
- Python 3.11+
- Node.js 20+
- Podman (optional)

**For macOS:**
- Python 3.11+ (via Homebrew)
- Node.js 20+ (via Homebrew)
- Podman Desktop (optional)

### Installation

#### Option 1: Development Mode

```bash
# Clone repository
git clone <repo-url>
cd redfixer

# Install dependencies
make install

# Run development servers
make dev
```

Access:
- API: http://localhost:8000/docs
- Frontend: http://localhost:5173

#### Option 2: Podman Deployment

```bash
# Build image
make docker-build

# Run with compose
make docker-run
```

#### Option 3: Production venv (RHEL9)

```bash
# Install system dependencies
sudo dnf install python3.11 python3.11-pip

# Create installation
sudo mkdir -p /opt/redfixer
cd /opt/redfixer
python3.11 -m venv venv
source venv/bin/activate
pip install /path/to/redfixer/backend

# Configure
cp /path/to/config.example.yaml ~/.redfixer/config.yaml
vim ~/.redfixer/config.yaml

# Install systemd service
sudo cp deploy/redfixer.service /etc/systemd/system/
sudo systemctl enable --now redfixer
```

## CLI Usage

```bash
# Look up vulnerability
redfixer vuln lookup RHSA-2024:1234

# Scan hosts
redfixer scan --vuln CVE-2024-12345 --hosts server1,server2

# Enable hunt mode
redfixer scan --vuln RHSA-2024:1234 --hosts-file hosts.txt --hunt

# Generate report
redfixer scan --vuln CVE-2024-12345 --hosts server1 --report report.html

# Validate connectivity
redfixer hosts validate server1,server2,server3

# View scan history
redfixer history

# Run API server
redfixer serve --host 0.0.0.0 --port 8000
```

## Configuration

Edit `~/.redfixer/config.yaml`:

```yaml
api:
  host: 0.0.0.0
  port: 8000
  api_key: "your-secret-key"

ssh:
  user: root
  key_path: ~/.ssh/id_rsa

llm:
  provider: ollama  # ollama | uai_studio | openai | anthropic
  ollama:
    endpoint: http://localhost:11434
    model: llama3.1:8b
```

## Architecture

```
┌─────────────────────────────────────────────┐
│              RedFixer                        │
├──────────┬──────────┬──────────────────────┤
│ Web UI   │   CLI    │        API           │
│ React 19 │  Typer   │      FastAPI         │
├──────────┴──────────┴──────────────────────┤
│           Core Services                     │
│  VulnFetcher │ HostScanner │ HuntEngine    │
├─────────────────────────────────────────────┤
│           SQLite Database                   │
└─────────────────────────────────────────────┘
```

## Development

```bash
# Run tests
make test

# Build production artifacts
make build

# Clean build files
make clean
```

## License

MIT

## Contributing

Pull requests welcome!
```

**Step 7: Make dev script executable and commit**

```bash
chmod +x scripts/dev.sh

git add deploy/ scripts/ Makefile README.md
git commit -m "feat: add deployment configuration and documentation

- Add multi-stage Containerfile for Podman
- Add podman-compose configuration
- Add systemd service file
- Add development script
- Add Makefile with common tasks
- Add comprehensive README

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Summary and Next Steps

This implementation plan provides a complete, phased approach to building RedFixer with:

**Phase 1**: Foundation (config, database models)
**Phase 2-4**: Core services (VulnFetcher, HostScanner, HuntEngine, LLM integration)
**Phase 5**: FastAPI backend with all routes
**Phase 6**: CLI with Typer
**Phase 7**: React frontend (partially detailed - full component implementation would be next)
**Phase 8**: Deployment configuration

**Total estimated tasks**: 20+ discrete tasks, each broken into 5-7 steps following TDD principles.

---

Plan complete and saved to `docs/plans/2025-12-06-redfixer-implementation.md`.

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration. Use `superpowers:subagent-driven-development` skill.

**2. Parallel Session (separate)** - Open new session with `superpowers:executing-plans`, batch execution with checkpoints.

**Which approach would you prefer?**
