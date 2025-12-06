"""Tests for HuntEngine service."""
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from typing import List

from redfixer.services.hunt_engine import HuntEngine
from redfixer.services.vuln_fetcher import VulnFetcher
from redfixer.services.host_scanner import HostScanner, HostScanResult, PackageFinding
from redfixer.llm.base import BaseLLM, LLMResponse
from redfixer.models.database import Scan, ScanHost, ScanFinding, ScanStatus, HostStatus, FindingType, Severity
from redfixer.models.schemas import VulnLookupResponse, SeverityEnum


@pytest.fixture
def mock_db():
    """Mock database session."""
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.commit = MagicMock()
    db.add = MagicMock()
    return db


@pytest.fixture
def mock_vuln_fetcher():
    """Mock VulnFetcher."""
    fetcher = AsyncMock(spec=VulnFetcher)
    fetcher.fetch_vulnerability.return_value = VulnLookupResponse(
        vuln_id="RHSA-2024-0001",
        title="Test Vulnerability",
        severity=SeverityEnum.IMPORTANT,
        description="Test description",
        affected_packages=[
            {"package": "httpd-2.4.51-1.el9"},
            {"package": "httpd-tools-2.4.51-1.el9"}
        ],
        references=["https://access.redhat.com/errata/RHSA-2024-0001"],
        published_date=datetime(2024, 1, 1)
    )
    return fetcher


@pytest.fixture
def mock_host_scanner():
    """Mock HostScanner."""
    scanner = AsyncMock(spec=HostScanner)
    return scanner


@pytest.fixture
def mock_llm():
    """Mock LLM."""
    llm = AsyncMock(spec=BaseLLM)
    llm.generate.return_value = LLMResponse(
        content="Search for suspicious httpd logs and recent file modifications",
        confidence=0.85
    )
    return llm


@pytest.fixture
def mock_scan(mock_db):
    """Mock Scan record."""
    scan = Scan(
        id="scan-123",
        vuln_id="RHSA-2024-0001",
        vuln_title="Test Vulnerability",
        hunt_mode=False,
        status=ScanStatus.PENDING,
        created_at=datetime.utcnow()
    )
    mock_db.query.return_value.filter.return_value.first.return_value = scan
    return scan


@pytest.mark.asyncio
async def test_run_scan_without_hunt_mode(mock_db, mock_vuln_fetcher, mock_host_scanner, mock_llm, mock_scan):
    """Test successful scan without hunt mode."""
    # Setup
    mock_scan.hunt_mode = False

    # Mock host scanner to return affected host
    mock_host_scanner.scan_host.return_value = HostScanResult(
        hostname="host1.example.com",
        is_affected=True,
        findings=[
            PackageFinding(
                name="httpd",
                current_version="2.4.50-1",
                expected_version="2.4.51-1",
                severity=SeverityEnum.IMPORTANT,
                fix_command="dnf update httpd"
            )
        ]
    )

    engine = HuntEngine(
        vuln_fetcher=mock_vuln_fetcher,
        host_scanner=mock_host_scanner,
        llm=mock_llm,
        db=mock_db
    )

    # Execute
    await engine.run_scan(
        scan_id="scan-123",
        vuln_id="RHSA-2024-0001",
        hostnames=["host1.example.com"],
        hunt_mode=False
    )

    # Verify vulnerability was fetched
    mock_vuln_fetcher.fetch_vulnerability.assert_called_once_with("RHSA-2024-0001")

    # Verify host was scanned
    mock_host_scanner.scan_host.assert_called_once()

    # Verify LLM was NOT called (hunt mode disabled)
    mock_llm.generate.assert_not_called()

    # Verify scan status was updated to COMPLETED
    assert mock_scan.status == ScanStatus.COMPLETED
    assert mock_scan.completed_at is not None

    # Verify database commit was called
    assert mock_db.commit.call_count >= 1


@pytest.mark.asyncio
async def test_run_scan_with_hunt_mode(mock_db, mock_vuln_fetcher, mock_host_scanner, mock_llm, mock_scan):
    """Test successful scan with hunt mode enabled."""
    # Setup
    mock_scan.hunt_mode = True

    # Mock host scanner to return affected host
    mock_host_scanner.scan_host.return_value = HostScanResult(
        hostname="host1.example.com",
        is_affected=True,
        findings=[
            PackageFinding(
                name="httpd",
                current_version="2.4.50-1",
                expected_version="2.4.51-1",
                severity=SeverityEnum.IMPORTANT,
                fix_command="dnf update httpd"
            )
        ]
    )

    engine = HuntEngine(
        vuln_fetcher=mock_vuln_fetcher,
        host_scanner=mock_host_scanner,
        llm=mock_llm,
        db=mock_db
    )

    # Execute
    await engine.run_scan(
        scan_id="scan-123",
        vuln_id="RHSA-2024-0001",
        hostnames=["host1.example.com"],
        hunt_mode=True
    )

    # Verify vulnerability was fetched
    mock_vuln_fetcher.fetch_vulnerability.assert_called_once_with("RHSA-2024-0001")

    # Verify host was scanned
    mock_host_scanner.scan_host.assert_called_once()

    # Verify LLM was called (hunt mode enabled and host affected)
    mock_llm.generate.assert_called_once()
    call_args = mock_llm.generate.call_args
    assert "RHSA-2024-0001" in call_args[1]["prompt"]
    assert "Test Vulnerability" in call_args[1]["prompt"]
    assert "host1.example.com" in call_args[1]["prompt"]
    assert call_args[1]["system_prompt"] is not None

    # Verify scan status was updated to COMPLETED
    assert mock_scan.status == ScanStatus.COMPLETED

    # Verify database commit was called
    assert mock_db.commit.call_count >= 1


@pytest.mark.asyncio
async def test_run_scan_multiple_hosts(mock_db, mock_vuln_fetcher, mock_host_scanner, mock_llm, mock_scan):
    """Test scan with multiple hosts."""
    # Setup
    mock_scan.hunt_mode = False

    # Mock different results for different hosts
    def scan_side_effect(hostname, vuln_id, severity, affected_packages):
        if hostname == "host1.example.com":
            return HostScanResult(
                hostname=hostname,
                is_affected=True,
                findings=[
                    PackageFinding(
                        name="httpd",
                        current_version="2.4.50-1",
                        expected_version="2.4.51-1",
                        severity=SeverityEnum.IMPORTANT,
                        fix_command="dnf update httpd"
                    )
                ]
            )
        else:
            return HostScanResult(
                hostname=hostname,
                is_affected=False,
                findings=[]
            )

    mock_host_scanner.scan_host.side_effect = scan_side_effect

    engine = HuntEngine(
        vuln_fetcher=mock_vuln_fetcher,
        host_scanner=mock_host_scanner,
        llm=mock_llm,
        db=mock_db
    )

    # Execute
    await engine.run_scan(
        scan_id="scan-123",
        vuln_id="RHSA-2024-0001",
        hostnames=["host1.example.com", "host2.example.com", "host3.example.com"],
        hunt_mode=False
    )

    # Verify all hosts were scanned
    assert mock_host_scanner.scan_host.call_count == 3

    # Verify scan completed successfully
    assert mock_scan.status == ScanStatus.COMPLETED


@pytest.mark.asyncio
async def test_run_scan_partial_failure(mock_db, mock_vuln_fetcher, mock_host_scanner, mock_llm, mock_scan):
    """Test scan continues when one host fails."""
    # Setup
    mock_scan.hunt_mode = False

    # Mock host scanner to fail on second host
    def scan_side_effect(hostname, vuln_id, severity, affected_packages):
        if hostname == "host2.example.com":
            return HostScanResult(
                hostname=hostname,
                is_affected=False,
                findings=[],
                error="Connection timeout"
            )
        else:
            return HostScanResult(
                hostname=hostname,
                is_affected=True,
                findings=[
                    PackageFinding(
                        name="httpd",
                        current_version="2.4.50-1",
                        expected_version="2.4.51-1",
                        severity=SeverityEnum.IMPORTANT,
                        fix_command="dnf update httpd"
                    )
                ]
            )

    mock_host_scanner.scan_host.side_effect = scan_side_effect

    engine = HuntEngine(
        vuln_fetcher=mock_vuln_fetcher,
        host_scanner=mock_host_scanner,
        llm=mock_llm,
        db=mock_db
    )

    # Execute
    await engine.run_scan(
        scan_id="scan-123",
        vuln_id="RHSA-2024-0001",
        hostnames=["host1.example.com", "host2.example.com", "host3.example.com"],
        hunt_mode=False
    )

    # Verify all hosts were attempted
    assert mock_host_scanner.scan_host.call_count == 3

    # Verify scan still completed
    assert mock_scan.status == ScanStatus.COMPLETED


@pytest.mark.asyncio
async def test_run_scan_vuln_fetch_failure(mock_db, mock_vuln_fetcher, mock_host_scanner, mock_llm, mock_scan):
    """Test scan fails gracefully when vulnerability fetch fails."""
    # Setup
    mock_vuln_fetcher.fetch_vulnerability.side_effect = ValueError("Vulnerability not found")

    engine = HuntEngine(
        vuln_fetcher=mock_vuln_fetcher,
        host_scanner=mock_host_scanner,
        llm=mock_llm,
        db=mock_db
    )

    # Execute - expect exception to be raised
    with pytest.raises(ValueError, match="Vulnerability not found"):
        await engine.run_scan(
            scan_id="scan-123",
            vuln_id="RHSA-9999-9999",
            hostnames=["host1.example.com"],
            hunt_mode=False
        )

    # Verify scan was marked as FAILED
    assert mock_scan.status == ScanStatus.FAILED

    # Verify hosts were not scanned
    mock_host_scanner.scan_host.assert_not_called()


@pytest.mark.asyncio
async def test_run_scan_database_updates(mock_db, mock_vuln_fetcher, mock_host_scanner, mock_llm, mock_scan):
    """Test that database records are created correctly."""
    # Setup
    mock_scan.hunt_mode = True
    created_hosts = []
    created_findings = []

    def add_side_effect(obj):
        if isinstance(obj, ScanHost):
            created_hosts.append(obj)
        elif isinstance(obj, ScanFinding):
            created_findings.append(obj)

    mock_db.add.side_effect = add_side_effect

    # Mock host scanner to return affected host
    mock_host_scanner.scan_host.return_value = HostScanResult(
        hostname="host1.example.com",
        is_affected=True,
        findings=[
            PackageFinding(
                name="httpd",
                current_version="2.4.50-1",
                expected_version="2.4.51-1",
                severity=SeverityEnum.IMPORTANT,
                fix_command="dnf update httpd"
            )
        ]
    )

    engine = HuntEngine(
        vuln_fetcher=mock_vuln_fetcher,
        host_scanner=mock_host_scanner,
        llm=mock_llm,
        db=mock_db
    )

    # Execute
    await engine.run_scan(
        scan_id="scan-123",
        vuln_id="RHSA-2024-0001",
        hostnames=["host1.example.com"],
        hunt_mode=True
    )

    # Verify ScanHost was created
    assert len(created_hosts) == 1
    host = created_hosts[0]
    assert host.scan_id == "scan-123"
    assert host.hostname == "host1.example.com"
    assert host.status == HostStatus.AFFECTED
    assert host.scanned_at is not None

    # Verify ScanFindings were created (package finding + hunt artifact)
    assert len(created_findings) >= 1

    # Verify at least one package finding exists
    package_findings = [f for f in created_findings if f.finding_type == FindingType.PACKAGE]
    assert len(package_findings) == 1
    pkg_finding = package_findings[0]
    assert pkg_finding.name == "httpd"
    assert pkg_finding.current_value == "2.4.50-1"
    assert pkg_finding.expected_value == "2.4.51-1"
    assert pkg_finding.severity == Severity.IMPORTANT

    # Verify hunt artifact finding was created
    hunt_findings = [f for f in created_findings if f.finding_type == FindingType.HUNT_ARTIFACT]
    assert len(hunt_findings) == 1
    hunt_finding = hunt_findings[0]
    assert "LLM Hunt Analysis" in hunt_finding.name
    assert hunt_finding.details is not None
    assert "confidence" in hunt_finding.details


@pytest.mark.asyncio
async def test_run_scan_clean_host_no_llm_call(mock_db, mock_vuln_fetcher, mock_host_scanner, mock_llm, mock_scan):
    """Test that LLM is not called for clean hosts even in hunt mode."""
    # Setup
    mock_scan.hunt_mode = True

    # Mock host scanner to return clean host
    mock_host_scanner.scan_host.return_value = HostScanResult(
        hostname="host1.example.com",
        is_affected=False,
        findings=[]
    )

    engine = HuntEngine(
        vuln_fetcher=mock_vuln_fetcher,
        host_scanner=mock_host_scanner,
        llm=mock_llm,
        db=mock_db
    )

    # Execute
    await engine.run_scan(
        scan_id="scan-123",
        vuln_id="RHSA-2024-0001",
        hostnames=["host1.example.com"],
        hunt_mode=True
    )

    # Verify LLM was NOT called (host is clean)
    mock_llm.generate.assert_not_called()

    # Verify scan completed successfully
    assert mock_scan.status == ScanStatus.COMPLETED
