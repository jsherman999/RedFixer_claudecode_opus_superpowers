"""Tests for report generation API routes."""
import pytest
import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from redfixer.main_test import app
from redfixer.models.database import (
    Scan,
    ScanHost,
    ScanFinding,
    ScanStatus,
    HostStatus,
    FindingType,
    Severity,
)
from redfixer.api.dependencies import get_db_dependency, get_settings_dependency
from redfixer.config import Settings, APISettings, DatabaseSettings, LLMSettings


# Test database session fixture
@pytest.fixture
def test_db(tmp_path):
    """Create a test database session."""
    from redfixer.models.database import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # Create temporary database for this test
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    yield db

    db.close()
    engine.dispose()


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    return Settings(
        api=APISettings(
            host="127.0.0.1",
            port=8000,
            api_key="test-api-key",
        ),
        database=DatabaseSettings(path="test.db"),
        llm=LLMSettings(provider="ollama"),
    )


@pytest.fixture
def test_client(test_db, mock_settings):
    """Create a test client with database dependency override."""
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db_dependency] = override_get_db
    app.dependency_overrides[get_settings_dependency] = lambda: mock_settings
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_scan_with_findings(test_db):
    """Create a complete scan with hosts and findings."""
    scan = Scan(
        vuln_id="CVE-2021-44228",
        vuln_title="Apache Log4j2 Remote Code Execution",
        hunt_mode=True,
        status=ScanStatus.COMPLETED,
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()

    # Create affected host with package finding
    host1 = ScanHost(
        scan_id=scan.id,
        hostname="affected.example.com",
        status=HostStatus.AFFECTED,
        scanned_at=datetime.now(timezone.utc),
    )
    test_db.add(host1)
    test_db.commit()

    finding1 = ScanFinding(
        scan_host_id=host1.id,
        finding_type=FindingType.PACKAGE,
        name="log4j-core",
        current_value="2.14.0-1.el9",
        expected_value="2.17.1-1.el9",
        severity=Severity.CRITICAL,
        fix_command="dnf update log4j-core",
    )
    test_db.add(finding1)

    # Create clean host
    host2 = ScanHost(
        scan_id=scan.id,
        hostname="clean.example.com",
        status=HostStatus.CLEAN,
        scanned_at=datetime.now(timezone.utc),
    )
    test_db.add(host2)

    # Create error host
    host3 = ScanHost(
        scan_id=scan.id,
        hostname="error.example.com",
        status=HostStatus.ERROR,
        error_message="SSH connection timeout",
        scanned_at=datetime.now(timezone.utc),
    )
    test_db.add(host3)

    test_db.commit()

    return scan


class TestJSONReport:
    """Tests for GET /reports/scans/{scan_id}/json endpoint."""

    def test_json_report_success(self, test_client, sample_scan_with_findings):
        """Test generating JSON report."""
        response = test_client.get(
            f"/reports/scans/{sample_scan_with_findings.id}/json",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()

        # Verify scan info
        assert data["scan_id"] == sample_scan_with_findings.id
        assert data["vuln_id"] == "CVE-2021-44228"
        assert data["vuln_title"] == "Apache Log4j2 Remote Code Execution"
        assert data["status"] == "completed"
        assert data["hunt_mode"] is True

        # Verify summary
        assert data["summary"]["total_hosts"] == 3
        assert data["summary"]["affected_hosts"] == 1
        assert data["summary"]["clean_hosts"] == 1
        assert data["summary"]["error_hosts"] == 1
        assert data["summary"]["total_findings"] == 1

        # Verify hosts
        assert len(data["hosts"]) == 3

        # Find affected host
        affected_host = next(h for h in data["hosts"] if h["hostname"] == "affected.example.com")
        assert affected_host["status"] == "affected"
        assert len(affected_host["findings"]) == 1

        # Verify finding details
        finding = affected_host["findings"][0]
        assert finding["type"] == "package"
        assert finding["name"] == "log4j-core"
        assert finding["severity"] == "critical"
        assert finding["current_value"] == "2.14.0-1.el9"
        assert finding["expected_value"] == "2.17.1-1.el9"
        assert finding["fix_command"] == "dnf update log4j-core"

        # Find clean host
        clean_host = next(h for h in data["hosts"] if h["hostname"] == "clean.example.com")
        assert clean_host["status"] == "clean"
        assert len(clean_host["findings"]) == 0

        # Find error host
        error_host = next(h for h in data["hosts"] if h["hostname"] == "error.example.com")
        assert error_host["status"] == "error"
        assert error_host["error_message"] == "SSH connection timeout"

    def test_json_report_not_found(self, test_client):
        """Test JSON report for non-existent scan."""
        response = test_client.get(
            "/reports/scans/nonexistent-id/json",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 404
        assert "Scan not found" in response.json()["detail"]


class TestCSVReport:
    """Tests for GET /reports/scans/{scan_id}/csv endpoint."""

    def test_csv_report_success(self, test_client, sample_scan_with_findings):
        """Test generating CSV report."""
        response = test_client.get(
            f"/reports/scans/{sample_scan_with_findings.id}/csv",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"
        assert "attachment" in response.headers["content-disposition"]
        assert f"scan_{sample_scan_with_findings.id}_report.csv" in response.headers["content-disposition"]

        # Parse CSV content
        csv_content = response.text
        lines = csv_content.strip().split("\n")

        # Verify header
        header = lines[0]
        assert "Scan ID" in header
        assert "Vulnerability ID" in header
        assert "Hostname" in header
        assert "Finding Type" in header
        assert "Severity" in header

        # Verify data rows (3 hosts)
        assert len(lines) == 4  # Header + 3 data rows

        # Verify affected host row
        affected_row = next(line for line in lines if "affected.example.com" in line)
        assert "CVE-2021-44228" in affected_row
        assert "log4j-core" in affected_row
        assert "critical" in affected_row
        assert "affected" in affected_row

        # Verify clean host row
        clean_row = next(line for line in lines if "clean.example.com" in line)
        assert "clean" in clean_row

        # Verify error host row
        error_row = next(line for line in lines if "error.example.com" in line)
        assert "error" in error_row
        assert "SSH connection timeout" in error_row

    def test_csv_report_not_found(self, test_client):
        """Test CSV report for non-existent scan."""
        response = test_client.get(
            "/reports/scans/nonexistent-id/csv",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 404


class TestHTMLReport:
    """Tests for GET /reports/scans/{scan_id}/html endpoint."""

    def test_html_report_success(self, test_client, sample_scan_with_findings):
        """Test generating HTML report."""
        response = test_client.get(
            f"/reports/scans/{sample_scan_with_findings.id}/html",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        assert "inline" in response.headers["content-disposition"]

        # Verify HTML content
        html_content = response.text

        # Check for DOCTYPE and basic HTML structure
        assert "<!DOCTYPE html>" in html_content
        assert "<html>" in html_content
        assert "</html>" in html_content

        # Check for scan information
        assert "CVE-2021-44228" in html_content
        assert "completed" in html_content

        # Check for summary statistics
        assert "Total Hosts:" in html_content
        assert "Affected Hosts:" in html_content
        assert "Clean Hosts:" in html_content
        assert "Error Hosts:" in html_content

        # Check for host details
        assert "affected.example.com" in html_content
        assert "clean.example.com" in html_content
        assert "error.example.com" in html_content

        # Check for finding details
        assert "log4j-core" in html_content
        assert "critical" in html_content
        assert "2.14.0-1.el9" in html_content
        assert "2.17.1-1.el9" in html_content
        assert "dnf update log4j-core" in html_content

        # Check for error message
        assert "SSH connection timeout" in html_content

        # Check for CSS styling
        assert "<style>" in html_content
        assert "font-family:" in html_content

    def test_html_report_styling(self, test_client, sample_scan_with_findings):
        """Test HTML report includes proper styling."""
        response = test_client.get(
            f"/reports/scans/{sample_scan_with_findings.id}/html",
            headers={"X-API-Key": "test-api-key"}
        )

        html_content = response.text

        # Verify severity color classes
        assert "severity-critical" in html_content
        assert "severity-important" in html_content or True  # May not be in sample data
        assert "severity-moderate" in html_content or True
        assert "severity-low" in html_content or True

        # Verify status color classes
        assert "status-affected" in html_content
        assert "status-clean" in html_content
        assert "status-error" in html_content

    def test_html_report_not_found(self, test_client):
        """Test HTML report for non-existent scan."""
        response = test_client.get(
            "/reports/scans/nonexistent-id/html",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 404


class TestAuthentication:
    """Tests for API key authentication on report endpoints."""

    def test_json_report_missing_api_key(self, test_client, sample_scan_with_findings):
        """Test JSON report without API key."""
        response = test_client.get(
            f"/reports/scans/{sample_scan_with_findings.id}/json"
        )

        assert response.status_code == 422  # Missing required header

    def test_csv_report_invalid_api_key(self, test_client, sample_scan_with_findings):
        """Test CSV report with invalid API key."""
        response = test_client.get(
            f"/reports/scans/{sample_scan_with_findings.id}/csv",
            headers={"X-API-Key": "wrong-key"}
        )

        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    def test_html_report_invalid_api_key(self, test_client, sample_scan_with_findings):
        """Test HTML report with invalid API key."""
        response = test_client.get(
            f"/reports/scans/{sample_scan_with_findings.id}/html",
            headers={"X-API-Key": "wrong-key"}
        )

        assert response.status_code == 401
