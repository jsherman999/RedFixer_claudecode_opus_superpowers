"""Tests for host API routes."""
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from redfixer.main_test import app
from redfixer.models.database import Scan, ScanHost, ScanStatus, HostStatus
from redfixer.api.dependencies import get_db_dependency, get_settings_dependency
from redfixer.config import Settings, APISettings, DatabaseSettings, LLMSettings


# Test database session fixture
@pytest.fixture
def test_db(tmp_path):
    """Create a test database session."""
    from redfixer.db.session import get_db, init_db
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
def sample_scan_with_hosts(test_db):
    """Create sample scan with multiple hosts."""
    scan = Scan(
        vuln_id="CVE-2021-44228",
        vuln_title="Log4j RCE",
        hunt_mode=False,
        status=ScanStatus.COMPLETED,
        completed_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()

    # Create hosts with different statuses
    hosts = [
        ScanHost(
            scan_id=scan.id,
            hostname="host1.example.com",
            status=HostStatus.AFFECTED,
            scanned_at=datetime.now(timezone.utc),
        ),
        ScanHost(
            scan_id=scan.id,
            hostname="host2.example.com",
            status=HostStatus.CLEAN,
            scanned_at=datetime.now(timezone.utc),
        ),
        ScanHost(
            scan_id=scan.id,
            hostname="host3.example.com",
            status=HostStatus.ERROR,
            error_message="Connection timeout",
            scanned_at=datetime.now(timezone.utc),
        ),
    ]

    for host in hosts:
        test_db.add(host)
    test_db.commit()

    return scan, hosts


class TestListHosts:
    """Tests for GET /hosts endpoint."""

    def test_list_hosts_success(self, test_client, sample_scan_with_hosts):
        """Test listing all hosts."""
        response = test_client.get(
            "/hosts",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

        # Verify host data
        hostnames = [h["hostname"] for h in data]
        assert "host1.example.com" in hostnames
        assert "host2.example.com" in hostnames
        assert "host3.example.com" in hostnames

    def test_list_hosts_filter_by_hostname(self, test_client, sample_scan_with_hosts):
        """Test filtering hosts by hostname."""
        response = test_client.get(
            "/hosts?hostname=host1.example.com",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["hostname"] == "host1.example.com"
        assert data[0]["status"] == "affected"

    def test_list_hosts_filter_by_status(self, test_client, sample_scan_with_hosts):
        """Test filtering hosts by status."""
        response = test_client.get(
            "/hosts?status=clean",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["hostname"] == "host2.example.com"
        assert data[0]["status"] == "clean"

    def test_list_hosts_invalid_status(self, test_client, sample_scan_with_hosts):
        """Test filtering with invalid status value."""
        response = test_client.get(
            "/hosts?status=invalid",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 400
        assert "Invalid status" in response.json()["detail"]

    def test_list_hosts_pagination(self, test_client, sample_scan_with_hosts):
        """Test pagination parameters."""
        # Get first 2 hosts
        response = test_client.get(
            "/hosts?limit=2",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

        # Get remaining hosts with skip
        response = test_client.get(
            "/hosts?skip=2&limit=10",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1

    def test_list_hosts_limit_validation(self, test_client, sample_scan_with_hosts):
        """Test limit validation."""
        response = test_client.get(
            "/hosts?limit=2000",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 400
        assert "cannot exceed 1000" in response.json()["detail"]

    def test_list_hosts_empty_result(self, test_client, test_db):
        """Test listing hosts when none exist."""
        response = test_client.get(
            "/hosts",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 0


class TestGetHostHistory:
    """Tests for GET /hosts/{hostname}/history endpoint."""

    def test_get_host_history_success(self, test_client, test_db):
        """Test getting scan history for a host."""
        # Create multiple scans for the same host
        for i in range(3):
            scan = Scan(
                vuln_id=f"CVE-2021-{i}",
                vuln_title=f"Test Vuln {i}",
                hunt_mode=False,
                status=ScanStatus.COMPLETED,
            )
            test_db.add(scan)
            test_db.commit()

            host = ScanHost(
                scan_id=scan.id,
                hostname="repeated.example.com",
                status=HostStatus.CLEAN,
                scanned_at=datetime.now(timezone.utc),
            )
            test_db.add(host)
            test_db.commit()

        response = test_client.get(
            "/hosts/repeated.example.com/history",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

        # All should be for the same hostname
        for host_record in data:
            assert host_record["hostname"] == "repeated.example.com"

    def test_get_host_history_not_found(self, test_client, test_db):
        """Test getting history for non-existent host."""
        response = test_client.get(
            "/hosts/nonexistent.example.com/history",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 404
        assert "No scan history found" in response.json()["detail"]

    def test_get_host_history_pagination(self, test_client, test_db):
        """Test pagination of host history."""
        # Create 5 scans for the same host
        for i in range(5):
            scan = Scan(
                vuln_id=f"CVE-2021-{i}",
                vuln_title=f"Test Vuln {i}",
                hunt_mode=False,
                status=ScanStatus.COMPLETED,
            )
            test_db.add(scan)
            test_db.commit()

            host = ScanHost(
                scan_id=scan.id,
                hostname="paginated.example.com",
                status=HostStatus.CLEAN,
                scanned_at=datetime.now(timezone.utc),
            )
            test_db.add(host)
            test_db.commit()

        # Get first 2
        response = test_client.get(
            "/hosts/paginated.example.com/history?limit=2",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

        # Get next 2
        response = test_client.get(
            "/hosts/paginated.example.com/history?skip=2&limit=2",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_get_host_history_limit_validation(self, test_client, test_db):
        """Test limit validation."""
        response = test_client.get(
            "/hosts/test.example.com/history?limit=2000",
            headers={"X-API-Key": "test-api-key"}
        )

        assert response.status_code == 400
        assert "cannot exceed 1000" in response.json()["detail"]


class TestAuthentication:
    """Tests for API key authentication."""

    def test_missing_api_key(self, test_client, sample_scan_with_hosts):
        """Test request without API key."""
        response = test_client.get("/hosts")

        assert response.status_code == 422  # Missing required header

    def test_invalid_api_key(self, test_client, sample_scan_with_hosts):
        """Test request with invalid API key."""
        response = test_client.get(
            "/hosts",
            headers={"X-API-Key": "wrong-key"}
        )

        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]
