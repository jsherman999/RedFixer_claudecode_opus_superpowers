"""Tests for health check API routes."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from unittest.mock import MagicMock

from redfixer.main_test import app
from redfixer.api.dependencies import get_db_dependency, get_settings_dependency
from redfixer.config import Settings


# Test database session fixture
@pytest.fixture
def test_db(tmp_path):
    """Create a test database session."""
    from redfixer.db.session import get_db, init_db

    # Initialize test database
    init_db()

    # Get session
    db = next(get_db())
    yield db
    db.close()


@pytest.fixture
def test_settings():
    """Create test settings."""
    from redfixer.config import APISettings, DatabaseSettings, LLMSettings

    settings = Settings(
        api=APISettings(
            host="127.0.0.1",
            port=8000,
            api_key="test-api-key",
        ),
        database=DatabaseSettings(
            path="test.db",
        ),
        llm=LLMSettings(
            provider="ollama",
        ),
    )
    return settings


@pytest.fixture
def test_client(test_db, test_settings):
    """Create a test client with dependency overrides."""
    def override_get_db():
        yield test_db

    def override_get_settings():
        return test_settings

    app.dependency_overrides[get_db_dependency] = override_get_db
    app.dependency_overrides[get_settings_dependency] = override_get_settings

    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


class TestHealthCheck:
    """Tests for GET /health endpoint."""

    def test_health_check_success(self, test_client):
        """Test basic health check."""
        response = test_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "redfixer"

    def test_health_check_no_auth(self, test_client):
        """Test health check doesn't require authentication."""
        response = test_client.get("/health")

        # Should succeed without API key
        assert response.status_code == 200


class TestReadinessCheck:
    """Tests for GET /health/ready endpoint."""

    def test_readiness_check_success(self, test_client):
        """Test readiness check when all dependencies are healthy."""
        response = test_client.get("/health/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert "checks" in data
        assert data["checks"]["database"] == "ok"
        assert data["checks"]["config"] == "ok"

    def test_readiness_check_database_error(self, test_settings):
        """Test readiness check when database is unavailable."""
        # Create a mock database that raises an error
        mock_db = MagicMock()
        mock_db.execute.side_effect = Exception("Database connection failed")

        def override_get_db():
            yield mock_db

        def override_get_settings():
            return test_settings

        app.dependency_overrides[get_db_dependency] = override_get_db
        app.dependency_overrides[get_settings_dependency] = override_get_settings

        client = TestClient(app)

        response = client.get("/health/ready")

        assert response.status_code == 503
        data = response.json()
        assert "checks" in data["detail"]
        assert "error" in data["detail"]["checks"]["database"]

        app.dependency_overrides.clear()

    def test_readiness_check_config_error(self, test_db):
        """Test readiness check when configuration is invalid."""
        # Create invalid settings (missing required fields)
        invalid_settings = MagicMock()
        invalid_settings.api.host = None  # Invalid

        def override_get_db():
            yield test_db

        def override_get_settings():
            return invalid_settings

        app.dependency_overrides[get_db_dependency] = override_get_db
        app.dependency_overrides[get_settings_dependency] = override_get_settings

        client = TestClient(app)

        response = client.get("/health/ready")

        assert response.status_code == 503

        app.dependency_overrides.clear()


class TestInfo:
    """Tests for GET /health/info endpoint."""

    def test_info_success(self, test_client):
        """Test service info endpoint."""
        response = test_client.get("/health/info")

        assert response.status_code == 200
        data = response.json()

        # Verify basic info
        assert data["service"] == "redfixer"
        assert data["version"] == "0.1.0"

        # Verify API info
        assert "api" in data
        assert data["api"]["host"] == "127.0.0.1"
        assert data["api"]["port"] == 8000

        # Verify LLM info
        assert "llm" in data
        assert data["llm"]["provider"] == "ollama"

        # Verify database info
        assert "database" in data
        assert data["database"]["type"] == "sqlite"
        assert "path" in data["database"]

    def test_info_no_auth(self, test_client):
        """Test info endpoint doesn't require authentication."""
        response = test_client.get("/health/info")

        # Should succeed without API key
        assert response.status_code == 200
