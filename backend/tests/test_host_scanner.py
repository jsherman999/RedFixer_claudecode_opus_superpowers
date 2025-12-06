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
