"""Host scanner service using Paramiko SSH."""
import asyncio
import re
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

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
    findings: List[PackageFinding]
    error: Optional[str] = None


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
        affected_packages: List[dict],
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
        affected_packages: List[dict],
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

    def _version_to_tuple(self, version: str) -> Tuple[int, ...]:
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
