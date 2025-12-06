"""HuntEngine service for orchestrating vulnerability scanning and LLM-powered artifact hunting."""
from datetime import datetime
from typing import List

from sqlalchemy.orm import Session

from redfixer.llm.base import BaseLLM
from redfixer.models.database import (
    Scan,
    ScanHost,
    ScanFinding,
    ScanStatus,
    HostStatus,
    FindingType,
    Severity,
)
from redfixer.models.schemas import SeverityEnum
from redfixer.services.host_scanner import HostScanner
from redfixer.services.vuln_fetcher import VulnFetcher


class HuntEngine:
    """
    Orchestrates vulnerability scanning and LLM-powered artifact hunting.

    This service coordinates:
    1. Fetching vulnerability data
    2. Scanning hosts for vulnerable packages
    3. Using LLM to search for exploitation artifacts (in hunt mode)
    4. Storing all results in the database
    """

    def __init__(
        self,
        vuln_fetcher: VulnFetcher,
        host_scanner: HostScanner,
        llm: BaseLLM,
        db: Session,
    ):
        """
        Initialize HuntEngine.

        Args:
            vuln_fetcher: Service for fetching vulnerability data
            host_scanner: Service for scanning hosts
            llm: LLM provider for artifact hunting
            db: Database session
        """
        self.vuln_fetcher = vuln_fetcher
        self.host_scanner = host_scanner
        self.llm = llm
        self.db = db

    async def run_scan(
        self,
        scan_id: str,
        vuln_id: str,
        hostnames: List[str],
        hunt_mode: bool,
    ) -> None:
        """
        Run a complete vulnerability scan.

        Args:
            scan_id: ID of the scan record
            vuln_id: RHSA or CVE identifier
            hostnames: List of hostnames to scan
            hunt_mode: Whether to use LLM for artifact hunting

        This method:
        1. Fetches vulnerability data
        2. Scans each host for vulnerable packages
        3. If hunt_mode and host is affected, uses LLM to search for artifacts
        4. Stores all results in database
        5. Updates scan status to COMPLETED or FAILED
        """
        # Get scan record
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Update scan status to RUNNING
        scan.status = ScanStatus.RUNNING
        self.db.commit()

        try:
            # Step 1: Fetch vulnerability data
            vuln_data = await self.vuln_fetcher.fetch_vulnerability(vuln_id)

            # Step 2: Scan each host
            for hostname in hostnames:
                await self._scan_single_host(
                    scan=scan,
                    hostname=hostname,
                    vuln_data=vuln_data,
                    hunt_mode=hunt_mode,
                )

            # Step 3: Mark scan as completed
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            self.db.commit()

        except Exception as e:
            # Mark scan as failed
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.utcnow()
            self.db.commit()
            raise

    async def _scan_single_host(
        self,
        scan: Scan,
        hostname: str,
        vuln_data,
        hunt_mode: bool,
    ) -> None:
        """
        Scan a single host and store results.

        Args:
            scan: Scan record
            hostname: Hostname to scan
            vuln_data: Vulnerability data from VulnFetcher
            hunt_mode: Whether to use LLM for artifact hunting
        """
        # Create ScanHost record
        scan_host = ScanHost(
            scan_id=scan.id,
            hostname=hostname,
            status=HostStatus.SCANNING,
        )
        self.db.add(scan_host)
        self.db.commit()

        try:
            # Scan host for vulnerable packages
            scan_result = await self.host_scanner.scan_host(
                hostname=hostname,
                vuln_id=vuln_data.vuln_id,
                severity=vuln_data.severity,
                affected_packages=vuln_data.affected_packages,
            )

            # Update host status based on scan result
            if scan_result.error:
                scan_host.status = HostStatus.ERROR
                scan_host.error_message = scan_result.error
            elif scan_result.is_affected:
                scan_host.status = HostStatus.AFFECTED
            else:
                scan_host.status = HostStatus.CLEAN

            scan_host.scanned_at = datetime.utcnow()
            self.db.commit()

            # Store package findings
            for finding in scan_result.findings:
                self._store_package_finding(scan_host, finding)

            # If host is affected and hunt mode is enabled, use LLM
            if scan_result.is_affected and hunt_mode and not scan_result.error:
                await self._hunt_for_artifacts(
                    scan_host=scan_host,
                    vuln_data=vuln_data,
                    hostname=hostname,
                )

        except Exception as e:
            # Update host with error
            scan_host.status = HostStatus.ERROR
            scan_host.error_message = str(e)
            scan_host.scanned_at = datetime.utcnow()
            self.db.commit()
            # Don't re-raise - continue with other hosts

    def _store_package_finding(self, scan_host: ScanHost, finding) -> None:
        """
        Store a package finding in the database.

        Args:
            scan_host: ScanHost record
            finding: PackageFinding from HostScanner
        """
        # Map SeverityEnum to database Severity enum
        severity_map = {
            SeverityEnum.CRITICAL: Severity.CRITICAL,
            SeverityEnum.IMPORTANT: Severity.IMPORTANT,
            SeverityEnum.MODERATE: Severity.MODERATE,
            SeverityEnum.LOW: Severity.LOW,
        }

        scan_finding = ScanFinding(
            scan_host_id=scan_host.id,
            finding_type=FindingType.PACKAGE,
            name=finding.name,
            current_value=finding.current_version,
            expected_value=finding.expected_version,
            severity=severity_map[finding.severity],
            fix_command=finding.fix_command,
            details=None,
        )
        self.db.add(scan_finding)
        self.db.commit()

    async def _hunt_for_artifacts(
        self,
        scan_host: ScanHost,
        vuln_data,
        hostname: str,
    ) -> None:
        """
        Use LLM to search for exploitation artifacts.

        Args:
            scan_host: ScanHost record
            vuln_data: Vulnerability data
            hostname: Hostname being analyzed
        """
        # Build package list for prompt
        package_names = [
            pkg.get("package", "").split("-")[0]
            for pkg in vuln_data.affected_packages
            if pkg.get("package")
        ]
        package_list = ", ".join(set(package_names)) if package_names else "unknown"

        # Build LLM prompt
        system_prompt = "You are a security analyst searching for signs of exploitation."

        prompt = f"""Analyze this RHEL system for signs that vulnerability {vuln_data.vuln_id} ({vuln_data.title}) has been exploited. Search for:
- Suspicious log entries related to {package_list}
- Recent file modifications in package directories
- Unusual processes or connections
- Common exploit artifacts for this CVE

Hostname: {hostname}
Affected packages: {package_list}

Provide specific commands to run and what to look for."""

        # Call LLM
        try:
            llm_response = await self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
            )

            # Store LLM finding
            scan_finding = ScanFinding(
                scan_host_id=scan_host.id,
                finding_type=FindingType.HUNT_ARTIFACT,
                name=f"LLM Hunt Analysis for {vuln_data.vuln_id}",
                current_value="N/A",
                expected_value="N/A",
                severity=Severity.MODERATE,  # Default severity for hunt artifacts
                fix_command="Review LLM recommendations and investigate",
                details={
                    "llm_analysis": llm_response.content,
                    "confidence": llm_response.confidence,
                    "vuln_id": vuln_data.vuln_id,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
            self.db.add(scan_finding)
            self.db.commit()

        except Exception as e:
            # Log error but don't fail the scan
            # In a production system, you'd log this properly
            pass
