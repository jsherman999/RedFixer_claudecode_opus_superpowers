"""Vulnerability fetcher service for Red Hat APIs."""
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.orm import Session

from redfixer.config import get_settings
from redfixer.models.database import VulnCache
from redfixer.models.schemas import SeverityEnum, VulnLookupResponse


class VulnFetcher:
    """Fetches vulnerability data from Red Hat APIs."""

    BASE_URL = "https://access.redhat.com/hydra/rest/securitydata"

    def __init__(self, db: Optional[Session] = None):
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

    async def _fetch_rhsa(self, rhsa_id: str) -> Dict[str, Any]:
        """Fetch RHSA data from Red Hat API."""
        url = f"{self.BASE_URL}/cvrf/{rhsa_id}.json"

        auth = None
        if self.settings.redhat.username and self.settings.redhat.password:
            auth = (self.settings.redhat.username, self.settings.redhat.password)

        try:
            response = await self.client.get(url, auth=auth)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(
                f"Failed to fetch RHSA {rhsa_id}: HTTP {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise ValueError(
                f"Failed to fetch RHSA {rhsa_id}: {str(e)}"
            ) from e

    async def _fetch_cve(self, cve_id: str) -> Dict[str, Any]:
        """Fetch CVE data from Red Hat API."""
        url = f"{self.BASE_URL}/cve/{cve_id}.json"

        auth = None
        if self.settings.redhat.username and self.settings.redhat.password:
            auth = (self.settings.redhat.username, self.settings.redhat.password)

        try:
            response = await self.client.get(url, auth=auth)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(
                f"Failed to fetch CVE {cve_id}: HTTP {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise ValueError(
                f"Failed to fetch CVE {cve_id}: {str(e)}"
            ) from e

    def _parse_vulnerability_data(self, vuln_id: str, data: Dict[str, Any]) -> VulnLookupResponse:
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
            title = data.get("bugzilla", {}).get("description", vuln_id)
            severity = self._map_severity(
                data.get("threat_severity", "Moderate")
            )
            # Handle details as either list or string
            details = data.get("details", "")
            if isinstance(details, list):
                description = "\n".join(details) if details else ""
            else:
                description = details

            # Extract affected packages from package_state
            affected_packages = []
            for state in data.get("package_state", []):
                package_name = state.get("package_name", "")
                if package_name:
                    affected_packages.append({"package": package_name})

            # Get references from upstream and advisories
            references = []
            for ref in data.get("references", []):
                references.append(ref)

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

    def _get_from_cache(self, vuln_id: str) -> Optional[VulnLookupResponse]:
        """Get vulnerability from cache if not expired."""
        cached = self.db.query(VulnCache).filter(VulnCache.vuln_id == vuln_id).first()

        if cached and cached.expires_at > datetime.utcnow():
            return self._parse_vulnerability_data(vuln_id, cached.data)

        return None

    def _cache_result(self, vuln_id: str, data: Dict[str, Any]) -> None:
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
