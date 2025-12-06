"""Report generation API routes."""
import csv
import io
from typing import Dict, Any, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session, joinedload

from redfixer.api.auth import verify_api_key
from redfixer.api.dependencies import get_db_dependency
from redfixer.models.database import Scan, ScanHost, ScanFinding

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/scans/{scan_id}/json")
async def get_scan_report_json(
    scan_id: str,
    db: Session = Depends(get_db_dependency),
    api_key: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Get scan report in JSON format.

    Args:
        scan_id: Scan ID to generate report for

    Returns:
        Comprehensive scan report with all findings
    """
    # Fetch scan with all related data
    scan = (
        db.query(Scan)
        .options(
            joinedload(Scan.hosts).joinedload(ScanHost.findings)
        )
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build report structure
    report = {
        "scan_id": scan.id,
        "vuln_id": scan.vuln_id,
        "vuln_title": scan.vuln_title,
        "status": scan.status.value,
        "hunt_mode": scan.hunt_mode,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "summary": {
            "total_hosts": len(scan.hosts),
            "affected_hosts": sum(1 for h in scan.hosts if h.status.value == "affected"),
            "clean_hosts": sum(1 for h in scan.hosts if h.status.value == "clean"),
            "error_hosts": sum(1 for h in scan.hosts if h.status.value == "error"),
            "total_findings": sum(len(h.findings) for h in scan.hosts),
        },
        "hosts": [],
    }

    # Add host details
    for host in scan.hosts:
        host_data = {
            "hostname": host.hostname,
            "status": host.status.value,
            "scanned_at": host.scanned_at.isoformat() if host.scanned_at else None,
            "error_message": host.error_message,
            "findings": [],
        }

        # Add findings
        for finding in host.findings:
            finding_data = {
                "type": finding.finding_type.value,
                "name": finding.name,
                "severity": finding.severity.value,
                "current_value": finding.current_value,
                "expected_value": finding.expected_value,
                "fix_command": finding.fix_command,
                "details": finding.details,
            }
            host_data["findings"].append(finding_data)

        report["hosts"].append(host_data)

    return report


@router.get("/scans/{scan_id}/csv")
async def get_scan_report_csv(
    scan_id: str,
    db: Session = Depends(get_db_dependency),
    api_key: str = Depends(verify_api_key),
) -> Response:
    """
    Get scan report in CSV format.

    Args:
        scan_id: Scan ID to generate report for

    Returns:
        CSV file with scan findings
    """
    # Fetch scan with all related data
    scan = (
        db.query(Scan)
        .options(
            joinedload(Scan.hosts).joinedload(ScanHost.findings)
        )
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        "Scan ID",
        "Vulnerability ID",
        "Vulnerability Title",
        "Hostname",
        "Host Status",
        "Scanned At",
        "Finding Type",
        "Finding Name",
        "Severity",
        "Current Value",
        "Expected Value",
        "Fix Command",
        "Error Message",
    ])

    # Write data rows
    for host in scan.hosts:
        if host.findings:
            for finding in host.findings:
                writer.writerow([
                    scan.id,
                    scan.vuln_id,
                    scan.vuln_title,
                    host.hostname,
                    host.status.value,
                    host.scanned_at.isoformat() if host.scanned_at else "",
                    finding.finding_type.value,
                    finding.name,
                    finding.severity.value,
                    finding.current_value,
                    finding.expected_value,
                    finding.fix_command,
                    host.error_message or "",
                ])
        else:
            # Host with no findings (clean or error)
            writer.writerow([
                scan.id,
                scan.vuln_id,
                scan.vuln_title,
                host.hostname,
                host.status.value,
                host.scanned_at.isoformat() if host.scanned_at else "",
                "",
                "",
                "",
                "",
                "",
                "",
                host.error_message or "",
            ])

    # Return as CSV response
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan_id}_report.csv"
        }
    )


@router.get("/scans/{scan_id}/html")
async def get_scan_report_html(
    scan_id: str,
    db: Session = Depends(get_db_dependency),
    api_key: str = Depends(verify_api_key),
) -> Response:
    """
    Get scan report in HTML format.

    Args:
        scan_id: Scan ID to generate report for

    Returns:
        HTML formatted scan report
    """
    # Fetch scan with all related data
    scan = (
        db.query(Scan)
        .options(
            joinedload(Scan.hosts).joinedload(ScanHost.findings)
        )
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Calculate summary statistics
    total_hosts = len(scan.hosts)
    affected_hosts = sum(1 for h in scan.hosts if h.status.value == "AFFECTED")
    clean_hosts = sum(1 for h in scan.hosts if h.status.value == "CLEAN")
    error_hosts = sum(1 for h in scan.hosts if h.status.value == "ERROR")
    total_findings = sum(len(h.findings) for h in scan.hosts)

    # Generate HTML report
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>RedFixer Scan Report - {scan.id}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #c00;
            border-bottom: 3px solid #c00;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #333;
            margin-top: 30px;
        }}
        .summary {{
            background-color: #f9f9f9;
            padding: 15px;
            border-left: 4px solid #c00;
            margin: 20px 0;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 10px;
        }}
        .summary-item {{
            background: white;
            padding: 10px;
            border-radius: 4px;
        }}
        .summary-item label {{
            font-weight: bold;
            color: #666;
            display: block;
            margin-bottom: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #c00;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .status-affected {{
            color: #d00;
            font-weight: bold;
        }}
        .status-clean {{
            color: #0a0;
            font-weight: bold;
        }}
        .status-error {{
            color: #f80;
            font-weight: bold;
        }}
        .severity-critical {{
            color: #d00;
            font-weight: bold;
        }}
        .severity-important {{
            color: #f80;
            font-weight: bold;
        }}
        .severity-moderate {{
            color: #fb0;
        }}
        .severity-low {{
            color: #999;
        }}
        .host-section {{
            margin: 30px 0;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 4px;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>RedFixer Vulnerability Scan Report</h1>

        <div class="summary">
            <h2>Scan Information</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <label>Scan ID:</label>
                    {scan.id}
                </div>
                <div class="summary-item">
                    <label>Vulnerability:</label>
                    {scan.vuln_id}
                </div>
                <div class="summary-item">
                    <label>Status:</label>
                    {scan.status.value}
                </div>
                <div class="summary-item">
                    <label>Hunt Mode:</label>
                    {'Enabled' if scan.hunt_mode else 'Disabled'}
                </div>
                <div class="summary-item">
                    <label>Created:</label>
                    <span class="timestamp">{scan.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.created_at else 'N/A'}</span>
                </div>
                <div class="summary-item">
                    <label>Completed:</label>
                    <span class="timestamp">{scan.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.completed_at else 'N/A'}</span>
                </div>
            </div>
        </div>

        <div class="summary">
            <h2>Summary Statistics</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <label>Total Hosts:</label>
                    {total_hosts}
                </div>
                <div class="summary-item">
                    <label>Affected Hosts:</label>
                    <span class="status-affected">{affected_hosts}</span>
                </div>
                <div class="summary-item">
                    <label>Clean Hosts:</label>
                    <span class="status-clean">{clean_hosts}</span>
                </div>
                <div class="summary-item">
                    <label>Error Hosts:</label>
                    <span class="status-error">{error_hosts}</span>
                </div>
                <div class="summary-item">
                    <label>Total Findings:</label>
                    {total_findings}
                </div>
            </div>
        </div>

        <h2>Host Details</h2>
"""

    # Add host details
    for host in scan.hosts:
        status_class = f"status-{host.status.value.lower()}"
        html += f"""
        <div class="host-section">
            <h3>{host.hostname} <span class="{status_class}">({host.status.value})</span></h3>
            <p class="timestamp">Scanned: {host.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC') if host.scanned_at else 'Not scanned'}</p>
"""

        if host.error_message:
            html += f"""
            <p style="color: #f80;"><strong>Error:</strong> {host.error_message}</p>
"""

        if host.findings:
            html += """
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Name</th>
                        <th>Severity</th>
                        <th>Current</th>
                        <th>Expected</th>
                        <th>Fix Command</th>
                    </tr>
                </thead>
                <tbody>
"""
            for finding in host.findings:
                severity_class = f"severity-{finding.severity.value.lower()}"
                html += f"""
                    <tr>
                        <td>{finding.finding_type.value}</td>
                        <td>{finding.name}</td>
                        <td class="{severity_class}">{finding.severity.value}</td>
                        <td>{finding.current_value}</td>
                        <td>{finding.expected_value}</td>
                        <td><code>{finding.fix_command}</code></td>
                    </tr>
"""
            html += """
                </tbody>
            </table>
"""
        else:
            html += """
            <p>No findings detected.</p>
"""

        html += """
        </div>
"""

    # Close HTML
    html += """
    </div>
</body>
</html>
"""

    return Response(
        content=html,
        media_type="text/html",
        headers={
            "Content-Disposition": f"inline; filename=scan_{scan_id}_report.html"
        }
    )
