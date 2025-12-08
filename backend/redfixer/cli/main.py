"""RedFixer CLI application."""
import asyncio
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from redfixer import __version__

app = typer.Typer(
    name="redfixer",
    help="RHEL 9 Vulnerability Assessment and Remediation Tool",
    no_args_is_help=True,
)
console = Console()


def get_api_client() -> httpx.AsyncClient:
    """Get configured API client."""
    from redfixer.config import get_settings

    settings = get_settings()

    return httpx.AsyncClient(
        base_url=f"http://{settings.api.host}:{settings.api.port}/api/v1",
        headers={"X-API-Key": settings.api.api_key},
        timeout=300.0,
    )


@app.command()
def version():
    """Show RedFixer version."""
    console.print(f"RedFixer version {__version__}", style="bold green")


# Subcommands
vuln_app = typer.Typer(help="Vulnerability lookup commands")
scan_app = typer.Typer(help="Scan management commands")
hosts_app = typer.Typer(help="Host management commands")
config_app = typer.Typer(help="Configuration commands")

app.add_typer(vuln_app, name="vuln")
app.add_typer(scan_app, name="scan")
app.add_typer(hosts_app, name="hosts")
app.add_typer(config_app, name="config")


# Vulnerability commands
@vuln_app.command("lookup")
def vuln_lookup(vuln_id: str):
    """Look up vulnerability details from Red Hat Security API."""

    async def _lookup():
        async with get_api_client() as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(
                    description=f"Looking up {vuln_id}...", total=None
                )

                response = await client.get(f"/vulnerabilities/{vuln_id}")
                response.raise_for_status()
                return response.json()

    try:
        result = asyncio.run(_lookup())

        table = Table(title=f"Vulnerability: {result['vuln_id']}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Title", result.get("title", "N/A"))
        table.add_row("Severity", result.get("severity", "N/A"))

        desc = result.get("description", "N/A")
        if len(desc) > 200:
            desc = desc[:200] + "..."
        table.add_row("Description", desc)

        affected = result.get("affected_packages", [])
        table.add_row("Affected Packages", str(len(affected)))

        console.print(table)

        if affected:
            console.print("\n[bold]Affected Packages:[/bold]")
            for pkg in affected[:10]:
                console.print(f"  • {pkg}")
            if len(affected) > 10:
                console.print(f"  ... and {len(affected) - 10} more")

    except httpx.HTTPStatusError as e:
        console.print(f"[red]Error: {e.response.status_code}[/red]")
        console.print(f"[red]{e.response.text}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# Scan commands
@scan_app.command("create")
def scan_create(
    vuln_id: str = typer.Argument(..., help="Vulnerability ID (RHSA or CVE)"),
    hosts: Optional[str] = typer.Option(None, help="Comma-separated hostnames"),
    hosts_file: Optional[Path] = typer.Option(None, help="File containing hostnames (one per line)"),
    hunt: bool = typer.Option(False, help="Enable LLM-powered hunt mode"),
):
    """Create and start a new vulnerability scan."""

    # Parse hostnames
    hostnames = []
    if hosts:
        hostnames = [h.strip() for h in hosts.split(",")]
    elif hosts_file:
        if not hosts_file.exists():
            console.print(f"[red]Error: File not found: {hosts_file}[/red]")
            raise typer.Exit(1)
        hostnames = [line.strip() for line in hosts_file.read_text().splitlines() if line.strip()]
    else:
        console.print("[red]Error: Must provide either --hosts or --hosts-file[/red]")
        raise typer.Exit(1)

    async def _create_scan():
        async with get_api_client() as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task(
                    description=f"Creating scan for {vuln_id} on {len(hostnames)} host(s)...",
                    total=None,
                )

                response = await client.post(
                    "/scans",
                    json={
                        "vuln_id": vuln_id,
                        "hostnames": hostnames,
                        "hunt_mode": hunt,
                    },
                )
                response.raise_for_status()
                return response.json()

    try:
        result = asyncio.run(_create_scan())

        console.print(f"\n[bold green]✓[/bold green] Scan created: {result['scan_id']}")
        console.print(f"Status: {result['status']}")
        console.print(f"Hosts: {len(result['hosts'])}")
        if hunt:
            console.print("[yellow]Hunt mode enabled[/yellow]")

        console.print(f"\nUse 'redfixer scan get {result['scan_id']}' to check status")

    except httpx.HTTPStatusError as e:
        console.print(f"[red]Error: {e.response.status_code}[/red]")
        console.print(f"[red]{e.response.text}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@scan_app.command("list")
def scan_list(limit: int = typer.Option(10, help="Number of scans to show")):
    """List recent scans."""

    async def _list_scans():
        async with get_api_client() as client:
            response = await client.get(f"/scans?limit={limit}")
            response.raise_for_status()
            return response.json()

    try:
        scans = asyncio.run(_list_scans())

        if not scans:
            console.print("[yellow]No scans found[/yellow]")
            return

        table = Table(title="Recent Scans")
        table.add_column("Scan ID", style="cyan")
        table.add_column("Vuln ID", style="yellow")
        table.add_column("Status", style="white")
        table.add_column("Hosts", style="white")
        table.add_column("Created", style="white")

        for scan in scans:
            table.add_row(
                scan["scan_id"][:8] + "...",
                scan["vuln_id"],
                scan["status"],
                str(scan["host_count"]),
                scan["created_at"][:19],
            )

        console.print(table)

    except httpx.HTTPStatusError as e:
        console.print(f"[red]Error: {e.response.status_code}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@scan_app.command("get")
def scan_get(scan_id: str = typer.Argument(..., help="Scan ID")):
    """Get detailed scan results."""

    async def _get_scan():
        async with get_api_client() as client:
            response = await client.get(f"/scans/{scan_id}")
            response.raise_for_status()
            return response.json()

    try:
        result = asyncio.run(_get_scan())

        # Summary table
        table = Table(title=f"Scan: {scan_id[:16]}...")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Scan ID", result["scan_id"])
        table.add_row("Vulnerability", result["vuln_id"])
        table.add_row("Status", result["status"])
        table.add_row("Started", result.get("started_at", "N/A")[:19] if result.get("started_at") else "N/A")
        table.add_row("Completed", result.get("completed_at", "N/A")[:19] if result.get("completed_at") else "N/A")
        table.add_row("Hunt Mode", "Yes" if result.get("hunt_mode") else "No")

        console.print(table)

        # Host results
        if result.get("hosts"):
            console.print(f"\n[bold]Hosts ({len(result['hosts'])}):[/bold]")

            host_table = Table()
            host_table.add_column("Hostname", style="cyan")
            host_table.add_column("Status", style="white")
            host_table.add_column("Vulnerable", style="white")
            host_table.add_column("Findings", style="white")

            for host in result["hosts"]:
                vuln_status = "Yes" if host.get("is_vulnerable") else "No"
                vuln_style = "red" if host.get("is_vulnerable") else "green"

                host_table.add_row(
                    host["hostname"],
                    host["status"],
                    f"[{vuln_style}]{vuln_status}[/{vuln_style}]",
                    str(len(host.get("findings", []))),
                )

            console.print(host_table)

    except httpx.HTTPStatusError as e:
        console.print(f"[red]Error: {e.response.status_code}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@scan_app.command("delete")
def scan_delete(scan_id: str = typer.Argument(..., help="Scan ID")):
    """Delete a scan and its results."""

    async def _delete_scan():
        async with get_api_client() as client:
            response = await client.delete(f"/scans/{scan_id}")
            response.raise_for_status()

    try:
        asyncio.run(_delete_scan())
        console.print(f"[bold green]✓[/bold green] Scan {scan_id[:16]}... deleted")

    except httpx.HTTPStatusError as e:
        console.print(f"[red]Error: {e.response.status_code}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# Host commands
@hosts_app.command("list")
def hosts_list():
    """List all scanned hosts."""

    async def _list_hosts():
        async with get_api_client() as client:
            response = await client.get("/hosts")
            response.raise_for_status()
            return response.json()

    try:
        hosts = asyncio.run(_list_hosts())

        if not hosts:
            console.print("[yellow]No hosts found[/yellow]")
            return

        table = Table(title="Scanned Hosts")
        table.add_column("Hostname", style="cyan")
        table.add_column("Total Scans", style="white")
        table.add_column("Last Scanned", style="white")

        for host in hosts:
            table.add_row(
                host["hostname"],
                str(host["scan_count"]),
                host["last_scan_at"][:19] if host.get("last_scan_at") else "N/A",
            )

        console.print(table)

    except httpx.HTTPStatusError as e:
        console.print(f"[red]Error: {e.response.status_code}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# Config commands
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
    table.add_row("API Key", settings.api.api_key[:8] + "..." if len(settings.api.api_key) > 8 else settings.api.api_key)
    table.add_row("SSH User", settings.ssh.user)
    table.add_row("SSH Key", str(settings.ssh.key_path))
    table.add_row("LLM Provider", settings.llm.provider)
    table.add_row("Database Path", str(settings.database.db_path))

    console.print(table)


@config_app.command("init")
def config_init():
    """Initialize configuration file."""
    config_dir = Path.home() / ".redfixer"
    config_file = config_dir / "config.yaml"

    if config_file.exists():
        console.print(f"[yellow]Config file already exists: {config_file}[/yellow]")
        if not typer.confirm("Overwrite?"):
            raise typer.Exit(0)

    config_dir.mkdir(parents=True, exist_ok=True)

    # Copy example config
    example_config = Path(__file__).parent.parent.parent / "config" / "config.example.yaml"

    if example_config.exists():
        import shutil
        shutil.copy(example_config, config_file)
        console.print(f"[bold green]✓[/bold green] Config file created: {config_file}")
        console.print("\nEdit this file to customize your settings")
    else:
        console.print(f"[red]Error: Example config not found at {example_config}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
