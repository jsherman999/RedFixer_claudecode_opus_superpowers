"""FastAPI application entry point."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from redfixer import __version__
from redfixer.api.routes import vulnerabilities, scans, hosts, reports, health
from redfixer.config import get_settings
from redfixer.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.

    Handles:
    - Database initialization on startup
    - Resource cleanup on shutdown
    """
    # Startup
    init_db()
    yield
    # Shutdown
    pass


app = FastAPI(
    title="RedFixer API",
    description="RHEL 9 Vulnerability Assessment and Remediation Tool",
    version=__version__,
    lifespan=lifespan,
)

# CORS middleware
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(vulnerabilities.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(hosts.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(health.router, prefix="/api/v1")


@app.get("/", tags=["root"])
async def root():
    """
    Root endpoint providing API information.

    Returns:
        Basic API metadata and links to documentation
    """
    return {
        "name": "RedFixer API",
        "version": __version__,
        "description": "RHEL 9 Vulnerability Assessment and Remediation Tool",
        "docs": "/docs",
        "redoc": "/redoc",
    }
