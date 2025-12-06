"""Test FastAPI application with all routes registered."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from redfixer.api.routes import vulnerabilities, scans, hosts, reports, health

# Create test app
app = FastAPI(title="RedFixer API (Test)", version="0.1.0")

# Add CORS middleware for tests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all routers
app.include_router(vulnerabilities.router)
app.include_router(scans.router)
app.include_router(hosts.router)
app.include_router(reports.router)
app.include_router(health.router)
