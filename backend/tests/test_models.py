"""Test database models."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from redfixer.models.database import Base, Scan, ScanHost, ScanStatus


@pytest.fixture
def db_session():
    """Create in-memory database session for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


def test_create_scan(db_session: Session):
    """Test creating a scan record."""
    scan = Scan(
        vuln_id="RHSA-2024:1234",
        vuln_title="Test Vulnerability",
        hunt_mode=False,
        status=ScanStatus.PENDING,
    )
    db_session.add(scan)
    db_session.commit()

    assert scan.id is not None
    assert scan.vuln_id == "RHSA-2024:1234"
    assert scan.status == ScanStatus.PENDING


def test_create_scan_with_hosts(db_session: Session):
    """Test creating a scan with hosts."""
    scan = Scan(
        vuln_id="CVE-2024-12345",
        vuln_title="Another Test",
        hunt_mode=True,
    )
    host = ScanHost(hostname="server1.example.com", scan=scan)

    db_session.add(scan)
    db_session.commit()

    assert len(scan.hosts) == 1
    assert scan.hosts[0].hostname == "server1.example.com"
