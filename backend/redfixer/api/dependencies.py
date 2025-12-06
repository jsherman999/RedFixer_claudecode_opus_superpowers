"""FastAPI dependency injection functions."""
from typing import Generator

from fastapi import Depends
from sqlalchemy.orm import Session

from redfixer.config import Settings, get_settings
from redfixer.db.session import get_db as db_session_generator
from redfixer.llm.base import BaseLLM
from redfixer.llm.factory import get_llm as llm_factory
from redfixer.services.host_scanner import HostScanner
from redfixer.services.hunt_engine import HuntEngine
from redfixer.services.vuln_fetcher import VulnFetcher


def get_settings_dependency() -> Settings:
    """
    Get application settings.

    Returns:
        Settings instance
    """
    return get_settings()


def get_db_dependency() -> Generator[Session, None, None]:
    """
    Get database session dependency.

    Yields:
        Database session
    """
    yield from db_session_generator()


def get_vuln_fetcher(
    settings: Settings = Depends(get_settings_dependency),
    db: Session = Depends(get_db_dependency),
) -> VulnFetcher:
    """
    Get VulnFetcher service instance.

    Args:
        settings: Application settings
        db: Database session

    Returns:
        VulnFetcher instance
    """
    return VulnFetcher(db=db)


def get_host_scanner(
    settings: Settings = Depends(get_settings_dependency),
) -> HostScanner:
    """
    Get HostScanner service instance.

    Args:
        settings: Application settings

    Returns:
        HostScanner instance
    """
    return HostScanner()


def get_llm(
    settings: Settings = Depends(get_settings_dependency),
) -> BaseLLM:
    """
    Get LLM provider instance using factory.

    Args:
        settings: Application settings

    Returns:
        BaseLLM instance for configured provider
    """
    return llm_factory(settings.llm.provider, settings)


def get_hunt_engine(
    vuln_fetcher: VulnFetcher = Depends(get_vuln_fetcher),
    host_scanner: HostScanner = Depends(get_host_scanner),
    llm: BaseLLM = Depends(get_llm),
    db: Session = Depends(get_db_dependency),
) -> HuntEngine:
    """
    Get HuntEngine service instance.

    Args:
        vuln_fetcher: VulnFetcher service
        host_scanner: HostScanner service
        llm: LLM provider
        db: Database session

    Returns:
        HuntEngine instance
    """
    return HuntEngine(
        vuln_fetcher=vuln_fetcher,
        host_scanner=host_scanner,
        llm=llm,
        db=db,
    )
