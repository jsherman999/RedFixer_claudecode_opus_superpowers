"""Configuration management using Pydantic Settings."""
from pathlib import Path
from typing import Literal, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class APISettings(BaseSettings):
    """API server settings."""
    host: str = "0.0.0.0"
    port: int = 8000
    api_key: str = Field(default="change-me-in-production")


class SSHSettings(BaseSettings):
    """SSH connection settings."""
    user: str = "root"
    key_path: Path = Path.home() / ".ssh" / "id_rsa"
    timeout: int = 30


class RedHatAPISettings(BaseSettings):
    """Red Hat API credentials (optional)."""
    username: Optional[str] = None
    password: Optional[str] = None


class OllamaSettings(BaseSettings):
    """Ollama LLM settings."""
    endpoint: str = "http://localhost:11434"
    model: str = "llama3.1:8b"


class UAIStudioSettings(BaseSettings):
    """UAI Studio (Azure AI) settings."""
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    model: str = "gpt-4"


class OpenAISettings(BaseSettings):
    """OpenAI API settings."""
    api_key: Optional[str] = None
    model: str = "gpt-4-turbo"


class AnthropicSettings(BaseSettings):
    """Anthropic API settings."""
    api_key: Optional[str] = None
    model: str = "claude-sonnet-4-20250514"


class LLMSettings(BaseSettings):
    """LLM provider configuration."""
    provider: Literal["ollama", "uai_studio", "openai", "anthropic"] = "ollama"
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    uai_studio: UAIStudioSettings = Field(default_factory=UAIStudioSettings)
    openai: OpenAISettings = Field(default_factory=OpenAISettings)
    anthropic: AnthropicSettings = Field(default_factory=AnthropicSettings)


class DatabaseSettings(BaseSettings):
    """Database settings."""
    path: Path = Path.home() / ".redfixer" / "redfixer.db"


class CacheSettings(BaseSettings):
    """Cache settings."""
    vuln_ttl_hours: int = 24


class Settings(BaseSettings):
    """Main application settings."""
    model_config = SettingsConfigDict(
        env_prefix="REDFIXER_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    api: APISettings = Field(default_factory=APISettings)
    ssh: SSHSettings = Field(default_factory=SSHSettings)
    redhat: RedHatAPISettings = Field(default_factory=RedHatAPISettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
