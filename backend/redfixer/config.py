"""Configuration management using Pydantic Settings."""
from pathlib import Path
from typing import Any, Literal, Optional, Tuple, Type

import yaml
from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)


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
    db_path: Path = Path.home() / ".redfixer" / "redfixer.db"


class CacheSettings(BaseSettings):
    """Cache settings."""
    vuln_ttl_hours: int = 24


class YamlConfigSettingsSource(PydanticBaseSettingsSource):
    """Custom settings source for loading YAML configuration files."""

    def get_field_value(
        self, field_name: str, field_info: Any
    ) -> Tuple[Any, str, bool]:
        """Not used for this source."""
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        """Load settings from YAML configuration files."""
        # Define config file paths in priority order
        config_paths = [
            Path.home() / ".redfixer" / "config.yaml",
            Path("/etc/redfixer/config.yaml"),
        ]

        # Try to load from each path
        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, "r") as f:
                        data = yaml.safe_load(f)
                        if data is None:
                            continue
                        # Expand ~ in paths
                        if isinstance(data, dict):
                            self._expand_paths(data)
                        return data
                except Exception:
                    # Continue to next path if loading fails
                    continue

        # Return empty dict if no config file found
        return {}

    def _expand_paths(self, data: dict[str, Any]) -> None:
        """Recursively expand ~ in path strings."""
        for key, value in data.items():
            if isinstance(value, str) and value.startswith("~"):
                data[key] = str(Path(value).expanduser())
            elif isinstance(value, dict):
                self._expand_paths(value)


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

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        """Customize settings sources to include YAML config file loading.

        Priority order:
        1. init_settings (arguments passed to Settings())
        2. env_settings (environment variables)
        3. YamlConfigSettingsSource (YAML config files)
        4. file_secret_settings (secrets from files)
        """
        return (
            init_settings,
            env_settings,
            YamlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
