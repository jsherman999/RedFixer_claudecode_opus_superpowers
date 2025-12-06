"""Tests for LLM factory and stub providers."""
import pytest

from redfixer.config import (
    AnthropicSettings,
    LLMSettings,
    OllamaSettings,
    OpenAISettings,
    Settings,
    UAIStudioSettings,
)
from redfixer.llm.factory import get_llm
from redfixer.llm.ollama import OllamaLLM
from redfixer.llm.openai_llm import OpenAILLM
from redfixer.llm.anthropic_llm import AnthropicLLM
from redfixer.llm.uai_studio import UAIStudioLLM


class TestLLMFactory:
    """Test LLM factory function."""

    def test_factory_returns_ollama(self):
        """Test factory returns Ollama instance for ollama provider."""
        settings = Settings(
            llm=LLMSettings(
                provider="ollama",
                ollama=OllamaSettings(endpoint="http://localhost:11434", model="llama3.1:8b")
            )
        )

        llm = get_llm("ollama", settings)

        assert isinstance(llm, OllamaLLM)
        assert llm.settings.endpoint == "http://localhost:11434"
        assert llm.settings.model == "llama3.1:8b"

    def test_factory_returns_openai(self):
        """Test factory returns OpenAI instance for openai provider."""
        settings = Settings(
            llm=LLMSettings(
                provider="openai",
                openai=OpenAISettings(api_key="test-key", model="gpt-4-turbo")
            )
        )

        llm = get_llm("openai", settings)

        assert isinstance(llm, OpenAILLM)
        assert llm.settings.api_key == "test-key"
        assert llm.settings.model == "gpt-4-turbo"

    def test_factory_returns_anthropic(self):
        """Test factory returns Anthropic instance for anthropic provider."""
        settings = Settings(
            llm=LLMSettings(
                provider="anthropic",
                anthropic=AnthropicSettings(api_key="test-key", model="claude-sonnet-4-20250514")
            )
        )

        llm = get_llm("anthropic", settings)

        assert isinstance(llm, AnthropicLLM)
        assert llm.settings.api_key == "test-key"
        assert llm.settings.model == "claude-sonnet-4-20250514"

    def test_factory_returns_uai_studio(self):
        """Test factory returns UAI Studio instance for uai_studio provider."""
        settings = Settings(
            llm=LLMSettings(
                provider="uai_studio",
                uai_studio=UAIStudioSettings(endpoint="https://api.example.com", api_key="test-key", model="gpt-4")
            )
        )

        llm = get_llm("uai_studio", settings)

        assert isinstance(llm, UAIStudioLLM)
        assert llm.settings.endpoint == "https://api.example.com"
        assert llm.settings.api_key == "test-key"
        assert llm.settings.model == "gpt-4"

    def test_factory_raises_for_unknown_provider(self):
        """Test factory raises ValueError for unknown provider."""
        settings = Settings()

        with pytest.raises(ValueError, match="Unknown LLM provider: unknown"):
            get_llm("unknown", settings)


class TestOpenAILLMStub:
    """Test OpenAI LLM stub provider."""

    def test_openai_can_be_instantiated(self):
        """Test OpenAI LLM can be instantiated."""
        settings = OpenAISettings(api_key="test-key", model="gpt-4-turbo")

        llm = OpenAILLM(settings)

        assert llm.settings == settings

    @pytest.mark.asyncio
    async def test_openai_raises_not_implemented(self):
        """Test OpenAI generate raises NotImplementedError."""
        settings = OpenAISettings(api_key="test-key", model="gpt-4-turbo")
        llm = OpenAILLM(settings)

        with pytest.raises(NotImplementedError, match="OpenAI provider not yet implemented"):
            await llm.generate("Test prompt")

    @pytest.mark.asyncio
    async def test_openai_validates_empty_prompt(self):
        """Test OpenAI validates empty prompt."""
        settings = OpenAISettings(api_key="test-key", model="gpt-4-turbo")
        llm = OpenAILLM(settings)

        with pytest.raises(ValueError, match="Prompt cannot be empty"):
            await llm.generate("")

        with pytest.raises(ValueError, match="Prompt cannot be empty"):
            await llm.generate("   ")

    @pytest.mark.asyncio
    async def test_openai_supports_context_manager(self):
        """Test OpenAI supports async context manager."""
        settings = OpenAISettings(api_key="test-key", model="gpt-4-turbo")

        async with OpenAILLM(settings) as llm:
            assert isinstance(llm, OpenAILLM)

        # Should not raise any errors when exiting context

    @pytest.mark.asyncio
    async def test_openai_close_succeeds(self):
        """Test OpenAI close method succeeds."""
        settings = OpenAISettings(api_key="test-key", model="gpt-4-turbo")
        llm = OpenAILLM(settings)

        await llm.close()
        # Should not raise any errors


class TestAnthropicLLMStub:
    """Test Anthropic LLM stub provider."""

    def test_anthropic_can_be_instantiated(self):
        """Test Anthropic LLM can be instantiated."""
        settings = AnthropicSettings(api_key="test-key", model="claude-sonnet-4-20250514")

        llm = AnthropicLLM(settings)

        assert llm.settings == settings

    @pytest.mark.asyncio
    async def test_anthropic_raises_not_implemented(self):
        """Test Anthropic generate raises NotImplementedError."""
        settings = AnthropicSettings(api_key="test-key", model="claude-sonnet-4-20250514")
        llm = AnthropicLLM(settings)

        with pytest.raises(NotImplementedError, match="Anthropic provider not yet implemented"):
            await llm.generate("Test prompt")

    @pytest.mark.asyncio
    async def test_anthropic_validates_empty_prompt(self):
        """Test Anthropic validates empty prompt."""
        settings = AnthropicSettings(api_key="test-key", model="claude-sonnet-4-20250514")
        llm = AnthropicLLM(settings)

        with pytest.raises(ValueError, match="Prompt cannot be empty"):
            await llm.generate("")

        with pytest.raises(ValueError, match="Prompt cannot be empty"):
            await llm.generate("   ")

    @pytest.mark.asyncio
    async def test_anthropic_supports_context_manager(self):
        """Test Anthropic supports async context manager."""
        settings = AnthropicSettings(api_key="test-key", model="claude-sonnet-4-20250514")

        async with AnthropicLLM(settings) as llm:
            assert isinstance(llm, AnthropicLLM)

        # Should not raise any errors when exiting context

    @pytest.mark.asyncio
    async def test_anthropic_close_succeeds(self):
        """Test Anthropic close method succeeds."""
        settings = AnthropicSettings(api_key="test-key", model="claude-sonnet-4-20250514")
        llm = AnthropicLLM(settings)

        await llm.close()
        # Should not raise any errors


class TestUAIStudioLLMStub:
    """Test UAI Studio LLM stub provider."""

    def test_uai_studio_can_be_instantiated(self):
        """Test UAI Studio LLM can be instantiated."""
        settings = UAIStudioSettings(endpoint="https://api.example.com", api_key="test-key", model="gpt-4")

        llm = UAIStudioLLM(settings)

        assert llm.settings == settings

    @pytest.mark.asyncio
    async def test_uai_studio_raises_not_implemented(self):
        """Test UAI Studio generate raises NotImplementedError."""
        settings = UAIStudioSettings(endpoint="https://api.example.com", api_key="test-key", model="gpt-4")
        llm = UAIStudioLLM(settings)

        with pytest.raises(NotImplementedError, match="UAI Studio provider not yet implemented"):
            await llm.generate("Test prompt")

    @pytest.mark.asyncio
    async def test_uai_studio_validates_empty_prompt(self):
        """Test UAI Studio validates empty prompt."""
        settings = UAIStudioSettings(endpoint="https://api.example.com", api_key="test-key", model="gpt-4")
        llm = UAIStudioLLM(settings)

        with pytest.raises(ValueError, match="Prompt cannot be empty"):
            await llm.generate("")

        with pytest.raises(ValueError, match="Prompt cannot be empty"):
            await llm.generate("   ")

    @pytest.mark.asyncio
    async def test_uai_studio_supports_context_manager(self):
        """Test UAI Studio supports async context manager."""
        settings = UAIStudioSettings(endpoint="https://api.example.com", api_key="test-key", model="gpt-4")

        async with UAIStudioLLM(settings) as llm:
            assert isinstance(llm, UAIStudioLLM)

        # Should not raise any errors when exiting context

    @pytest.mark.asyncio
    async def test_uai_studio_close_succeeds(self):
        """Test UAI Studio close method succeeds."""
        settings = UAIStudioSettings(endpoint="https://api.example.com", api_key="test-key", model="gpt-4")
        llm = UAIStudioLLM(settings)

        await llm.close()
        # Should not raise any errors
