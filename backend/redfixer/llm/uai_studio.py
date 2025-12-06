"""UAI Studio (Azure AI) LLM provider implementation (stub)."""
from typing import Optional

from redfixer.config import UAIStudioSettings
from redfixer.llm.base import BaseLLM, LLMResponse


class UAIStudioLLM(BaseLLM):
    """UAI Studio LLM provider (not yet implemented)."""

    def __init__(self, settings: UAIStudioSettings):
        """
        Initialize UAI Studio client.

        Args:
            settings: UAI Studio configuration settings
        """
        self.settings = settings

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> LLMResponse:
        """
        Generate response using UAI Studio.

        Args:
            prompt: User prompt to send to the LLM
            system_prompt: Optional system prompt to set context/behavior

        Returns:
            LLMResponse with generated content and confidence score

        Raises:
            ValueError: If prompt is empty or invalid
            NotImplementedError: This provider is not yet implemented
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty")

        raise NotImplementedError(
            "UAI Studio provider not yet implemented. "
            "This is a stub for future implementation."
        )

    async def close(self):
        """Close any open connections."""
        # No-op for stub implementation
        pass
