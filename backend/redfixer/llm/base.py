"""Base LLM interface."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMResponse:
    """Response from LLM."""
    content: str
    confidence: float  # 0.0 to 1.0


class BaseLLM(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> LLMResponse:
        """
        Generate a response from the LLM.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Returns:
            LLMResponse with content and confidence
        """
        pass

    @abstractmethod
    async def close(self):
        """Close any open connections."""
        pass
