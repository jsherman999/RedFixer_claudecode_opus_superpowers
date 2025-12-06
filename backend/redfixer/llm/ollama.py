"""Ollama LLM provider implementation."""
import httpx
from typing import Optional

from redfixer.config import OllamaSettings
from redfixer.llm.base import BaseLLM, LLMResponse

# Ollama doesn't provide confidence scores
# Use fixed values: 0.8 for valid responses, 0.0 for empty responses
DEFAULT_CONFIDENCE = 0.8


class OllamaLLM(BaseLLM):
    """Ollama LLM provider."""

    def __init__(self, settings: OllamaSettings):
        """Initialize Ollama client."""
        self.settings = settings
        self.client = httpx.AsyncClient(timeout=120.0)

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> LLMResponse:
        """
        Generate response using Ollama.

        Args:
            prompt: User prompt to send to the LLM
            system_prompt: Optional system prompt to set context/behavior

        Returns:
            LLMResponse with generated content and confidence score

        Raises:
            ValueError: If prompt is empty or invalid
            RuntimeError: If Ollama API call fails or returns invalid response
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty")

        url = f"{self.settings.endpoint}/api/generate"

        payload = {
            "model": self.settings.model,
            "prompt": prompt,
            "stream": False,
        }

        if system_prompt:
            payload["system"] = system_prompt

        try:
            response = await self.client.post(url, json=payload)
            response.raise_for_status()
        except httpx.TimeoutException as e:
            raise RuntimeError(f"Ollama request timed out after {self.client.timeout}s: {e}") from e
        except httpx.ConnectError as e:
            raise RuntimeError(f"Failed to connect to Ollama at {url}: {e}") from e
        except httpx.HTTPStatusError as e:
            error_detail = e.response.text if e.response else "No response body"
            raise RuntimeError(f"Ollama API error {e.response.status_code}: {error_detail}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error calling Ollama: {e}") from e

        try:
            data = response.json()
        except Exception as e:
            raise RuntimeError(f"Failed to parse Ollama response as JSON: {e}") from e

        content = data.get("response", "")
        confidence = DEFAULT_CONFIDENCE if content else 0.0

        return LLMResponse(content=content, confidence=confidence)

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
