"""Ollama LLM provider implementation."""
import httpx
from typing import Optional

from redfixer.config import OllamaSettings
from redfixer.llm.base import BaseLLM, LLMResponse


class OllamaLLM(BaseLLM):
    """Ollama LLM provider."""

    def __init__(self, settings: OllamaSettings):
        """Initialize Ollama client."""
        self.settings = settings
        self.client = httpx.AsyncClient(timeout=120.0)

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> LLMResponse:
        """Generate response using Ollama."""
        url = f"{self.settings.endpoint}/api/generate"

        payload = {
            "model": self.settings.model,
            "prompt": prompt,
            "stream": False,
        }

        if system_prompt:
            payload["system"] = system_prompt

        response = await self.client.post(url, json=payload)
        response.raise_for_status()

        data = response.json()
        content = data.get("response", "")

        # Ollama doesn't provide confidence, estimate based on response
        confidence = 0.8 if content else 0.0

        return LLMResponse(content=content, confidence=confidence)

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
