"""Test LLM base interface."""
import pytest
from typing import Optional

from redfixer.llm.base import BaseLLM, LLMResponse


class MockLLM(BaseLLM):
    """Mock LLM for testing."""

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> LLMResponse:
        """Return mock response."""
        return LLMResponse(content=f"Mock response to: {prompt}", confidence=0.95)

    async def close(self):
        """No-op close."""
        pass


@pytest.mark.asyncio
async def test_mock_llm():
    """Test mock LLM implementation."""
    llm = MockLLM()

    response = await llm.generate("Test prompt")

    assert "Test prompt" in response.content
    assert response.confidence > 0.9

    await llm.close()
