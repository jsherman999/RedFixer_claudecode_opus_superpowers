"""Test Ollama LLM implementation."""
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from redfixer.config import OllamaSettings
from redfixer.llm.ollama import OllamaLLM


@pytest.mark.asyncio
async def test_ollama_generate():
    """Test Ollama generate with mocked HTTP client."""
    settings = OllamaSettings(
        endpoint="http://localhost:11434",
        model="llama3.1:8b"
    )

    with patch("httpx.AsyncClient") as mock_client_class:
        # Setup mock
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "response": "This is a test response from Ollama"
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.aclose = AsyncMock()

        llm = OllamaLLM(settings)

        try:
            result = await llm.generate("Test prompt")

            assert result.content == "This is a test response from Ollama"
            assert result.confidence == 0.8

            # Verify the API was called correctly
            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            assert call_args[0][0] == "http://localhost:11434/api/generate"
            assert call_args[1]["json"]["model"] == "llama3.1:8b"
            assert call_args[1]["json"]["prompt"] == "Test prompt"
            assert call_args[1]["json"]["stream"] is False
        finally:
            await llm.close()


@pytest.mark.asyncio
async def test_ollama_generate_with_system_prompt():
    """Test Ollama generate with system prompt."""
    settings = OllamaSettings(
        endpoint="http://localhost:11434",
        model="llama3.1:8b"
    )

    with patch("httpx.AsyncClient") as mock_client_class:
        # Setup mock
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "response": "Response with system prompt"
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.aclose = AsyncMock()

        llm = OllamaLLM(settings)

        try:
            result = await llm.generate("Test prompt", system_prompt="You are a helpful assistant")

            assert result.content == "Response with system prompt"
            assert result.confidence == 0.8

            # Verify system prompt was included
            call_args = mock_client.post.call_args
            assert call_args[1]["json"]["system"] == "You are a helpful assistant"
        finally:
            await llm.close()


@pytest.mark.asyncio
async def test_ollama_empty_response():
    """Test handling of empty response from Ollama."""
    settings = OllamaSettings(
        endpoint="http://localhost:11434",
        model="llama3.1:8b"
    )

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {"response": ""}
        mock_response.raise_for_status = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.aclose = AsyncMock()

        llm = OllamaLLM(settings)

        try:
            result = await llm.generate("Test prompt")

            assert result.content == ""
            assert result.confidence == 0.0
        finally:
            await llm.close()


@pytest.mark.asyncio
async def test_ollama_empty_prompt():
    """Test validation of empty prompt."""
    settings = OllamaSettings(
        endpoint="http://localhost:11434",
        model="llama3.1:8b"
    )

    llm = OllamaLLM(settings)

    try:
        with pytest.raises(ValueError, match="Prompt cannot be empty"):
            await llm.generate("")
    finally:
        await llm.close()


@pytest.mark.asyncio
async def test_ollama_connection_error():
    """Test handling of connection errors."""
    settings = OllamaSettings(
        endpoint="http://invalid:11434",
        model="llama3.1:8b"
    )

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.aclose = AsyncMock()

        llm = OllamaLLM(settings)

        try:
            with pytest.raises(RuntimeError, match="Failed to connect"):
                await llm.generate("Test prompt")
        finally:
            await llm.close()


@pytest.mark.asyncio
async def test_ollama_context_manager():
    """Test async context manager support."""
    settings = OllamaSettings(
        endpoint="http://localhost:11434",
        model="llama3.1:8b"
    )

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.json.return_value = {"response": "Test"}
        mock_response.raise_for_status = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.aclose = AsyncMock()

        async with OllamaLLM(settings) as llm:
            result = await llm.generate("Test prompt")
            assert result.content == "Test"

        # Verify close was called
        mock_client.aclose.assert_called_once()
