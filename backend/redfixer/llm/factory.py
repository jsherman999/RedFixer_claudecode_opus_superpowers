"""LLM provider factory."""
from redfixer.config import Settings
from redfixer.llm.base import BaseLLM
from redfixer.llm.ollama import OllamaLLM
from redfixer.llm.openai_llm import OpenAILLM
from redfixer.llm.anthropic_llm import AnthropicLLM
from redfixer.llm.uai_studio import UAIStudioLLM


def get_llm(llm_type: str, config: Settings) -> BaseLLM:
    """
    Get LLM provider instance based on type.

    Args:
        llm_type: Type of LLM provider ("ollama", "openai", "anthropic", "uai_studio")
        config: Application settings containing LLM configuration

    Returns:
        BaseLLM instance for the specified provider

    Raises:
        ValueError: If llm_type is not supported
    """
    if llm_type == "ollama":
        return OllamaLLM(config.llm.ollama)
    elif llm_type == "openai":
        return OpenAILLM(config.llm.openai)
    elif llm_type == "anthropic":
        return AnthropicLLM(config.llm.anthropic)
    elif llm_type == "uai_studio":
        return UAIStudioLLM(config.llm.uai_studio)
    else:
        raise ValueError(f"Unknown LLM provider: {llm_type}")
