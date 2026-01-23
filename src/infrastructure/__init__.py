"""
Infrastructure Layer

This package contains external service interfaces and configurations
for the ReCopilot plugin.

Organized into:
- llm_api: LLM API clients (OpenAI, Anthropic, etc.)
- ida_api: IDA API wrapper (future)
- config: Configuration management (future)

Example usage:
    # Old way (still works - backward compatible)
    from remote_model import OpenAIModel
    model = OpenAIModel()
    response = await model.call_model(prompt, task_tag)

    # New way (recommended)
    from infrastructure import LLMApiFactory, LLMRequest
    api = LLMApiFactory.create_from_config(settings)
    request = LLMRequest(prompt, task_tag, max_tokens)
    response = await api.call(request)
"""

from .llm_api import (
    LLMRequest,
    LLMResponse,
    LLMApi,
    OpenAIApi,
    AnthropicApi,
    LLMApiFactory,
)

__all__ = [
    'LLMRequest',
    'LLMResponse',
    'LLMApi',
    'OpenAIApi',
    'AnthropicApi',
    'LLMApiFactory',
]
