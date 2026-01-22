"""
Infrastructure Layer - 基础设施层

此模块包含外部服务的抽象接口和实现：
- llm_api: LLM API 客户端抽象
- config: 配置管理

这些模块与外部 API（OpenAI、Anthropic 等）交互，
提供统一的接口供上层使用。
"""

from .llm_api import (
    LLMRequest,
    LLMResponse,
    LLMProvider,
    OpenAIProvider,
    AnthropicProvider,
    MockProvider,
    LLMClient,
)

from .config import (
    ModelConfig,
    AnalysisConfig,
    UIConfig,
    ConfigManager,
)

__all__ = [
    # LLM API
    'LLMRequest',
    'LLMResponse',
    'LLMProvider',
    'OpenAIProvider',
    'AnthropicProvider',
    'MockProvider',
    'LLMClient',
    # Config
    'ModelConfig',
    'AnalysisConfig',
    'UIConfig',
    'ConfigManager',
]
