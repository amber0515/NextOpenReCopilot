"""
LLM API - 统一的大语言模型 API 调用接口

此模块提供统一的 LLM API 调用抽象，支持多种提供商：
- OpenAI 兼容 API
- Anthropic Claude API
- Mock 实现（用于调试）

使用 Provider 模式，易于扩展新的 API 提供商。
"""

import asyncio
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

import openai
import anthropic

from config import settings_manager, PROMPT_TEMPLATE
from task_guides import TASK_GUIDES, TASK_OUTPUT_FORMATS, get_mock_response


# ============================================================================
# 数据类
# ============================================================================

@dataclass
class LLMRequest:
    """LLM 请求"""
    prompt: str
    task_tag: str
    max_tokens: int
    timeout: int = 600
    template_name: str = "general"


@dataclass
class LLMResponse:
    """LLM 响应"""
    content: str
    raw_prompt: str
    is_error: bool = False
    error_type: str = ""
    error_details: dict = field(default_factory=dict)


# ============================================================================
# 抽象接口
# ============================================================================

class LLMProvider(ABC):
    """LLM 提供商抽象接口"""

    @abstractmethod
    async def call(self, request: LLMRequest) -> LLMResponse:
        """
        调用 LLM API

        Args:
            request: LLM 请求对象

        Returns:
            LLMResponse: 响应对象
        """
        pass

    @abstractmethod
    def cancel(self):
        """取消当前请求"""
        pass


# ============================================================================
# 提示词格式化工具
# ============================================================================

class PromptFormatter:
    """提示词格式化工具"""

    @staticmethod
    def format(request: LLMRequest) -> tuple[str, str]:
        """
        格式化提示词

        Args:
            request: LLM 请求对象

        Returns:
            (formatted_prompt, prompt_for_feedback)
        """
        template_name = request.template_name or settings_manager.settings.get('prompt_template', 'general')
        current_template_str = PROMPT_TEMPLATE.get(template_name, "{input}")

        # 根据模板名称决定是否使用指南
        if template_name.endswith("_wo_guide"):
            formatted_prompt = current_template_str.replace("{format}", TASK_OUTPUT_FORMATS.get(request.task_tag, "")) \
                                                 .replace("{input}", request.prompt)
        else:
            formatted_prompt = current_template_str.replace("{format}", TASK_OUTPUT_FORMATS.get(request.task_tag, "")) \
                                                 .replace("{guide}", TASK_GUIDES.get(request.task_tag, "")) \
                                                 .replace("{input}", request.prompt)

        prompt_for_feedback = formatted_prompt

        # 调试模式打印
        if settings_manager.settings.get('debug_mode', False):
            debug_prompt_lines = [f"\n[DEBUG🐛] {line}" for line in formatted_prompt.split('\n')]
            print("".join(debug_prompt_lines))

        return formatted_prompt, prompt_for_feedback


# ============================================================================
# OpenAI 兼容 API 实现
# ============================================================================

class OpenAIProvider(LLMProvider):
    """OpenAI 兼容 API 提供商"""

    def __init__(self):
        self._current_completion = None
        self._cancelled = False

    async def call(self, request: LLMRequest) -> LLMResponse:
        """调用 OpenAI 兼容 API"""
        self._cancelled = False

        # 格式化提示词
        formatted_prompt, prompt_for_feedback = PromptFormatter.format(request)

        # 获取配置
        base_url = settings_manager.settings.get('base_url', '')
        api_key = settings_manager.settings.get('api_key', 'sk-none')
        model_name = settings_manager.settings.get('model_name', 'gpt-3.5-turbo')

        # 调试信息
        if settings_manager.settings.get('debug_mode', False):
            print(f"[🔗] OpenAIProvider: model={model_name}, timeout={request.timeout}s")
            print(f"[🔗] OpenAIProvider: sending {len(formatted_prompt)} chars")

        try:
            # 构建客户端
            client_args = {'api_key': api_key}
            if base_url:
                client_args['base_url'] = base_url

            client = openai.AsyncOpenAI(**client_args)

            # 构建消息
            messages = [{"role": "user", "content": formatted_prompt}]

            # 发送请求
            self._current_completion = await client.chat.completions.create(
                model=model_name,
                temperature=0.6,
                stream=True,
                max_tokens=request.max_tokens,
                messages=messages,
                timeout=float(request.timeout)
            )

            # 处理流式响应
            response_parts = []
            async for chunk in self._current_completion:
                if self._cancelled:
                    print("\n[!💥] OpenAIProvider: Cancelled by user")
                    await self._current_completion.close()
                    self._current_completion = None
                    return LLMResponse(
                        content="<Cancelled>Analysis cancelled by user",
                        raw_prompt=prompt_for_feedback,
                        is_error=False
                    )

                # 提取内容
                chunk_content = None
                if chunk.choices and chunk.choices[0].delta:
                    delta = chunk.choices[0].delta
                    if hasattr(delta, 'reasoning_content') and delta.reasoning_content:
                        chunk_content = delta.reasoning_content
                    elif hasattr(delta, 'content') and delta.content:
                        chunk_content = delta.content

                if chunk_content:
                    print(chunk_content, end="")
                    response_parts.append(chunk_content)

            print()  # 换行
            self._current_completion = None
            final_response = "".join(response_parts)

            return LLMResponse(
                content=final_response,
                raw_prompt=prompt_for_feedback,
                is_error=False
            )

        except openai.APITimeoutError as e:
            print(f"[!💥] OpenAIProvider: Timeout - {e}")
            self._current_completion = None
            return LLMResponse(
                content=f"<RequestException>Request timed out: {e}",
                raw_prompt=prompt_for_feedback,
                is_error=True,
                error_type="APITimeoutError"
            )
        except openai.APIConnectionError as e:
            print(f"[!💥] OpenAIProvider: Connection failed - {e}")
            self._current_completion = None
            return LLMResponse(
                content=f"<RequestException>Connection failed: {e}",
                raw_prompt=prompt_for_feedback,
                is_error=True,
                error_type="APIConnectionError"
            )
        except openai.AuthenticationError as e:
            print(f"[!💥] OpenAIProvider: Authentication failed - {e}")
            self._current_completion = None
            return LLMResponse(
                content=f"<RequestException>Authentication failed: {e}",
                raw_prompt=prompt_for_feedback,
                is_error=True,
                error_type="AuthenticationError"
            )
        except Exception as e:
            print(f"[!💥] OpenAIProvider: Error - {e}")
            traceback.print_exc()
            self._current_completion = None
            return LLMResponse(
                content=f"<RequestException>{str(e)}",
                raw_prompt=prompt_for_feedback,
                is_error=True,
                error_type=Exception.__name__
            )

    def cancel(self):
        """取消当前请求"""
        self._cancelled = True


# ============================================================================
# Anthropic API 实现
# ============================================================================

class AnthropicProvider(LLMProvider):
    """Anthropic Claude API 提供商"""

    def __init__(self):
        self._current_completion = None
        self._cancelled = False

    async def call(self, request: LLMRequest) -> LLMResponse:
        """调用 Anthropic API"""
        self._cancelled = False

        # 格式化提示词
        formatted_prompt, prompt_for_feedback = PromptFormatter.format(request)

        # 获取配置
        base_url = settings_manager.settings.get('base_url', '')
        api_key = settings_manager.settings.get('api_key', '')
        model_name = settings_manager.settings.get('model_name', 'claude-3-opus-20240229')

        try:
            # 构建客户端
            client_args = {'api_key': api_key}
            if base_url:
                client_args['base_url'] = base_url

            client = anthropic.AsyncAnthropic(**client_args)

            # 构建消息
            messages = [{"role": "user", "content": formatted_prompt}]

            # 发送流式请求
            response_parts = []

            async with client.messages.stream(
                model=model_name,
                max_tokens=request.max_tokens,
                messages=messages,
            ) as stream:
                self._current_completion = stream
                async for text in stream.text_stream:
                    if self._cancelled:
                        print("\n[!💥] AnthropicProvider: Cancelled by user")
                        self._current_completion = None
                        return LLMResponse(
                            content="<Cancelled>Analysis cancelled by user",
                            raw_prompt=prompt_for_feedback,
                            is_error=False
                        )

                    print(text, end="")
                    response_parts.append(text)

            print()  # 换行
            self._current_completion = None
            final_response = "".join(response_parts)

            return LLMResponse(
                content=final_response,
                raw_prompt=prompt_for_feedback,
                is_error=False
            )

        except anthropic.APIConnectionError as e:
            print(f"[!💥] AnthropicProvider: Connection failed - {e}")
            self._current_completion = None
            return LLMResponse(
                content=f"<RequestException>Connection failed: {e}",
                raw_prompt=prompt_for_feedback,
                is_error=True,
                error_type="APIConnectionError"
            )
        except anthropic.AuthenticationError as e:
            print(f"[!💥] AnthropicProvider: Authentication failed - {e}")
            self._current_completion = None
            return LLMResponse(
                content=f"<RequestException>Authentication failed: {e}",
                raw_prompt=prompt_for_feedback,
                is_error=True,
                error_type="AuthenticationError"
            )
        except anthropic.RateLimitError as e:
            print(f"[!💥] AnthropicProvider: Rate limit exceeded - {e}")
            self._current_completion = None
            return LLMResponse(
                content=f"<RequestException>Rate limit exceeded: {e}",
                raw_prompt=prompt_for_feedback,
                is_error=True,
                error_type="RateLimitError"
            )
        except Exception as e:
            print(f"[!💥] AnthropicProvider: Error - {e}")
            traceback.print_exc()
            self._current_completion = None
            return LLMResponse(
                content=f"<RequestException>{str(e)}",
                raw_prompt=prompt_for_feedback,
                is_error=True,
                error_type=Exception.__name__
            )

    def cancel(self):
        """取消当前请求"""
        self._cancelled = True


# ============================================================================
# Mock 实现（用于调试）
# ============================================================================

class MockProvider(LLMProvider):
    """Mock 提供商，用于调试"""

    def __init__(self):
        self._cancelled = False

    async def call(self, request: LLMRequest) -> LLMResponse:
        """模拟调用 LLM"""
        self._cancelled = False

        # 格式化提示词
        formatted_prompt, prompt_for_feedback = PromptFormatter.format(request)

        # 调试信息
        if settings_manager.settings.get('debug_mode', False):
            base_url = settings_manager.settings.get('base_url', 'N/A')
            api_key = settings_manager.settings.get('api_key', 'N/A')[:5] + "..."
            model_name = settings_manager.settings.get('model_name', 'mock_model')
            print(f"[DEBUG🐛] MockProvider: base_url={base_url}, api_key={api_key}")
            print(f"[DEBUG🐛] MockProvider: model={model_name}, timeout={request.timeout}s")
            print(f"[DEBUG🐛] MockProvider: sending {len(formatted_prompt)} chars")

        # 获取 mock 响应
        mock_response_full = get_mock_response(request.task_tag)

        print(f"[DEBUG🐛] Mock response for {request.task_tag}:")
        response_parts = []

        for line in mock_response_full.split('\n'):
            if self._cancelled:
                print("\n[!💥] MockProvider: Cancelled by user")
                return LLMResponse(
                    content="<Cancelled>Analysis cancelled by user",
                    raw_prompt=prompt_for_feedback,
                    is_error=False
                )

            print(f"[DEBUG🐛] {line}")
            response_parts.append(line)
            await asyncio.sleep(0.1)  # 模拟网络延迟

        return LLMResponse(
            content="\n".join(response_parts),
            raw_prompt=prompt_for_feedback,
            is_error=False
        )

    def cancel(self):
        """取消当前请求"""
        self._cancelled = True


# ============================================================================
# 工厂类
# ============================================================================

class LLMProviderFactory:
    """LLM 提供商工厂"""

    @staticmethod
    def create(base_url: str = None, use_mock: bool = False) -> LLMProvider:
        """
        创建 LLM 提供商实例

        Args:
            base_url: API 基础 URL
            use_mock: 是否使用 Mock 提供商

        Returns:
            LLMProvider: 提供商实例
        """
        if use_mock or settings_manager.settings.get('debug_mode', False):
            return MockProvider()

        if not base_url:
            base_url = settings_manager.settings.get('base_url', '')

        # 检测是否为 Anthropic API
        if 'anthropic' in base_url.lower():
            return AnthropicProvider()

        # 默认使用 OpenAI 兼容 API
        return OpenAIProvider()


# ============================================================================
# 统一客户端
# ============================================================================

class LLMClient:
    """统一的 LLM 客户端"""

    def __init__(self, provider: LLMProvider = None):
        """
        初始化客户端

        Args:
            provider: LLM 提供商，如果为 None 则自动创建
        """
        self.provider = provider or LLMProviderFactory.create()

    async def call(self, request: LLMRequest) -> LLMResponse:
        """
        调用 LLM API

        Args:
            request: LLM 请求对象

        Returns:
            LLMResponse: 响应对象
        """
        return await self.provider.call(request)

    def cancel(self):
        """取消当前请求"""
        self.provider.cancel()
