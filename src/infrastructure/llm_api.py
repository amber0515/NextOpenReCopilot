"""
Infrastructure Layer - LLM API

This module provides a unified interface for LLM API calls,
supporting OpenAI-compatible and Anthropic Claude APIs.
Extracted and refactored from remote_model.py.

Following the architecture design in ARCHITECTURE_REFACTORING_PLAN.md
"""

import asyncio
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator, Optional


@dataclass
class LLMRequest:
    """LLM 请求"""
    prompt: str
    task_tag: str
    max_tokens: int = 2048
    temperature: float = 0.6
    timeout: int = 600


@dataclass
class LLMResponse:
    """LLM 响应"""
    content: str
    raw_prompt: str


class LLMApi(ABC):
    """LLM API 抽象接口"""

    def __init__(self, base_url: str, api_key: str, model_name: str):
        self.base_url = base_url
        self.api_key = api_key
        self.model_name = model_name
        self._cancelled = False

    def cancel(self):
        """取消当前请求"""
        self._cancelled = True

    def _reset_cancel_state(self):
        """重置取消标志"""
        self._cancelled = False

    def _is_cancelled(self) -> bool:
        """检查是否已取消"""
        return self._cancelled

    @abstractmethod
    async def call(self, request: LLMRequest) -> LLMResponse:
        """
        调用 LLM（返回完整响应）

        Args:
            request: LLM 请求

        Returns:
            LLM 响应
        """
        pass

    @abstractmethod
    async def call_stream(self, request: LLMRequest) -> AsyncIterator[str]:
        """
        流式调用 LLM（返回迭代器）

        Args:
            request: LLM 请求

        Yields:
            响应文本片段
        """
        pass


class OpenAIApi(LLMApi):
    """
    OpenAI 兼容 API 实现

    支持：
    - OpenAI 官方 API
    - DeepSeek (https://api.deepseek.com)
    - Ollama 本地 API (http://localhost:11434)
    - 其他 OpenAI 兼容的 API
    """

    async def call(self, request: LLMRequest) -> LLMResponse:
        """
        调用 OpenAI 兼容 API，返回完整响应
        """
        self._reset_cancel_state()

        try:
            import openai
        except ImportError:
            raise ImportError("openai package is required. Install with: pip install openai")

        # 构建客户端参数
        client_args = {'api_key': self.api_key or 'sk-none'}
        if self.base_url:
            client_args['base_url'] = self.base_url

        client = openai.AsyncOpenAI(**client_args)

        # 构建消息
        messages = [{"role": "user", "content": request.prompt}]

        try:
            # 发送请求（非流式）
            response = await client.chat.completions.create(
                model=self.model_name,
                temperature=request.temperature,
                stream=False,
                max_tokens=request.max_tokens,
                messages=messages,
                timeout=float(request.timeout)
            )

            content = response.choices[0].message.content
            return LLMResponse(content=content, raw_prompt=request.prompt)

        except openai.APITimeoutError as e:
            error_msg = f"<RequestException>Request timed out: {e}"
            return LLMResponse(content=error_msg, raw_prompt=request.prompt)
        except openai.APIConnectionError as e:
            error_msg = f"<RequestException>Connection failed: {e}"
            return LLMResponse(content=error_msg, raw_prompt=request.prompt)
        except openai.AuthenticationError as e:
            error_msg = f"<RequestException>Authentication failed - check your API key: {e}"
            return LLMResponse(content=error_msg, raw_prompt=request.prompt)
        except Exception as e:
            error_msg = f"<RequestException>{str(e)}"
            traceback.print_exc()
            return LLMResponse(content=error_msg, raw_prompt=request.prompt)

    async def call_stream(self, request: LLMRequest) -> AsyncIterator[str]:
        """
        流式调用 OpenAI 兼容 API

        实时打印响应内容，并逐块返回
        """
        self._reset_cancel_state()

        try:
            import openai
        except ImportError:
            raise ImportError("openai package is required. Install with: pip install openai")

        # 构建客户端参数
        client_args = {'api_key': self.api_key or 'sk-none'}
        if self.base_url:
            client_args['base_url'] = self.base_url

        client = openai.AsyncOpenAI(**client_args)

        # 构建消息
        messages = [{"role": "user", "content": request.prompt}]

        try:
            # 发送流式请求
            completion = await client.chat.completions.create(
                model=self.model_name,
                temperature=request.temperature,
                stream=True,
                max_tokens=request.max_tokens,
                messages=messages,
                timeout=float(request.timeout)
            )

            async for chunk in completion:
                if self._is_cancelled():
                    print("\n[!💥] Analysis cancelled by user")
                    yield "<Cancelled>Analysis cancelled by user"
                    break

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
                    yield chunk_content

            print()  # 流结束后换行

        except openai.APITimeoutError as e:
            print(f"\n[!💥] Error: Request timed out: {e}")
            yield f"<RequestException>Request timed out: {e}"
        except openai.APIConnectionError as e:
            print(f"\n[!💥] Error: Connection failed: {e}")
            yield f"<RequestException>Connection failed: {e}"
        except openai.AuthenticationError as e:
            print(f"\n[!💥] Error: Authentication failed: {e}")
            yield f"<RequestException>Authentication failed: {e}"
        except Exception as e:
            print(f"\n[!💥] Error: {e}")
            traceback.print_exc()
            yield f"<RequestException>{str(e)}"


class AnthropicApi(LLMApi):
    """
    Anthropic Claude API 实现

    支持：
    - Anthropic 官方 API (https://api.anthropic.com)
    - 兼容 Anthropic 的第三方 API
    """

    async def call(self, request: LLMRequest) -> LLMResponse:
        """
        调用 Anthropic API，返回完整响应
        """
        self._reset_cancel_state()

        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package is required. Install with: pip install anthropic")

        # 构建客户端参数
        client_args = {'api_key': self.api_key}
        if self.base_url:
            client_args['base_url'] = self.base_url

        client = anthropic.AsyncAnthropic(**client_args)

        # 构建消息
        messages = [{"role": "user", "content": request.prompt}]

        try:
            # 发送请求（非流式）
            response = await client.messages.create(
                model=self.model_name,
                max_tokens=request.max_tokens,
                messages=messages,
            )

            content = response.content[0].text
            return LLMResponse(content=content, raw_prompt=request.prompt)

        except anthropic.APIConnectionError as e:
            error_msg = f"<RequestException>Connection failed: {e}"
            return LLMResponse(content=error_msg, raw_prompt=request.prompt)
        except anthropic.AuthenticationError as e:
            error_msg = f"<RequestException>Authentication failed: {e}"
            return LLMResponse(content=error_msg, raw_prompt=request.prompt)
        except anthropic.RateLimitError as e:
            error_msg = f"<RequestException>Rate limit exceeded: {e}"
            return LLMResponse(content=error_msg, raw_prompt=request.prompt)
        except Exception as e:
            error_msg = f"<RequestException>{str(e)}"
            traceback.print_exc()
            return LLMResponse(content=error_msg, raw_prompt=request.prompt)

    async def call_stream(self, request: LLMRequest) -> AsyncIterator[str]:
        """
        流式调用 Anthropic API

        实时打印响应内容，并逐块返回
        """
        self._reset_cancel_state()

        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package is required. Install with: pip install anthropic")

        # 构建客户端参数
        client_args = {'api_key': self.api_key}
        if self.base_url:
            client_args['base_url'] = self.base_url

        client = anthropic.AsyncAnthropic(**client_args)

        # 构建消息
        messages = [{"role": "user", "content": request.prompt}]

        try:
            # 发送流式请求
            async with client.messages.stream(
                model=self.model_name,
                max_tokens=request.max_tokens,
                messages=messages,
            ) as stream:
                async for text in stream.text_stream:
                    if self._is_cancelled():
                        print("\n[!💥] Analysis cancelled by user")
                        yield "<Cancelled>Analysis cancelled by user"
                        break

                    print(text, end="")
                    yield text

            print()  # 流结束后换行

        except anthropic.APIConnectionError as e:
            print(f"\n[!💥] Error: Connection failed: {e}")
            yield f"<RequestException>Connection failed: {e}"
        except anthropic.AuthenticationError as e:
            print(f"\n[!💥] Error: Authentication failed: {e}")
            yield f"<RequestException>Authentication failed: {e}"
        except anthropic.RateLimitError as e:
            print(f"\n[!💥] Error: Rate limit exceeded: {e}")
            yield f"<RequestException>Rate limit exceeded: {e}"
        except Exception as e:
            print(f"\n[!💥] Error: {e}")
            traceback.print_exc()
            yield f"<RequestException>{str(e)}"


class LLMApiFactory:
    """
    LLM API 工厂类

    根据配置创建合适的 API 实例
    """

    @staticmethod
    def _is_anthropic_api(base_url: str) -> bool:
        """检测是否为 Anthropic API"""
        if not base_url:
            return False
        return 'anthropic' in base_url.lower()

    @staticmethod
    def create_from_config(settings: dict) -> LLMApi:
        """
        根据配置字典创建 API 实例

        Args:
            settings: 配置字典，应包含 base_url, api_key, model_name

        Returns:
            配置好的 LLMApi 实例
        """
        base_url = settings.get('base_url', '')
        api_key = settings.get('api_key', '')
        model_name = settings.get('model_name', 'gpt-4o')

        # 检测 API 类型
        if LLMApiFactory._is_anthropic_api(base_url):
            return AnthropicApi(base_url, api_key, model_name)
        else:
            return OpenAIApi(base_url, api_key, model_name)

    @staticmethod
    def create_openai(base_url: str = '', api_key: str = '', model_name: str = 'gpt-4o') -> OpenAIApi:
        """创建 OpenAI API 实例"""
        return OpenAIApi(base_url, api_key, model_name)

    @staticmethod
    def create_anthropic(base_url: str = 'https://api.anthropic.com',
                        api_key: str = '', model_name: str = 'claude-3-opus-20240229') -> AnthropicApi:
        """创建 Anthropic API 实例"""
        return AnthropicApi(base_url, api_key, model_name)
