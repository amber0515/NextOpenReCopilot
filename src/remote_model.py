"""
Remote Model - OpenAI/Anthropic API Client

This module provides backward-compatible interface to LLM APIs.
Internally delegates to infrastructure.llm_api for actual API calls.
"""

import asyncio
from infrastructure.llm_api import LLMApiFactory, LLMRequest, LLMApi

# Configuration and templates
from config import settings_manager, PROMPT_TEMPLATE
from task_guides import TASK_GUIDES, TASK_OUTPUT_FORMATS, get_mock_response


class OpenAIModel:
    """
    OpenAI/Anthropic Model client with backward-compatible interface.

    This class acts as a facade/adapter that:
    1. Formats prompts using templates and task guides
    2. Delegates actual API calls to infrastructure.llm_api
    3. Maintains the same return format: (response_text, prompt_for_feedback)
    """

    def __init__(self):
        self._api: LLMApi = None
        self._cancelled = False

    def _refresh_api(self):
        """Refresh API instance based on current settings."""
        if self._api is None:
            self._api = LLMApiFactory.create_from_config(settings_manager.settings)

    def cancel(self):
        """取消当前正在进行的模型调用。"""
        self._cancelled = True
        if self._api:
            self._api.cancel()

    def _reset_cancel_state(self):
        """重置取消标志"""
        self._cancelled = False

    async def call_model(self, prompt: str, task_tag: str, timeout: int = 600):
        """
        异步调用 OpenAI 模型。

        Args:
            prompt: 用户提供的核心提示内容。
            task_tag: 任务的唯一标识符，用于选择任务指南和输出格式。
            timeout: API 调用的超时时间（秒）。

        Returns:
            一个元组 (model_response_text, prompt_for_feedback)。
        """
        self._reset_cancel_state()

        # 1. 格式化 Prompt
        formatted_prompt, prompt_for_feedback = self._format_prompt(prompt, task_tag)

        # 2. 调试输出
        self._debug_output(formatted_prompt, task_tag, timeout)

        # 3. 获取 API 实例并调用
        self._refresh_api()

        # 4. 构建 LLMRequest
        request = LLMRequest(
            prompt=formatted_prompt,
            task_tag=task_tag,
            max_tokens=settings_manager.settings.get('max_output_tokens', 2048),
            temperature=0.6,
            timeout=timeout
        )

        # 5. 流式调用并收集响应
        response_parts = []
        async for chunk in self._api.call_stream(request):
            if self._cancelled and chunk.startswith("<Cancelled>"):
                print("\n[!💥] Analysis cancelled by user")
                return chunk, prompt_for_feedback
            response_parts.append(chunk)

        print()  # 流结束后换行
        final_response = "".join(response_parts)
        return final_response, prompt_for_feedback

    async def _call_anthropic_model(self, formatted_prompt: str, model_name: str,
                                     api_key: str, base_url: str, timeout: int, prompt_for_feedback: str):
        """
        保留用于向后兼容。现在委托给统一的 API 调用。
        """
        from infrastructure.llm_api import AnthropicApi

        api = AnthropicApi(base_url, api_key, model_name)
        request = LLMRequest(
            prompt=formatted_prompt,
            task_tag="",  # Not used in direct call
            max_tokens=settings_manager.settings.get('max_output_tokens', 2048),
            timeout=timeout
        )

        response_parts = []
        async for chunk in api.call_stream(request):
            response_parts.append(chunk)

        return "".join(response_parts), prompt_for_feedback

    async def call_model_mock(self, prompt: str, task_tag: str, timeout: int = 600):
        """
        异步模拟调用AI模型，用于调试。
        """
        self._reset_cancel_state()

        # 格式化 Prompt
        formatted_prompt, prompt_for_feedback = self._format_prompt(prompt, task_tag)

        # 调试输出
        if settings_manager.settings.get('debug_mode', False):
            debug_prompt_lines = [f"\n[DEBUG🐛] {line}" for line in formatted_prompt.split('\n')]
            print("".join(debug_prompt_lines))

            base_url_setting = settings_manager.settings.get('base_url', 'N/A')
            api_key_setting = settings_manager.settings.get('api_key', 'N/A')[:5] + "..."
            model_name_setting = settings_manager.settings.get('model_name', 'mock_model')
            print(f"[DEBUG🐛] OpenAIModel.call_model_mock: base_url={base_url_setting}, api_key={api_key_setting}, model_name={model_name_setting}, timeout={timeout}s")
            print(f"[DEBUG🐛] OpenAIModel.call_model_mock: recv {len(formatted_prompt)} chars prompt")

        mock_response_full = get_mock_response(task_tag)

        print(f"[DEBUG🐛] Mock response for {task_tag}:")
        response_parts = []
        for line in mock_response_full.split('\n'):
            if self._cancelled:
                print("\n[!💥] Analysis cancelled by user (during mock streaming)")
                return "<Cancelled>Analysis cancelled by user", prompt_for_feedback

            print(f"[DEBUG🐛] {line}")
            response_parts.append(line)
            await asyncio.sleep(0.1)

        return "\n".join(response_parts), prompt_for_feedback

    def _format_prompt(self, prompt: str, task_tag: str):
        """
        格式化 prompt，使用模板和任务指南。

        Returns:
            (formatted_prompt, prompt_for_feedback)
        """
        template_name = settings_manager.settings.get('prompt_template', 'recopilot')
        current_template_str = PROMPT_TEMPLATE.get(template_name, "{input}")

        if template_name.endswith("_wo_guide"):
            formatted = current_template_str.replace("{format}", TASK_OUTPUT_FORMATS.get(task_tag, "")) \
                                         .replace("{input}", prompt)
        else:
            formatted = current_template_str.replace("{format}", TASK_OUTPUT_FORMATS.get(task_tag, "")) \
                                         .replace("{guide}", TASK_GUIDES.get(task_tag, "")) \
                                         .replace("{input}", prompt)

        return formatted, formatted

    def _debug_output(self, formatted_prompt: str, task_tag: str, timeout: int):
        """打印调试信息"""
        if settings_manager.settings.get('debug_mode', False):
            debug_prompt_lines = [f"\n[DEBUG🐛] {line}" for line in formatted_prompt.split('\n')]
            print("".join(debug_prompt_lines))

            model_name_setting = settings_manager.settings.get('model_name', 'unknown_model')
            print(f"[🔗] OpenAIModel.call_model: model_name={model_name_setting}, timeout={timeout}s")
            print(f"[🔗] OpenAIModel.call_model: send {len(formatted_prompt)} chars prompt")

        # 总是打印正在调用的模型
        base_url = settings_manager.settings.get('base_url', '')
        model_name = settings_manager.settings.get('model_name', 'unknown')
        print(f"[🔗] Calling model: {model_name} at {base_url or 'OpenAI default'}")


# 全局实例（向后兼容）
model = OpenAIModel()
