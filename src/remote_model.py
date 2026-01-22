"""
Remote Model - 适配层

此文件作为向后兼容的适配层，重新导出 infrastructure.llm_api 的所有公共接口。

原有的 handler.py 和 recopilot.py 从此文件导入，无需修改。

注意: 此文件仅为适配层，实际实现已迁移到 infrastructure.llm_api 模块。
"""

# 从新模块导入所有公共接口
from infrastructure.llm_api import (
    LLMClient,
    LLMRequest,
    LLMResponse,
    LLMProviderFactory,
)

# 从 config 导入（保留向后兼容）
from config import settings_manager, PROMPT_TEMPLATE
from task_guides import TASK_GUIDES, TASK_OUTPUT_FORMATS, get_mock_response


# ============================================================================
# 适配器类 - 保持原有接口
# ============================================================================

class OpenAIModel:
    """
    OpenAI Model 适配器

    保持原有 OpenAIModel 类的接口，内部使用新的 LLMClient。
    """

    def __init__(self):
        """初始化适配器"""
        self.client = LLMClient()
        self._cancelled = False

    def _is_anthropic_api(self, base_url: str) -> bool:
        """
        检测是否为 Anthropic API

        保留此方法以保持向后兼容，虽然新实现使用工厂模式。
        """
        return 'anthropic' in base_url.lower() if base_url else False

    def cancel(self):
        """取消当前正在进行的模型调用"""
        self._cancelled = True
        self.client.cancel()

    async def call_model(self, prompt: str, task_tag: str, timeout: int = 600):
        """
        异步调用 OpenAI 模型

        保留原有接口签名，内部转换为新的 LLMRequest/LLMResponse。

        Args:
            prompt: 用户提供的核心提示内容
            task_tag: 任务的唯一标识符
            timeout: API 调用的超时时间（秒）

        Returns:
            (model_response_text, original_prompt_for_feedback)
        """
        self._cancelled = False

        # 创建 LLMRequest
        request = LLMRequest(
            prompt=prompt,
            task_tag=task_tag,
            max_tokens=settings_manager.settings.get('max_output_tokens', 2048),
            timeout=timeout,
            template_name=settings_manager.settings.get('prompt_template', 'general'),
        )

        # 调用 LLM API
        response = await self.client.call(request)

        # 转换返回值以匹配旧接口
        if response.is_error:
            # 错误情况：返回错误消息
            return response.content, response.raw_prompt

        # 成功情况：返回响应内容
        return response.content, response.raw_prompt

    async def call_model_mock(self, prompt: str, task_tag: str, timeout: int = 600):
        """
        异步模拟调用 AI 模型，用于调试

        保留此方法以保持向后兼容。
        """
        self._cancelled = False

        # 创建 Mock 提供商的请求
        from infrastructure.llm_api import MockProvider

        provider = MockProvider()
        request = LLMRequest(
            prompt=prompt,
            task_tag=task_tag,
            max_tokens=settings_manager.settings.get('max_output_tokens', 2048),
            timeout=timeout,
            template_name=settings_manager.settings.get('prompt_template', 'general'),
        )

        response = await provider.call(request)

        if response.is_error:
            return response.content, response.raw_prompt

        return response.content, response.raw_prompt


# ============================================================================
# 全局实例 - 保持向后兼容
# ============================================================================

# 保留原有的全局实例
model = OpenAIModel()
