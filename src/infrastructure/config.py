"""
Config - 配置管理

此模块提供 ReCopilot 的配置管理功能。
配置存储在 settings.json 文件中，支持模型、分析和 UI 配置。

保持向后兼容，同时提供新的数据类接口。
"""

import os
import json
from dataclasses import dataclass, field
from typing import Optional

# 加载 prompts.json
prompt_json_path = os.path.join(os.path.dirname(__file__), '..', 'prompts.json')

if not os.path.exists(prompt_json_path):
    # 尝试从 src 目录加载
    prompt_json_path = os.path.join(os.path.dirname(__file__), 'prompts.json')

PROMPT_TEMPLATE = {}
try:
    with open(prompt_json_path, 'r', encoding='utf-8') as f:
        PROMPT_TEMPLATE = json.load(f)
    print(f"[👏] load {len(PROMPT_TEMPLATE)} prompt templates:\n{list(PROMPT_TEMPLATE.keys())}")
except Exception as e:
    print(f"Error loading prompts.json: {e}")


# ============================================================================
# 配置数据类
# ============================================================================

@dataclass
class ModelConfig:
    """模型配置"""
    model_name: str
    base_url: str
    api_key: str
    prompt_template: str
    max_output_tokens: int
    temperature: float = 0.6
    stream: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> 'ModelConfig':
        """从字典创建 ModelConfig"""
        return cls(
            model_name=data.get('model_name', 'gpt-3.5-turbo'),
            base_url=data.get('base_url', ''),
            api_key=data.get('api_key', ''),
            prompt_template=data.get('prompt_template', 'general'),
            max_output_tokens=data.get('max_output_tokens', 2048),
        )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'model_name': self.model_name,
            'base_url': self.base_url,
            'api_key': self.api_key,
            'prompt_template': self.prompt_template,
            'max_output_tokens': self.max_output_tokens,
        }


@dataclass
class AnalysisConfig:
    """分析配置"""
    max_trace_caller_depth: int
    max_trace_callee_depth: int
    max_context_func_num: int
    data_flow_analysis: bool
    measure_info_score: bool

    @classmethod
    def from_dict(cls, data: dict) -> 'AnalysisConfig':
        """从字典创建 AnalysisConfig"""
        return cls(
            max_trace_caller_depth=data.get('max_trace_caller_depth', 1),
            max_trace_callee_depth=data.get('max_trace_callee_depth', 1),
            max_context_func_num=data.get('max_context_func_num', 10),
            data_flow_analysis=data.get('data_flow_analysis', True),
            measure_info_score=data.get('measure_info_score', True),
        )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'max_trace_caller_depth': self.max_trace_caller_depth,
            'max_trace_callee_depth': self.max_trace_callee_depth,
            'max_context_func_num': self.max_context_func_num,
            'data_flow_analysis': self.data_flow_analysis,
            'measure_info_score': self.measure_info_score,
        }


@dataclass
class UIConfig:
    """UI 配置"""
    need_confirm: bool
    debug_mode: bool
    feedback: bool

    @classmethod
    def from_dict(cls, data: dict) -> 'UIConfig':
        """从字典创建 UIConfig"""
        return cls(
            need_confirm=data.get('need_confirm', True),
            debug_mode=data.get('debug_mode', False),
            feedback=data.get('feedback', False),
        )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'need_confirm': self.need_confirm,
            'debug_mode': self.debug_mode,
            'feedback': self.feedback,
        }


# ============================================================================
# 配置管理器
# ============================================================================

class ConfigManager:
    """
    统一配置管理器

    管理模型、分析和 UI 配置，提供向后兼容的字典接口。
    """
    def __init__(self):
        self.settings_dir = os.path.dirname(os.path.abspath(__file__))
        self.settings_file = os.path.join(self.settings_dir, 'settings.json')
        os.makedirs(self.settings_dir, exist_ok=True)
        print(f"[DEBUG🐛] Settings file: {self.settings_file}")

        # 加载配置
        settings_dict = self._load_settings_from_file()

        # 创建配置对象
        self.model = ModelConfig.from_dict(settings_dict)
        self.analysis = AnalysisConfig.from_dict(settings_dict)
        self.ui = UIConfig.from_dict(settings_dict)

        # 保持向后兼容的 settings 字典
        self._settings = settings_dict

    def get_default_settings(self) -> dict:
        """获取默认配置字典"""
        return {
            'model_name': 'GLM-4.7',
            'base_url': 'https://open.bigmodel.cn/api/paas/v4',
            'api_key': '496120a33182490c8158e3a95edfc889.siiIvQQMsI5NnSji',
            'prompt_template': 'general',
            'max_output_tokens': 8000,
            'max_trace_caller_depth': 1,
            'max_trace_callee_depth': 1,
            'max_context_func_num': 10,
            'data_flow_analysis': True,
            'measure_info_score': True,
            'need_confirm': True,
            'debug_mode': False,
            'feedback': False
        }

    def _load_settings_from_file(self) -> dict:
        """从文件加载配置"""
        if not os.path.exists(self.settings_file):
            return self.get_default_settings()

        try:
            with open(self.settings_file, 'r') as f:
                loaded_settings = json.load(f)

            # 合并默认设置，确保所有键都存在
            default_settings = self.get_default_settings()
            for key in default_settings:
                if key not in loaded_settings:
                    loaded_settings[key] = default_settings[key]

            return loaded_settings
        except Exception as e:
            print(f"Error loading settings: {str(e)}")
            return self.get_default_settings()

    def save_settings(self, settings_data: dict):
        """保存配置到文件"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings_data, f, indent=4)

            # 更新内部状态
            self._settings = settings_data
            self.model = ModelConfig.from_dict(settings_data)
            self.analysis = AnalysisConfig.from_dict(settings_data)
            self.ui = UIConfig.from_dict(settings_data)
        except Exception as e:
            print(f"Error saving settings: {str(e)}")

    def get_setting(self, key: str):
        """获取特定配置项"""
        return self._settings.get(key, None)

    def set_setting(self, key: str, value):
        """修改并保存单个配置项"""
        if key in self._settings:
            self._settings[key] = value
            self.save_settings(self._settings)

    @property
    def settings(self) -> dict:
        """向后兼容：返回扁平字典"""
        return self._settings.copy()


# ============================================================================
# 全局实例
# ============================================================================

# 创建全局配置管理器实例
settings_manager = ConfigManager()
