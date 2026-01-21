"""
ReCopilot Qt - 适配层

此文件作为向后兼容的适配层，重新导出 presentation 模块的所有公共接口。

原有的 handler.py 和 recopilot.py 从此文件导入，无需修改。

注意: 此文件仅为适配层，实际实现已迁移到 presentation 模块。
"""

# 从新模块导入所有公共接口
from presentation.qt_views import (
    ReCopilotSettingsDialog,
)
from presentation.qt_helpers import (
    create_variable_selection_view,
    create_decompilation_view,
    create_user_confirm_view_for_funcname,
    create_user_confirm_view,
    add_cancel_button,
    remove_cancel_button,
)

# 保持原有导出接口，确保 handler.py 和 recopilot.py 无需修改
__all__ = [
    'ReCopilotSettingsDialog',
    'create_decompilation_view',
    'create_user_confirm_view',
    'create_variable_selection_view',
    'create_user_confirm_view_for_funcname',
    'add_cancel_button',
    'remove_cancel_button',
]
