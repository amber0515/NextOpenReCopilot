"""
Presentation Layer - UI 组件和视图

此模块包含 IDA Pro 插件的所有 UI 相关代码：
- qt_widgets: 可复用的 PyQt5 UI 组件
- qt_views: IDA 特定的视图类
- qt_helpers: 视图创建辅助函数
"""

from .qt_widgets import (
    EditablePredictionWidget,
    NameTypeWidget,
    StructFieldWidget,
    EnumFieldWidget,
    ComplexTypeWidget,
    VariableSelectionWidget,
    OutputWindowButton,
)

from .qt_views import (
    DecompilationViewPluginForm,
    UserConfirmForm,
    UserConfirmFormForFuncName,
    VariableSelectionForm,
    ReCopilotSettingsDialog,
)

from .qt_helpers import (
    create_variable_selection_view,
    create_decompilation_view,
    create_user_confirm_view_for_funcname,
    create_user_confirm_view,
    add_cancel_button,
    remove_cancel_button,
)

__all__ = [
    # Widgets
    'EditablePredictionWidget',
    'NameTypeWidget',
    'StructFieldWidget',
    'EnumFieldWidget',
    'ComplexTypeWidget',
    'VariableSelectionWidget',
    'OutputWindowButton',
    # Views
    'DecompilationViewPluginForm',
    'UserConfirmForm',
    'UserConfirmFormForFuncName',
    'VariableSelectionForm',
    'ReCopilotSettingsDialog',
    # Helpers
    'create_variable_selection_view',
    'create_decompilation_view',
    'create_user_confirm_view_for_funcname',
    'create_user_confirm_view',
    'add_cancel_button',
    'remove_cancel_button',
]
