"""
Presentation Layer

This package contains UI components and views for the ReCopilot plugin.
It is organized into three modules:

- qt_widgets: Reusable UI components (widgets)
- qt_views: IDA-integrated views and forms
- view_factory: Factory functions for creating views

Example usage:
    # Old way (still works - backward compatible)
    from recopilot_qt import create_user_confirm_view

    # New way (recommended)
    from presentation import create_user_confirm_view
    # or
    from presentation.view_factory import create_user_confirm_view
"""

# Import factory functions for convenient access
from .view_factory import (
    create_variable_selection_view,
    create_decompilation_view,
    create_user_confirm_view,
    create_user_confirm_view_for_funcname,
    add_cancel_button,
    remove_cancel_button,
)

# Import views for direct access if needed
from .qt_views import (
    DecompilationViewPluginForm,
    UserConfirmForm,
    UserConfirmFormForFuncName,
    VariableSelectionForm,
    ReCopilotSettingsDialog,
)

# Import widgets for direct access if needed
from .qt_widgets import (
    EditablePredictionWidget,
    NameTypeWidget,
    StructFieldWidget,
    EnumFieldWidget,
    ComplexTypeWidget,
    VariableSelectionWidget,
    OutputWindowButton,
)

__all__ = [
    # Factory functions
    'create_variable_selection_view',
    'create_decompilation_view',
    'create_user_confirm_view',
    'create_user_confirm_view_for_funcname',
    'add_cancel_button',
    'remove_cancel_button',
    # Views
    'DecompilationViewPluginForm',
    'UserConfirmForm',
    'UserConfirmFormForFuncName',
    'VariableSelectionForm',
    'ReCopilotSettingsDialog',
    # Widgets
    'EditablePredictionWidget',
    'NameTypeWidget',
    'StructFieldWidget',
    'EnumFieldWidget',
    'ComplexTypeWidget',
    'VariableSelectionWidget',
    'OutputWindowButton',
]
