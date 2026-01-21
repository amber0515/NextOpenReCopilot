"""
Qt Helpers - 视图创建辅助函数

此模块包含创建视图的辅助函数，连接 handler 和视图层。
这些函数提供了简洁的接口来创建和显示各种 IDA 视图。

函数列表:
- create_variable_selection_view: 创建变量选择视图
- create_decompilation_view: 创建反编译视图
- create_user_confirm_view_for_funcname: 创建函数名确认视图
- create_user_confirm_view: 创建通用确认视图
- add_cancel_button: 添加取消按钮
- remove_cancel_button: 移除取消按钮
"""

import idc
import idaapi
import ida_hexrays
import ida_kernwin

from .qt_views import (
    DecompilationViewPluginForm,
    UserConfirmForm,
    UserConfirmFormForFuncName,
    VariableSelectionForm,
)
from .qt_widgets import OutputWindowButton


def create_variable_selection_view(ea):
    """
    创建变量选择视图。

    Args:
        ea: 函数地址

    Returns:
        VariableSelectionForm 实例，失败返回 None
    """
    try:
        f = idaapi.get_func(ea)
        if not f:
            print("[!] No function found at this address")
            return None

        df = ida_hexrays.decompile(f)
        if not df:
            print("[!] Failed to decompile function")
            return None

        args = []
        vars = []
        for var in df.lvars:
            if var.is_arg_var:
                args.append(var.name)
            else:
                vars.append(var.name)

        form = VariableSelectionForm(ea, args, vars)
        form.Show(form.title)
        return form
    except Exception as e:
        print(f"Error creating variable selection view: {e}")
        return None


def create_decompilation_view(ea, task_tag, prompt, response_raw, response):
    """
    在 IDA 主线程中创建反编译视图 (使用 PluginForm)

    Args:
        ea: 函数地址
        task_tag: 任务标签 (未使用，保持签名一致)
        prompt: prompt 用于反馈 (未使用，保持签名一致)
        response_raw: 原始响应 (未使用，保持签名一致)
        response: 处理后的响应 - 反编译代码内容

    Returns:
        bool: 成功返回 True，失败返回 False
    """
    print('[*] Try to create ReCopilot decompilation view using PluginForm')
    func_name = idc.get_func_name(ea)
    title = f'ReCopilot Decompilation - {func_name}'
    # 对于反编译视图，使用 response 作为内容（已解析的响应）
    content = response if response else response_raw
    try:
        form = DecompilationViewPluginForm(title, content)
        form.Show()  # Show() already uses self.title internally
        if ida_kernwin.find_widget(title):
            print(f'[+] Successfully created/shown decompilation view with PluginForm, title: {title}')
            return True
        else:
            print(f'[!] Failed to verify creation/showing of decompilation view with PluginForm, title: {title}.')
            return False
    except Exception as e:
        print(f'[!] Error creating decompilation view with PluginForm: {str(e)}')
        import traceback
        traceback.print_exc(0)
        return False


def create_user_confirm_view_for_funcname(ea, task_tag, prompt, response_raw, response):
    """
    创建函数名确认视图。

    Args:
        ea: 函数地址
        task_tag: 任务标签
        prompt: prompt 用于反馈
        response_raw: 原始响应
        response: 处理后的响应

    Returns:
        bool: 成功返回 True
    """
    form = UserConfirmFormForFuncName(ea, task_tag, prompt, response_raw, response)
    title = f'ReCopilot - Function Name Analysis - {hex(ea)}'
    form.Show(title)
    return True


def create_user_confirm_view(ea, task_tag, prompt, response_raw, response):
    """
    创建通用确认视图。

    Args:
        ea: 函数地址
        task_tag: 任务标签
        prompt: prompt 用于反馈
        response_raw: 原始响应
        response: 处理后的响应

    Returns:
        bool: 成功返回 True
    """
    form = UserConfirmForm(ea, task_tag, prompt, response_raw, response)
    title = f'ReCopilot - {task_tag} - {hex(ea)}'
    form.Show(title)
    return True


def add_cancel_button(model):
    """
    在输出窗口底部添加取消按钮。

    Args:
        model: OpenAIModel 实例，用于调用 cancel 方法

    Returns:
        OutputWindowButton 实例，失败返回 None
    """
    output_window = ida_kernwin.find_widget('Output window')
    if output_window:
        output_qwidget = ida_kernwin.PluginForm.FormToPyQtWidget(output_window)
        if output_qwidget:
            button_widget = OutputWindowButton(model, output_qwidget)
            output_qwidget.layout().addWidget(button_widget)
            button_widget.show()
            return button_widget
    return None


def remove_cancel_button(button_widget):
    """
    移除取消按钮。

    Args:
        button_widget: 要移除的 OutputWindowButton 实例
    """
    if button_widget:
        button_widget.hide()
        button_widget.deleteLater() # Schedule for deletion
