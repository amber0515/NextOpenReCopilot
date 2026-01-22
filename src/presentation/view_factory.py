"""
Presentation Layer - View Factory Functions

This module contains factory functions for creating and displaying various views.
These functions abstract the view creation process and provide a consistent interface.
"""

import idaapi
import ida_hexrays
import ida_kernwin
import idc

from .qt_views import (
    DecompilationViewPluginForm,
    UserConfirmForm,
    UserConfirmFormForFuncName,
    VariableSelectionForm
)
from .qt_widgets import OutputWindowButton


def create_variable_selection_view(ea):
    """
    Creates a variable selection view for selecting specific variables to analyze.

    Args:
        ea: Function address

    Returns:
        VariableSelectionForm instance or None if failed
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
    Creates a decompilation view in IDA using PluginForm.

    Displays improved/syntax-highlighted decompiled code using Pygments.

    Args:
        ea: Function address
        task_tag: Task tag (unused but kept for consistent signature)
        prompt: Prompt for feedback (unused but kept for consistent signature)
        response_raw: Raw response (unused but kept for consistent signature)
        response: Processed response - the decompiled code content

    Returns:
        bool: True if success, False otherwise
    """
    print('[*] Try to create ReCopilot decompilation view using PluginForm')
    func_name = idc.get_func_name(ea)
    title = f'ReCopilot Decompilation - {func_name}'
    # For decompilation view, use response as content (already parsed)
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


def create_user_confirm_view(ea, task_tag, prompt, response_raw, response):
    """
    Creates a user confirmation view for analysis results.

    Displays a form with all predicted values (function name, types, args, vars, docs)
    allowing the user to review and selectively accept/reject each field.

    Args:
        ea: Function address
        task_tag: Task type tag
        prompt: Original prompt sent to LLM
        response_raw: Raw LLM response
        response: Parsed and validated response dictionary

    Returns:
        bool: True if view created successfully
    """
    form = UserConfirmForm(ea, task_tag, prompt, response_raw, response)
    title = f'ReCopilot - {task_tag} - {hex(ea)}'
    form.Show(title)
    return True


def create_user_confirm_view_for_funcname(ea, task_tag, prompt, response_raw, response):
    """
    Creates a simplified user confirmation view specifically for function name recovery.

    Shows only the function name field with original vs predicted comparison.

    Args:
        ea: Function address
        task_tag: Task type tag
        prompt: Original prompt sent to LLM
        response_raw: Raw LLM response
        response: Parsed function name prediction

    Returns:
        bool: True if view created successfully
    """
    form = UserConfirmFormForFuncName(ea, task_tag, prompt, response_raw, response)
    title = f'ReCopilot - Function Name Analysis - {hex(ea)}'
    form.Show(title)
    return True


def add_cancel_button(model):
    """
    Adds a cancel button to the bottom of the Output window.

    The button appears during long-running LLM operations and allows
    users to cancel the request.

    Args:
        model: OpenAIModel instance with a cancel() method

    Returns:
        OutputWindowButton instance or None if failed
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
    Removes the cancel button from the Output window.

    Args:
        button_widget: OutputWindowButton instance to remove
    """
    if button_widget:
        button_widget.hide()
        button_widget.deleteLater()  # Schedule for deletion
