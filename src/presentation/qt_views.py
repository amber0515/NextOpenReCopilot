"""
Qt Views - IDA 特定的视图类

此模块包含所有 IDA Pro 特定的视图类，继承自 ida_kernwin.PluginForm。
这些视图依赖 IDA API 和 qt_widgets 组件。

视图列表:
- DecompilationViewPluginForm: 反编译代码展示视图
- UserConfirmForm: 通用确认对话框
- UserConfirmFormForFuncName: 函数名确认对话框
- VariableSelectionForm: 变量选择对话框
- ReCopilotSettingsDialog: 设置对话框
"""

import idc
import idaapi
import ida_kernwin
from pygments import highlight
from pygments.lexers import CppLexer
from pygments.formatters import HtmlFormatter
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QWidget, QLineEdit,
    QGroupBox, QGridLayout, QMessageBox, QSpinBox, QCheckBox, QComboBox
)

from .qt_widgets import (
    EditablePredictionWidget,
    NameTypeWidget,
    ComplexTypeWidget,
    VariableSelectionWidget,
)

from ext_info import apply_prediction
from config import settings_manager, PROMPT_TEMPLATE


class DecompilationViewPluginForm(ida_kernwin.PluginForm):
    """
    反编译代码展示视图。

    使用 Pygments 进行语法高亮显示重新生成的伪代码。
    """
    def __init__(self, title, initial_content):
        super(DecompilationViewPluginForm, self).__init__()
        self.title = title
        self.initial_content = initial_content
        self.parent_widget = None
        self.code_browser = None

        # Check and close existing widget if it exists
        existing_widget = ida_kernwin.find_widget(title)
        if existing_widget:
            print(f"[*] Found existing widget with title '{title}'. Closing it before recreating.")
            ida_kernwin.close_widget(existing_widget, 0)

    def OnCreate(self, form):
        self.parent_widget = self.FormToPyQtWidget(form)
        layout = QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        self.code_browser = QtWidgets.QTextBrowser()
        self.code_browser.setOpenExternalLinks(False)
        self.code_browser.setFontFamily('Consolas')
        self.code_browser.setStyleSheet('font-size: 12px;')
        layout.addWidget(self.code_browser)
        self.parent_widget.setLayout(layout)

        if self.initial_content:
            self.set_content(self.initial_content)

    def set_content(self, code):
        if self.code_browser:
            lexer = CppLexer()
            formatter = HtmlFormatter(style='vs', noclasses=True)
            highlighted_code = highlight(code, lexer, formatter)
            self.code_browser.setHtml(highlighted_code)

    def OnClose(self, form):
        pass

    def Show(self):
        super(DecompilationViewPluginForm, self).Show(
            self.title,
            options=ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_RESTORE
        )


class UserConfirmForm(ida_kernwin.PluginForm):
    """
    通用用户确认对话框。

    显示各种分析结果的预测，允许用户编辑和选择要应用的内容。
    支持函数名、返回类型、参数、局部变量、文档注释等。
    """
    def __init__(self, ea, task_tag, prompt, response_raw, response):
        super(UserConfirmForm, self).__init__()
        self.ea = ea
        self.task_tag = task_tag
        self.prompt = prompt
        self.response_raw = response_raw
        self.response = response
        self.widgets = {}

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        main_layout = QVBoxLayout()
        main_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)

        # Function Name
        if 'funcname' in self.response:
            func_name_widget = EditablePredictionWidget('Function Name', self.response['funcname'])
            self.widgets['funcname'] = func_name_widget
            main_layout.addWidget(func_name_widget)

        # Return Type
        if 'ret_type' in self.response:
            ret_type_widget = EditablePredictionWidget('Return Type', self.response['ret_type'])
            self.widgets['ret_type'] = ret_type_widget
            main_layout.addWidget(ret_type_widget)

        # Function Arguments
        if 'args' in self.response and self.response['args']:
            args_group = QGroupBox('Function Arguments')
            args_layout = QVBoxLayout(args_group)
            self.widgets['args'] = {}
            args_data = self.response['args']
            # Handle both dict and list formats
            if isinstance(args_data, dict):
                for arg_name, arg_type in args_data.items():
                    arg_widget = ComplexTypeWidget(arg_name, arg_type)
                    self.widgets['args'][arg_name] = arg_widget
                    args_layout.addWidget(arg_widget)
            elif isinstance(args_data, list):
                for item in args_data:
                    if isinstance(item, dict):
                        # Format: {'original': [...], 'prediction': [...]}
                        arg_name = item.get('original', ['', ''])[1] if isinstance(item.get('original'), list) else str(item.get('original', ''))
                        arg_type = item.get('prediction', [])
                        arg_widget = ComplexTypeWidget(arg_name, arg_type)
                        self.widgets['args'][arg_name] = arg_widget
                        args_layout.addWidget(arg_widget)
            args_group.setLayout(args_layout)
            main_layout.addWidget(args_group)

        # Local Variables
        if 'vars' in self.response and self.response['vars']:
            vars_group = QGroupBox('Local Variables')
            vars_layout = QVBoxLayout(vars_group)
            self.widgets['vars'] = {}
            vars_data = self.response['vars']
            # Handle both dict and list formats
            if isinstance(vars_data, dict):
                for var_name, var_type in vars_data.items():
                    var_widget = ComplexTypeWidget(var_name, var_type)
                    self.widgets['vars'][var_name] = var_widget
                    vars_layout.addWidget(var_widget)
            elif isinstance(vars_data, list):
                for item in vars_data:
                    if isinstance(item, dict):
                        var_name = item.get('original', ['', ''])[1] if isinstance(item.get('original'), list) else str(item.get('original', ''))
                        var_type = item.get('prediction', [])
                        var_widget = ComplexTypeWidget(var_name, var_type)
                        self.widgets['vars'][var_name] = var_widget
                        vars_layout.addWidget(var_widget)
            vars_group.setLayout(vars_layout)
            main_layout.addWidget(vars_group)

        # Function Documentation (Brief, Detailed, Return, Category, Algorithm)
        doc_fields = {
            'brief': ('Brief Description', True, True),
            'details': ('Detailed Description', True, False),
            'return': ('Return Description', True, True),
            'category': ('Category', False, True),
            'algorithm': ('Algorithm', False, False)
        }
        if any(key in self.response for key in ['brief', 'details', 'return', 'category', 'algorithm']):
            doc_group = QGroupBox('Function Documentation')
            doc_layout = QVBoxLayout(doc_group)
            for key, (title, is_multiline, force_single_line) in doc_fields.items():
                if key in self.response:
                    doc_widget = EditablePredictionWidget(title, self.response[key], is_multiline, force_single_line=force_single_line)
                    self.widgets[key] = doc_widget
                    doc_layout.addWidget(doc_widget)
            doc_group.setLayout(doc_layout)
            main_layout.addWidget(doc_group)

        # Inline Comments
        if 'inline_comment' in self.response:
            inline_comment_group = QGroupBox('Inline Comments')
            inline_comment_layout = QVBoxLayout(inline_comment_group)
            self.widgets['inline_comment'] = {}
            for line_num, comment_text in self.response['inline_comment'].items():
                comment_widget = EditablePredictionWidget(f'Line {line_num}', comment_text, True, len(comment_text.split('\n')), True)
                self.widgets['inline_comment'][line_num] = comment_widget
                inline_comment_layout.addWidget(comment_widget)
            inline_comment_group.setLayout(inline_comment_layout)
            main_layout.addWidget(inline_comment_group)

        # Buttons
        button_layout = QHBoxLayout()
        accept_button = QPushButton('Accept Selected')
        accept_button.clicked.connect(self.on_accept_clicked)
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.on_cancel_clicked)
        button_layout.addWidget(accept_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)

        # Add main layout to a scroll area
        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        container_widget = QWidget()
        container_widget.setLayout(main_layout)
        scroll_area.setWidget(container_widget)

        form_layout = QVBoxLayout(self.parent)
        form_layout.addWidget(scroll_area)
        self.parent.setLayout(form_layout)

    def validate_fields(self):
        """验证所有字段是否都已正确填写"""
        # Validate simple text fields
        for field_name in ['funcname', 'ret_type']:
            if field_name in self.widgets and self.widgets[field_name].accepted and not self.widgets[field_name].get_content().strip():
                return False, field_name + " " # Indicate which field is problematic

        # Validate complex type fields (args, vars)
        for collection_name in ['args', 'vars']:
            if collection_name in self.widgets:
                for name, widget in self.widgets[collection_name].items():
                    if not widget.validate():
                        return False, f'Please fill in all fields in {collection_name}: {name}'

        # Validate docstring fields
        for doc_key in ['brief', 'details', 'return', 'category', 'algorithm']:
            if doc_key in self.widgets and self.widgets[doc_key].accepted and not self.widgets[doc_key].get_content().strip():
                return False, doc_key + " "

        return True, ""

    def on_accept_clicked(self):
        is_valid, error_field = self.validate_fields()
        if not is_valid:
            QMessageBox.warning(self.parent, 'Validation Error', f'{error_field}\nPlease fill in all selected fields before applying, otherwise unselect it.')
            return

        # Collect accepted content
        accepted_content = {}
        for key, widget in self.widgets.items():
            if isinstance(widget, EditablePredictionWidget) and widget.accepted:
                accepted_content[key] = widget.get_content()
            elif isinstance(widget, dict): # For args and vars (complex types)
                accepted_content[key] = {name: data for name, w in widget.items() if (data := w.get_type_info()) is not None}

        apply_prediction(self.ea, self.task_tag, accepted_content)
        self.Close(0)

    def on_cancel_clicked(self):
        self.Close(0)


class UserConfirmFormForFuncName(ida_kernwin.PluginForm):
    """
    函数名专用确认对话框。

    简化版的 UserConfirmForm，仅用于函数名预测和确认。
    """
    def __init__(self, ea, task_tag, prompt, response_raw, response):
        super(UserConfirmFormForFuncName, self).__init__()
        self.ea = ea
        self.task_tag = task_tag
        self.prompt = prompt
        self.response_raw = response_raw
        self.response = response
        self.widgets = [] # Simplified for func name only

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        main_layout = QVBoxLayout()
        main_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)

        # Function Name field
        func_name_original = idc.get_func_name(self.ea)
        func_name_widget = EditablePredictionWidget(f'Function Name (Original: {func_name_original})', self.response)
        self.widgets.append({'widget': func_name_widget, 'original': func_name_original, 'prediction': self.response})
        main_layout.addWidget(func_name_widget)

        # Buttons
        button_layout = QHBoxLayout()
        accept_button = QPushButton('Accept Selected')
        accept_button.clicked.connect(self.on_accept_clicked)
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.on_cancel_clicked)
        button_layout.addWidget(accept_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)

        self.parent.setLayout(main_layout)

    def validate_fields(self):
        """验证所有字段是否都已正确填写"""
        for item in self.widgets:
            if item['widget'].accepted and not item['widget'].get_content().strip():
                return False, 'Please fill in all selected function names'
        return True, ""

    def on_accept_clicked(self):
        is_valid, error_msg = self.validate_fields()
        if not is_valid:
            QMessageBox.warning(self.parent, 'Validation Error', f'{error_msg}\nPlease fill in all selected fields before applying, otherwise unselect it.')
            return

        accepted_content = {}
        for item in self.widgets:
            if item['widget'].accepted:
                accepted_content['funcname'] = {'original': item['original'], 'prediction': item['widget'].get_content()}

        apply_prediction(self.ea, self.task_tag, accepted_content)
        self.Close(0)

    def on_cancel_clicked(self):
        self.Close(0)


class VariableSelectionForm(ida_kernwin.PluginForm):
    """
    变量选择对话框。

    允许用户选择要分析的参数和局部变量。
    支持全选/取消全选功能。
    """
    def __init__(self, ea, args, vars_):
        super(VariableSelectionForm, self).__init__()
        self.ea = ea
        self.args = args
        self.vars = vars_
        self.selected_args = []
        self.selected_vars = []
        self.title = f'Select Variables to Analyze - {hex(ea)}'

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        ida_kernwin.set_dock_pos(self.title, 'Output window', ida_kernwin.DP_RIGHT) # Dock to output window

    def PopulateForm(self):
        main_layout = QVBoxLayout()

        # Select all checkbox at the top
        select_all_layout = QHBoxLayout()
        self.main_select_all = QCheckBox('Select All Variables')
        self.main_select_all.setChecked(True)
        self.main_select_all.stateChanged.connect(self.on_main_select_all)
        select_all_layout.addWidget(self.main_select_all)
        select_all_layout.addStretch()
        main_layout.addLayout(select_all_layout)

        # Arguments section
        if self.args:
            self.args_widget = VariableSelectionWidget('Function Arguments', self.args)
            main_layout.addWidget(self.args_widget)

        # Local variables section
        if self.vars:
            self.vars_widget = VariableSelectionWidget('Local Variables', self.vars)
            main_layout.addWidget(self.vars_widget)

        # Buttons
        button_layout = QHBoxLayout()
        analyze_button = QPushButton('Analyze Selected')
        analyze_button.clicked.connect(self.on_analyze_clicked)
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.on_cancel_clicked)
        button_layout.addWidget(analyze_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)

        self.parent.setLayout(main_layout)

    def on_main_select_all(self, state):
        checked = (state == QtCore.Qt.Checked)
        if hasattr(self, 'args_widget'):
            self.args_widget.select_all_checkbox.setChecked(checked)
        if hasattr(self, 'vars_widget'):
            self.vars_widget.select_all_checkbox.setChecked(checked)

    def on_analyze_clicked(self):
        if hasattr(self, 'args_widget'):
            self.selected_args = self.args_widget.get_selected_variables()
        if hasattr(self, 'vars_widget'):
            self.selected_vars = self.vars_widget.get_selected_variables()
        self.Close(1) # Close with accepted status

    def on_cancel_clicked(self):
        self.Close(0)


class ReCopilotSettingsDialog(QDialog):
    """
    ReCopilot 设置对话框。

    用于配置模型设置和分析设置。
    """
    def __init__(self, parent=None):
        super(ReCopilotSettingsDialog, self).__init__(parent)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Configure ReCopilot')
        main_layout = QVBoxLayout(self)

        # Model Settings Group
        model_group = QGroupBox('Model Settings')
        model_layout = QGridLayout(model_group)

        # Model Name
        model_layout.addWidget(QLabel('Model Name:'), 0, 0)
        self.model_name_edit = QLineEdit(settings_manager.settings['model_name'])
        model_layout.addWidget(self.model_name_edit, 0, 1)

        # Base URL
        model_layout.addWidget(QLabel('Base URL:'), 1, 0)
        self.base_url_edit = QLineEdit(settings_manager.settings['base_url'])
        model_layout.addWidget(self.base_url_edit, 1, 1)

        # API Key
        model_layout.addWidget(QLabel('API Key:'), 2, 0)
        self.api_key_edit = QLineEdit(settings_manager.settings['api_key'])
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        model_layout.addWidget(self.api_key_edit, 2, 1)

        # Prompt Template
        model_layout.addWidget(QLabel('Prompt Template:'), 3, 0)
        self.prompt_template_combo = QComboBox()
        self.prompt_template_combo.addItems(list(PROMPT_TEMPLATE.keys()))
        self.prompt_template_combo.setCurrentText(settings_manager.settings['prompt_template'])
        self.prompt_template_combo.setToolTip('Select the prompt template to query the model')
        model_layout.addWidget(self.prompt_template_combo, 3, 1)

        # Max Output Tokens
        model_layout.addWidget(QLabel('Max Output Tokens:'), 4, 0)
        self.max_output_tokens_spin = QSpinBox()
        self.max_output_tokens_spin.setRange(1, 2147483647) # Max int value
        self.max_output_tokens_spin.setValue(settings_manager.settings['max_output_tokens'])
        self.max_output_tokens_spin.setToolTip('Maximum number of tokens to generate in the output (1-2147483647)')
        model_layout.addWidget(self.max_output_tokens_spin, 4, 1)

        main_layout.addWidget(model_group)

        # Analysis Settings Group
        analysis_group = QGroupBox('Analysis Settings')
        analysis_layout = QGridLayout(analysis_group)

        # Max Trace Caller Depth
        analysis_layout.addWidget(QLabel('Max Trace Caller Depth:'), 0, 0)
        self.caller_depth_spin = QSpinBox()
        self.caller_depth_spin.setRange(0, 10)
        self.caller_depth_spin.setValue(settings_manager.settings['max_trace_caller_depth'])
        self.caller_depth_spin.setToolTip('Maximum depth when tracing function callers (0-10)')
        analysis_layout.addWidget(self.caller_depth_spin, 0, 1)

        # Max Trace Callee Depth
        analysis_layout.addWidget(QLabel('Max Trace Callee Depth:'), 1, 0)
        self.callee_depth_spin = QSpinBox()
        self.callee_depth_spin.setRange(0, 10)
        self.callee_depth_spin.setValue(settings_manager.settings['max_trace_callee_depth'])
        self.callee_depth_spin.setToolTip('Maximum depth when tracing function callees (0-10)')
        analysis_layout.addWidget(self.callee_depth_spin, 1, 1)

        # Max Context Functions
        analysis_layout.addWidget(QLabel('Max Context Functions:'), 2, 0)
        self.context_func_spin = QSpinBox()
        self.context_func_spin.setRange(-1, 100) # -1 for no limit, up to 100
        self.context_func_spin.setValue(settings_manager.settings['max_context_func_num'])
        self.context_func_spin.setToolTip('Maximum number of functions to include in context (-1 for no limit)')
        analysis_layout.addWidget(self.context_func_spin, 2, 1)

        # Data Flow Analysis Enable
        analysis_layout.addWidget(QLabel('Data Flow Analysis Enable:'), 3, 0)
        self.data_flow_switch = QCheckBox()
        self.data_flow_switch.setToolTip('Enable/Disable Data Flow Analysis')
        self.data_flow_switch.setChecked(settings_manager.settings['data_flow_analysis'])
        analysis_layout.addWidget(self.data_flow_switch, 3, 1)

        # Measure Info Score
        analysis_layout.addWidget(QLabel('Measure Info Score:'), 4, 0)
        self.measure_info_score_switch = QCheckBox()
        self.measure_info_score_switch.setToolTip('Enable/disable information score measurement')
        self.measure_info_score_switch.setChecked(settings_manager.settings['measure_info_score'])
        analysis_layout.addWidget(self.measure_info_score_switch, 4, 1)

        # Need User Confirm
        analysis_layout.addWidget(QLabel('Need User Confirm:'), 5, 0)
        self.need_confirm_switch = QCheckBox()
        self.need_confirm_switch.setToolTip('Enable/disable user confirm before send request to LLM')
        self.need_confirm_switch.setChecked(settings_manager.settings['need_confirm'])
        analysis_layout.addWidget(self.need_confirm_switch, 5, 1)

        # Mock Mode
        analysis_layout.addWidget(QLabel('Mock Mode (Developer Only):'), 6, 0)
        self.debug_mode_switch = QCheckBox()
        self.debug_mode_switch.setToolTip('Enable/disable mock mode for debug')
        self.debug_mode_switch.setChecked(settings_manager.settings['debug_mode'])
        analysis_layout.addWidget(self.debug_mode_switch, 6, 1)

        # Feedback Enable
        analysis_layout.addWidget(QLabel('Feedback Enable:'), 7, 0)
        self.feedback_switch = QCheckBox()
        self.feedback_switch.setToolTip('Enable/Disable Send Feedback')
        self.feedback_switch.setChecked(settings_manager.settings['feedback'])
        analysis_layout.addWidget(self.feedback_switch, 7, 1)

        main_layout.addWidget(analysis_group)

        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton('Save Settings')
        save_button.clicked.connect(self.save_settings)
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)

        self.setLayout(main_layout)

    def save_settings(self):
        """Save current settings and close dialog."""
        model_name = self.model_name_edit.text().strip()
        prompt_template = self.prompt_template_combo.currentText()
        base_url = self.base_url_edit.text().strip()
        api_key = self.api_key_edit.text().strip()

        # 基本验证
        if not model_name:
            QMessageBox.warning(self, 'Invalid Configuration', 'Model name cannot be empty.')
            return

        # 如果使用第三方API，需要提供API Key
        if base_url and not api_key:
            QMessageBox.warning(self, 'Invalid Configuration', 'API Key is required when using custom Base URL.')
            return

        new_settings = {
            'model_name': model_name,
            'base_url': self.base_url_edit.text().strip(),
            'api_key': self.api_key_edit.text().strip(),
            'prompt_template': prompt_template,
            'max_output_tokens': self.max_output_tokens_spin.value(),
            'max_trace_caller_depth': self.caller_depth_spin.value(),
            'max_trace_callee_depth': self.callee_depth_spin.value(),
            'max_context_func_num': self.context_func_spin.value(),
            'data_flow_analysis': self.data_flow_switch.isChecked(),
            'measure_info_score': self.measure_info_score_switch.isChecked(),
            'need_confirm': self.need_confirm_switch.isChecked(),
            'debug_mode': self.debug_mode_switch.isChecked(),
            'feedback': self.feedback_switch.isChecked(),
        }
        settings_manager.save_settings(new_settings)
        QMessageBox.information(self, 'Success', 'Settings saved successfully!')
        self.accept()
