"""
Presentation Layer - Reusable Qt Widgets

This module contains reusable UI components for the ReCopilot plugin.
Extracted from recopilot_qt.py for better organization and reusability.
"""

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import (
    QWidget, QLineEdit, QCheckBox, QGroupBox, QHBoxLayout,
    QVBoxLayout, QPushButton, QLabel
)


class EditablePredictionWidget(QWidget):
    """
    A single editable prediction field with checkbox for acceptance.

    Supports both single-line (QLineEdit) and multi-line (QTextEdit) modes.
    """
    def __init__(self, title, content="", is_multiline=False, line_count=None, force_single_line=False):
        super(EditablePredictionWidget, self).__init__()
        self.accepted = True
        layout = QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        group_box = QGroupBox(title)
        h_layout = QHBoxLayout()
        h_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        h_layout.setSpacing(10)

        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)

        if force_single_line or ('\n' not in content and not force_single_line):
            self.is_multiline = False
            self.line_count = 1
        else:
            self.is_multiline = is_multiline
            self.line_count = line_count

        if self.is_multiline:
            self.content_edit = QtWidgets.QTextEdit()
            self.content_edit.setMinimumWidth(500)
            if self.line_count:
                self.content_edit.setMinimumHeight(min(20 * self.line_count + 10, 300))
            else:
                self.content_edit.setMinimumHeight(100)
        else:
            self.content_edit = QLineEdit()
            self.content_edit.setMinimumWidth(500)

        self.content_edit.setText(content)
        h_layout.addWidget(self.checkbox)
        h_layout.addWidget(self.content_edit)
        group_box.setLayout(h_layout)
        layout.addWidget(group_box)
        self.setLayout(layout)

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.content_edit.setEnabled(self.accepted)

    def get_content(self):
        if isinstance(self.content_edit, QtWidgets.QTextEdit):
            return self.content_edit.toPlainText()
        else:
            return self.content_edit.text()


class NameTypeWidget(QWidget):
    """
    Base widget with name, type/value, and optional size fields.
    Includes checkbox controls for each field and signals for dynamic management.
    """
    field_added = QtCore.pyqtSignal()
    field_removed = QtCore.pyqtSignal(QWidget)

    def __init__(self, title="", name="", type_str="", size="", is_enum=False):
        super(NameTypeWidget, self).__init__()
        self.accepted = True
        self.accepted_name = True
        self.accepted_type = True
        self.accepted_size = True
        self.is_enum = is_enum

        layout = QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        group_box = QGroupBox(title)
        h_layout = QHBoxLayout()
        h_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        h_layout.setSpacing(10)

        # Name field
        name_layout = QHBoxLayout()
        self.name_checkbox = QCheckBox('Name')
        self.name_checkbox.setCheckState(QtCore.Qt.Checked)
        self.name_checkbox.stateChanged.connect(self.name_state_change)
        self.name_edit = QLineEdit(name)
        self.name_edit.setMinimumWidth(200)
        name_layout.addWidget(self.name_checkbox)
        name_layout.addWidget(self.name_edit)

        # Type field
        type_layout = QHBoxLayout()
        self.type_checkbox = QCheckBox('Value' if is_enum else 'Type')
        self.type_checkbox.setCheckState(QtCore.Qt.Checked)
        self.type_checkbox.stateChanged.connect(self.type_state_change)
        self.type_edit = QLineEdit(type_str)
        self.type_edit.setMinimumWidth(200)
        type_layout.addWidget(self.type_checkbox)
        type_layout.addWidget(self.type_edit)

        # Size field (only for enum members and struct fields)
        if is_enum:
            size_layout = QHBoxLayout()
            self.size_checkbox = QCheckBox('Size')
            self.size_checkbox.setCheckState(QtCore.Qt.Checked)
            self.size_checkbox.stateChanged.connect(self.size_state_change)
            self.size_edit = QLineEdit(str(size))
            self.size_edit.setMinimumWidth(80)
            size_layout.addWidget(self.size_checkbox)
            size_layout.addWidget(self.size_edit)

            h_layout.addLayout(size_layout)

        # Add/Remove buttons for enum and struct fields
        if is_enum:
            add_button = QPushButton('+')
            add_button.setMaximumWidth(30)
            add_button.clicked.connect(self.on_add_clicked)
            remove_button = QPushButton('-')
            remove_button.setMaximumWidth(30)
            remove_button.clicked.connect(self.on_remove_clicked)
            h_layout.addWidget(add_button)
            h_layout.addWidget(remove_button)

        h_layout.addStretch()  # Push widgets to the left
        group_box.setLayout(h_layout)
        layout.addWidget(group_box)
        self.setLayout(layout)

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.name_checkbox.setEnabled(self.accepted)
        self.type_checkbox.setEnabled(self.accepted)
        self.name_edit.setEnabled(self.accepted and self.accepted_name)
        self.type_edit.setEnabled(self.accepted and self.accepted_type)
        if self.is_enum:
            self.size_checkbox.setEnabled(self.accepted)
            self.size_edit.setEnabled(self.accepted and self.accepted_size)
            self.add_button.setEnabled(self.accepted)
            self.remove_button.setEnabled(self.accepted)

    def name_state_change(self, state):
        self.accepted_name = (state == QtCore.Qt.Checked)
        self.name_edit.setEnabled(self.accepted and self.accepted_name)

    def type_state_change(self, state):
        self.accepted_type = (state == QtCore.Qt.Checked)
        self.type_edit.setEnabled(self.accepted and self.accepted_type)

    def size_state_change(self, state):
        self.accepted_size = (state == QtCore.Qt.Checked)
        self.size_edit.setEnabled(self.accepted and self.accepted_size)

    def get_content(self):
        # Returns a list: [name, type_str, size] for enum fields, or [name, type_str] for others
        size_val = None
        if self.is_enum:
            if self.accepted and self.accepted_size:
                try:
                    size_val = int(self.size_edit.text())
                except ValueError:
                    size_val = None  # Handle invalid integer input

        name_val = self.name_edit.text().strip() if self.accepted and self.accepted_name else None
        type_val = self.type_edit.text().strip() if self.accepted and self.accepted_type else None

        if self.is_enum:
            return [name_val, type_val, size_val]
        else:
            return [name_val, type_val]

    def validate(self):
        if not self.accepted:
            return True  # If not accepted, validation passes as it's not applied

        if self.accepted_name and not self.name_edit.text().strip():
            return False
        if self.accepted_type and not self.type_edit.text().strip():
            return False
        if self.is_enum and self.accepted_size:
            try:
                size_val = int(self.size_edit.text().strip())
                if size_val <= 0:
                    return False
            except ValueError:
                return False
        return True

    def on_add_clicked(self):
        self.field_added.emit()

    def on_remove_clicked(self):
        self.field_removed.emit(self)  # Emit the widget itself for removal


class StructFieldWidget(NameTypeWidget):
    """
    Specialized widget for struct fields (type, name, size).
    Includes add/remove buttons for dynamic struct building.
    """
    field_added = QtCore.pyqtSignal()
    field_removed = QtCore.pyqtSignal(QWidget)

    def __init__(self, type_str="", name="", size="", parent=None):
        super(StructFieldWidget, self).__init__("Struct Field", name, type_str, size, parent=parent)
        self.accepted = True

        h_layout = QHBoxLayout()
        h_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(5)

        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)

        self.type_edit = QLineEdit(type_str)
        self.type_edit.setMinimumWidth(150)
        self.type_edit.setPlaceholderText('Type')

        self.name_edit = QLineEdit(name)
        self.name_edit.setMinimumWidth(150)
        self.name_edit.setPlaceholderText('Name')

        self.size_edit = QLineEdit(str(size))
        self.size_edit.setMinimumWidth(80)
        self.size_edit.setPlaceholderText('Size')

        add_button = QPushButton('+')
        add_button.setMaximumWidth(30)
        add_button.clicked.connect(self.on_add_clicked)
        remove_button = QPushButton('-')
        remove_button.setMaximumWidth(30)
        remove_button.clicked.connect(self.on_remove_clicked)

        h_layout.addWidget(self.checkbox)
        h_layout.addWidget(self.type_edit)
        h_layout.addWidget(self.name_edit)
        h_layout.addWidget(self.size_edit)
        h_layout.addWidget(add_button)
        h_layout.addWidget(remove_button)
        h_layout.addStretch()
        self.setLayout(h_layout)

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.type_edit.setEnabled(self.accepted)
        self.name_edit.setEnabled(self.accepted)
        self.size_edit.setEnabled(self.accepted)
        self.add_button.setEnabled(self.accepted)
        self.remove_button.setEnabled(self.accepted)

    def get_content(self):
        if not self.accepted:
            return None
        type_val = self.type_edit.text().strip()
        name_val = self.name_edit.text().strip()
        try:
            size_val = int(self.size_edit.text().strip())
        except ValueError:
            size_val = None  # Handle invalid integer input
        return [type_val, name_val, size_val]

    def validate(self):
        if not self.accepted:
            return True
        if not self.type_edit.text().strip():
            return False
        if not self.name_edit.text().strip():
            return False
        try:
            size_val = int(self.size_edit.text().strip())
            if size_val <= 0:
                return False
        except ValueError:
            return False
        return True

    def on_add_clicked(self):
        self.field_added.emit()

    def on_remove_clicked(self):
        self.field_removed.emit(self)


class EnumFieldWidget(NameTypeWidget):
    """
    Specialized widget for enum members (name, value, size).
    Includes add/remove buttons for dynamic enum building.
    """
    field_added = QtCore.pyqtSignal()
    field_removed = QtCore.pyqtSignal(QWidget)

    def __init__(self, name="", value="", size="", parent=None):
        super(EnumFieldWidget, self).__init__("Enum Field", name, value, size, parent=parent)
        self.accepted = True

        h_layout = QHBoxLayout()
        h_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(5)

        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)

        self.name_edit = QLineEdit(name)
        self.name_edit.setMinimumWidth(200)
        self.name_edit.setPlaceholderText('Name')

        self.value_edit = QLineEdit(str(value))
        self.value_edit.setMinimumWidth(200)
        self.value_edit.setPlaceholderText('Value')

        self.size_edit = QLineEdit(str(size))
        self.size_edit.setMinimumWidth(80)
        self.size_edit.setPlaceholderText('Size')

        add_button = QPushButton('+')
        add_button.setMaximumWidth(30)
        add_button.clicked.connect(self.on_add_clicked)
        remove_button = QPushButton('-')
        remove_button.setMaximumWidth(30)
        remove_button.clicked.connect(self.on_remove_clicked)

        h_layout.addWidget(self.checkbox)
        h_layout.addWidget(self.name_edit)
        h_layout.addWidget(self.value_edit)
        h_layout.addWidget(self.size_edit)
        h_layout.addWidget(add_button)
        h_layout.addWidget(remove_button)
        h_layout.addStretch()
        self.setLayout(h_layout)

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.name_edit.setEnabled(self.accepted)
        self.value_edit.setEnabled(self.accepted)
        self.size_edit.setEnabled(self.accepted)
        self.add_button.setEnabled(self.accepted)
        self.remove_button.setEnabled(self.accepted)

    def get_content(self):
        if not self.accepted:
            return None
        size_val = 4  # Default size if not provided or invalid
        if self.size_edit.text().strip():
            try:
                size_val = int(self.size_edit.text().strip())
            except ValueError:
                pass  # Keep default size_val if parsing fails

        name_val = self.name_edit.text().strip()
        value_val = self.value_edit.text().strip()
        if value_val.isdigit():  # Check if value is a valid integer string
            value_val = int(value_val)

        return [name_val, value_val, size_val]

    def validate(self):
        if not self.accepted:
            return True
        if not self.name_edit.text().strip():
            return False
        if not self.value_edit.text().strip():
            return False
        try:
            if self.size_edit.text().strip():
                size_val = int(self.size_edit.text().strip())
                if size_val <= 0:
                    return False
        except ValueError:
            return False
        return True

    def on_add_clicked(self):
        self.field_added.emit()

    def on_remove_clicked(self):
        self.field_removed.emit(self)


class ComplexTypeWidget(QWidget):
    """
    Container widget for complex type definitions (structs, enums, arrays).

    Supports:
    - Structs: Name + multiple StructFieldWidget children
    - Enums: Name + multiple EnumFieldWidget children
    - Arrays: Dimension input (comma-separated)

    Features dynamic field addition/removal and nested validation.
    """
    def __init__(self, title, type_info=None, parent=None):
        super(ComplexTypeWidget, self).__init__(parent)
        self.accepted = True
        self.type_info = type_info if type_info is not None else ["", "", "", []]
        self.field_widgets = []

        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)

        group_box = QGroupBox(title, self)
        group_box_layout = QVBoxLayout(group_box)

        # Main name and type fields
        name_type_layout = QHBoxLayout()
        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)
        name_type_layout.addWidget(self.checkbox)

        self.name_type_widget = NameTypeWidget(
            "",
            self.type_info[1],  # Name
            self.type_info[0],  # Type string
            "",  # Size (not directly used here for type declaration itself)
            is_enum=(self.type_info[2] == "enum")
        )
        name_type_layout.addWidget(self.name_type_widget)
        group_box_layout.addLayout(name_type_layout)

        # Fields section for structs and enums
        if self.type_info[2] == "struct":
            fields_group = QGroupBox("Struct Fields")
            self.fields_layout = QVBoxLayout(fields_group)

            # Struct name edit
            struct_name_layout = QHBoxLayout()
            struct_name_layout.addWidget(QLabel("Struct Name:"))
            struct_name_value = list(self.type_info[3].keys())[0] if self.type_info[3] else ""
            self.struct_name_edit = QLineEdit(struct_name_value.replace(" *", "").strip())
            struct_name_layout.addWidget(self.struct_name_edit)
            self.fields_layout.addLayout(struct_name_layout)

            # Add existing struct fields
            if isinstance(self.type_info[3], dict) and self.type_info[3].get(struct_name_value):
                for field_type, field_name, field_size in self.type_info[3][struct_name_value]:
                    self.add_struct_field(field_type, field_name, field_size)

        elif self.type_info[2] == "enum":
            fields_group = QGroupBox("Enum Fields")
            self.fields_layout = QVBoxLayout(fields_group)

            # Enum name edit
            enum_name_layout = QHBoxLayout()
            enum_name_layout.addWidget(QLabel("Enum Name:"))
            enum_name_value = list(self.type_info[3].keys())[0] if self.type_info[3] else ""
            self.enum_name_edit = QLineEdit(enum_name_value.strip())
            enum_name_layout.addWidget(self.enum_name_edit)
            self.fields_layout.addLayout(enum_name_layout)

            # Add existing enum fields
            if isinstance(self.type_info[3], dict) and self.type_info[3].get(enum_name_value):
                for member_name, member_value, member_size in self.type_info[3][enum_name_value]:
                    self.add_enum_field(member_name, member_value, member_size)
            else:
                self.add_enum_field()  # Add at least one empty field if none exist

        elif self.type_info[2] == "array":
            fields_group = QGroupBox("Array Dimensions")
            self.fields_layout = QHBoxLayout(fields_group)

            # Array dimensions edit
            dimensions_str = ",".join(map(str, self.type_info[3] if self.type_info[3] else []))
            self.array_edit = QLineEdit(dimensions_str)
            self.array_edit.setPlaceholderText('Enter dimensions separated by commas')
            self.fields_layout.addWidget(self.array_edit)

        group_box_layout.addWidget(fields_group)
        main_layout.addWidget(group_box)
        self.setLayout(main_layout)

    def add_struct_field(self, type_str="", name="", size="", after_widget=None):
        widget = StructFieldWidget(type_str=type_str, name=name, size=size)
        widget.field_added.connect(self._create_add_struct_callback(widget))
        widget.field_removed.connect(self.remove_struct_field)

        if after_widget:
            idx = self.field_widgets.index(after_widget) + 1
            self.field_widgets.insert(idx, widget)
            self.fields_layout.insertWidget(idx + 1, widget)  # +1 to account for the QGroupBox
        else:
            self.field_widgets.append(widget)
            self.fields_layout.addWidget(widget)

    def add_enum_field(self, name="", value="", size="", after_widget=None):
        widget = EnumFieldWidget(name=name, value=value, size=size)
        widget.field_added.connect(self._create_add_enum_callback(widget))
        widget.field_removed.connect(self.remove_enum_field)

        if after_widget:
            idx = self.field_widgets.index(after_widget) + 1
            self.field_widgets.insert(idx, widget)
            self.fields_layout.insertWidget(idx + 1, widget)
        else:
            self.field_widgets.append(widget)
            self.fields_layout.addWidget(widget)

    def remove_struct_field(self, widget):
        if len(self.field_widgets) > 1:  # Don't remove the last field
            self.fields_layout.removeWidget(widget)
            self.field_widgets.remove(widget)
            widget.deleteLater()

    def remove_enum_field(self, widget):
        if len(self.field_widgets) > 1:  # Don't remove the last field
            self.fields_layout.removeWidget(widget)
            self.field_widgets.remove(widget)
            widget.deleteLater()

    def validate(self):
        if not self.accepted:
            return True
        if not self.name_type_widget.validate():
            return False

        # Validate fields based on type
        if self.type_info[2] == "struct" or self.type_info[2] == "enum":
            for field_widget in self.field_widgets:
                if not field_widget.validate():
                    return False
        elif self.type_info[2] == "array":
            try:
                dimensions = [int(d.strip()) for d in self.array_edit.text().split(',') if d.strip()]
                for dim in dimensions:
                    if dim <= 0:
                        return False
            except ValueError:
                return False
        return True

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.name_type_widget.setEnabled(self.accepted)
        for field_widget in self.field_widgets:
            field_widget.setEnabled(self.accepted)
        if hasattr(self, 'array_edit'):
            self.array_edit.setEnabled(self.accepted)
        if hasattr(self, 'struct_name_edit'):
            self.struct_name_edit.setEnabled(self.accepted)
        if hasattr(self, 'enum_name_edit'):
            self.enum_name_edit.setEnabled(self.accepted)

    def get_type_info(self):
        if not self.accepted:
            return None  # If not accepted, return None or an empty dict based on needs

        # Get data from NameTypeWidget
        name, type_str = self.name_type_widget.get_content()
        type_data = None
        if self.type_info[2] == "struct":
            struct_name = self.struct_name_edit.text().strip()
            type_data = {struct_name: [fw.get_content() for fw in self.field_widgets if fw.get_content() is not None]}
        elif self.type_info[2] == "enum":
            enum_name = self.enum_name_edit.text().strip()
            type_data = {enum_name: [fw.get_content() for fw in self.field_widgets if fw.get_content() is not None]}
        elif self.type_info[2] == "array":
            try:
                type_data = [int(d.strip()) for d in self.array_edit.text().split(',') if d.strip()]
            except ValueError:
                type_data = None  # Or handle error appropriately

        return [type_str, name, self.type_info[2], type_data]

    def _create_add_enum_callback(self, widget):
        """Create a callback function for adding an enum field after the specified widget"""
        def callback():
            self.add_enum_field(after_widget=widget)
        return callback

    def _create_add_struct_callback(self, widget):
        """Create a callback function for adding a struct field after the specified widget"""
        def callback():
            self.add_struct_field(after_widget=widget)
        return callback


class VariableSelectionWidget(QWidget):
    """
    Checkbox list widget for variable selection with "Select All" functionality.
    Used in VariableSelectionForm for choosing which variables to analyze.
    """
    def __init__(self, title, variables):
        super(VariableSelectionWidget, self).__init__()
        self.variables = variables
        self.checkboxes = []

        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()

        title_label = QLabel(title)
        top_layout.addWidget(title_label)

        self.select_all_checkbox = QCheckBox('Select All Variables')
        self.select_all_checkbox.setChecked(True)
        self.select_all_checkbox.stateChanged.connect(self.on_select_all)
        top_layout.addWidget(self.select_all_checkbox)
        top_layout.addStretch()  # Pushes checkbox to the right
        main_layout.addLayout(top_layout)

        for var_name in self.variables:
            checkbox = QCheckBox(var_name)
            checkbox.setChecked(True)  # All variables are selected by default
            self.checkboxes.append(checkbox)
            main_layout.addWidget(checkbox)

        self.setLayout(main_layout)

    def on_select_all(self, state):
        checked = (state == QtCore.Qt.Checked)
        for checkbox in self.checkboxes:
            checkbox.setChecked(checked)

    def get_selected_variables(self):
        return [checkbox.text() for checkbox in self.checkboxes if checkbox.isChecked()]


class OutputWindowButton(QWidget):
    """
    Cancel button widget added to IDA's output window during analysis.
    Provides a way for users to cancel long-running LLM requests.
    """
    def __init__(self, model, parent=None):
        super(OutputWindowButton, self).__init__(parent)
        self.model = model
        self.setFixedHeight(30)  # Set a fixed height for the button container

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(5, 0, 15, 0)  # Margins: left, top, right, bottom
        main_layout.setSpacing(5)  # Spacing between widgets

        # Add stretch to push the button to the right
        main_layout.addStretch(1)

        self.button = QPushButton('Cancel Analysis', self)
        self.button.setStyleSheet("""
            QPushButton {
                background-color: #823432;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 5px 10px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #9a3f3d;
            }
            QPushButton:pressed {
                background-color: #6b2a29;
            }
        """)
        self.button.clicked.connect(self.on_cancel_clicked)
        main_layout.addWidget(self.button)
        self.setLayout(main_layout)

    def on_cancel_clicked(self):
        self.model.cancel()  # Call the cancel method on the provided model
        self.hide()  # Hide the button after cancellation
