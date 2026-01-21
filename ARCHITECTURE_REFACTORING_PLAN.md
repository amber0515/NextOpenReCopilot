# OpenReCopilot 架构重构计划

## 1. 现状分析

### 1.1 当前架构问题总结

| 问题类别 | 严重程度 | 具体描述 |
|---------|---------|---------|
| **职责混乱** | 高 | `handler.py` 混合了线程管理、工作流编排、UI 交互、Mock 测试 |
| **UI 层过重** | 高 | `recopilot_qt.py` 1243 行，包含业务逻辑调用 |
| **循环依赖** | 高 | handler → qt → ext_info → checker → remote_model 形成环 |
| **代码重复** | 高 | StructFieldWidget/EnumFieldWidget 大量重复；解析逻辑分散 |
| **全局状态滥用** | 中 | 全局 model 实例，多处全局变量 |
| **数据流不清晰** | 中 | 各阶段数据结构无明确定义 |
| **错误处理不一致** | 中 | 有的返回 None，有的返回空字典，有的抛异常 |

### 1.2 当前模块依赖关系

```
                    ┌─────────────────────┐
                    │    recopilot.py     │
                    │  (IDA Plugin Entry) │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  handler.py  │  │recopilot_qt  │  │remote_model  │
    │  (306 lines) │  │ (1243 lines) │  │  (278 lines) │
    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
           │                 │                  │
           │         ┌───────┴────────┐         │
           │         │                │         │
           ▼         ▼                ▼         │
    ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐
    │  checker.py  │ │  ext_info.py  │ │   task_guides.py     │
    │  (582 lines) │  │(2000 lines)  │ │    (812 lines)       │
    └──────┬───────┘ └──────┬───────┘ └──────────────────────┘
           │                │
           ▼                ▼
    ┌──────────────┐ ┌──────────────┐
    │ data_flow.py │ │  config.py   │
    │  (798 lines) │  │ (106 lines) │
    └──────────────┘ └──────────────┘
```

---

## 2. 目标架构

### 2.1 分层架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                         Presentation Layer                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  ida_hooks.py│  │  qt_views.py │  │    qt_widgets.py     │  │
│  │ (菜单/钩子)   │  │  (视图协调)  │  │    (可复用UI组件)    │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                      Application Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  workflow.py │  │   task.py    │  │    result_handler.py │  │
│  │ (工作流编排)  │  │  (任务定义)  │  │    (结果处理)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                        Domain Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  context.py  │  │ data_flow.py │  │      types.py        │  │
│  │ (上下文构建)  │  │ (数据流分析) │  │  (类型定义/数据类)   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                     Infrastructure Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   llm_api.py │  │  ida_api.py  │  │      config.py       │  │
│  │  (LLM接口)   │  │ (IDA封装)    │  │    (配置管理)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 新模块文件结构

```
src/
├── recopilot.py              # 插件入口（保持不变）
│
├── presentation/             # UI 层
│   ├── __init__.py
│   ├── ida_hooks.py          # IDA 菜单、钩子注册（从 recopilot.py 提取）
│   ├── qt_views.py           # 视图创建器、Form 类（从 recopilot_qt.py 提取）
│   └── qt_widgets.py         # 可复用 UI 组件（从 recopilot_qt.py 提取）
│
├── application/              # 应用层
│   ├── __init__.py
│   ├── workflow.py           # 分析工作流编排（从 handler.py 提取）
│   ├── task.py               # 任务定义和注册
│   └── result_handler.py     # 结果处理和验证（从 checker.py 提取）
│
├── domain/                   # 领域层
│   ├── __init__.py
│   ├── context.py            # 上下文构建（从 ext_info.py 提取）
│   ├── data_flow.py          # 数据流分析（保持）
│   └── types.py              # 数据类定义（新建）
│
├── infrastructure/           # 基础设施层
│   ├── __init__.py
│   ├── llm_api.py            # LLM API 客户端（从 remote_model.py 提取）
│   ├── ida_api.py            # IDA API 封装（新建）
│   └── config.py             # 配置管理（保持）
│
├── shared/                   # 共享工具
│   ├── __init__.py
│   ├── threading_utils.py    # 线程工具（从 handler.py 提取）
│   └── parsing_utils.py      # 解析工具（从 checker.py 提取）
│
└── prompts/                  # Prompt 模板
    ├── __init__.py
    └── task_guides.py        # 任务指南（保持）
```

---

## 3. 详细重构计划

### 阶段一：基础设施层重构（优先级：高）

#### 3.1 创建 `infrastructure/ida_api.py`

**目的**: 封装 IDA API，提供统一接口，便于测试和解耦

```python
# infrastructure/ida_api.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List, Dict

@dataclass
class FunctionInfo:
    """函数信息"""
    start_ea: int
    end_ea: int
    name: str
    arguments: List['VariableInfo']
    variables: List['VariableInfo']

@dataclass
class VariableInfo:
    """变量信息"""
    name: str
    type_str: str
    is_arg: bool
    size: int

class IDAApi(ABC):
    """IDA API 抽象接口"""

    @abstractmethod
    def get_function(self, ea: int) -> Optional[FunctionInfo]:
        """获取函数信息"""

    @abstractmethod
    def decompile(self, ea: int) -> Optional[str]:
        """反编译函数"""

    @abstractmethod
    def set_function_comment(self, ea: int, comment: str) -> bool:
        """设置函数注释"""

    @abstractmethod
    def set_variable_type(self, func_ea: int, var_name: str, type_str: str) -> bool:
        """设置变量类型"""

    @abstractmethod
    def set_variable_name(self, func_ea: int, old_name: str, new_name: str) -> bool:
        """设置变量名称"""

class IDAProApi(IDAApi):
    """IDA Pro API 实现"""
    # 具体实现...
```

#### 3.2 创建 `infrastructure/llm_api.py`

**目的**: 统一 LLM API 调用接口

```python
# infrastructure/llm_api.py
from dataclasses import dataclass
from typing import Optional, AsyncIterator
from abc import ABC, abstractmethod

@dataclass
class LLMRequest:
    """LLM 请求"""
    prompt: str
    task_tag: str
    max_tokens: int

@dataclass
class LLMResponse:
    """LLM 响应"""
    content: str
    raw_prompt: str

class LLMApi(ABC):
    """LLM API 抽象接口"""

    @abstractmethod
    async def call(self, request: LLMRequest) -> LLMResponse:
        """调用 LLM"""
        pass

    @abstractmethod
    async def call_stream(self, request: LLMRequest) -> AsyncIterator[str]:
        """流式调用 LLM"""
        pass

class OpenAIApi(LLMApi):
    """OpenAI API 实现"""
    # 具体实现...
```

#### 3.3 创建 `domain/types.py`

**目的**: 定义清晰的数据结构

```python
# domain/types.py
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Literal
from enum import Enum

class ComplexTypeKind(Enum):
    """复杂类型种类"""
    SIMPLE = ""
    STRUCT = "struct"
    ENUM = "enum"
    ARRAY = "array"

@dataclass
class TypeInfo:
    """类型信息"""
    type_str: str
    name: str
    kind: ComplexTypeKind = ComplexTypeKind.SIMPLE
    details: Optional[Dict] = None

@dataclass
class VariablePrediction:
    """变量预测结果"""
    original_name: str
    type_info: TypeInfo

@dataclass
class FunctionComment:
    """函数注释"""
    brief: str = ""
    details: str = ""
    params: Dict[str, str] = field(default_factory=dict)
    return_desc: str = ""
    category: str = "none"
    algorithm: str = "none"

@dataclass
class InlineComment:
    """行内注释"""
    line_number: int
    comment: str

@dataclass
class SummaryPrediction:
    """Summary 预测结果"""
    comment: FunctionComment
    inline_comments: List[InlineComment] = field(default_factory=list)

@dataclass
class AnalysisResult:
    """分析结果"""
    task_tag: str
    function_ea: int
    summary: Optional[SummaryPrediction] = None
    funcname: Optional[str] = None
    ret_type: Optional[str] = None
    args: Optional[Dict[str, TypeInfo]] = None
    vars: Optional[Dict[str, TypeInfo]] = None
```

---

### 阶段二：应用层重构（优先级：高）

#### 3.4 创建 `application/workflow.py`

**目的**: 分离工作流编排逻辑

```python
# application/workflow.py
from dataclasses import dataclass
from typing import Callable, Optional
from infrastructure.llm_api import LLMRequest, LLMResponse
from domain.types import AnalysisResult
from domain.context import build_context
from application.result_handler import parse_and_validate

@dataclass
class WorkflowConfig:
    """工作流配置"""
    need_confirm: bool = True
    max_output_tokens: int = 4096
    enable_data_flow: bool = True

class AnalysisWorkflow:
    """分析工作流"""

    def __init__(self, llm_api: 'LLMApi', ida_api: 'IDAApi', config: WorkflowConfig):
        self.llm_api = llm_api
        self.ida_api = ida_api
        self.config = config

    async def execute(self, ea: int, task_tag: str) -> AnalysisResult:
        """执行分析工作流"""
        # 1. 构建上下文
        context = build_context(self.ida_api, ea, task_tag)

        # 2. 构建 prompt
        prompt = self._build_prompt(context, task_tag)

        # 3. 用户确认（如果需要）
        if self.config.need_confirm:
            if not self._request_confirmation(ea, task_tag, prompt):
                return None

        # 4. 调用 LLM
        response = await self._call_llm(prompt, task_tag)

        # 5. 解析和验证
        result = parse_and_validate(response, task_tag, ea)

        return result

    def _build_prompt(self, context, task_tag: str) -> str:
        """构建 prompt"""
        # 从 prompts.task_guides 获取模板
        pass

    async def _call_llm(self, prompt: str, task_tag: str) -> LLMResponse:
        """调用 LLM"""
        request = LLMRequest(prompt, task_tag, self.config.max_output_tokens)
        return await self.llm_api.call(request)
```

#### 3.5 创建 `application/result_handler.py`

**目的**: 统一结果处理逻辑

```python
# application/result_handler.py
from domain.types import AnalysisResult, TypeInfo, SummaryPrediction

class ResultHandler:
    """结果处理器"""

    def parse(self, raw_response: str, task_tag: str) -> dict:
        """解析原始响应"""
        # 从 checker.py 提取解析逻辑
        pass

    def validate(self, parsed: dict, task_tag: str) -> bool:
        """验证解析结果"""
        # 从 checker.py 提取验证逻辑
        pass

    def refine(self, parsed: dict, task_tag: str, function_ea: int) -> AnalysisResult:
        """提炼结果为标准格式"""
        # 从 checker.py 提取提炼逻辑
        pass

    def apply(self, result: AnalysisResult, ida_api: 'IDAApi') -> bool:
        """应用结果到 IDA"""
        # 从 ext_info.py 提取应用逻辑
        pass
```

#### 3.6 创建 `application/task.py`

**目的**: 统一任务定义和注册

```python
# application/task.py
from dataclasses import dataclass
from typing import Callable, Optional
from enum import Enum

class TaskType(Enum):
    """任务类型"""
    FUNCTION_ANALYSIS = "<func-analysis>"
    DECOMPILATION = "<decompilation>"
    SPECIFIC_VARS = "<specific-vars>"
    ALL_VARS = "<vars>"
    ALL_ARGS = "<args>"
    FUNCTION_NAME = "<funcname>"
    SUMMARY = "<summary>"

@dataclass
class Task:
    """任务定义"""
    task_type: TaskType
    name: str
    description: str
    shortcut: str
    response_parser: str  # "json" or "string"
    view_type: str  # "confirm", "display", "summary"

class TaskRegistry:
    """任务注册表"""

    _tasks: Dict[TaskType, Task] = {}

    @classmethod
    def register(cls, task: Task):
        """注册任务"""
        cls._tasks[task.task_type] = task

    @classmethod
    def get(cls, task_type: TaskType) -> Optional[Task]:
        """获取任务"""
        return cls._tasks.get(task_type)

    @classmethod
    def all(cls) -> List[Task]:
        """获取所有任务"""
        return list(cls._tasks.values())
```

---

### 阶段三：表现层重构（优先级：中）

#### 3.7 创建 `presentation/qt_widgets.py`

**目的**: 提取可复用 UI 组件

```python
# presentation/qt_widgets.py
from PyQt5.QtWidgets import QWidget, QCheckBox, QLineEdit, QTextEdit, QGroupBox, QHBoxLayout, QVBoxLayout, QPushButton
from PyQt5.QtCore import pyqtSignal

class EditableFieldWidget(QWidget):
    """可编辑字段组件"""
    value_changed = pyqtSignal(str)

    def __init__(self, label: str, value: str = "", multiline: bool = False, parent=None):
        super().__init__(parent)
        self._setup_ui(label, value, multiline)

    def _setup_ui(self, label: str, value: str, multiline: bool):
        layout = QVBoxLayout()

        # Checkbox
        self.checkbox = QCheckBox(label)
        self.checkbox.setChecked(True)
        self.checkbox.stateChanged.connect(self._on_state_changed)
        layout.addWidget(self.checkbox)

        # Input
        if multiline:
            self.input = QTextEdit()
            self.input.setPlainText(value)
        else:
            self.input = QLineEdit()
            self.input.setText(value)

        layout.addWidget(self.input)
        self.setLayout(layout)

    def _on_state_changed(self, state):
        self.input.setEnabled(state == 2)  # 2 = Checked

    def get_value(self) -> tuple[bool, str]:
        """返回 (是否选中, 值)"""
        return self.checkbox.isChecked(), self.input.text() if isinstance(self.input, QLineEdit) else self.input.toPlainText()

class TypeFieldWidget(QWidget):
    """类型字段组件（用于 args/vars）"""
    # 类似 ComplexTypeWidget，但更简洁
    pass
```

#### 3.8 创建 `presentation/qt_views.py`

**目的**: 统一视图创建和 Form 类

```python
# presentation/qt_views.py
from ida_kernwin import PluginForm
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextBrowser
from pygments import highlight
from pygments.lexers import CppLexer
from pygments.formatters import HtmlFormatter
from domain.types import AnalysisResult, SummaryPrediction

class BaseViewForm(PluginForm):
    """视图基类"""

    def __init__(self, title: str):
        super().__init__()
        self.title = title
        self._ensure_single_instance()

    def _ensure_single_instance(self):
        """确保只有一个实例"""
        existing = ida_kernwin.find_widget(self.title)
        if existing:
            ida_kernwin.close_widget(existing, 0)

    def show_view(self):
        """显示视图"""
        self.Show(self.title, options=PluginForm.WOPN_TAB | PluginForm.WOPN_PERSIST)

class DisplayViewForm(BaseViewForm):
    """只读显示视图（用于 Decompilation）"""

    def OnCreate(self, form):
        parent = self.FormToPyQtWidget(form)
        layout = QVBoxLayout(parent)

        self.browser = QTextBrowser()
        self.browser.setFontFamily('Consolas')
        layout.addWidget(self.browser)

        if hasattr(self, 'content'):
            self._set_content(self.content)

    def set_content(self, content: str):
        """设置内容"""
        lexer = CppLexer()
        formatter = HtmlFormatter(style='vs', noclasses=True)
        html = highlight(content, lexer, formatter)
        self.browser.setHtml(html)

class SummaryViewForm(BaseViewForm):
    """Summary 分析视图（自动应用）"""

    def __init__(self, title: str, result: AnalysisResult, ida_api: 'IDAApi'):
        super().__init__(title)
        self.result = result
        self.ida_api = ida_api

    def OnCreate(self, form):
        parent = self.FormToPyQtWidget(form)
        layout = QVBoxLayout(parent)

        # 显示分析结果
        self.browser = QTextBrowser()
        layout.addWidget(self.browser)

        # 自动应用结果
        self._apply_result()

        # 显示应用后的结果
        self._display_result()

    def _apply_result(self):
        """应用分析结果"""
        if self.result.summary:
            # 应用函数注释
            comment = self._build_doxygen_comment(self.result.summary.comment)
            self.ida_api.set_function_comment(self.result.function_ea, comment)

            # 应用 inline comments
            for inline in self.result.summary.inline_comments:
                self.ida_api.set_inline_comment(self.result.function_ea, inline.line_number, inline.comment)

    def _build_doxygen_comment(self, comment) -> str:
        """构建 Doxygen 注释"""
        lines = ["/**"]
        if comment.brief:
            lines.append(f" * @brief {comment.brief}")
        if comment.details:
            lines.append(f" * @details {comment.details}")
        for name, desc in comment.params.items():
            lines.append(f" * @param {name}: {desc}")
        if comment.return_desc:
            lines.append(f" * @return {comment.return_desc}")
        lines.append(" */")
        return "\n".join(lines)
```

#### 3.9 创建 `presentation/ida_hooks.py`

**目的**: 分离 IDA 钩子注册逻辑

```python
# presentation/ida_hooks.py
import idaapi
import ida_kernwin
from application.task import TaskType, TaskRegistry
from application.workflow import AnalysisWorkflow

class AnalysisHandler(ida_kernwin.action_handler_t):
    """分析处理器基类"""

    def __init__(self, task_type: TaskType, workflow: AnalysisWorkflow):
        self.task_type = task_type
        self.workflow = workflow

    def activate(self, ctx):
        if ctx.widget_type != ida_kernwin.BWN_PSEUDOCODE:
            return 0

        ea = idaapi.get_screen_ea()
        if ea == idaapi.BADADDR:
            return 0

        # 在后台线程执行分析
        import threading
        thread = threading.Thread(target=self._execute_analysis, args=(ea,))
        thread.start()

        return 1

    def _execute_analysis(self, ea: int):
        """执行分析"""
        import asyncio
        result = asyncio.run(self.workflow.execute(ea, self.task_type.value))
        # 处理结果...

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

def register_actions(workflow: AnalysisWorkflow):
    """注册所有 IDA actions"""
    for task in TaskRegistry.all():
        handler = AnalysisHandler(task.task_type, workflow)
        action_desc = idaapi.action_desc_t(
            f"recopilot:{task.task_type.value}",
            task.name,
            handler,
            task.shortcut,
            task.description,
            0
        )
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_popup(ida_kernwin.BWN_PSEUDOCODE, action_desc.id, "ReCopilot/")

def attach_popup_hooks():
    """附加右键菜单钩子"""
    class PopupHooks(ida_kernwin.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
                idaapi.attach_action_to_popup(widget, popup, "recopilot:summary", "ReCopilot/")

    hooks = PopupHooks()
    hooks.hook()
    return hooks
```

---

### 阶段四：共享工具提取（优先级：中）

#### 3.10 创建 `shared/threading_utils.py`

**目的**: 提取线程管理工具

```python
# shared/threading_utils.py
import ida_kernwin
from typing import Callable, Any, Tuple

def execute_on_main_thread(func: Callable, args: Tuple = (), kwargs: dict = None) -> Any:
    """在 IDA 主线程执行函数"""
    result_container = {'result': None}

    def wrapper():
        try:
            if kwargs:
                result_container['result'] = func(*args, **kwargs)
            else:
                result_container['result'] = func(*args)
        except Exception as e:
            print(f"[!] Error in execute_on_main_thread: {e}")
            result_container['result'] = None
        return 1

    ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)
    return result_container['result']
```

#### 3.11 创建 `shared/parsing_utils.py`

**目的**: 提取解析工具

```python
# shared/parsing_utils.py
import re
import json
from typing import Optional

def extract_json_from_response(response: str) -> Optional[dict]:
    """从响应中提取 JSON"""
    # 尝试直接解析
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    # 尝试提取 <Output>...</Output> 标签
    match = re.search(r'<Output>(.*?)</Output>', response, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 尝试提取 ```json...``` 代码块
    match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    return None
```

---

## 4. 迁移步骤

### 第一步：创建新目录结构（不破坏现有代码）

```bash
mkdir -p src/presentation
mkdir -p src/application
mkdir -p src/domain
mkdir -p src/infrastructure
mkdir -p src/shared
mkdir -p src/prompts

# 移动文件
mv src/task_guides.py src/prompts/
mv src/config.py src/infrastructure/
mv src/data_flow.py src/domain/
```

### 第二步：逐步迁移和测试

1. **迁移基础设施层**（低风险）
   - 创建 `infrastructure/ida_api.py`，编写测试
   - 创建 `infrastructure/llm_api.py`，从 `remote_model.py` 迁移
   - 创建 `domain/types.py`，定义数据类

2. **迁移应用层**（中风险）
   - 创建 `application/workflow.py`，从 `handler.py` 迁移工作流逻辑
   - 创建 `application/result_handler.py`，从 `checker.py` 迁移
   - 创建 `application/task.py`，定义任务注册表

3. **迁移表现层**（高风险）
   - 创建 `presentation/qt_widgets.py`，从 `recopilot_qt.py` 提取组件
   - 创建 `presentation/qt_views.py`，从 `recopilot_qt.py` 提取视图
   - 创建 `presentation/ida_hooks.py`，从 `recopilot.py` 提取钩子

4. **更新导入**（最后一步）
   - 逐步更新各模块的导入语句
   - 运行测试验证功能

### 第三步：清理旧代码

确认所有功能正常后，删除旧文件：
- `handler.py`
- `recopilot_qt.py`
- `remote_model.py`
- `ext_info.py`（部分迁移到 `domain/context.py`）
- `checker.py`

---

## 5. 优先级排序

| 阶段 | 任务 | 优先级 | 预计工作量 | 风险 |
|-----|------|-------|-----------|-----|
| 1 | 创建 `domain/types.py` | 高 | 2小时 | 低 |
| 1 | 创建 `infrastructure/ida_api.py` | 高 | 3小时 | 低 |
| 1 | 创建 `infrastructure/llm_api.py` | 高 | 2小时 | 低 |
| 2 | 创建 `application/workflow.py` | 高 | 4小时 | 中 |
| 2 | 创建 `application/result_handler.py` | 高 | 3小时 | 中 |
| 2 | 创建 `application/task.py` | 中 | 2小时 | 低 |
| 3 | 创建 `presentation/qt_views.py`（含 SummaryView） | 高 | 4小时 | 中 |
| 3 | 创建 `presentation/qt_widgets.py` | 中 | 4小时 | 中 |
| 3 | 创建 `presentation/ida_hooks.py` | 中 | 2小时 | 低 |
| 4 | 创建 `shared/threading_utils.py` | 低 | 1小时 | 低 |
| 4 | 创建 `shared/parsing_utils.py` | 低 | 1小时 | 低 |

**总计**: 约 28 小时（按优先级分 4-5 天完成）

---

## 6. 当前问题快速修复（Summary Analysis）

在完整重构之前，可以先快速修复 Summary Analysis 的问题：

### 6.1 立即修复方案

在 `recopilot_qt.py` 中添加新的视图类：

```python
# 在 DecompilationViewPluginForm 之后添加

class SummaryViewForm(ida_kernwin.PluginForm):
    """Summary 分析视图 - 自动应用结果"""

    def __init__(self, title: str, ea: int, prediction: dict):
        super().__init__()
        self.title = title
        self.ea = ea
        self.prediction = prediction

    def OnCreate(self, form):
        from ext_info import build_doxygen_comment, apply_prediction_func_comment

        parent = self.FormToPyQtWidget(form)
        layout = QVBoxLayout(parent)

        # 显示结果预览
        self.browser = QTextBrowser()
        self.browser.setFontFamily('Consolas')
        layout.addWidget(self.browser)

        # 自动应用函数注释
        doxygen_comment = build_doxygen_comment(self.prediction)
        apply_prediction_func_comment(self.ea, doxygen_comment)

        # 应用 inline comments
        if 'inline_comment' in self.prediction:
            func = idaapi.get_func(self.ea)
            if func:
                df = ida_hexrays.decompile(func)
                if df:
                    for line_str, comment in self.prediction['inline_comment'].items():
                        try:
                            line_num = int(line_str)
                            # 设置行注释
                            idaapi.set_cmt(df.eamap[line_num][0].ea, comment, 0)
                        except (ValueError, KeyError):
                            pass

        # 显示应用的内容
        display_content = f"Summary Analysis Result for {hex(self.ea)}\n\n"
        display_content += doxygen_comment
        display_content += "\n\nInline comments applied."

        lexer = CppLexer()
        formatter = HtmlFormatter(style='vs', noclasses=True)
        html = highlight(display_content, lexer, formatter)
        self.browser.setHtml(html)

    def Show(self):
        super().Show(
            self.title,
            options=ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_RESTORE
        )

def create_summary_view(ea, task_tag, prompt, response_raw, response):
    """创建 Summary 分析视图（自动应用）"""
    from ext_info import build_doxygen_comment, apply_prediction_func_comment
    import ida_hexrays

    print('[*] Creating Summary Analysis view with auto-apply')
    func_name = idc.get_func_name(ea)
    title = f'ReCopilot Summary - {func_name}'

    # 自动应用 inline comments
    if 'inline_comment' in response:
        func = idaapi.get_func(ea)
        if func:
            df = ida_hexrays.decompile(func)
            if df:
                for line_str, comment in response['inline_comment'].items():
                    try:
                        line_num = int(line_str)
                        # 获取该行的第一个地址
                        if line_num in df.eamap and df.eamap[line_num]:
                            idaapi.set_cmt(df.eamap[line_num][0].ea, comment, 0)
                    except (ValueError, KeyError):
                        pass

    # 应用函数注释
    doxygen_comment = build_doxygen_comment(response)
    apply_prediction_func_comment(ea, doxygen_comment)

    # 创建显示视图
    form = SummaryViewForm(title, ea, response)
    form.Show()

    return True
```

然后在 `handler.py` 中修改 `summary_analysis` 函数：

```python
# handler.py line 202-203
def summary_analysis(ea):
    common_analysis_logic(ea, '<summary>',
                        response_parser=parse_model_response_json,
                        view_creator=create_summary_view,
                        check_refine_parser_args_count=0)
```

---

## 7. 验证清单

重构完成后，需要验证以下功能：

- [ ] Function Overall Analysis
- [ ] Decompilation
- [ ] Specific Variables Analysis
- [ ] All Variables Analysis
- [ ] All Arguments Analysis
- [ ] Function Name Recovery
- [ ] Summary Analysis（修复后自动应用）

---

## 8. 总结

本重构计划采用分层架构模式，将现有代码按职责划分为四层：

1. **表现层** (Presentation): UI 组件和视图
2. **应用层** (Application): 工作流编排和任务管理
3. **领域层** (Domain): 业务逻辑和数据模型
4. **基础设施层** (Infrastructure): 外部服务接口封装

重构遵循以下原则：

- **单一职责**: 每个模块只负责一件事
- **依赖倒置**: 高层模块不依赖低层模块，都依赖抽象
- **开闭原则**: 对扩展开放，对修改关闭
- **接口隔离**: 使用接口隔离外部依赖
- **最少知识**: 模块间通过明确接口通信

建议按优先级逐步实施，先修复 Summary Analysis 的问题，再进行完整重构。
