# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 提供在此代码库中工作的指导。

## 项目概述

**OpenReCopilot** 是一个逆向工程的 IDA Pro 插件，提供 AI 辅助二进制分析功能。它与 IDA Pro 的 Hex-Rays Decompiler 集成，通过大语言模型 (LLM) 提供智能代码分析。该项目是对商业 ReCopilot 插件的净室重新实现，通过静态解包和 LLM 辅助代码恢复从 PyArmor 保护的字节码中重建。

**技术栈：** Python 3.8+, IDA Pro Plugin API, PyQt5, OpenAI/Anthropic APIs

## 安装与开发

### 安装
```bash
# 安装 Python 依赖
pip install -r src/requirements.txt

# 复制到 IDA 插件目录
# macOS: ~/.idapro/plugins/
# Windows: %APPDATA%\Hex-Rays\IDA Pro\plugins\
# Linux: ~/.idapro/plugins/
```

### 依赖项
- `openai>=1.58.1` - OpenAI API 客户端
- `anthropic>=0.40.0` - Anthropic Claude API 客户端
- `requests>=2.31.0` - HTTP 库
- `termcolor>=2.4.0` - 终端颜色
- `pygments>=2.17.0` - 代码高亮
- PyQt5 (通常随 IDA Pro 捆绑)

### 无构建过程
这是一个纯 Python 插件，无需编译步骤。不存在 Makefile 或构建脚本。

## 架构

### 分层架构

```
IDA Pro Integration (recopilot.py)
          ↓
      UI Layer (recopilot_qt.py - PyQt5)
          ↓
   Handler/Orchestration (handler.py)
          ↓
  ┌──────────────┬────────────────┐
  │ Analysis     │ Data Flow      │
  │ (ext_info.py)│ (data_flow.py) │
  └──────────────┴────────────────┘
          ↓
  Response Processing (checker.py)
          ↓
  AI Integration (remote_model.py)
```

### 入口点

- **[recopilot.py](src/recopilot.py)** - 插件注册、IDA action 处理器、右键菜单钩子
- **PLUGIN_ENTRY()** - IDA Pro 的插件入口点，返回 `ReCopilotPlugin` 实例

### 核心模块（按职责）

| 模块                                   | 代码行数 | 用途                                      |
| -------------------------------------- | -------- | ----------------------------------------- |
| [recopilot_qt.py](src/recopilot_qt.py) | ~1,243   | PyQt5 对话框、设置 UI、变量选择、结果展示 |
| [ext_info.py](src/ext_info.py)         | ~2,000   | 上下文构建、伪代码生成、struct/enum 分析  |
| [handler.py](src/handler.py)           | ~306     | 分析工作流协调、线程管理、IDA 主线程执行  |
| [task_guides.py](src/task_guides.py)   | ~812     | 各任务类型的 Prompt 模板和输出格式        |
| [data_flow.py](src/data_flow.py)       | ~798     | 数据流分析、变量使用跟踪                  |
| [checker.py](src/checker.py)           | ~582     | JSON 解析、响应验证、优化                 |
| [remote_model.py](src/remote_model.py) | ~278     | OpenAI/Anthropic API 客户端、流式响应     |
| [config.py](src/config.py)             | ~106     | 设置持久化、默认配置                      |

### 数据流

1. 用户在 Pseudocode 视图中通过右键菜单触发操作
2. `handler.py` 提取函数上下文（伪代码、调用链、数据流）
3. `ext_info.py` 使用任务特定的指南构建分析 prompt
4. `remote_model.py` 调用 LLM API 并支持流式响应
5. `checker.py` 验证并优化 JSON 响应
6. Qt 对话框显示可编辑的预测结果
7. 用户确认/修改后应用到 IDA 数据库

## 分析任务

通过 Pseudocode 视图 (`BWN_PSEUDOCODE`) 的右键菜单使用：

- **Function Overall Analysis** - 完整的函数语义、类型、名称分析
- **Decompilation** - 生成更清晰的反编译伪代码
- **All Variables Analysis** - 所有变量的类型和名称恢复
- **Specific Variables Analysis** - 仅分析选定的变量
- **All Arguments Analysis** - 所有输入参数类型和语义分析
- **Function Name Recovery** - 推断有意义的函数名
- **Summary Analysis** - 生成函数摘要和内联注释

## 关键模式与约定

### 线程模型
- UI 操作通过 `ida_execute()` 在 IDA 主线程运行
- 分析任务在后台线程运行以避免阻塞 IDA
- 使用 async/await 进行 API 调用并支持流式响应
- 长时间运行的操作支持取消机制

### 命名约定
- 函数和变量使用 snake_case
- 类使用 PascalCase
- 前缀约定：`is_*()` 表示布尔值，`get_*()` 表示访问器
- 调试输出中使用表情符号指示器 (🐛, 👏, 💥, 🔗)

### 错误处理
- 使用 try-except 块并在 debug 模式下记录日志（设置中 `debug_mode: True`）
- IDA API 不可用时优雅降级
- 执行昂贵操作前显示用户确认对话框

### 配置
- 设置存储在 JSON 文件中（`settings.json` - 已从 git 排除）
- 默认值与用户设置合并
- `config.py` 中使用 Settings manager 单例模式
- 从 `prompts.json` 加载 prompt 模板

### IDA API 集成
- 使用 `idaapi`、`idc`、`ida_hexrays` 模块（由 IDA Pro 提供）
- 通过 `idaapi.register_action()` 注册 action
- 通过 `ida_kernwin.UI_Hooks` 添加右键菜单钩子
- 通过 `ida_hexrays` 集成反编译器

## 代码组织说明

### 这是逆向工程的代码
- 原始代码受 PyArmor 保护
- 通过 [Pyarmor-Static-Unpack-1shot](https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot) + LLM 辅助恢复代码
- 包含反编译过程的标记
- 部分段可能不完整或有问题
- 中文注释与英文代码混合

### 无自动化测试
- 未检测到测试套件
- 可通过设置启用 debug 模式
- `handler.py` 中提供 mock 函数用于离线测试

## 支持的 LLM 提供商

通过设置对话框配置 (`Edit -> Plugins -> ReCopilot Settings`)：

| 提供商                 | Base URL                  | 模型示例            |
| ---------------------- | ------------------------- | ------------------- |
| OpenAI                 | (留空)                    | gpt-4o, gpt-4-turbo |
| DeepSeek               | https://api.deepseek.com  | deepseek-chat       |
| Ollama                 | http://localhost:11434    | llama3, qwen2       |
| OpenRouter             | https://openrouter.ai/api | openai/gpt-4o       |
| 任何兼容 OpenAI 的 API | 自定义                    | 自定义              |

## 重要约束

### Token 限制
大型函数可能超出模型上下文长度限制。缓解方法：
- 在设置中减少 `Max Output Tokens`
- 对大型函数禁用 `Data Flow Analysis`

### 模型输出格式
某些模型可能不严格遵循 JSON 输出格式。建议使用 GPT-4o 以获得最佳效果。

### 设置不在 Git 中
`settings.json` 已被 gitignore，包含用户的 API 密钥。切勿提交该文件。

## 快捷键

- `Ctrl+Shift+Alt+F` - Function Overall Analysis
- `Ctrl+Shift+Alt+D` - Decompilation
- `Ctrl+Shift+Alt+V` - Specific Variables Analysis
- `Ctrl+Shift+Alt+S` - Settings
