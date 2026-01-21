# OpenReCopilot 功能测试计划

## 测试目标

验证重构后的插件功能与重构前保持一致，确保所有用户可见功能正常工作。

---

## 测试环境

### 必需条件
- IDA Pro (推荐 7.5+)
- 已安装 OpenReCopilot 插件
- 配置有效的 LLM API（OpenAI/DeepSeek/Ollama 等）
- 测试用二进制文件

### 测试设置
1. 在 IDA 中加载测试二进制文件
2. 确保插件已正确加载
3. 配置 API 密钥（Settings 中 debug_mode 可设为 False 使用真实 API，或 True 使用 mock）

---

## 功能测试用例

### 1. Function Overall Analysis（函数整体分析）

**触发方式**: 右键菜单 → ReCopilot → Function Overall Analysis
**快捷键**: `Ctrl+Shift+Alt+F`

#### 测试步骤
1. 在 Pseudocode 视图中选择一个函数
2. 右键点击 → ReCopilot → Function Overall Analysis
3. 如需确认，点击 "Yes"

#### 预期结果
- [ ] 显示确认对话框（如设置中启用了 need_confirm）
- [ ] 分析过程在后台线程运行，不阻塞 IDA UI
- [ ] 显示结果对话框，包含：
  - [ ] 函数名称建议
  - [ ] 返回类型
  - [ ] 参数列表（类型和名称）
  - [ ] 局部变量列表（类型和名称）
  - [ ] 函数注释（brief, details, category, algorithm）
- [ ] 用户可以编辑预测结果
- [ ] 点击 "Apply" 后，IDA 数据库被更新：
  - [ ] 函数名称改变
  - [ ] 参数类型改变
  - [ ] 变量类型改变
  - [ ] 函数注释添加

#### 失败判定
- 对话框未显示
- 结果格式错误
- 应用后 IDA 数据库未更新

---

### 2. Decompilation（反编译）

**触发方式**: 右键菜单 → ReCopilot → Decompilation
**快捷键**: `Ctrl+Shift+Alt+D`

#### 测试步骤
1. 在 Pseudocode 视图中选择一个函数
2. 右键点击 → ReCopilot → Decompilation

#### 预期结果
- [ ] 显示只读视图窗口
- [ ] 内容为重新生成的伪代码（带语法高亮）
- [ ] 窗口标题显示函数名
- [ ] 代码可读性优于原始 Hex-Rays 输出

#### 失败判定
- 窗口未显示
- 内容为空
- 无语法高亮

---

### 3. All Variables Analysis（所有变量分析）

**触发方式**: 右键菜单 → ReCopilot → All Variables Analysis

#### 测试步骤
1. 选择一个包含多个局部变量的函数
2. 右键点击 → ReCopilot → All Variables Analysis

#### 预期结果
- [ ] 显示确认对话框
- [ ] 结果包含所有局部变量的预测：
  - [ ] 变量名称
  - [ ] 变量类型（包括 struct/enum/array 等复杂类型）
- [ ] Struct/Enum 类型显示详情（字段列表）
- [ ] Apply 后 IDA 中变量类型被更新

#### 失败判定
- 变量列表不完整
- 类型信息错误
- 应用后未更新

---

### 4. Specific Variables Analysis（特定变量分析）

**触发方式**: 右键菜单 → ReCopilot → Specific Variables Analysis
**快捷键**: `Ctrl+Shift+Alt+V`

#### 测试步骤
1. 选择一个函数
2. 右键点击 → ReCopilot → Specific Variables Analysis
3. 在弹出的选择对话框中勾选 2-3 个变量
4. 点击 "OK"

#### 预期结果
- [ ] 显示变量选择对话框
- [ ] 对话框包含所有参数和局部变量
- [ ] 可以勾选/取消勾选变量
- [ ] 选择后点击 "OK"，分析仅针对选中的变量
- [ ] 结果仅包含选中的变量

#### 失败判定
- 选择对话框未显示
- 选择后分析了所有变量

---

### 5. All Arguments Analysis（所有参数分析）

**触发方式**: 右键菜单 → ReCopilot → All Arguments Analysis

#### 测试步骤
1. 选择一个包含多个参数的函数
2. 右键点击 → ReCopilot → All Arguments Analysis

#### 预期结果
- [ ] 结果仅包含函数参数
- [ ] 每个参数显示类型和名称
- [ ] 支持复杂类型（struct 指针等）
- [ ] Apply 后参数类型在 IDA 中被更新

#### 失败判定
- 结果包含局部变量
- 参数信息错误

---

### 6. Function Name Recovery（函数名恢复）

**触发方式**: 右键菜单 → ReCopilot → Function Name Recovery

#### 测试步骤
1. 选择一个函数（建议选择名称模糊的如 `sub_1234`）
2. 右键点击 → ReCopilot → Function Name Recovery

#### 预期结果
- [ ] 显示建议的函数名
- [ ] 函数名符合代码功能
- [ ] 用户可以编辑函数名
- [ ] Apply 后 IDA 中函数名被更新

#### 失败判定
- 未显示建议
- 建议的函数名不合理

---

### 7. Summary Analysis（总结分析）

**触发方式**: 右键菜单 → ReCopilot → Summary Analysis

#### 测试步骤
1. 选择一个函数
2. 右键点击 → ReCopilot → Summary Analysis

#### 预期结果
- [ ] 显示分析结果窗口
- [ ] 结果包含：
  - [ ] 函数注释（brief, details）
  - [ ] 参数说明
  - [ ] 返回值说明
  - [ ] 行内注释（inline_comment）
- [ ] **自动应用结果到 IDA**：
  - [ ] 函数注释被添加
  - [ ] 行内注释被设置
- [ ] 窗口显示已应用的内容

#### 失败判定
- 注释未自动应用
- 行内注释未设置
- 需要手动点击 Apply

---

### 8. Settings（设置）

**触发方式**: Edit → Plugins → ReCopilot Settings

#### 测试步骤
1. 打开 Settings 对话框
2. 修改各项设置
3. 点击 "Apply" 或 "OK"

#### 预期结果
- [ ] 显示所有设置项：
  - [ ] Base URL
  - [ ] API Key
  - [ ] Model Name
  - [ ] Max Output Tokens
  - [ ] Data Flow Analysis (开关)
  - [ ] Need Confirm (开关)
  - [ ] Debug Mode (开关)
- [ ] 设置被保存到 settings.json
- [ ] 重启 IDA 后设置保持

#### 失败判定
- 设置未保存
- 重启后设置丢失

---

### 9. 取消操作

**触发方式**: 分析运行时点击 "Cancel" 按钮

#### 测试步骤
1. 启动任一分析功能
2. 在分析过程中点击 "Cancel" 按钮

#### 预期结果
- [ ] 分析被中断
- [ ] 显示取消消息
- [ ] IDA 继续正常响应
- [ ] 无部分结果被应用

#### 失败判定
- 无法取消
- 取消后 IDA 卡死

---

### 10. 线程安全

**测试步骤**
1. 连续启动多个分析任务
2. 在分析期间操作 IDA UI

#### 预期结果
- [ ] IDA UI 保持响应
- [ ] 多个任务可同时运行
- [ ] 无崩溃或死锁

#### 失败判定
- IDA 卡死
- 出现 Python 错误

---

## 测试方法

### 方法一：手动测试（推荐）

1. **准备测试二进制**
   ```bash
   # 使用任何编译过的二进制文件
   # 推荐使用有清晰函数结构的程序
   ```

2. **配置真实 API 或 Mock 模式**
   - 真实 API: 在 Settings 中配置 API Key，debug_mode = False
   - Mock 模式: debug_mode = True，使用内置 mock 函数

3. **逐项执行测试用例**
   - 使用测试检查表记录结果
   - 截图保存关键步骤

4. **回归测试**
   - 重构前记录基线结果
   - 重构后对比验证

### 方法二：对比测试

1. **重构前基线**
   ```bash
   git checkout <重构前commit>
   # 执行所有测试用例，记录结果
   ```

2. **重构后验证**
   ```bash
   git checkout <重构后commit>
   # 执行相同测试，对比结果
   ```

3. **对比项**
   - UI 窗口显示是否一致
   - 结果格式是否一致
   - IDA 数据库更新是否一致

---

## 测试检查表

使用此表记录测试结果：

| 用例 | 测试日期 | 测试人员 | 结果 | 备注 |
|-----|---------|---------|------|------|
| 1. Function Overall Analysis | | | ☐ 通过 ☐ 失败 | |
| 2. Decompilation | | | ☐ 通过 ☐ 失败 | |
| 3. All Variables Analysis | | | ☐ 通过 ☐ 失败 | |
| 4. Specific Variables Analysis | | | ☐ 通过 ☐ 失败 | |
| 5. All Arguments Analysis | | | ☐ 通过 ☐ 失败 | |
| 6. Function Name Recovery | | | ☐ 通过 ☐ 失败 | |
| 7. Summary Analysis | | | ☐ 通过 ☐ 失败 | |
| 8. Settings | | | ☐ 通过 ☐ 失败 | |
| 9. 取消操作 | | | ☐ 通过 ☐ 失败 | |
| 10. 线程安全 | | | ☐ 通过 ☐ 失败 | |

---

## 常见问题排查

### 问题：右键菜单没有 ReCopilot 选项
**可能原因**: 插件未正确加载
**解决**:
1. 检查 `Edit → Plugins → ReCopilot Settings` 是否存在
2. 查看 IDA 输出窗口的 Python 错误

### 问题：分析无响应
**可能原因**: API 调用失败
**解决**:
1. 检查 Settings 中的 API Key
2. 启用 debug_mode 查看详细日志
3. 测试网络连接

### 问题：结果格式错误
**可能原因**: LLM 响应解析失败
**解决**:
1. 启用 debug_mode 查看原始响应
2. 尝试使用 GPT-4o 等更可靠的模型
3. 检查 Max Output Tokens 设置

### 问题：应用后 IDA 未更新
**可能原因**: IDA API 调用失败
**解决**:
1. 查看 IDA 输出窗口的错误信息
2. 确认函数地址有效
3. 检查 IDA 版本兼容性

---

## 测试完成标准

重构被视为完成当且仅当：

- [ ] 所有 10 个测试用例通过
- [ ] 对比测试显示与重构前功能一致
- [ ] 无新增 bug 或回归问题
- [ ] IDA Pro 中正常使用无障碍

---

## 附录：测试数据示例

### 推荐测试函数类型

| 函数类型 | 特征 | 用于测试 |
|---------|------|---------|
| 简单计算函数 | 少量参数，无复杂类型 | 基础功能 |
| 字符串处理 | 涉及指针和数组 | 指针类型推断 |
| 结构体操作 | 访问 struct 成员 | Struct 恢复 |
| 枚举使用 | switch/case 语句 | Enum 恢复 |
| 回调函数 | 函数指针参数 | 函数指针类型 |
| 大型函数 | >100 行伪代码 | 数据流分析 |
