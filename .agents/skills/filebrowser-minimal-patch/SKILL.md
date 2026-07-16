---
name: filebrowser-minimal-patch
description: "用于 FileBrowser Quantum 的普通二次开发和常规 Bug 修复，要求最小范围、上游兼容和范围匹配的验证；不要用于以权限、安全审查、纯回归或上游比较为主的任务。"
---

# FileBrowser 最小修改

## 工作流程

1. 先读取根目录 `AGENTS.md`、相关实现和现有测试。
2. 运行 `git status --short`，识别并保留用户已有修改，尤其不得触碰 `backend/http/resource_test.go`。
3. 确定满足需求的最小文件集合，优先复用现有结构、辅助函数和调用路径。
4. Bug 修复先添加或运行能够复现问题的测试，再实施最小修复。
5. 只运行与改动范围匹配的仓库现有检查。
6. 完成后检查 `git diff --stat`、具体 diff 和 `git status --short`。

## 修改约束

- 保持上游兼容，避免改变无关公开行为。
- 不修改无关代码，不进行无关重构或全仓格式化。
- 不擅自升级依赖或修改锁文件、`go.mod`、`go.sum`。
- 不为统一 `golangci-lint` 版本修改 Makefile、CI 或 Go 工具声明。
- 不删除、覆盖、恢复、暂存、提交或推送用户修改。
- 修改超过 3 个核心模块前，先报告影响范围、入口和回归风险。
- 测试失败时不得宣称完成；未运行的检查必须说明原因。

## 验证与输出

从 Makefile、CI、`package.json` scripts 和现有测试中选择命令，不凭空创建替代流程。最终输出：

- 修改文件及每个文件的修改原因。
- 实际运行的测试命令与结果。
- 未运行的测试及原因。
- `git diff --stat`。
- `git status --short`。
