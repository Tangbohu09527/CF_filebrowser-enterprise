# 项目目标

本项目是基于 FileBrowser Quantum 的公司内部二次开发版本。采用最小侵入式开发，优先保持上游兼容，并优先通过自动化测试保护行为。

# 强制规则

1. 不得进行无关重构、全仓格式化或依赖升级。
2. Bug 修复应优先添加能够复现问题的失败测试，再实施最小修复。
3. 不得擅自提交、推送、合并、重置、清理或恢复 Git 内容。
4. 不得删除、覆盖或恢复用户已有改动。
5. 不得删除、弱化或绕过现有安全回归测试；修改测试时必须保留原有测试意图和关键断言。
6. 修改前必须先阅读相关实现和现有测试，优先复用现有结构与辅助函数。
7. 只修改当前需求直接相关的文件，不做顺手修复。
8. 只运行与修改范围匹配的测试；测试未通过时不得宣称任务完成。
9. 未执行的测试必须明确列出并说明原因。
10. 修改涉及超过 3 个核心模块时，必须先说明影响范围、调用入口和回归风险。
11. 不得访问生产服务器、生产数据库或正式存储目录。测试只能使用仓库测试目录或独立临时目录。
12. 不得通过删除断言、关闭测试、跳过检查或使用管理员权限绕过问题。
13. 项目检查优先使用仓库 Makefile、CI、`package.json` scripts 或 Go `tool` 中已有命令。
14. 不得为统一 `golangci-lint` 版本而修改 `backend/go.mod`、CI 或 Makefile。Makefile 的 `go tool golangci-lint` 与 CI 各自保持仓库现状。
15. 不得擅自修改 `package.json`、锁文件、`go.mod` 或 `go.sum`；确有需求时必须先说明原因和影响。

# 权限与文件写入

权限修改必须分别验证以下场景：

- 新建文件与覆盖已有文件。
- `Create` 权限与 `Modify` 权限。
- 普通用户行为，不能只测试管理员。
- 用户权限与 Token 权限的交集、撤销和越权边界。

修改文件写入逻辑时必须检查所有相关入口：

- HTTP `PUT`。
- HTTP `POST`。
- WebDAV。
- 分享上传。
- 编辑器保存。

涉及 `Delete`、`Download`、`Share` 或其他权限时，按同样原则检查普通用户、Token、分享和协议入口。

# 仓库检查入口

按修改范围选择现有命令，不得为了方便发明替代流程：

- 后端测试：`make test-backend`。
- 后端 Lint：`make lint-backend`，内部使用 `go tool golangci-lint`。
- 前端类型检查：在 `frontend` 目录运行 `npm run typecheck`。
- 前端 Lint：`make lint-frontend`。
- 前端单元测试：`make test-frontend`。
- 构建检查：`make build-backend`、`make build-frontend` 或 `make build`。
- 现有 Playwright E2E：`make test-playwright`，不得新建 Playwright 配置或 smoke test。
- Git 差异检查：`git diff --stat` 和 `git status --short`。

# 完成任务后的固定输出

- 修改文件列表。
- 每个文件的修改原因。
- 实际执行的测试命令。
- 测试结果。
- 未执行的测试及原因。
- `git diff --stat`。
- `git status --short`。
