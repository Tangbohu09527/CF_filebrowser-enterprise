---
name: filebrowser-regression-test
description: "用于 FileBrowser Quantum 修改完成后的回归验证和验证结果报告，根据实际 diff 从仓库已有 Makefile、CI、package scripts 与 Playwright 配置选择命令；不要用于实现功能或修改权限逻辑。"
---

# FileBrowser 回归验证

## 选择流程

1. 读取根目录 `AGENTS.md`、`git diff`、受影响实现和相关测试。
2. 读取当前 Makefile、CI、`backend/go.mod`、`backend/.golangci.yml`、`frontend/package.json` 和测试配置，确认命令仍然存在。
3. 按修改范围选择最小充分检查，不默认运行全套测试。
4. 原样记录命令、退出结果和失败输出，不关闭规则或删除断言。
5. 运行 `git diff --stat` 和 `git status --short`，确认验证过程未产生意外文件。

## 仓库现有命令

仅在对应范围需要时使用：

| 检查项 | 仓库命令 |
| --- | --- |
| Go 单元测试 | `make test-backend` |
| 权限专项测试 | 先从现有 `*_test.go` 确认包和测试名，再使用 `go test` 的 `-run` 过滤器 |
| Go Lint | `make lint-backend` |
| 前端类型检查 | 在 `frontend` 目录运行 `npm run typecheck` |
| 前端 Lint | `make lint-frontend` |
| 前端单元测试 | `make test-frontend` |
| 现有 Playwright E2E | `make test-playwright` |
| 后端构建 | `make build-backend` |
| 前端构建 | `make build-frontend` |
| 全项目构建 | `make build` |
| Git 差异 | `git diff --stat`、`git status --short` |

`make lint-backend` 使用 `go tool golangci-lint`。CI 另有自己的固定版本；不得为统一版本修改 `go.mod`、CI 或 Makefile。Playwright 已存在于 `frontend/playwright.config.ts` 和 Docker 测试入口中，不得新建配置或 smoke test。

## 输出格式

输出以下表格，并把未运行项也列出：

| 检查项 | 命令 | 结果 | 失败原因 | 是否与本次修改有关 |
| --- | --- | --- | --- | --- |

无法判断失败归因时标记为“待确认”，不要猜测或宣称通过。
