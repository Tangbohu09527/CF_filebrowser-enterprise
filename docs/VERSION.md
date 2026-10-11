# 版本信息

| 项目 | 值 |
| --- | --- |
| 项目名称 | FileBrowser Enterprise |
| 基线版本 | `v0.9-enterprise-base` |
| 现有文档版本标识 | `v1.0-beta`（沿用，不构成发布或安装版本声明） |
| Git commit（文档初始化基线） | `4750a97cfdf5bd067e04b6b36bf9616f5ada836d` |

Git commit 记录的是初始化本组开发文档时所基于的源码提交。

## 2026-10-11 只读核对快照

本次文档固定基线为 `bb11be4944b5325f2d10aa5a1adb88a3f467da72`，新分支为
`codex/docs-filebrowser-status-20261011`，文档 PR base 为 `feat/filebridge-hermes-crud`。
本次不推进原功能分支、不升级版本、不打 Tag；下表不是部署状态表。

| 对象 | GitHub HEAD | 状态及目标 |
| --- | --- | --- |
| [main](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/tree/4750a97cfdf5bd067e04b6b36bf9616f5ada836d) | `4750a97cfdf5bd067e04b6b36bf9616f5ada836d` | 未包含下列未合并 PR 的交付声明 |
| [PR #1](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/pull/1) | `8ff37ef0da322aa2194d9ef37e26eb7f7035cbb2` | Draft / Open；`feat/file-service-clean-device` → `feat/v1-integration`，未合并 |
| [PR #2](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/pull/2) | `bb11be4944b5325f2d10aa5a1adb88a3f467da72` | Draft / Open；`feat/filebridge-hermes-crud` → `feat/file-service-clean-device`，未合并 |
| 总文档 [PR #9](https://github.com/Tangbohu09527/CF_ecommerce-automation-docs/pull/9) | `8179533ffade1027d01727cbf5a89a26b491c400` | Draft / Open；`docs/file-business-workflows-20260927` → `main`；仅通过 GitHub 读取[需求快照](https://github.com/Tangbohu09527/CF_ecommerce-automation-docs/blob/8179533ffade1027d01727cbf5a89a26b491c400/requirements/file-workflows.md) |

## 对应 HEAD 的 CI

以下为 GitHub 在上述提交上的既有结果，本轮未重跑；不能写成全仓 CI 全绿或业务已上线。

| 对象 | 已通过 | 失败/缺项 |
| --- | --- | --- |
| main `4750a97c` | [main release](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/29586464929)（2026-07-17） | 该历史 workflow 成功不证明后续集成能力已发布或部署 |
| PR #1 `8ff37ef0` | [deployment-assets](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34934594670)；regular tests 中后端/前端测试、前端 Lint、format、翻译与 check-docs | [regular tests](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34934594644) 的 `lint-backend` 失败；[shared-host-delivery](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34934594696) 的 backend-regression、source-regression、fixed-image 失败，storage-control/name-resolution-control 跳过（2026-09-15） |
| PR #2 `bb11be49` | [FileBridge client](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/37407661714)、[Windows config](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/37407661618)、[deployment-assets](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/37407661634)；regular tests 中除后端 Lint 外的六项 | [regular tests](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/37407661615) 的 `lint-backend` 失败（2026-10-06）；组件成功不替代实机验收 |

本次仅按 run/job 结果确认失败阶段，不推断新的根因或删除历史失败。Makefile 的 `go tool golangci-lint` 与 CI 保持原样。

## 安装与现场证据的版本边界

- 9 月 26 日用户证据对应 FileBrowser 服务端 `8ff37ef0`、客户端/插件 `04c7e717` 的只读链路；9 月 27 日用户另行提供受控文本新建/回读及客户端审计关联。后者不能被更早“尚未安装”覆盖，也不证明全部当前源码均已安装。见 [FileBridge](../integrations/hermes-filebridge/README.md)。
- 10 月 6 日原生读取核验使用 Hermes `0f4a98f87c17007b81500239d0bd5b9574027b73` 与 Python 3.14.7；固定来源文件及 PDF/PNG 样本成功，不是全安装目录完整性证明或任意文档格式验收。
- 专用安装器路线暂停；部分安装现场和原备份保留，未执行回退或恢复。当前受限 HTTP API 下载后使用官方原生能力，不以修复安装器为前置。
- 完整 Agent/微信文字返回与 10 月 6 日本机工具结果分开，见 [FileBridge 状态及 Gateway 记录入口](../integrations/hermes-filebridge/README.md)；它们不证明微信实际文件/图片回传或自动分类归档。
- 用户 2026-10-11 已执行 CFserver reboot，FileBrowser 重启后未核验，**当前健康/在线状态未知**。本轮未连接服务、读取凭据或业务文件，也未做写入验收。
