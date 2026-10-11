# FileBrowser Enterprise

## 中文

### 项目介绍

FileBrowser Enterprise 是基于 FileBrowser Quantum 的公司内部二次开发版本，优先保持上游兼容。

### 定位

FileBrowser 是 AI 与员工共同使用的**唯一正式企业文件系统**。AI 通过受限文件工具/API 访问同一套正式文件，根据实际内容、公司既定分类及目录规则，把收到或待整理的文件存到对应目录；员工在同一系统继续查看、编辑和使用。

文件服务负责文件 API、存储授权与持久审计。检索、分类、商品匹配和内容加工由外部 Hermes/文件业务工具承担；Gateway 负责身份、会话、附件引用、任务及投递状态，微信适配负责收发。文件服务核心不另造 Agent、AI Gateway、OCR 或 RAG 平台，也不把文件整理逻辑塞入 Gateway。

### 当前能力与证据（2026-10-11）

下表描述固定基线 `bb11be49` 所在集成分支与带日期的历史证据。PR #1、#2 均为 **Draft / Open**，未合并；不能写成 `main` 已发布。用户 10 月 11 日已执行 CFserver reboot，**FileBrowser 重启后未核验，当前健康状态未知**。本轮仅核对文档、源码和 GitHub，不连接真实服务。

| 能力/业务 | 已有证据 | 待验收或边界 |
| --- | --- | --- |
| 服务端文件 CRUD、权限与审计 | 资源 API 有上传、读取、修改、移动/重命名、删除入口；Browse/Preview/Download、用户与 Token 权限交集、Share/Archive 安全及持久审计有实现与回归 | 服务端 API 存在不等于 Agent 已开放对应工具，也不证明现场完整 CRUD 上线；见 [API 契约](docs/API_CONTRACT.md) |
| Agent 工具与已安装版本 | CLI 支持只读、下载、新建目录和 `upload-new`；插件开放只读与显式启用的受控文本新建，入站内容组件默认关闭 | 不开放任意覆盖、移动、删除；源码、制品与安装现场分开，见 [接入指南](docs/AGENT_API_GUIDE.md)及 [FileBridge](integrations/hermes-filebridge/README.md) |
| 微信只读与受控文本新建 | [9 月 26 日](integrations/hermes-filebridge/validation/2026-09-26-wechat-read.md)用户回传完整文本、摘要与客户端审计关联；[9 月 27 日](integrations/hermes-filebridge/CONTROLLED_CREATE.md)用户回传受控新建 53 字节文本及回读证据 | 原始 Hermes trace 与服务端持久审计跨层关联未独立核验；不扩展为任意附件归档 |
| PDF/图片下载与读取 | [10 月 6 日](integrations/hermes-filebridge/validation/2026-10-06-native-media-read.md)真实 PDF/PNG 下载与原始摘要一致，原生 PDF 正文及真实辅助视觉独立核对 42/42 | 限定样本通过；不代表扫描 PDF/OCR、完整 Agent 工具循环或微信实际文件/图片实收 |
| 微信查找和实际文件收发 | Gateway [10 月 7 日记录](https://github.com/Tangbohu09527/CF_agent-gateway/blob/f9c601cba25cbc5459bb03519d1954ae55995ded/docs/validation/2026-10-07-wechat-file-api-text-closeout.md)收口两条指定任务的文字指令→API→新副本→原生读取→原聊天文字实收；工具副作用边界见 [FileBridge](integrations/hermes-filebridge/README.md) | 当前优先完成真实附件取得、READY Artifact/Delivery 与微信文件/图片实收；文字回复不能代替附件回传 |
| 自动分类归档 | 既定业务覆盖商品图、质检、手卡、授权，已有文件 API 和有限内容读取基础 | 群/发送人准入、目录模板、商品匹配、去重、待确认及 AI 离线恢复未完成业务验收 |
| 并发写冲突 | 受控新建有同计划独占占位、不覆盖与结果不确定处理；见 [受控新建](integrations/hermes-filebridge/CONTROLLED_CREATE.md) | 客户端预检或先读哈希再写不等于服务端原子条件写；跨入口、多写入者及掉电恢复未完整验收 |
| 工作副本加工后回存 | CLI 有下载/新增上传基础，10 月 6 日已取得并读取实际副本 | 完整 Agent 下载→加工→API 另存结果→原件关联→按需分发尚待验收；另存不等于完整版本管理 |
| WebDAV / OnlyOffice | 有协议/回调权限实现及隔离测试，历史 VM 有 WebDAV 分项结果 | 目标设备 WebDAV 客户端、实际 OnlyOffice Document Server/客户端编辑保存未完整验收，见 [部署记录](deploy/shared-host/verification-notes.md) |
| 备份恢复与新设备交付 | 有部署资产、保护检查和历史隔离演练证据 | 真实目标设备、完整恢复及交付仍有缺项和 CI 失败，见 [共享主机部署](deploy/shared-host/README.md)；历史健康不能替代重启后核验 |

### 既定文件业务与实施顺序

1. **优先微信文件收发**：自然语言查找、受控取得真实原件并回传实际文件/图片，分别记录内容读取、投递和微信实收。
2. 指定资料群收取商品图、质检、手卡、授权，按实际内容和公司规则分类归档。常规预授权、范围内且不覆盖的新增归档不逐文件要求终端审批；未知归属进入待确认，同名冲突不得静默覆盖。
3. AI 主机下载工作副本加工，再通过 FileBrowser API 另存结果，默认保留原件与来源关系；员工在同一系统继续使用。

这些是已确认业务，不是新增可选建议。需求来源为总文档 [PR #9 固定快照中的文件工作流](https://github.com/Tangbohu09527/CF_ecommerce-automation-docs/blob/8179533ffade1027d01727cbf5a89a26b491c400/requirements/file-workflows.md)（Draft/Open，2026-09-27 用户确认）；当前终端 plan/approve/apply 是受控文本新建验收入口，不是常规自动归档的最终体验。

### 版本与文档入口

沿用现有文档标识 `v1.0-beta`，历史基线为 `v0.9-enterprise-base`；本次不升级版本、不打 Tag。版本标识不构成发布或部署声明。[版本/PR/CI 快照](docs/VERSION.md)记录 `main` 和集成分支的区别。

- [路线与待验收顺序](docs/ROADMAP.md)
- [部署基线](docs/DEPLOYMENT.md)与[共享主机验证记录](deploy/shared-host/verification-notes.md)
- [Agent API 指南](docs/AGENT_API_GUIDE.md)与[FileBridge 当前状态](integrations/hermes-filebridge/README.md)

当前接入优先受限 API 下载后使用 Hermes 官方原生能力。专用安装器路线暂停，部分安装及其备份、失败和历史证据保留；修复安装器不是该路线的前置条件。

## English

FileBrowser Enterprise is an internal extension of FileBrowser Quantum, with upstream compatibility as a priority.

### Purpose

The single official enterprise file system shared by employees and AI. External Hermes/tools access the same files through authorized APIs, classify them using their actual content and company directory rules, and save results for employees to continue using. FileBrowser owns file storage, authorization and persistent audit; Gateway owns identity, task and delivery state. Classification and processing belong in external file tools.

### Current capabilities

The integration branch contains server CRUD APIs and permission/audit controls. Agent tools expose a narrower set. Dated evidence covers WeChat text reading (September 26), controlled text creation (September 27), and real PDF/PNG download plus native PDF/auxiliary vision reading (October 6). Gateway's October 7 record closes two specific file-reading tasks with text replies received in WeChat, with a recorded Skill modification. These do not establish automatic filing, arbitrary attachment creation or actual WeChat file/image delivery.

PRs #1 and #2 remain Draft/Open. The existing documentation label is `v1.0-beta`, not a new release. FileBrowser health after the user's October 11 CFserver reboot is unverified. See the [version and CI snapshot](docs/VERSION.md).

### Roadmap

Prioritize actual WeChat file transfer, then rule-based filing of product images, quality reports, product cards and authorizations, followed by working-copy processing and API save-as. Routine preauthorized additions should not require per-file terminal approval; uncertain ownership awaits confirmation, conflicts must not silently overwrite, and originals are retained by default. These are established requirements. The installer route is paused; restricted API downloads and official native tools are the current path. See the [roadmap](docs/ROADMAP.md).

## License

This repository contains proprietary enterprise extensions and internal modifications based on FileBrowser.

Redistribution is not allowed without authorization.
