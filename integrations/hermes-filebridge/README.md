# Hermes FileBridge：只读接入、受控新建与入站内容读取

当前推荐路线（2026-10-11 文档核对）：通过受限 FileBrowser HTTP API 将已批准文件下载到 AI 主机，
再用 Hermes 原生能力读取；安装器路线暂停。实际验证进度与边界见
[首次文本记录](validation/2026-10-06-native-api-read.md)及
[PDF / PNG 实际下载与原生读取记录](validation/2026-10-06-native-media-read.md)。
这条路线读取 FileBrowser 已存文件；下述 Gateway 微信入站附件能力使用独立契约。
获批 PDF / PNG 均与上传前原始字节基准一致；PDF 正文及真实辅助视觉回答完成独立核对。
10 月 7 日 Gateway 记录另外收口了两个指定样本的完整 Agent 读取与原微信聊天**文字结果**实收；
不等于微信实际 PDF 文件/图片回传、入站原件取件或自动分类归档验收，详见下表。

FileBrowser 是 AI 与员工共同使用的唯一正式企业文件系统。AI 通过文件工具/API 访问同一套
正式文件，根据实际内容、公司既定分类及目录规则归档，员工继续在这里查看、编辑和使用。
微信查找回传、商品图/质检/手卡/授权归档、工作副本加工后 API 另存结果均是
[已确认业务](https://github.com/Tangbohu09527/CF_ecommerce-automation-docs/blob/8179533ffade1027d01727cbf5a89a26b491c400/requirements/file-workflows.md)。
常规预授权新增归档不逐文件要求终端审批；未知归属先待确认，同名冲突不得静默覆盖，默认保留原件。
分类和加工由外部 Hermes/文件工具承担；Gateway 管理准入、任务、附件引用和投递状态，
不承担文件整理逻辑。当前优先验收微信实际文件收发，本轮只更新文档。

## 能力、证据与待验收范围

| 层次/业务 | 已有能力或带日期证据 | 尚不能据此认定 |
| --- | --- | --- |
| 服务端 CRUD | 资源 API 已有读取、上传/新建、修改、移动/重命名、删除入口，受账号/Token 和 Source/Scope 限制 | 服务端入口存在不等于 Agent 已开放相同工具或文件整理已上线；分支与 CI 状态见 [VERSION](../../docs/VERSION.md) |
| Agent 开放工具 | `filebrowser_files` 只读；另行启用的 `filebrowser_create_text` 仅计划/执行/状态；CLI 另有 `mkdir` / `upload-new` | CLI 命令、示例 Skill 和真实插件工具集合不能混同；未开放任意附件上传、移动、覆盖或删除工具 |
| 9 月 26 日只读 | 已安装 `04c7e717` 的单个 122 字节文件读取、摘要和客户端审计关联通过，[用户现场记录](validation/2026-09-26-wechat-read.md)保留 | 不是写入或服务端持久审计逐请求关联证明 |
| 9 月 27 日受控新建 | 用户回传 53 字节文本的计划、终端批准、微信 apply、回读/摘要及本地记录/客户端审计关联成功，见[需求记录 §6](https://github.com/Tangbohu09527/CF_ecommerce-automation-docs/blob/8179533ffade1027d01727cbf5a89a26b491c400/requirements/file-workflows.md) | 不能再以早期“未安装”否定该限定成功；未据此确定当前安装提交，也不是任意附件或自动归档验收 |
| 10 月 6 日受限 API 与原生能力 | [实际 PDF/PNG 下载](validation/2026-10-06-native-media-read.md)、原始字节对照、官方 PDF 正文、一次真实辅助视觉及独立核验 42/42 通过 | 当日记录不证明完整 Agent/微信链；不扩大为扫描 PDF/OCR 或任意格式 |
| 10 月 7 日完整 Agent 与微信文字 | [Gateway 固定记录](https://github.com/Tangbohu09527/CF_agent-gateway/blob/f9c601cba25cbc5459bb03519d1954ae55995ded/docs/validation/2026-10-07-wechat-file-api-text-closeout.md)：两个指定任务经 API 新下载副本、原生读取、同轮回答与用户提供的服务器记录关联，用户确认原聊天文字实收 | 不是实际 PDF/PNG 附件回传；该轮模型传输图像字节未独立观测，PDF 轮次附带 Skill 修改，不能称工具全程只读 |
| 入站下载/内容插件与安装器 | 代码、隔离 HTTPS/NTFS、官方加载和联合测试有历史证据；9 月 30 日部分升级、10 月 6 日复核记录保留 | 暂存/CI 不等于实机启用；安装器路线暂停，修复旧安装不是当前 API 路线前置条件 |
| 自动分类归档、工作副本回存 | 已有 API/CLI 基础及下载读取的分项证据 | 群原件收妥、规则分类、去重/待确认、正式归档；加工后 API 另存及原件关联仍待完整业务验收 |
| 并发与交付 | 受控文本有本地一次执行/重放防护；安装、恢复有分项设计和测试 | 客户端预检/哈希不等于服务端原子条件写；多写入者冲突、备份恢复、新设备统一交付仍需专项验收；WebDAV/OnlyOffice 见[部署范围](../../docs/DEPLOYMENT.md) |

以上均为历史或代码证据。用户于 2026-10-11 执行了 CFserver reboot；FileBrowser 重启后尚未核验，
本页不声明当前服务健康在线。历史 validation 保留各自日期和当时未完成项，后来进展以上表为准。

此前的 Windows 安装器入口是 [统一安装与中断恢复](WINDOWS_SETUP.md)：下载固定制品后双击
`FileBridge-Setup.exe`，由入口选择安全路径。原 Check / Apply / Resume 保留为内部组件，
不再要求操作者逐段复制 PowerShell。2026-09-30 已确认存在部分升级现场；开发测试没有
执行现场恢复、启停或安装。

0.4.0 新增 [入站内容读取](INBOUND_CONTENT.md)：一次 `filebrowser_read_inbound`
调用沿用已授权下载与工作副本句柄，提取 PDF / DOCX / XLSX / PPTX 文本，或把实际图片
字节交给官方 Hermes 视觉入口。内容能力默认关闭；增量安装入口保留原客户端、模型、
CA、宿主凭据引用和工作根。隔离测试通过不代表已安装环境或微信端到端已验收。

已核对的官方 Hermes `0f4a98f` / 独立 Python 3.14.7 与旧版参考的兼容检查，见
[当前版本兼容记录](CURRENT_HERMES_COMPATIBILITY.md)。固定源码用于复现，不要求修改已安装 Hermes；
新旧结果、原候选与更新制品、隔离联合测试和现场验收分别记录。

新增入站附件开发入口见 [INBOUND_DOWNLOAD.md](INBOUND_DOWNLOAD.md)。专用下载 worker
将固定 Gateway 契约的字节验证后落到任务目录；模型不能传 URL、凭据或任务上下文。
此能力默认关闭。宿主适配消费 Gateway `0ec54bf0` 的权威 resolve / events / closed 契约，
通过官方 tool_execution middleware 复用原 HostBridge，见 [联合验证与配置](JOINT_HOST_VALIDATION.md)。隔离 HTTPS / Windows 测试和真实插件加载测试
分别记录；这些结果不代表实际 AI 主机已安装启用或真实 Dispatch 下载已经验收。

9 月 26 日只读与 9 月 27 日[受控新建文本](CONTROLLED_CREATE.md)是分别记录的限定成功；
原只读工具的命令不变，不开放覆盖、修改或删除。完整微信 CRUD 与统一新设备交付尚未完成。

## 接口基线与目录

适配已检查的 Hermes `4d55ca91656ac5f83e1506679b7f81e0238e5e16` 的 `PluginContext.register_tool(name, toolset, schema, handler, ..., override=False)` 和 profile-scoped `ctx.get_config`。`plugin/` 是待部署的用户插件目录内容，目录名为 `cf-filebridge`。清单 `plugin.yaml` 和 `__init__.py` 不修改 Hermes 内置工具。

插件注册 `filebrowser_files`，toolset 为 `cf_filebridge`，仅允许 `ping`、`whoami`、`capabilities`、`sources`、`list`、`stat`、`checksum`、`read`。可执行文件、配置文件和可执行文件 SHA-256 均由操作者配置，模型不能覆盖 URL、凭据、进程参数或本地路径；插件不调用 shell，不转发子进程 stderr。返回的文件正文仍是不可信数据，不得作为指令执行。

插件并非 OS 沙箱。其他使用同一 OS 身份的 Hermes 工具可能具有独立权限，不能声称此插件使同身份进程无法读取 Token。生产接入必须继续审核该 Profile 的其他工具权限和本地文件 ACL。

## 客户端新增配置

在已有 `filebrowser-agentctl` 配置结构中新增以下**操作者字段**：

```json
{
  "ca_file": "./trust/ca.crt",
  "ca_sha256": "REPLACE_WITH_INDEPENDENTLY_VERIFIED_CA_PEM_SHA256",
  "direct_connection": true
}
```

`ca_file` 和 `ca_sha256` 必须同时给出或同时省略。给出时，相对路径以客户端配置目录为准；验证 CA PEM 的 SHA-256、普通文件及非符号链接路径、每一段证书的 CA/签名用途，然后使用独立根池。不会写 Windows 或 Linux 全局信任库，不提供跳过 TLS 校验的开关；服务端名称、有效期和链仍由 TLS 正常验证。该根池替换而非追加系统根池。两项均省略时仍使用正常系统信任。

`direct_connection=true` 只让这个客户端直连固定服务，不使用环境代理。默认 false 保留环境代理兼容性。HTTP 仍只允许原有的显式本机回环开发例外；不放宽跨机器 HTTP。

CA、配置、Token、客户端二进制、审计目录的写权限必须只属于操作者和实际运行身份。尤其 Windows NTFS ACL 必须由安装流程独立复核；跨平台 Go 权限位不足以证明 ACL 隔离。

## Profile 配置示例（不直接覆盖现有配置）

将以下片段合并到**实际 API 进程使用的 Profile**。`plugins.enabled` 的既有条目必须保留；已有 disabled 冲突必须明确处理，不能假定放进目录就已生效。路径和摘要是占位符，不能当真实部署命令执行。

```yaml
plugins:
  enabled:
    - cf-filebridge
  entries:
    cf-filebridge:
      settings:
        client_path: C:/PATH/TO/filebrowser-agentctl.exe
        client_sha256: REPLACE_WITH_VERIFIED_BINARY_SHA256
        config_path: C:/PATH/TO/filebridge-config.json
```

只读工具不会因 `allow_writes: true` 或模型传入 `apply` 而开放写入。原有 CLI `mkdir` / `upload-new` 保持原行为，不作为任意文件写工具暴露。新建文本必须另行显式启用第二个工具、配置单独的创建策略、完成外部操作者批准；见受控新建文档。

## Scope 与工具路径不能混淆

FileBrowser 用户的 Source Scope 是服务端授权根。假设账号 Scope 为 `/wechat-acceptance`，资源 API 的 `/` 是**该账号的 scoped root**，不是服务器磁盘根；`/sample.txt` 对应该 Scope 内的文件。不要在每个客户端请求中重复拼接 `/wechat-acceptance`。

本地 `allowed_sources` 是附加限制。只有独立核验服务账号确实被限制在批准 Scope 后，才可以把本地 `read_roots` 设为 `["/"]`；它不扩大服务端授权，也不能替代服务端校验。只有配置了相应 allowlist 的 Source 才可调用。查询返回路径和内容仍需按现有客户端规则核对。

示例工具输入（仅演示，不自动发送）：

```json
{"command":"list","input":{"source":"enterprise-files","path":"/"}}
```

## 验证与阶段边界

CI 使用独立 Go module 原来的 `go test ./...` / `go vet ./...`，在 Linux 和 Windows 上运行，不修改 module/依赖锁文件。额外 TLS 用例包含实际本地 HTTPS 握手：正确 CA 通过、错误 CA/名称失败、摘要/路径/PEM 拒绝，且不替换进程全局 Transport。Go 源文件固定 LF，避免 Windows checkout 自动换行导致格式化门禁误报；门禁保留。

原只读/受控新建 Python 单元测试使用临时文件、模拟进程与模拟 PluginContext，不连接业务服务。下载组件另有真实 HTTPS/原生 worker、官方 loader 和请求边界探针，各层证据见 [宿主桥接验证记录](HOST_BRIDGE_VALIDATION.md)，不能扩大为微信现场验收。CI 产出固定提交的二进制、源码包和 SHA256SUMS；下载后必须对照成功的相应提交、平台和文件摘要。

既有只读版本的受限 Token 交付、安装目录 NTFS ACL、实际 Profile 插件启用、API 工具可见性和微信只读实收有带日期证据；9 月 27 日另有受控文本新建用户证据。修改/删除、强隔离审批与写入恢复、新环境统一交付仍未完成。后来的部分升级不是全新版本安装成功，CI 通过也不是现场上线证明。

新建/修改/删除扩展不得绕过服务端 API、路径授权、审计或不确定结果处理。特别是客户端的“先读哈希再写”不等于服务端原子的 compare-and-swap；在补齐条件写契约前，不能对多写入者并发作安全承诺。
