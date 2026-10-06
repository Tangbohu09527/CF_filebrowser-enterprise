# Hermes FileBridge：只读接入、受控新建与入站内容读取

当前推荐路线（2026-10-06）：通过受限 FileBrowser HTTP API 将已批准文件下载到 AI 主机，
再用 Hermes 原生能力读取；安装器路线暂停。实际验证进度与边界见
[首次文本记录](validation/2026-10-06-native-api-read.md)及
[PDF / PNG 实际下载与原生读取记录](validation/2026-10-06-native-media-read.md)。
这条路线读取 FileBrowser 已存文件；下述 Gateway 微信入站附件能力使用独立契约。
获批 PDF / PNG 均与上传前原始字节基准一致；PDF 正文及真实辅助视觉回答完成独立核对。
完整 Agent 会话与微信端到端仍未验收，不以本机成功替代。

此前的 Windows 安装器入口是 [统一安装与中断恢复](WINDOWS_SETUP.md)：下载固定制品后双击
`FileBridge-Setup.exe`，由入口选择安全路径。原 Check / Apply / Resume 保留为内部组件，
不再要求操作者逐段复制 PowerShell。2026-09-30 已确认存在部分升级现场；开发测试没有
执行现场恢复、启停或安装。

0.4.0 新增 [入站内容读取](INBOUND_CONTENT.md)：一次 `filebrowser_read_inbound`
调用沿用已授权下载与工作副本句柄，提取 PDF / DOCX / XLSX / PPTX 文本，或把实际图片
字节交给官方 Hermes 视觉入口。内容能力默认关闭；增量安装入口保留原客户端、模型、
CA、宿主凭据引用和工作根。隔离测试通过不代表已安装环境或微信端到端已验收。

当前官方 Hermes `0f4a98f` / 独立 Python 3.14.7 与旧版参考的兼容检查，见
[当前版本兼容记录](CURRENT_HERMES_COMPATIBILITY.md)。固定源码用于复现，不要求修改已安装 Hermes；
新旧结果、原候选与更新制品、隔离联合测试和现场验收分别记录。

新增入站附件开发入口见 [INBOUND_DOWNLOAD.md](INBOUND_DOWNLOAD.md)。专用下载 worker
将固定 Gateway 契约的字节验证后落到任务目录；模型不能传 URL、凭据或任务上下文。
此能力默认关闭。宿主适配消费 Gateway `0ec54bf0` 的权威 resolve / events / closed 契约，
通过官方 tool_execution middleware 复用原 HostBridge，见 [联合验证与配置](JOINT_HOST_VALIDATION.md)。隔离 HTTPS / Windows 测试和真实插件加载测试
分别记录；这些结果不代表实际 AI 主机已安装启用或真实 Dispatch 下载已经验收。

状态分层（2026-09-26）：已安装的 `04c7e717` 只读版本完成了微信真实文件读取、哈希和客户端审计关联的现场核验，详见[只读验收记录](validation/2026-09-26-wechat-read.md)。本分支新增[显式启用的受控新建文本](CONTROLLED_CREATE.md)代码，**新建版本尚未现场安装或验收**；原只读工具的命令不变，不开放覆盖、修改或删除。没有修改 Hermes 核心、Gateway 或 FileBrowser 服务端。完整微信 CRUD 与统一新机安装器尚未交付。

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

已安装的只读版本：受限 Token 交付、该安装目录的 NTFS ACL 检查、实际 Profile 插件启用、API 工具集合可见性和微信只读实收有带日期的现场证据。尚未完成：新建版本现场安装/验收、修改/删除、强隔离审批与写入恢复、新环境统一一条命令安装。不能把旧版只读验收扩大为新版写操作验收，也不能把 CI 通过写成现场上线。

新建/修改/删除扩展不得绕过服务端 API、路径授权、审计或不确定结果处理。特别是客户端的“先读哈希再写”不等于服务端原子的 compare-and-swap；在补齐条件写契约前，不能对多写入者并发作安全承诺。
