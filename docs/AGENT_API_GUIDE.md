# Hermes FileBridge 接入指南

本文说明如何在 AI 主机上部署 `filebrowser-agentctl`，让 Hermes Skill 通过固定、结构化、可审计的接口访问 FileBrowser Enterprise。它不是 Hermes、微信中转或任务调度的部署文档。

## 1. 架构边界

Debian 服务器只承担以下职责：

- 微信消息纯转发；
- 任务分发；
- FileBrowser Enterprise 服务；
- 企业文件存储。

Hermes、模型运行时、`filebrowser-agentctl`、本地 allowlist 和 Hermes Skill 均运行在一台或多台 AI 主机。禁止在 FileBrowser 中嵌入模型，也不在本接入中开发 OCR、RAG、本地推理、微信机器人或多节点调度器。

数据访问链路固定为：

```text
Hermes Skill
  -> AI 主机上预注册的 filebrowser_agentctl 结构化工具适配器
  -> filebrowser-agentctl（固定配置、Token、本地 allowlist）
  -> HTTPS Authorization Header
  -> FileBrowser Enterprise（账号、Token、Source/Scope、服务端权限）
  -> 企业文件存储
```

客户端 allowlist 是附加约束，不是服务端授权替代。一个请求必须同时通过：

1. Hermes Skill 命令 allowlist；
2. AI 主机配置中的 source、远端 read/write roots 和本地 read/write roots；
3. FileBrowser 当前账号权限与 full Token 权限的交集；
4. FileBrowser Source/Scope 和资源接口的服务端检查。

## 2. 工具位置与构建

工具位于 `tools/filebrowser-agentctl`，是独立 Go module，要求 Go 1.25 或兼容的更新版本。

Windows 本机构建：

```powershell
Set-Location tools/filebrowser-agentctl
go test ./...
go vet ./...
go build -trimpath -o filebrowser-agentctl.exe ./cmd/filebrowser-agentctl
```

Linux 本机构建：

```sh
cd tools/filebrowser-agentctl
go test ./...
go vet ./...
go build -trimpath -o filebrowser-agentctl ./cmd/filebrowser-agentctl
```

从 Windows 构建 Windows amd64 和 Linux amd64：

```powershell
Set-Location tools/filebrowser-agentctl
New-Item -ItemType Directory -Force dist | Out-Null
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -trimpath -o dist/filebrowser-agentctl-windows-amd64.exe ./cmd/filebrowser-agentctl
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -trimpath -o dist/filebrowser-agentctl-linux-amd64 ./cmd/filebrowser-agentctl
Remove-Item Env:GOOS, Env:GOARCH
```

二进制、配置和 Secret 只部署到 AI 主机。不要将它们写入 Debian 的 FileBrowser 部署目录。

## 3. `hermes-agent` 服务账号

### 3.1 管理员创建账号

管理员在 FileBrowser 管理界面中创建独立账号 `hermes-agent`，为它设置实际需要的 Sources/Scopes，并精确设置以下账号权限：

| 账号权限 | 值 | 原因 |
| --- | --- | --- |
| `Api` | `true` | 允许服务账号登录后为自己签发和管理 API Token |
| `Browse` | `true` | `list`、`search`、`stat` 和上传后元数据验证需要；`sources` 另行返回账号 Scope |
| `Download` | `true` | `read`、`download` 及上传后 HEAD 验证需要 |
| `Create` | `true` | 只创建新目录和新文件 |
| `Admin` | `false` | 不需要管理能力 |
| `Delete` | `false` | 客户端不实现删除 |
| `Share` | `false` | 客户端不实现分享 |
| `Realtime` | `false` | 第一版不使用实时连接 |
| `Preview` | `false` | `read` 使用受限 download 接口，不调用 Preview 接口 |
| `Modify` | `false` | 禁止覆盖或修改已有文件 |

不要授予额外权限来规避 `403`。如果某个命令失败，应先核对该命令的真实接口、Source/Scope 和本地 allowlist，而不是把账号提升为 Admin。

账号 Scope 应比企业 Source 根目录更窄。例如账号只处理供应商资料时，将其 Scope 限制到供应商资料区域；随后 AI 主机的 `read_roots` 和 `write_roots` 再进一步收窄。管理员只负责创建账号、设置权限和 Scope，不得用管理员身份替服务账号签发运行 Token。

### 3.2 服务账号自行 enrollment

Token enrollment 必须由 `hermes-agent` 自己登录后完成：

1. 管理员完成账号和 Scope 配置后退出管理员会话。
2. 操作员在独立受控会话中以 `hermes-agent` 登录。
3. 在该服务账号的 API Token 界面启用 **Customize Token**，创建 **full Token**；该开关对应 `minimal=false`，界面默认的 minimal Token 不适合本接入。
4. full Token 只勾选 `browse`、`download`、`create`，不勾选 `api`、`admin`、`modify`、`delete`、`share`、`realtime` 或 `preview`。
5. 将 Token 一次性写入 AI 主机 Secret Manager、受限环境变量或受限 Token 文件；不要写入仓库、文档、Prompt 或工单。
6. 注销服务账号 enrollment 会话，并按企业周期轮换和撤销 Token。

当前服务端 enrollment 契约是：先通过 `/api/auth/login` 获得 `hermes-agent` 自己的登录会话，再由该会话请求 `/api/auth/token`，参数语义为 `name=<node-specific-name>`、`days=<policy>`、`minimal=false`、`permissions=browse,download,create`。认证始终放在 Header。此接口为当前认证/权限基线能力，不使用 Public Share，也不依赖 sharing 分支。

上述端点只允许人工 enrollment 流程或受控的账号配置工具调用，绝不能暴露给 Hermes Skill。`filebrowser-agentctl` 本身不实现登录、Token 创建、列出、续期或删除。账号登录密码保存在企业凭据系统中，不写入 AI 主机的 agentctl 配置、环境变量或 Token 文件。

推荐每台 AI 主机创建独立名称的 Token，例如 `hermes-agent-ai-01`、`hermes-agent-ai-02`。这样可以单独撤销受影响节点，而无需中断其他节点。不要在 Token 名称中加入密码、机器 Secret 或业务敏感内容。

### 3.3 验证有效权限

配置 AI 主机后，由操作员运行 `whoami` 或 `capabilities`。对上述 full Token，预期关键结果为：

```json
{
  "username": "hermes-agent",
  "permissions": {
    "api": false,
    "admin": false,
    "modify": false,
    "share": false,
    "realtime": false,
    "delete": false,
    "create": true,
    "browse": true,
    "preview": false,
    "download": true
  },
  "capabilities_exact": true,
  "permission_source": "account_and_full_token_intersection"
}
```

账号自身的 `Api=true` 仅用于自行 enrollment；运行 full Token 不含 `api`，所以有效能力中 `api=false` 是预期结果。`capabilities_exact=false` 或 `permission_source=conservative_unknown_token` 表示 Token 不是当前可识别的权限快照，部署验证应失败关闭，不能据此启用写入。

随后运行 `sources`，确认结果仅包含：账号 Scope、本地 `allowed_sources` 和服务端当前可用 Source 的交集。不得通过扩大本地配置来探测账号无权访问的 Source。

## 4. Token 配置

客户端不接受 `--token` 参数，不从 URL query 认证。Token 只写入 `Authorization: Bearer ...` Header，并按以下优先级读取：

1. 出现 `--token-stdin` 时，从 stdin 第一行读取；
2. 否则读取 `FILEBROWSER_AGENT_TOKEN` 环境变量；
3. 否则读取配置中的 `token_file`。

使用 `--token-stdin` 时，JSON 应通过 `--input request.json` 提供；不要让 Token 与 JSON 在一个模型可见的文本缓冲区中拼接。环境变量应由服务管理器或 Secret Manager 启动时注入，不要长期写入用户 profile。

### 4.1 Linux 文件权限

Token 文件必须是普通、非符号链接文件，权限为 `0600` 或更严格；客户端会检查并拒绝 group/other 权限：

```sh
chmod 600 /opt/hermes-filebridge/secrets/hermes-agent.token
```

目录也应只允许 Hermes 服务身份进入。不要通过 bind mount 或符号链接把文件绕到 allowlist 外。

### 4.2 Windows 文件权限

Token 文件同样必须是普通、非符号链接文件。Windows Go 权限位不能可靠表达 NTFS ACL，客户端无法替代部署检查。部署者必须关闭继承并只授权运行 Hermes 的服务身份，例如：

```powershell
$TokenFile = "C:\ProgramData\Hermes\FileBridge\secrets\hermes-agent.token"
icacls.exe $TokenFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)"
```

实际部署应把 `$env:USERNAME` 替换为 Hermes Windows 服务所用身份，并用 `icacls.exe $TokenFile` 复核 ACL。不要将 Token 放入仓库目录或多人可读的临时目录。

## 5. 客户端配置与路径策略

以 `tools/filebrowser-agentctl/config.example.json` 为模板。配置不包含 Token 值；`token_file` 只是本地受限文件路径。

```json
{
  "base_url": "https://files.example.internal/filebrowser/",
  "token_file": "./secrets/hermes-agent.token",
  "audit_log": "./logs/filebrowser-agentctl.audit.jsonl",
  "allowed_sources": {
    "enterprise-files": {
      "read_roots": ["/supplier-materials"],
      "write_roots": ["/supplier-materials/organized"]
    }
  },
  "local_read_roots": ["./upload-staging"],
  "local_write_roots": ["./downloads"]
}
```

所有相对本地路径均以配置文件所在目录为基准。JSON 示例使用 `/`，Linux 原生支持，Windows Go 运行时也可解析；生产中建议每个平台保存独立配置，以明确本地根目录和 ACL。Token、审计日志、本地根目录及目标父目录必须预先创建。

### 5.1 Base URL

- `base_url` 是每台 AI 主机的固定配置，Hermes 请求不能覆盖它。
- 必须是绝对 HTTPS URL，不能包含用户名、密码、query、fragment 或 `..`。
- 客户端不跟随 HTTP redirect，避免 Authorization Header 被带到其他主机。
- 只有本地开发可以显式传 `--allow-localhost-http`，且目标必须是 `localhost`、`127.0.0.0/8` 或 IPv6 loopback。
- 远程 HTTP 即使带开发参数也会拒绝。

### 5.2 远端逻辑路径

- 路径必须以 `/` 开头，表示 FileBrowser Source 内的逻辑路径，不是服务器物理路径。
- 禁止反斜杠、Windows 盘符、NUL、换行、`.` 和 `..` 路径段。
- `allowed_sources` 不得为空；source 必须与 FileBrowser 返回给账号的显示名称完全一致。
- `read_roots` 用于 `list`、`search`、`stat`、`checksum`、`read` 和 `download`。
- `write_roots` 用于 `mkdir` 和 `upload-new`，不会从 `read_roots` 自动继承。
- 搜索结果和目录子项也会重新检查 allowlist；服务端返回越界或不安全路径时，整个命令失败。

客户端在这里校验的是逻辑路径字符串。当前资源 API 不返回每个路径组件的服务端 canonical path 或 symlink 信息，因此部署必须同时满足：服务账号的服务端 Scope/Access 不宽于批准根；批准根中不存在指向根外的符号链接、junction 或其他 reparse point；企业存储上的链接只能由受控管理员变更。若存储必须使用可能逃逸的链接，应先在 FileBrowser 服务端提供 canonical-path/symlink 边界并增加服务端回归，本客户端不能替代该授权契约。

### 5.3 本地路径

- `local_read_roots` 只授权 `upload-new.local_file`。
- `local_write_roots` 只授权 `download.output_file`。
- `upload-new` 要求本地文件为可解析的普通文件；符号链接解析后的路径必须仍在本地读取根内。
- `download` 要求目标父目录存在，目标必须尚不存在，并通过同目录临时文件进行不可覆盖发布。
- 如果底层文件系统不支持安全的 no-replace 发布，客户端返回 `atomic_publish_failed`，不能改用覆盖式复制绕过。
- 配置文件、Token 文件及其父目录、上传 staging、下载目录和 audit 目录只能由管理员或运行 Hermes 的 OS 身份写入。跨平台标准库的 `EvalSymlinks` 后再打开文件存在检查/使用时间差，不能防御同机恶意写入者在检查后替换目录项。

本地路径 allowlist 与远端路径 allowlist 完全独立。例如 Windows 可以把 `C:\Hermes\upload-staging\summary.csv` 上传到 `/supplier-materials/organized/summary.csv`，Linux 可以把 `/var/lib/hermes/upload-staging/summary.csv` 上传到同一远端逻辑路径；两台主机不共享本地路径。

## 6. JSON 命令协议

CLI 用法：

```text
filebrowser-agentctl --config <file> [--input <file|->] [--token-stdin] [--allow-localhost-http] [--apply] <command>
```

`--input` 默认从 stdin 读取。即使是 `ping`、`whoami`、`capabilities` 和 `sources`，也必须提供 `{}`。输入必须是唯一一个 JSON 对象，未知字段会被拒绝。命令还会拒绝其他命令才使用的字段，例如 `ping` 中的 `path` 或 `mkdir` 中的 `output_file`，从而保持调用和审计语义唯一。source 名称最长 255 字节，远端逻辑路径和搜索词最长 4096 字节。

公共可选字段：

| 字段 | 说明 |
| --- | --- |
| `schema_version` | 省略或精确设置为 `filebrowser-agentctl/v1` |
| `request_id` | 最长 128 字符，仅允许字母、数字、`.`、`_`、`:`、`-` |
| `operation_id` | 同上；用于跨 dry-run/apply 和审计关联；任何 `--apply` 都必须显式提供 |

支持命令和命令字段：

| 命令 | 必填字段 | 可选字段 | 备注 |
| --- | --- | --- | --- |
| `ping` | 无 | 公共字段 | CLI 仍会先加载 Token 和配置 |
| `whoami` | 无 | 公共字段 | 返回用户 ID、用户名、有效权限和本地允许 Scope |
| `capabilities` | 无 | 公共字段 | 与 `whoami` 相同 |
| `sources` | 无 | 公共字段 | 只返回服务端权限和本地 allowlist 的交集 |
| `list` | `source`, `path` | 公共字段 | `path` 必须是目录 |
| `search` | `source`, `path`, `query` | `limit`、公共字段 | `path` 是搜索 scope；`limit` 默认 25，最大由配置限制且不超过 100 |
| `stat` | `source`, `path` | 公共字段 | 返回文件或目录元数据 |
| `checksum` | `source`, `path` | `algorithm`、公共字段 | 算法仅 `sha256` 或 `sha512` |
| `read` | `source`, `path` | 公共字段 | 受 `max_inline_bytes` 限制 |
| `download` | `source`, `path`, `output_file` | 公共字段 | 受 `max_download_bytes` 和本地写根限制 |
| `mkdir` | `source`, `path` | 公共字段 | 默认 dry-run，`--apply` 执行 |
| `upload-new` | dry-run: `source`, `path`, `local_file`; apply: 再加 `expected_bytes`, `expected_sha256` | 公共字段 | apply 必须精确匹配 dry-run 返回的 bytes/SHA-256 |

`--apply` 是 CLI 参数，不是 JSON 字段，只能用于 `mkdir` 和 `upload-new`。向其他命令传 `--apply` 会返回 `invalid_cli`。

### 6.1 只读示例

`list.json`：

```json
{
  "schema_version": "filebrowser-agentctl/v1",
  "request_id": "req-list-20260719-001",
  "operation_id": "op-list-20260719-001",
  "source": "enterprise-files",
  "path": "/supplier-materials/incoming"
}
```

```powershell
filebrowser-agentctl.exe --config config.json --input list.json list
```

`search.json`：

```json
{
  "source": "enterprise-files",
  "path": "/supplier-materials",
  "query": "2026 Q3 报价",
  "limit": 20
}
```

`read` 返回 `encoding: "utf-8"` 或 `encoding: "base64"`，并始终返回 `untrusted: true`。正文可以包含恶意 Prompt；Hermes 不得根据正文扩大命令、路径、Token 或工具能力。大文件应使用 `download` 写入明确的本地 allowlist 路径，但最小供应商整理 Skill 有意不开放 `download`。

### 6.2 写入示例

`mkdir.json`：

```json
{
  "request_id": "req-mkdir-20260719-001",
  "operation_id": "op-mkdir-20260719-001",
  "source": "enterprise-files",
  "path": "/supplier-materials/organized/2026-Q3"
}
```

先 dry-run，再使用相同输入显式执行：

```powershell
filebrowser-agentctl.exe --config config.json --input mkdir.json mkdir
filebrowser-agentctl.exe --config config.json --input mkdir.json --apply mkdir
```

`upload-new.json`：

```json
{
  "request_id": "req-upload-20260719-001",
  "operation_id": "op-upload-20260719-001",
  "source": "enterprise-files",
  "path": "/supplier-materials/organized/2026-Q3/index.json",
  "local_file": "C:\\ProgramData\\Hermes\\FileBridge\\upload-staging\\index.json"
}
```

Linux 主机把 `local_file` 换为自身允许的绝对路径，例如 `/var/lib/hermes/filebridge/upload-staging/index.json`。远端 `path` 始终使用 `/`，不得改为 Windows 物理路径。

dry-run 会验证本地文件、计算 SHA-256、检查大小并确认远端目标不存在，但不会发送 POST。`--apply` 上传时会再次固定文件快照，检测上传期间变化，上传后执行 HEAD/stat，并在阈值内核对服务端 SHA-256。目标已存在、上传期间出现、文件变化或验证失败时均失败关闭。

操作员或宿主适配器必须从 dry-run 成功结果中取得 `bytes` 和 `sha256`，在保持 `operation_id`、source、path 和 local_file 不变的 apply 输入中加入：

```json
{
  "expected_bytes": 12345,
  "expected_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

该片段表示要合并到原 upload-new 输入的两个字段，不是独立 CLI 输入。客户端会在任何 POST 前重新计算当前 staging 文件；不匹配时返回 `approval_mismatch`，不得用新 dry-run 自动替代原批准内容。`expected_sha256` 必须是 64 位小写十六进制 SHA-256，零字节文件的 `expected_bytes` 为 `0`。

如果返回 `upload_outcome_unknown`，连接中断前服务端可能已创建目标。必须先对同一路径执行 `stat`，不得直接重试或改为 overwrite。

### 6.3 响应和审计

stdout 始终为单行 JSON：

```json
{
  "schema_version": "filebrowser-agentctl/v1",
  "ok": false,
  "command": "list",
  "request_id": "req-list-20260719-001",
  "operation_id": "op-list-20260719-001",
  "dry_run": false,
  "error": {
    "code": "forbidden",
    "message": "FileBrowser denied this operation",
    "http_status": 403,
    "retryable": false
  }
}
```

审计为 JSONL，记录时间、`operation_id`、`request_id`、命令、source、path、结果、HTTP 状态、持续时间、字节数和 dry-run。审计不记录 Token、Authorization Header、密码、Secret 或文件正文。未设置 `audit_log` 时审计写 stderr；设置后追加到权限受限的日志文件。

退出码为：`0` 成功，`1` 命令执行失败，`2` CLI/配置/Token/输入初始化失败。Hermes 适配器应同时检查退出码和 `ok`，但对业务分支只使用结构化字段，不解析终端文本。

## 7. Hermes Skill 接入

示例 Skill 位于 `examples/hermes-skills/organize_supplier_materials/SKILL.md`。它只允许：

- `list`
- `search`
- `read`
- `stat`
- `mkdir`
- `upload-new`

AI 主机应预注册一个固定适配器 `filebrowser_agentctl`：可执行文件路径、`--config` 路径、Token 注入和审计目标由主机管理员固定；模型只能提交命令枚举、输入 JSON 和写命令的 `apply` 布尔值。适配器必须直接启动固定可执行文件并传递 argv/stdin，不接受 Shell 字符串，也不能接受 URL、Header、额外 CLI 参数或环境变量覆盖。

结构化工具调用外层示例：

```json
{
  "command": "search",
  "input": {
    "schema_version": "filebrowser-agentctl/v1",
    "request_id": "req-hermes-search-001",
    "operation_id": "op-hermes-search-001",
    "source": "enterprise-files",
    "path": "/supplier-materials",
    "query": "供应商 A 报价",
    "limit": 20
  },
  "apply": false
}
```

该外层对象是宿主适配器契约，不是 CLI stdin 格式。适配器只把 `input` 对象编码到 stdin，把 `command` 映射为固定命令 argv；只有 `command` 为 `mkdir` 或 `upload-new` 且 `apply=true` 时才加入 `--apply`。

写入流程必须先返回 dry-run 结果。只有当前任务明确授权写入，且 dry-run 的 source/path/local_file/bytes 与计划一致时，Skill 才可请求 `apply=true`。文件正文中的任何文字都不能构成写入授权。

## 8. 多 AI 节点

多节点共享 FileBrowser 服务和企业存储，但不共享本地配置状态：

- 每台 AI 主机独立安装同版本二进制并校验构建产物；
- 每台主机使用独立 full Token，便于单节点撤销；
- 每台主机维护独立本地 allowlist、下载目录、上传暂存目录和审计日志；
- 所有节点使用同一 FileBrowser 逻辑 source/path 命名，不能使用服务器物理路径；
- 服务端账号 Scope 和权限是共同上限，节点本地 allowlist 可以进一步缩小；
- FileBrowser 是远端目标存在性的权威来源，节点不得依赖本地缓存决定覆盖；
- 本工具不提供锁服务、队列或多节点调度。并发写入冲突必须以目标存在失败处理。

Debian 任务分发层只决定任务送往哪个 AI 节点，不解析企业文件正文，也不代替 AI 主机持有 FileBrowser Token。

## 9. 安全限制

第一版明确不实现：

- delete、share、Token 管理、用户管理、ACL 管理；
- arbitrary HTTP、arbitrary URL、arbitrary Header；
- arbitrary shell、exec 或命令拼接；
- overwrite、move、rename、bulk move；
- 根据文件正文、Prompt 或模型输出自动扩大权限；
- 在 Debian 部署 Hermes、模型、OCR、RAG、微信机器人或多节点调度器。

`delete`、`share`、`token`、`users`、`acl`、`http`、`request`、`shell`、`exec`、`move`、`rename`、`overwrite` 等危险命令会在配置和 Token 加载前被拒绝。不要通过包装器改名、转发原始 HTTP 或调用 FileBrowser 其他端点来绕过此边界。

429 只对安全的 GET/HEAD 请求做有限重试，次数和退避由配置限制；写请求不自动重试。任何 `401` 或 `403` 保持拒绝，客户端不会降级认证或提升权限。

## 10. 故障诊断

| 错误码/现象 | 检查项 | 处理 |
| --- | --- | --- |
| `invalid_config` | 未知字段、空 allowlist、限制值越界、本地路径配置 | 修正配置，不修改服务端权限 |
| `insecure_base_url` | 非 HTTPS 或远程 HTTP | 使用固定 HTTPS；localhost 开发才加 `--allow-localhost-http` |
| `token_unavailable` / `invalid_token` | Token 来源、JWT 格式、stdin 与 JSON 冲突 | 从 Secret Manager 重新注入；不要在命令行传 Token |
| `insecure_token_file` | Unix 文件 group/other 可读写 | 收紧为 `0600` 或更严格 |
| `unauthorized` / HTTP 401 | Token 过期、撤销、签名或权限版本不兼容 | 由 `hermes-agent` 重新 enrollment，不用管理员 Token 替代 |
| `forbidden` / HTTP 403 | 账号/Token 权限交集或服务端 Scope 拒绝 | 核对精确权限和 Scope；不要授予 Admin |
| `source_denied` | source 不在本地配置 | 核对部署配置和 `sources`，不要探测其他 source |
| `path_denied` | 远端路径超出 read/write roots | 调整任务路径；只有部署者可审查并修改 allowlist |
| `local_path_denied` | 本地上传/下载路径超出根目录 | 使用预配置 staging/download 目录 |
| `target_exists` / `local_target_exists` | 远端或本地目标已存在 | 停止并报告；禁止覆盖、删除或自动重命名 |
| `download_too_large` / `checksum_too_large` / `upload_too_large` | 超过配置大小 | 缩小任务或由部署者审查限额；模型不能自行放宽 |
| `rate_limited` | 429 且有限重试耗尽 | 尊重 `retryable` 和服务端 `Retry-After`，禁止无限循环 |
| `timeout` / `connection_failed` | 网络、TLS、服务健康、超时 | 先 `ping` 和检查网络；写入中断按未知结果处理 |
| `upload_outcome_unknown` | 上传期间连接中断或 5xx | 先 `stat` 同一路径，绝不直接重试 |
| `local_file_changed` | 上传前后文件快照变化 | 停止并重新生成稳定暂存文件；先检查远端是否已存在 |
| `approval_mismatch` | apply 时 staging 文件与 dry-run 批准的 bytes/SHA-256 不同 | 停止；不得上传替换内容，重新取得人工批准后才能开始新操作 |
| `verification_failed` | 上传后 HEAD/stat/checksum 不一致 | 停止并人工核对服务端，不宣称上传成功 |
| `atomic_publish_failed` | 本地文件系统不支持安全 no-replace 发布 | 改用支持该语义的本地文件系统，禁止退化为覆盖复制 |
| `capabilities_exact=false` | 旧版、minimal 或无法识别的 Token | 重新签发当前 full Token，写能力保持关闭 |

诊断时只使用 `error.code`、`http_status`、`retryable`、请求/操作 ID 和脱敏审计。不要打开会打印 Header、Token 或正文的 HTTP debug。

## 11. 与 permission/sharing 分支的集成

本工具要求所连接的 FileBrowser 基线具备当前权限契约：独立的 `Browse`、`Preview`、`Download`、`Create`、`Modify` 等权限，账号与 full Token 权限取交集，以及当前 versioned full Token 权限快照。`capabilities` 当前识别 `permissionsVersion=4` 的 full Token；版本不匹配时保守返回未知能力。

运行 Token 只需要 `browse,download,create`，不依赖 Share 权限、Public Share 上传或 sharing 分支的 Token 生命周期变化。Token enrollment 只使用服务账号自身登录和认证基线的 `/api/auth/token`。与 permission 分支集成时，应回归验证普通用户、账号/Token 交集、Create 与 Modify 分离、目标存在拒绝以及 Source/Scope；不得把 sharing 分支作为签发 Token 的前置条件，也不得复制或绕过服务端签发实现。

部署前最后检查：

1. `whoami/capabilities` 用户名为 `hermes-agent` 且有效权限精确匹配；
2. `sources` 只出现批准的 Sources/Scopes；
3. 本地 read/write roots 和远端 read/write roots 分离；
4. `mkdir`、`upload-new` 不带 `--apply` 时无写请求；
5. 已存在目标返回拒绝；
6. 审计和错误输出中没有 Token、Header 或文件正文；
7. Hermes Skill 适配器只暴露六个批准命令，没有 URL、Header、Shell 或额外 argv 入口。
