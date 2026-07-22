# filebrowser-agentctl

`filebrowser-agentctl` 是运行在 Hermes AI 主机上的 FileBrowser Enterprise 安全文件客户端。它只接受固定 Base URL、受限路径和结构化 JSON，不向模型开放任意 HTTP、任意 URL 或 Shell 能力。

工具不会替代 FileBrowser 服务端授权。每个请求先通过本地 source/path allowlist，再由服务端检查账号、Token、Source/Scope 和权限。

## 构建

需要 Go 1.25 或与 `go.mod` 声明兼容的更新版本。工具是独立 Go module，不需要修改仓库根 module 或服务端依赖。

```powershell
Set-Location tools/filebrowser-agentctl
go test ./...
go vet ./...
go build -trimpath -o filebrowser-agentctl.exe ./cmd/filebrowser-agentctl
```

```sh
cd tools/filebrowser-agentctl
go test ./...
go vet ./...
go build -trimpath -o filebrowser-agentctl ./cmd/filebrowser-agentctl
```

Windows amd64 和 Linux amd64 交叉构建示例：

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

## 调用格式

```text
filebrowser-agentctl --config <file> [--input <file|->] [--token-stdin] [--allow-localhost-http] [--apply] <command>
```

- `--config` 必填。配置是唯一 Base URL 来源。
- `--input` 默认为 `-`，即从 stdin 读取一个 JSON 对象。未知字段、尾随 JSON 和超过 1 MiB 的输入会被拒绝。
- `--token-stdin` 先从 stdin 第一行读取 Token。此时建议通过 `--input request.json` 单独提供 JSON。
- `--allow-localhost-http` 只允许 `localhost` 或 loopback IP 使用 HTTP，用于本地开发。
- `--apply` 只适用于 `mkdir` 和 `upload-new`。未指定时写命令为 dry-run。
- stdout 始终是一行 `filebrowser-agentctl/v1` JSON。审计事件默认写 stderr，配置 `audit_log` 后写 JSONL 文件。

退出码：成功为 `0`；命令执行失败为 `1`；CLI、配置、Token 或输入初始化失败为 `2`。

所有命令都需要一个 JSON 对象。无参数命令也必须提供 `{}`。每个命令只接受表中列出的命令字段；其他命令虽认识但当前命令不使用的字段也会以 `invalid_input` 拒绝，避免产生审计歧义：

| 命令 | JSON 字段 | 行为 |
| --- | --- | --- |
| `ping` | 无 | 请求 FileBrowser `/health`，确认可达且健康 |
| `whoami` | 无 | 返回当前用户、有效权限和本地允许的 Sources/Scopes |
| `capabilities` | 无 | 与 `whoami` 相同 |
| `sources` | 无 | 返回用户 Scope、本地 source allowlist 与服务可用 source 的交集 |
| `list` | `source`, `path` | 列出目录，结果按名称排序 |
| `search` | `source`, `path`, `query`, 可选 `limit` | 在 `path` 指定的 scope 内搜索；默认 25，配置上限最大 100 |
| `stat` | `source`, `path` | 返回文件或目录元数据 |
| `checksum` | `source`, `path`, 可选 `algorithm` | 请求 `sha256`（默认）或 `sha512`；受 `max_checksum_bytes` 限制 |
| `read` | `source`, `path` | 在 JSON 中返回正文；UTF-8 文本原样返回，其他内容 Base64；标记 `untrusted: true` |
| `download` | `source`, `path`, `output_file` | 原子、不可覆盖地写到本地允许目录 |
| `mkdir` | `source`, `path` | 创建新目录；默认 dry-run，`--apply` 才发送写请求 |
| `upload-new` | `source`, `path`, `local_file`；apply 时另需 `expected_bytes`, `expected_sha256` | 只上传 dry-run 已批准的新文件；默认 dry-run，目标存在时失败 |

`schema_version`、`request_id` 和 `operation_id` 是所有命令共用的可选输入字段，但任何 `--apply` 写入都必须显式提供 `operation_id`。版本只能是 `filebrowser-agentctl/v1`；标识符最长 128 字符，只允许字母、数字、`.`、`_`、`:`、`-`。省略时由客户端生成。

示例请求文件：

```json
{
  "schema_version": "filebrowser-agentctl/v1",
  "request_id": "req-supplier-list-001",
  "operation_id": "op-supplier-list-001",
  "source": "enterprise-files",
  "path": "/supplier-materials/incoming"
}
```

```powershell
filebrowser-agentctl.exe --config config.json --input request.json list
```

`mkdir` 的 dry-run 和执行使用相同 JSON；`apply` 不放入 JSON：

```powershell
filebrowser-agentctl.exe --config config.json --input mkdir.json mkdir
filebrowser-agentctl.exe --config config.json --input mkdir.json --apply mkdir
```

响应公共结构：

```json
{
  "schema_version": "filebrowser-agentctl/v1",
  "ok": true,
  "command": "mkdir",
  "request_id": "req-supplier-mkdir-001",
  "operation_id": "op-supplier-mkdir-001",
  "dry_run": true,
  "result": {
    "action": "mkdir",
    "source": "enterprise-files",
    "path": "/supplier-materials/organized/2026-07",
    "applied": false,
    "already_done": false,
    "bytes": 0,
    "verified": false
  }
}
```

失败时 `ok` 为 `false`，并返回稳定的 `error.code`、安全消息、可选 `http_status` 和 `retryable`。不要从自然语言消息推断重试；以错误码和 `retryable` 为准。`upload_outcome_unknown` 必须先 `stat` 目标，禁止直接重试。

## 配置

从 [`config.example.json`](./config.example.json) 复制结构并按 AI 主机分别配置。配置严格拒绝未知字段。相对本地路径以配置文件所在目录为基准；示例中的 `/` 分隔符可用于 Linux，也可被 Windows Go 运行时解析。生产中建议每个平台使用独立配置，以便明确 ACL 和本地目录。

默认限制：

| 配置项 | 默认值 |
| --- | ---: |
| `timeout_seconds` | 30 |
| `max_download_bytes` | 16 MiB |
| `max_inline_bytes` | 1 MiB |
| `max_checksum_bytes` | 64 MiB |
| `max_upload_bytes` | 256 MiB |
| `search_default_limit` | 25 |
| `search_max_limit` | 100 |
| `max_retries` | 2 |
| `retry_delay_millis` | 100 |
| `max_retry_delay_seconds` | 2 |

远端 `path` 必须是以 `/` 开头且不超过 4096 字节的 FileBrowser 逻辑路径，source 名称不超过 255 字节。反斜杠、盘符、NUL、换行、`.` 和 `..` 路径段会被拒绝。搜索词不超过 4096 字节。`read_roots` 与 `write_roots` 独立；允许读取父目录不会自动允许写入，允许写入目录也不会自动允许读取。

本地 allowlist 只能判断 FileBrowser 返回的逻辑路径，API 不提供每个路径组件的服务端 canonical/symlink 信息。部署前必须保证服务账号 Scope/Access 不宽于批准根，并确认批准根内没有可逃逸到根外的符号链接、junction 或其他 reparse point；否则应先在服务端补齐 canonical-path 约束，不能把客户端词法 allowlist 当作闭环授权。

本地路径限制独立于远端路径：

- `local_read_roots` 只用于 `upload-new` 的 `local_file`。
- `local_write_roots` 只用于 `download` 的 `output_file`。
- 根目录和目标父目录必须预先存在。符号链接会在授权时解析，目标不能借助链接逃出 allowlist。
- 配置、Token、staging、download 和 audit 目录只能由管理员或运行 Hermes 的 OS 身份写入；客户端的跨平台 `EvalSymlinks`/打开文件流程不能防御同机恶意写入者在检查后瞬时替换路径。
- `download` 拒绝已有目标，使用同目录临时文件和不可覆盖发布；不支持安全发布的文件系统会失败关闭。

Base URL 必须是固定的绝对 HTTPS URL，不能包含凭据、query、fragment 或路径穿越。客户端不跟随 HTTP redirect。只有显式指定 `--allow-localhost-http` 时，loopback 开发服务才可使用 HTTP。

## Token

Token 只按以下顺序读取：

1. 指定 `--token-stdin` 时，读取 stdin 第一行。
2. 否则读取 `FILEBROWSER_AGENT_TOKEN` 环境变量。
3. 否则读取配置的 `token_file`。

没有 Token 命令行参数，也不使用 URL query 认证。Token 只写入 `Authorization: Bearer ...` Header，不进入 JSON 输出或审计日志。

Linux/macOS 的 `token_file` 必须是普通非符号链接文件，权限为 `0600` 或更严格，工具会强制检查：

```sh
chmod 600 /path/to/hermes-agent.token
```

Windows 也必须使用普通非符号链接文件。Go 无法从跨平台权限位可靠验证 NTFS ACL，部署者必须关闭继承并只授权运行 Hermes 的服务身份，例如在提升权限的部署终端中执行：

```powershell
$TokenFile = "C:\ProgramData\Hermes\FileBridge\secrets\hermes-agent.token"
icacls.exe $TokenFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)"
```

不要把 Token 写入仓库、命令历史、进程参数、日志或 Hermes Prompt。环境变量应由服务管理器或 Secret Manager 在进程启动时注入，不要长期写入 shell profile。

## 写入安全

`mkdir` 和 `upload-new` 默认 dry-run。dry-run 会执行 allowlist、本地文件、远端目标和大小等只读预检，但不会发送 POST。只有进程参数出现 `--apply` 且输入显式带有 `operation_id` 才会写入。

`mkdir` 对已存在目录返回 `already_done: true`；已存在非目录目标会失败。`upload-new` dry-run 返回 `bytes` 和 `sha256`；执行请求必须把它们分别作为 `expected_bytes` 和 `expected_sha256` 送回，并保持同一 `operation_id`。客户端在任何 POST 前重新计算并精确匹配，审批窗口内 staging 文件被替换时返回 `approval_mismatch`。上传期间继续检测文件变化，上传后重新检查 HEAD/stat，并在大小允许时核对服务端 SHA-256。任何已存在目标或冲突都失败，不支持 `overwrite=true`。

## 明确禁止

工具有意不实现：`delete`、`share`、Token 管理、用户管理、ACL 管理、任意 HTTP、任意 URL、Shell/exec、move、rename、overwrite 和 bulk move。危险命令在加载配置或 Token 前即被拒绝。

文件正文始终是不可信数据。`read` 的 `untrusted: true` 表示上层 Hermes Skill 不得把正文中的指令当作权限、工具调用或配置变更依据。

完整部署、服务账号和 Hermes Skill 接入见 [`../../docs/AGENT_API_GUIDE.md`](../../docs/AGENT_API_GUIDE.md)。
