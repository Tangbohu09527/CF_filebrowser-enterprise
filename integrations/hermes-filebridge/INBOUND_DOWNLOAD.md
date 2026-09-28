# Hermes 入站附件工作副本下载

状态：本项目包含专用下载引擎、原生安全落盘、插件宿主 API、隔离测试和独立暂存检查入口。
**功能默认关闭。** 真实宿主适配已消费 Gateway `0ec54bf0` 的固定后台契约；
联合测试及现场验收边界见 [JOINT_HOST_VALIDATION.md](JOINT_HOST_VALIDATION.md)。
官方 middleware 可承载工具执行范围；外部认证交接缺口及固定源码证据见 [INBOUND_CONTEXT.md](INBOUND_CONTEXT.md)。本轮未修改 Hermes
核心、Gateway、运行中的 Profile、客户端或凭据，未连接 CFserver、发送微信或正式归档。

## 固定契约与调用入口

只消费 [Gateway `a26f234fbe60f9a3212bf6bd3471bba3f5802997` 下载契约](https://github.com/Tangbohu09527/CF_agent-gateway/blob/a26f234fbe60f9a3212bf6bd3471bba3f5802997/docs/development/inbound-media-download-contract.md)。
服务端队列、取件、claim 和授权实现仍属于 Gateway，本项目没有复制它们。

```text
实际 Hermes loader -> plugin.register(ctx)
  -> 操作者 inbound_enabled=true 才注册 filebrowser_download_inbound
  -> handler({attachment_id})
  -> 当前执行范围的 HostBridge Dispatch（缺失即拒绝）
  -> 私有 stdin/stdout 管道 -> filebridge-inbound 原生进程
  -> 固定 Gateway HTTPS origin /inbound-media/{positive-job-id}/content
  -> 任务目录中唯一临时对象 -> 大小/SHA-256 -> 原子不覆盖发布
  -> 不含路径的 inbound:... 工作副本句柄
  -> HostBridge.open_workcopy(handle) / Go Engine.Resolve(handle)
  -> 同一有效 Dispatch 内的下游工具读取实际文件
```

真实宿主必须在认证后的任务创建位置调用 `HostBridge.start_dispatch(binding)`，在实际工具
调用线程内进入 `bridge.activate(dispatch_id)`，并将结束、取消和租约撤销连接到
`end_dispatch` / `close`。这些方法复用本项目现有 HostBridge；官方 `register_middleware("tool_execution", ...)`
能够在真实工具分派范围调用 activate，不需要 Hermes 新增 current_dispatch。
`inbound_host.py` 负责官方 middleware/lifecycle 接线，`inbound_control.py` 验证
固定 HTTPS resolve / events / closed；收到首个有效 running 快照才启动现有 worker。
插件不从正文、一般 kwargs 或未经认证的 `session_metadata` 推导授权。
服务凭据来自操作者指定的专用环境变量，只用于控制接口，不传给 worker。

`Binding` 仅经过私有管道传入 worker：`dispatch_id`、`task_id`、`thread_id`、
`enterprise_identity_id`、`work_dir`、`gateway_origin`、`expires_at`、`max_bytes`、
可选 `ca_file` / `ca_sha256` 和可信 `attachments`。其中 `expires_at` 必须是实际
Dispatch/租约截止时间，不能用附件凭据的较长期限替代。可信宿主须为每个任务分配私有目录。
模型工具接口只有 `attachment_id`，额外的 `task_context`、URL、路径、凭据或命令一律拒绝。

worker 是 `tools/filebrowser-agentctl/cmd/filebridge-inbound`，只依赖独立 `internal/inbound`
包和 Go 标准库。它不读取 FileBrowser 配置、runtime-token 或继承 Token 环境变量，
不改变原有 `filebrowser_files` / `filebrowser_create_text` 的命令或授权行为。

## 下载、期限与文件边界

- origin 必须由宿主预配置为规范 HTTPS origin；只接受规定的内容读取路径，拒绝 userinfo、
  查询参数、fragment、编码绕路和任意其他路径。禁用代理及自动重定向；验证 CA 链和主机名。
  可选独立 CA 文件须核对 SHA-256，不写全局信任库，没有忽略证书错误的开关。
- 附件短期 Authorization 仅放请求 header。worker 不接受命令行参数中的凭据；不输出请求、
  原始异常或 stderr。公开结果使用固定分类，不带内部路径或授权值。
- 每个任务/附件终局状态及首次调用的单调时钟截止点保存在同一个 worker 中。总共最多
  4 次 HTTP 尝试、30 秒，且受附件过期及 Dispatch 期限进一步限制。仅 503 可退避重试。
  新连接、TLS、body、写盘、Sync、SHA-256 和发布均检查同一预算。其他响应、TLS 失败、
  完整性失败和取消终止；不刷新凭据，不改 claim。禁用连接复用以避免 Transport 隐式重放。
- 重复和并发调用复用同一状态，成功复用前重新验证本地文件。HostBridge 保留失败/结束
  tombstone，不重启 worker，不允许换 Dispatch ID 续用同一任务/附件预算。宿主重启必须
  撤销旧 Dispatch；不能从提示词或旧元数据重建它们。
- 最大下载 64 MiB，宿主可进一步缩小上限。原文件名仅是元数据，绝不拼接到本地路径。
  临时内容完整且大小/SHA-256 一致后才发布；不覆盖现有文件，不清理未知文件。
- Windows 只接受本地 NTFS 私有任务目录。使用实际 SID / protected DACL 和 Win32
  `CREATE_NEW`、对象 ID、无共享删除的祖先/文件句柄、按句柄原子重命名，拒绝 junction、
  reparse point、UNC、ADS 及目录替换。不会用 chmod 模拟 NTFS 权限或修改宿主已有 ACL。
- Linux 使用私有目录及匿名 `O_TMPFILE`，通过持有的 inode 发布；缺少所需文件系统支持或
  `/proc/self/fd` 时拒绝。Abort 只关闭匿名对象，不按可能被替换的路径删除文件。
  取消若恰好发生在原子发布之后，可留下一份完整但未交付句柄的工作副本；它不会被当作成功。
  进程被强杀或系统崩溃也不触发猜测性的目录清理，应由宿主按自己的任务生命周期处理。
- `open_workcopy` 向受信任的下游工具提供经过再次校验的只读流，结束/取消时关闭；Go
  `Engine.Resolve` 提供实际打开的文件。内部 `resolve_workcopy` 路径结果仅供宿主使用，
  不得作为聊天返回。工具必须在活动 Dispatch 内消费，不能缓存路径跨任务复用。

成功包含 `handle`、`bytes_written`、`sha256`、任务绑定、`verified=true`、
`formal_archive=false`。`declared_quality`（包括 `null`）和 `original_comparison`
原样保留；摘要一致只证明与 Gateway 字节一致，不升级为“原图”。该目录不是正式文件库。

同一 OS 身份运行的任意恶意代码可攻击宿主进程和凭据；本插件不构成这个身份之外的 OS
沙箱。可信宿主和插件文件必须由操作者管理，不能让模型通过其他 shell/code 工具修改桥接代码。

## 可重复暂存与检查

现有 `FileBridge client` CI 生成固定源码产物 `inbound-bundle/`：原生 worker、六个插件文件
和 `inventory.json`。外部 `SHA256SUMS` 包含 inventory 的 SHA-256，inventory 中绑定
完整源码提交与每个文件 SHA-256。Windows 使用 `.exe` bundle。

`windows/Manage-InboundClient.ps1` 提供 `Stage`、`Resume`、`Check`、`SelfTest`；默认
`Check`，必须显式指定源目录、独立暂存目录和已独立核验的 inventory 摘要。父目录应已由
操作者建立正确私有 NTFS ACL。工具不默认指向当前 Hermes 安装，不读取、迁移或覆盖配置
及凭据，不启用插件。内容或 ACL 冲突会保留现场并失败；Resume 只补缺失的已登记文件。

```powershell
# 仅在独立验收/暂存目录另行执行。占位符不是当前运行环境的安装指令。
./integrations/hermes-filebridge/windows/Manage-InboundClient.ps1 -Mode Stage `
  -SourceDirectory '<verified-artifact>/inbound-bundle' `
  -StageDirectory '<private-test-parent>/inbound-<source-sha>' `
  -ExpectedInventorySHA256 '<independently-verified-inventory-sha256>'
# 同一参数用 -Mode Resume 续接；-Mode Check 只核对，不覆盖或修正权限。
```

暂存成功输出仍为 `live_enabled=false`、`host_bridge_connected=false`。
暂存检查不会发起请求，不能把检查通过当作安装启用或现场验收。

## 验证的三个层次

1. **隔离替身/原生实现**：`go test -count=1 ./...`、`go vet ./...`（独立 module），
   实际回环 HTTPS 和本机文件系统；Python 使用编译后的原生 worker，模拟的是可信宿主
   binding，不是 HTTP 请求或文件字节。测试使用公开非秘密证书和临时目录。
2. **真实插件加载**：固定公开 Hermes 源码、独立 venv 和真实 manager/context/registry。
   验证发现、注册、默认关闭与缺桥接拒绝；测试不运行真实 Dispatch。命令见上下文文档。
3. **隔离组合链路**：真实 Gateway 数据库/claim/HTTP 与固定官方 Hermes 请求/Agent/loader/
   middleware 共同驱动本项目适配和 worker，见联合 runner；仅模型及微信取件使用测试替身。
4. **实际 AI 主机**：本轮未安装、启用或连接服务，尚未验收。两端均未在本轮部署。
   PDF 上游长期 pending 问题不由合成 PDF 通过而消失。

仓库已有 CI 的原有只读/受控新建断言保留。新增测试覆盖 PDF/JPEG、503 成功/耗尽、
重复并发预算、到期/取消、错误身份线程、CA/主机名/重定向、截断/超限/错误摘要、
路径及 NTFS 边界、失败不交付半文件、工作句柄实际消费和授权值不外泄。

## 后续一次性实际验收（本轮不执行）

1. 采用 [JOINT_HOST_VALIDATION.md](JOINT_HOST_VALIDATION.md) 的固定两端版本、候选产物
   与独立验收输入，确认 Dispatch、lease、thread、identity、工作目录和允许 origin。
   保留默认关闭，不从正文提取授权；现场启用必须另行授权。
2. 另行批准的隔离 AI 主机使用固定提交成功 CI 产物；核对 source SHA、inventory、
   Windows ACL、CA 链/主机名及 binary SHA，再按 Stage/Check 暂存。不覆盖旧版和凭据。
3. 用专门验收 Profile 接上桥接，取得真实有效 Dispatch 的 PDF/JPEG；由专用工具下载，
   下游工具通过 handle 打开实际文件，记录大小、摘要、非正式归档和原始质量结论。
4. 在验收 Gateway 注入 503 / 403 / 404 / 超时，测试四次与期限、重复/并发、过期、
   claim 更换、任务取消和线程/身份不匹配；确认旧 worker/handle 失效，不能刷新预算。
5. 核对输出/日志无凭据或内部路径，未知文件未改变，原有只读及受控新建行为仍符合既有
   约束。逐项记录实际宿主与 Gateway 版本；未取得这些证据时保持启用门禁关闭。
