# Gateway / Hermes 入站附件联合适配（2026-09-28）

起点 `2b3894c1ae3146a5f6c29084068345f70e6892d9`，分支 `feat/filebridge-hermes-crud`，
PR #2 保持 Draft/Open。工作树 `C:\Users\Admin\.codex\worktrees\6330\CF_filebrowser-enterprise`。
先核对路径、branch/status/remote/HEAD/log/diff 再 fetch，起点本地/远端一致且干净。

固定依赖：

- [Gateway `0ec54bf0f25f421e37e16e11bd098a814beca258`](https://github.com/Tangbohu09527/CF_agent-gateway/tree/0ec54bf0f25f421e37e16e11bd098a814beca258)。读取了该提交的 host-binding 契约、JSON 夹具、session compatibility 文档及真实 routes；旧配套提案只作历史记录。
- [官方 Hermes `4d55ca91656ac5f83e1506679b7f81e0238e5e16`](https://github.com/NousResearch/hermes-agent/tree/4d55ca91656ac5f83e1506679b7f81e0238e5e16)。固定测试基线用于可复现，不要求用户降级或锁死运行版本。

两份上游源码只放独立临时测试目录/CI dependency 目录，不修改快照或访问活动工作树。
Gateway zip SHA-256 为 `c0ad44618fcd7c640c640f921e8910b8292dcadc24dd2c03cc03a34c2761c445`；
测试还核对实际执行边界的 Git blob。JSON 夹具不用于运行时授权或时间。

## 实际接线与认证来源

```text
Gateway DB 身份/线程 -> Dispatch claim -> 专用 Hermes child session 预绑定
  -> 真实 Hermes HTTP /v1/chat/completions -> AIAgent -> 官方 plugin loader
  -> 官方 tool_execution middleware（实际 session_id / task_id）
  -> inbound_host.HostAdapter -> 固定 HTTPS inbound_control.ControlClient
     resolve -> profile/身份/附件/claim/owner/lease/字段类型校验
     events -> 首个有效 running -> 原 HostBridge.start_dispatch（只一次）
  -> activate -> 原 download handler（只有 attachment_id）
  -> 原 NDJSON worker -> HTTPS 字节 -> 私有任务目录完整文件
  -> 原验证 handle -> 显式允许的下游工具 -> inbound_host.open_workcopy
  -> 撤销/结束/超时 -> 关闭流、确认 worker 退出、工具执行退出 -> owner-only closed
```

框架 session/task 只用于关联；企业身份、线程、附件、Dispatch/claim 与租约来自服务认证后的
Gateway 控制响应。v1 要求 task=session。专用 Hermes 入口/Profile 必须仅接受该 Gateway
授权调用；公开共享入口及仅知道 session ID 的请求不构成企业授权。

后台字段显式映射：`dispatch_id`、`message_id`、`profile_revision`、`event_sequence` 均为正整数；
binding/claim/thread/identity 是规范 UUID；只接收一份 v1 attachment，核对 message/thread/identity
和 `message:<id>:attachment:<id>` budget_scope。worker 的字符串 Dispatch ID 使用
`gateway:<binding_uuid>`，目录由本地随机分配，不接受后台或模型提供路径。
worker 的 `expires_at` 使用较早 host lease，不采用 read grant 的较长过期时间。

每个进程使用固定随机 instance，每个 session/task 首次调用固定 nonce、一个 worker 和原预算。
并发首次调用合并；终局留 tombstone，失败后不重新 resolve、不重连 events、不刷新凭据。
相同序号且内容完全相同的快照仅保活；首帧非 running、字段变化、倒序、丢序、断线或终态失败关闭。
ContextVar 在实际工具线程内设置并在 finally 恢复，未经过/失败的 middleware 仍由 handler 无绑定拒绝。

on_session_end、on_unload/atexit 辅助清理；Gateway events 与本地不可续期定时器覆盖异常缺 hook。
强杀宿主时 worker 通过父管道 EOF 及自身截止退出，Gateway 通过断线/固定 lease 有界收口。
closed 只有在本地 worker 已退出、已打开流已关闭且受控工具调用退出后发出一次有界请求。
ACK 失败不恢复任何本地权限；忽略取消、未退出的下游调用不 ACK，等待 Gateway 的有限租约屏障。
撤销句柄不会删除已发布完整副本或未知文件。

## 默认关闭与操作者输入

以下仅是独立验收 Profile 的配置模板，不操作当前安装。合并原 settings，不覆盖既有只读/创建配置。
运行身份事先拥有私有 work_root；Windows 要求当前 SID 所有、受保护 DACL，仅当前 SID/SYSTEM/
Administrators 的允许项。子目录创建时即带原生 NTFS DACL，锁住全部祖先，拒绝重解析点。
Linux 要求当前用户所有、0700，无符号链接路径。不会修复已有 ACL 或清理已有目录。

```yaml
plugins:
  enabled: [cf-filebridge]
  entries:
    cf-filebridge:
      settings:
        inbound_enabled: false
        inbound_host_enabled: false
        inbound_host:
          gateway_origin: https://gateway.acceptance.invalid
          service_token_env: CF_FILEBRIDGE_HOST_SERVICE_TOKEN
          profile_reference: dedicated-acceptance-profile
          profile_revision: 1
          work_root: 'C:\PRIVATE-ACCEPTANCE\work'
          client_path: 'C:\PRIVATE-ACCEPTANCE\bundle\filebridge-inbound.exe'
          client_sha256: <independently-verified-worker-sha256>
          ca_file: 'C:\PRIVATE-ACCEPTANCE\trust\ca.pem'
          ca_sha256: <independently-verified-ca-sha256>
          max_bytes: 67108864
          consumer_tools: [approved_workcopy_consumer]
```

服务凭据是专用至少 32 字符的 secret，变量名限定 `CF_FILEBRIDGE_HOST_*`；不是附件短期 Bearer、
Hermes API key、WeChat key 或 FileBrowser runtime-token。插件不会读取 FileBrowser token 来请求 Gateway。
所有 `CF_FILEBRIDGE_HOST_*` 变量从 worker 与既有 CLI 子进程环境移除。秘密不进入 URL、命令行、
工具输出、普通异常或日志；resolve 的完整响应仅存于宿主内存/worker 私有管道。
CA 文件及 worker 都使用操作者固定 SHA-256；TLS 校验链和名称、拒绝重定向、忽略代理环境。

**30 秒限制**：host lease 从 Gateway 首次认领开始，keepalive 与重复工具都不能续期。
本地 deadline 进一步从首次 resolve 请求起计，下载仍最多 4 次/30 秒且服从更早 lease。
模型决定、下载、后续加工及 handle 使用共享这段有效授权时间；慢速 PDF/OCR 或长时间加工可能
在读取中被撤销。本轮未扩大租约，也不支持跨 lease 保留可用 handle 或所有长时间加工。

## 可重复验证入口

沿用 `.github/workflows/filebridge-client.yaml`；Linux 新增真实组合步骤，Windows 保留原生回归。

```text
go test -count=1 ./...                 # tools/filebrowser-agentctl
go vet ./...                         # 同独立 module
python -B -m unittest discover -s integrations/hermes-filebridge/tests -v
<isolated-python> -I -B integrations/hermes-filebridge/tests/test_gateway_hermes_joint.py \
  --gateway-source <fixed-0ec54-snapshot> --hermes-source <fixed-4d55-snapshot> \
  --worker <current-native-linux-worker>
powershell.exe -NoProfile -NonInteractive -File integrations/hermes-filebridge/windows/Manage-InboundClient.ps1 -Mode SelfTest
```

Gateway 的安全暂存依赖 Linux openat/dir_fd。Windows 不使用内存暂存替身冒充整条联合通过；
联合 venv 使用 Python 3.12（固定 Gateway 的类型别名语法要求）；原客户端/官方 Hermes 探针仍用原矩阵 Python 3.11。
Linux 组合使用真实数据库、admission/claim/预绑定、认证 HTTP/events 和真实 Hermes 执行链。
只允许模型服务与微信上游取件使用明确的测试替身。合成控制端点的 Windows 测试另标组件测试。
旧 `test_hermes_loader.py`、`test_hermes_middleware.py`、`test_hermes_request_probe.py --lifecycle`
继续运行，其历史断言不删减。

本轮执行结果和对应提交/CI 在交付时补录。现场 Windows AI 主机、CFserver、实际微信入口没有测试。
不修改 backend Lint 规则；历史红项独立保留。PDF 上游长期 pending 也独立未解决。

## 一次性联合实机验收（需另行授权，本轮不执行）

输入必须齐全：两端候选源码/成功 CI SHA、对应平台 bundle 与独立 inventory SHA、隔离 Gateway
HTTPS origin/CA、专用 host_id/profile reference/revision、合成服务 secret、独占 Hermes
入口/Profile/API认证、正确私有 NTFS 根、独立测试身份/线程、PDF/JPEG 样本及预期摘要、
已登记且只通过 `inbound_host.open_workcopy` 读取的下游工具。不得复用生产凭据。

1. 用现有 `Manage-InboundClient.ps1 -Mode Stage/Resume/Check` 在独立父目录核对完整 bundle；
   不覆盖配置或已安装版本。检查只暂存，不连接任何服务、不启用插件。
2. 在专用验收 Profile 按上述模板提供独立输入，另行批准启用两个开关；Gateway 使用固定契约的
   host binding 模式与专用 session 入口，按兼容文档显式固定 profile runtime。
3. 由真实 Gateway admission 发起“文本 → PDF/JPEG 附件 → 文本”；观察 resolve/events
   首帧门槛、实际任务文件、大小/摘要和 handle 完整读取；保留原质量字段及 `formal_archive=false`。
4. 两身份并发、重复调用、503 成功/耗尽、早期 lease、下载中取消、模型 failed、异常缺 hook、
   宿主退出、旧 nonce/instance/claim 重放、丢 closed；逐项记录本地退出与 Gateway 有界收口。
5. 检查历史顺序与无秘密投影、日志/结果无授权，原只读/受控创建回归；失败保留现场且门禁关闭。
   不自动刷新旧权限，不删除完整副本或未知文件。该流程完成前不声称 CFserver 到 Windows AI 主机已验收。
