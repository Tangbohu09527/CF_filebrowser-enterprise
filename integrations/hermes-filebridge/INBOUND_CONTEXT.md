# 入站附件：官方 middleware 接线与外部认证契约

核验基线：[官方 Hermes `4d55ca91656ac5f83e1506679b7f81e0238e5e16`](https://github.com/NousResearch/hermes-agent/tree/4d55ca91656ac5f83e1506679b7f81e0238e5e16)；[Gateway `0ec54bf0f25f421e37e16e11bd098a814beca258`](https://github.com/Tangbohu09527/CF_agent-gateway/tree/0ec54bf0f25f421e37e16e11bd098a814beca258)。本页不读取或描述用户正在运行的安装。

**官方 middleware 在真实工具线程包住 `HostBridge.activate`，无需修改 Hermes 核心。**
`plugin/inbound_host.py` 消费 `inbound_control.py` 对已实现 Gateway 契约的严格验证结果。
配置与联合证据见 [JOINT_HOST_VALIDATION.md](JOINT_HOST_VALIDATION.md)；旧配套请求保留为历史文档。

`filebrowser_download_inbound` 仍默认关闭。开启只注册工具；没有经过认证的绑定仍返回 `trusted_context_unavailable`。模型仅能传入 `attachment_id`，不能签发任务、选择路径、origin 或凭据。

## 真实请求和工具执行的公开接线

```text
Gateway HTTP client (Bearer + X-Hermes-Session-Id)
  -> 官方 APIServerAdapter /v1/chat/completions
  -> 官方 AIAgent.run_conversation（框架 session/task/turn 关联）
  -> agent.tool_executor 的 tool_execution middleware
     或 model_tools.handle_function_call -> _execute_tool 的同名 middleware
  -> 插件 middleware 在当前工具执行线程内：
       固定后台客户端 resolve -> 字段/身份/profile/lease 验证
       events -> 首个有效 running 快照 -> start_dispatch（一次）
       with existing_bridge.activate(authoritative_dispatch_id):
           return next_call(args)
  -> 官方 registry -> 当前 filebrowser_download_inbound handler
  -> 现有 NDJSON worker -> HTTPS -> NTFS 文件 -> 验证后的 handle
  -> 同样授权范围内的下游工具 -> existing_bridge.open_workcopy(handle)
```

| 扩展点与固定源码 | 已确认的作用及限制 |
| --- | --- |
| [`PluginContext.register_middleware`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/plugins.py) | 插件公开注册 `tool_execution` 包装，无需私有成员或 monkey patch。`register(ctx)` 本身只负责注册，不激活全局任务。 |
| [`run_tool_execution_middleware` / `_run_execution_chain`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/middleware.py) | 同步调用 `next_call(args)`，可正确进入/恢复 ContextVar。**调用 next_call 前的 callback 异常会跳过该 middleware 并继续执行**，因此授权拒绝必须返回固定失败结果，不能依赖抛异常阻止执行；handler 的无绑定拒绝仍须保留。 |
| [`model_tools._execute_tool`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/model_tools.py) | 真实 registry 分派经过该 middleware；框架传入 session/task/turn/tool_call 关联。模型参数不是这些框架参数的授权来源。 |
| [`agent.tool_executor`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/agent/tool_executor.py) | agent 路径外层包住 middleware，内层跳过重复包装。应在实际工具执行线程激活，不应只在 HTTP 线程设置 ContextVar。 |
| [`tools.thread_context`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/tools/thread_context.py) | 官方工具并发通过 copy_context 传播上下文。每次执行仍需用自己的框架关联核验绑定，不使用进程全局“当前任务”。 |
| [`APIServerAdapter._run_agent`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/gateway/platforms/api_server.py) | executor 边界显式传播部分官方 ContextVar；HTTP 线程里设定的任意插件 ContextVar 不能假定自动传播。 |
| [`OpenAICompatRoutesMixin._handle_chat_completions`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/gateway/platforms/api_server_openai_routes.py) | 消费 `X-Hermes-Session-Id`，没有消费 Gateway 的 `session_metadata.inbound_attachments`；metadata 的真实性与字段是否到达插件是两个问题。 |

这些链接用于审查固定版本，不是运行时代码按源码行号打补丁，也不要求用户降级或永久锁定 Hermes。

## 关联与授权分开

- `session_id` / `task_id` / `turn_id` 可用于定位真实执行，但不能证明企业身份、附件权限或仍活动的 Gateway claim。工作目录只能取自操作者配置下分配的私有目录，不能从这些 ID、原文件名或模型输入直接拼接。
- Gateway 的 DB 身份检查、claim 预绑定和读授权是权威来源；固定 HTTPS 服务认证接口返回的 binding 经过完整字段验证后才使用。普通 metadata 或提示正文不提供授权。
- `descriptor.expires_at` 是读能力期限，不是 Dispatch 租约期限。收到有效 read token 也不能据此让下游文件句柄跨任务存活。
- 新 Gateway host-binding 模式只把无凭据投影送入模型；完整 grant 仅经控制接口交给宿主。旧基线的正文泄露探针保留在历史记录，不从该正文提取任何授权。
- `on_session_end` 只是辅助通知。固定 Hermes 的模型异常仍可能缺结束 hook；Gateway events 撤销及不可续期的 30 秒本地定时器覆盖该缺口。相同序号快照只保活，不续期；倒序、丢序、断线、终态均停止，禁止重连旧绑定。
- plugin `on_unload` / 正常退出负责 close；意外进程退出使管道 EOF 撤销原 worker。重启必须由 Gateway 拒绝旧 claim 重放，不能重建旧下载预算。

## 证据分层

1. `tests/test_inbound_plugin.py`：合成可信 binding、实际 HTTPS 和当前原生 worker，验证下载、预算、句柄消费及回收。它不证明请求认证。
2. `tests/test_hermes_loader.py`：隔离固定官方 loader、真实 PluginContext 和 registry；验证发现、默认关闭及无绑定拒绝。
3. 历史 middleware 组件和请求探针见 [HOST_BRIDGE_VALIDATION.md](HOST_BRIDGE_VALIDATION.md)。新的真实 Gateway / Hermes 组合 runner 与 Linux 结果单独记录于 [JOINT_HOST_VALIDATION.md](JOINT_HOST_VALIDATION.md)。
4. 实际 AI 主机与已部署 Gateway 的现场验收仍未执行，功能默认关闭；隔离 Linux 联合测试不等于 CFserver 到 Windows 现场验收。

## 独立 Windows 暂存与检查

[`windows/Manage-InboundClient.ps1`](windows/Manage-InboundClient.ps1) 提供 `Stage`、`Resume`、`Check`、`SelfTest`，默认 `Check`。使用原生 Windows PowerShell 5.1；暂存不执行 worker，不导入或启用 Hermes，不读取现有配置与凭据。工具没有用户运行目录的默认值。

除 `SelfTest` 外，必须显式提供本地绝对路径 `SourceDirectory`、独立的 `StageDirectory` 和从可信发布记录独立核验的 `ExpectedInventorySHA256`。不要仅对一个仍可变的下载目录现算摘要，就把该摘要当成发布者的独立校验值。

来源包必须恰好包含下面清单中的七个文件及 `inventory.json`。`source_commit` 是制品真实源码提交：

```json
{
  "schema": "cf-inbound-bundle/v1",
  "source_commit": "<40-hex-actual-source-commit>",
  "files": {
    "filebridge-inbound.exe": "<64-hex-sha256>",
    "plugin/__init__.py": "<64-hex-sha256>",
    "plugin/plugin.yaml": "<64-hex-sha256>",
    "plugin/inbound.py": "<64-hex-sha256>",
    "plugin/inbound_control.py": "<64-hex-sha256>",
    "plugin/inbound_directory.py": "<64-hex-sha256>",
    "plugin/inbound_host.py": "<64-hex-sha256>"
  }
}
```

`ExpectedInventorySHA256` 固定的是清单文件的实际字节。清单只允许上述字段和文件，拒绝重复键；固定 ASCII 字段不接受 JSON 字符串转义。单文件上限 64 MiB，清单上限 64 KiB。

目标父目录须预先存在于本地固定 NTFS 盘，DACL 受保护且只有当前 SID、SYSTEM 和可选 Administrators 的显式完整控制权限；脚本不修复 ACL 或接管所有权。新目录和文件在创建时即带当前 SID / SYSTEM 的私有受保护 DACL。路径链拒绝 reparse，文件拒绝 hardlink，源与目标不能相同或互相包含。

`Stage` 要求目标目录全新；`Resume` 只复用摘要与精确 ACL 均符合的文件，仅以 `CREATE_NEW` 补缺。脚本在写入前检查所有已有内容；未知文件、改变的文件、错误 ACL 和中断留下的不完整文件均保留并报告，绝不覆盖或自动清理。`Check` 验证完整来源和目标，目标缺失时也不会创建。读取、复制前后均验证摘要。

```powershell
# Replace all three values with independently verified staging inputs.
powershell.exe -NoProfile -NonInteractive -File .\integrations\hermes-filebridge\windows\Manage-InboundClient.ps1 `
  -Mode Stage -SourceDirectory C:\INDEPENDENT-BUNDLE `
  -StageDirectory C:\PRIVATE-STAGING\NEW-RELEASE `
  -ExpectedInventorySHA256 <verified-inventory-sha256>

# Entirely isolated temporary fixtures; no bundle, installed runtime or credentials.
powershell.exe -NoProfile -NonInteractive -File .\integrations\hermes-filebridge\windows\Manage-InboundClient.ps1 -Mode SelfTest
```

成功输出为 JSON，包含 `staged=true`、真实 `source_commit`、固定的清单摘要，以及 `live_enabled=false`、`host_bridge_connected=false`。这仅表示制品完整地暂存在新目录，不能作为宿主已接通或客户端已上线的证据。

2026-09-27 原生 Windows PowerShell 5.1 自测通过 18 个场景，覆盖 Stage / Resume / 默认 Check、部分补缺、外部 pin 缺失/不匹配、重复清单键、来源/目标篡改、未知文件保留、ACL 拒绝、源/目标 junction 拒绝、文件大小上限和真实祖先目录重命名锁。后者先证明相同身份在无句柄时可以重命名，再确认持有 `FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES` 且不共享删除的句柄时被拒绝，释放后恢复可重命名；旧的仅 `READ_ATTRIBUTES` 实现已由该用例复现失败。所有用例仅使用新建的临时虚构文件，不申请管理员特权。
