# 入站附件：真实 Hermes 接口与尚未接通的宿主上下文

本页核验的是公开 Hermes 源码，不是运行中的 Hermes、微信 Gateway 或已安装客户端。固定接口基线为 [`NousResearch/hermes-agent@4d55ca91656ac5f83e1506679b7f81e0238e5e16`](https://github.com/NousResearch/hermes-agent/tree/4d55ca91656ac5f83e1506679b7f81e0238e5e16)，与本目录 README 一致。

`filebrowser_download_inbound` 默认关闭。开启 `inbound_enabled` 只注册工具；没有可信宿主绑定时返回 `trusted_context_unavailable`。模型只能传入正整数 `attachment_id`。文本中的附件描述、`session_metadata`、工具参数和 handler 的 `task_id` / `session_id` / `user_task` kwargs 都不能自行生成授权。

## 已核验的官方调用链

| 能力 | 固定源码证据 | 适用边界 |
| --- | --- | --- |
| 真实插件发现与加载 | [`PluginManager.discover_and_load`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/plugins.py#L1218-L1254)；[`_discover_and_load_inner`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/plugins.py#L1324-L1351)；[`register_fn(PluginContext(manifest, self))`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/plugins_loader.py#L264-L337) | loader 确实构造真实 `PluginContext`，然后调用插件 `register(ctx)`。仅此不能证明当前请求来自可信 Gateway。 |
| 插件配置 | [`PluginContext.get_config`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/plugins.py#L225-L267) | 读取当前 Profile 下的插件配置，不是当前任务授权或附件清单。 |
| 工具分派关联信息 | [`_CallIds`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/model_tools.py#L632-L643)；[`_execute_tool`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/model_tools.py#L807-L830) | 一般 handler 收到 `task_id`、`session_id` 和 `user_task`；hooks / middleware 还可收到 `turn_id` / `tool_call_id`。这些关联字段没有附件授权、Gateway origin allowlist、租约或下载预算。 |
| `ctx.dispatch_tool` | [`dispatch_tool`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/plugins.py#L690-L699) | 只在可用时从 CLI 引用取得 `parent_agent`；源码明确 Gateway 中 `_cli_ref` 为 `None`。不能把该接口当作所有运行入口的当前可信 Dispatch。 |
| 用户、线程、路由信息 | [`set_session_vars`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/gateway/session_context.py#L115-L144)；[`get_session_env`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/gateway/session_context.py#L173-L179) | 核心有任务局部 ContextVar；通用 getter 在未绑定时回退进程环境变量。它不携带身份认证证明，也不提供附件能力授权，插件不能据此接受伪造或陈旧环境值。 |
| 工作目录 | [`runtime_cwd`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/agent/runtime_cwd.py#L38-L94) | 有 session cwd、`TERMINAL_CWD` 和启动目录回退。它是运行目录解析，不是“此附件可以写入这里”的授权；缺失绑定时不得回退使用这些目录。 |
| Gateway 入站 hook | [`pre_gateway_dispatch` 定义](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/plugins.py#L130-L137) | 在 auth / pairing 之前触发。收到 `event` / `gateway` 对象不等于认证已经通过，不能直接签发下载权限。 |
| 停止通知 | [`_interrupt_and_clear_session`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/gateway/run_agent_cache.py#L460-L489) | `agent_loop_stopped` 有 session key 和原因，返回值被忽略；没有本插件的 Dispatch ID、可撤销句柄或自动关闭本插件 worker 的实现。 |
| 结束与卸载 | [`on_session_end` 发出位置](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/agent/turn_finalizer.py#L626-L640)；[`on_unload` / `spawn_task`](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/plugins.py#L413-L431) | 结束 hook 是观察通知，且 `_persist_disabled` 路径不发出该通知；`spawn_task` 管理的是插件卸载时的任务。它们不构成覆盖所有结束/取消入口的租约契约。 |

因此，核验的公开 `PluginContext` 没有本插件需要的完整 current-Dispatch API。不能编造 `ctx.current_task`、`ctx.allowed_origin` 或 `ctx.authorized_workdir`，也不能仅用模拟 Context 的单元测试宣称这些能力存在。

## 待配套宿主接线的最小要求

本项目 `plugin/inbound.py` 的 `HostBridge` 是本项目新增的进程内宿主 API，**不是上述 Hermes 公共接口**。真实接入仍需认证边界的宿主适配器，完成以下工作：

1. 在入站认证、权限检查与实际任务创建完成后，取得不可由模型覆盖的任务 / 用户 / 线程关联、附件清单、允许的 Gateway origin、任务工作目录、有效期限与预算。一个普通的 `session_metadata.inbound_attachments` 字段不自动满足这些条件。
2. 使用操作者固定的独立下载 worker 路径和 SHA-256 创建 `HostBridge`，调用 `start_dispatch(binding)`。该 worker 与已有 FileBrowser Token 客户端的配置、凭据和命令分离。不能从聊天正文、模型工具参数、一般 kwargs 或继承环境拼装 binding。
3. 在实际工具执行范围内使用 `bridge.activate(dispatch_id)`，并确保 ContextVar 正确传到执行线程 / 异步任务。`register(ctx)` 发生在插件加载阶段，不能在此为后续所有请求绑定一个全局任务。
4. 将真实任务结束、取消、超时、租约撤销和宿主退出连接到 `end_dispatch` / `close`。结束后拒绝后续下载和 handle 解析；不得通过重新创建 worker、替换 Dispatch ID 或自动重试刷新同一任务的预算。仅订阅一个结束 hook 不足以覆盖全部路径。
5. 后续处理通过宿主的工作副本 handle 解析接口完成，并复核活动 Dispatch 与文件完整性。内部绝对路径、bearer URL 和凭据不能回传聊天。该 host-only API 与同 OS 身份的其他工具之间没有额外的操作系统安全边界。

目前没有修改或部署外部 Hermes / Gateway 来实现这套适配器。启用插件不会补上这些缺口；无绑定拒绝是预期行为。

## 真实 loader 验证

[`tests/test_hermes_loader.py`](tests/test_hermes_loader.py) 是显式执行的集成检查，不会在普通 `unittest discover` 中自动下载或跳过上游验证。它要求调用者提供上述固定提交的官方源代码副本，并校验关键 loader / registry 文件的 Git blob ID。

准备方式：从[固定提交源码包](https://codeload.github.com/NousResearch/hermes-agent/zip/4d55ca91656ac5f83e1506679b7f81e0238e5e16)提取到独立测试临时目录，使用 Python 3.11–3.13 的独立虚拟环境。此次在 Windows / Python 3.12 上仅需安装 `PyYAML==6.0.3`，版本来自该提交的 `pyproject.toml`。这不是完整 Hermes 运行环境的依赖清单，不安装、升级或替换实际 Hermes。

```text
<test-venv-python> -I -B integrations/hermes-filebridge/tests/test_hermes_loader.py --hermes-source <fixed-commit-source-directory>
```

检查使用临时 Profile、空 bundled 插件目录和复制的本项目插件；不读取真实 Profile、Token 或已安装客户端。实际 `PluginManager` 完成发现和加载，实际 `PluginContext` 注册处理器，实际工具 registry 接受分派。测试不替换这些核心对象，并通过 Python audit hook 拒绝发现/调用阶段的网络和子进程启动。

2026-09-27 本地结果：默认配置不注册下载工具；显式 `inbound_enabled=true` 后注册；传入一般 handler 关联 kwargs 而不绑定宿主时，真实 registry 调用返回 `trusted_context_unavailable`。两个配置场景均通过，`host_bridge_connected=false`。

该结果只证明固定上游 loader 的兼容性和无绑定拒绝。它没有运行 Hermes 会话、Gateway 认证、微信传输或真实任务取消，也没有验证实际 worker 下载。那些行为必须分别由下载引擎/桥接测试和后续真实宿主联调证明；模拟 binding 或模拟 PluginContext 的成功用例不能替代宿主联调。

## 独立 Windows 暂存与检查

[`windows/Manage-InboundClient.ps1`](windows/Manage-InboundClient.ps1) 提供 `Stage`、`Resume`、`Check`、`SelfTest`，默认 `Check`。使用原生 Windows PowerShell 5.1；暂存不执行 worker，不导入或启用 Hermes，不读取现有配置与凭据。工具没有用户运行目录的默认值。

除 `SelfTest` 外，必须显式提供本地绝对路径 `SourceDirectory`、独立的 `StageDirectory` 和从可信发布记录独立核验的 `ExpectedInventorySHA256`。不要仅对一个仍可变的下载目录现算摘要，就把该摘要当成发布者的独立校验值。

来源包必须恰好包含 `filebridge-inbound.exe`、`plugin/__init__.py`、`plugin/plugin.yaml`、`plugin/inbound.py` 和 `inventory.json`。清单格式如下；`source_commit` 是制品真实源码提交，不能填入尚未包含当前改动的提交：

```json
{
  "schema": "cf-inbound-bundle/v1",
  "source_commit": "<40-hex-actual-source-commit>",
  "files": {
    "filebridge-inbound.exe": "<64-hex-sha256>",
    "plugin/__init__.py": "<64-hex-sha256>",
    "plugin/plugin.yaml": "<64-hex-sha256>",
    "plugin/inbound.py": "<64-hex-sha256>"
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
