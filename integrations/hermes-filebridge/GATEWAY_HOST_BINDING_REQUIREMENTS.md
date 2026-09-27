# Gateway 与 Hermes 宿主的入站附件绑定配套要求

**状态：尚未实现的 Gateway 配套请求。** 本文选择唯一方案：Gateway 为每次附件 Dispatch claim 创建或分叉一个专用的真实 Hermes session，预登记权威绑定；本项目从公开 tool execution middleware 取得实际 session/task，通过固定 Gateway 的服务认证接口取得附件 grant 和撤销 lease。**不依赖插件读取 HTTP header、HTTP metadata、提示正文中的凭据或模型提供的 task_context，不需要修改 Hermes 核心。**

本文没有执行这些接口，没有修改 Gateway、Hermes 安装或凭据。以下“拟新增”接口当前不存在；只有明确列出的 Hermes session API 已从固定源码核实。

核对版本：
- Gateway：a26f234fbe60f9a3212bf6bd3471bba3f5802997。
- 公开 Hermes 候选：4d55ca91656ac5f83e1506679b7f81e0238e5e16。该源码证明接口形状，不证明它就是当前安装版本。

## 1. 为什么需要后台交接

Gateway 已有 metadata 并非天然不可信。[HermesDispatchService.dispatch_record、_dispatch、_session_metadata](https://github.com/Tangbohu09527/CF_agent-gateway/blob/a26f234fbe60f9a3212bf6bd3471bba3f5802997/src/cf_agent_gateway/hermes/service.py) 从持久记录构造并核验消息、身份、线程和 profile，在 V2 metadata 中发送 inbound_attachments。**如果宿主能够直接取得经批准 Gateway 认证的本次请求 metadata，这些授权字段可以可信；模型复述则不具备相同来源证明。**

但固定公开 Hermes [OpenAI chat 路由](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/gateway/platforms/api_server_openai_routes.py) 没有把 Gateway 的 session_metadata 交给本插件。[公开插件注册及执行上下文](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/hermes_cli/plugins.py) 提供真实执行 session/task 等字段，不能据此假设还能读取原 HTTP Authorization 或完整 HTTP body。

因此本方案不从 metadata 启动下载，也不要求先持有附件 Authorization 才能取得附件 Authorization，避免循环依赖。

现有 Gateway 的关键边界：

| 源码符号 | 已核实行为 | 配套必须补足 |
| --- | --- | --- |
| [HermesClient.chat](https://github.com/Tangbohu09527/CF_agent-gateway/blob/a26f234fbe60f9a3212bf6bd3471bba3f5802997/src/cf_agent_gateway/hermes/client.py) | POST v1/chat/completions，使用 Hermes API Key；会话放 X-Hermes-Session-Id，持久幂等键放 Idempotency-Key；不发送 JSON session_id | 真实 session 必须由已存在的 Hermes session API 建立；不能假定额外 JSON metadata 会自动进入工具上下文 |
| [_initial_hermes_thread_id、_dispatch](https://github.com/Tangbohu09527/CF_agent-gateway/blob/a26f234fbe60f9a3212bf6bd3471bba3f5802997/src/cf_agent_gateway/hermes/service.py) | 初始会话引用为 v1:cf-agent-gateway:<AIThread.id>，之后沿用持久会话并推进响应返回值 | 新方案改变附件调用的会话分配，必须显式保留历史，不能偷偷改为空会话 |
| [grant_read、_authorized_manifest、read_authorized](https://github.com/Tangbohu09527/CF_agent-gateway/blob/a26f234fbe60f9a3212bf6bd3471bba3f5802997/src/cf_agent_gateway/inbound/access.py) | 读授权绑定当前 claim；读前后验证身份、claim、lease、登记；描述符凭据期限为生成时加 3660 秒 | 描述符期限不是 Dispatch lease；现有描述符没有足够的宿主任务生命周期信息 |
| [authorized_source](https://github.com/Tangbohu09527/CF_agent-gateway/blob/a26f234fbe60f9a3212bf6bd3471bba3f5802997/src/cf_agent_gateway/inbound/store.py) | 再查当前来源映射、身份、workspace、thread、profile、source fingerprint | 权威后台交接应复用这些判断，不让插件仿造身份授权 |
| [HermesDispatchWorker、_LeaseHeartbeat](https://github.com/Tangbohu09527/CF_agent-gateway/blob/a26f234fbe60f9a3212bf6bd3471bba3f5802997/src/cf_agent_gateway/hermes/worker.py) | 续租失败只停止续租并记录警告；没有向本插件发送撤销事件 | 须补权威撤销通道；HTTP socket 关闭不证明 Hermes 已结束 |

## 2. 认证和专用 session 的前提

本方案要求用于附件执行的 Hermes 入口/Profile **只允许被批准的 Gateway 调用方建立或续接任务**。可以使用该固定版本现有的认证/Profile 路由能力和受控网络边界，不修改 Hermes 核心；具体入口、Profile、Key 归属及访问限制必须由对应部署验证。

普通调用方不能与 Gateway 共用一个可任意访问该执行入口的 Key。共享 Key 只证明持有 Key，不能区分调用来源。尤其官方 OpenAI 路由会把旧 X-Hermes-Session-Id 解析到 live continuation tip：仅仅 fork 新 session，不能阻止持有同一通用 Key 的另一调用方通过旧 header 发起新请求并进入该 tip。若无法落实专用入口，**本方案不得启用**，不能声称 session/task 字符串已经解决来源鉴别。

宿主到 Gateway 的后台交接使用另行配置的、限于指定宿主和执行 Profile 的服务认证。它与 Hermes API Key、附件短期 Authorization、FileBrowser runtime-token 分离；不得取 FileBrowser 或 Gateway 管理 Token 代用。服务认证只供插件的固定控制客户端使用，不进入模型参数、命令行、URL、普通日志或工具输出。凭据准备和实机配置由后续获准接入完成，本文不生成或替换凭据。

## 3. Gateway 如何先取得真实 session，并保留历史

固定 Hermes [api_server.py](https://github.com/NousResearch/hermes-agent/blob/4d55ca91656ac5f83e1506679b7f81e0238e5e16/gateway/platforms/api_server.py) 已有受认证公开 HTTP 入口：

| 已有入口及符号 | 核实字段与行为 |
| --- | --- |
| POST /api/sessions，_handle_create_session | JSON 可给 id（或 session_id）；也支持 system_prompt、source、title 及运行模型设置。成功返回 201 和 {object: "hermes.session", session: {id: ...}}；同 ID 冲突返回 409 |
| POST /api/sessions/{source_session_id}/fork，_handle_fork_session | JSON 可给 id（或 session_id）、title。创建 child、把 source 标记为 branched、复制 source messages；成功返回同类 201 session 响应 |
| _run_agent | 在该 API 路径中 effective_task_id 使用实际 session_id，然后传给真实 agent.run_conversation |
| OpenAI _handle_chat_completions | X-Hermes-Session-Id 决定续接会话，旧引用可解析为 live tip；JSON session_id 不是该路径的会话选择字段 |

Gateway 配套必须按如下单一流程实现：

1. 在取得真实 RUNNING claim、确定身份/线程/Profile 后，为该 claim 生成全新、不可复用且满足路径约束的 session ID，例如固定前缀加完整随机 UUID。绝不把 Idempotency-Key 当作 claim 或 session 的权限证明。
2. 逻辑线程没有历史时，调用现有 POST /api/sessions 创建该 ID。有历史时，在既有 per-thread FIFO 和 claim fence 内，从上次确认的真实 continuation tip 调用现有 fork API，创建新的 claim 专用 child。
3. 必须验证 HTTP 201、返回 ID、父子关系、消息复制和所需运行配置。fork 会结束父 session，并且源码只显式把 _branched_from 放进新的 model_config；不能宣称全部 provider/model lock/profile 配置自动继承。相应配置及逻辑线程上下文必须由 Gateway 集成明确验证。
4. fork 是多步操作。失败、超时或不确定响应不能直接再 fork 一个新 ID，也不能清理未知 session。先按该次预分配 ID 检查已发生的结果，保留现场并进入明确恢复状态；未经确认不派发附件执行。
5. Gateway 预登记 child 的权威 Dispatch/claim/身份/附件绑定，**然后**才发起原有 chat 请求，并在 X-Hermes-Session-Id 中发送这个真实 child ID。模型正文只提供用户文本、附件 ID 和专用工具说明。
6. 接收 chat 响应后，按原有 fenced 结果持久化流程推进 AIThread 的真实会话 tip。fork/prebind 不能绕过既有并发比较条件；也不能因创建 child 就提前宣称 Dispatch 成功。

这会把“多次附件 Dispatch 复用一个长期 Hermes session”改为“每个 claim 有独立 child、历史沿 lineage 保留”。这是 **Gateway 的显式兼容性变更和验收责任**，不是本插件静默改变线程语义。它不得改变 Gateway 逻辑 thread/enterprise identity，也不得通过丢弃历史来凑出隔离成功。失败 claim 的历史是否进入下一次执行，须由原有恢复流程明确决定。

如果原 session 是无法在真实 Hermes 查到的历史占位引用，必须停止并报告迁移/来源缺口，不能自动创建空 session 伪称已保留历史。

## 4. 拟新增的服务认证 lookup/exchange

以下接口及 JSON **是配套请求，当前未实现**：

POST /internal/hermes/inbound-bindings/resolve

本插件公开 tool_execution middleware 只使用官方执行上下文中的实际 session_id、task_id，并在本进程为该组合固定 host_instance_id 和 host_nonce；不能使用模型 kwargs 覆盖。Middleware 不需要 HTTP header、metadata、提示 carrier 或附件 Authorization。

最小请求：

~~~json
{
  "schema": "cf-inbound-host-binding/v1",
  "session_id": "actual-hermes-session-id",
  "task_id": "actual-middleware-task-id",
  "host_instance_id": "fresh-process-instance",
  "host_nonce": "fresh-unpredictable-binding-nonce"
}
~~~

Authorization header 此处是限定用途的宿主服务认证，不是尚未取得的附件授权。固定 Gateway HTTPS origin、CA/主机名验证、拒绝重定向、输入大小和请求期限由宿主配置决定；服务地址不接受模型输入。

Gateway 依据该服务 principal 和预登记 session 查找绑定，不能仅把请求字段原样回显当成授权。首次成功认领必须原子固定宿主实例、nonce 和真实 task；后续相同调用返回同一绑定，冲突调用拒绝。至少检查：

- session 确由 Gateway 为该 claim 创建/分叉且从未绑定其他 Dispatch；没有仅凭 session 字符串新建权限的逻辑。
- 当前 claim 仍有效，Dispatch 为 RUNNING，lease 未失效；身份、线程、profile 和附件登记仍一致。
- 服务 principal 被授权消费这个 session 所属的执行 Profile/宿主范围。
- 实际 task 满足该固定 Hermes 路径已验证的 task/session 关系。当前 API 路径二者相同，不能把这种实现关系当作跨所有入口的通用假设。
- 尚无不同宿主实例、nonce 或 task 认领该 claim；错误/空上下文不触发猜测、搜索其他线程或降级取件。

最小成功响应：

~~~json
{
  "schema": "cf-inbound-host-binding/v1",
  "binding_id": "opaque-binding-reference",
  "session_id": "actual-hermes-session-id",
  "task_id": "actual-middleware-task-id",
  "host_instance_id": "fresh-process-instance",
  "host_nonce": "fresh-unpredictable-binding-nonce",
  "dispatch_id": 123,
  "claim_epoch": "opaque-current-claim-generation",
  "message_id": 3,
  "thread_id": "authoritative-logical-thread",
  "enterprise_identity_id": "authoritative-identity",
  "profile_reference": "authoritative-profile",
  "profile_revision": 1,
  "lease_valid_until": "2026-09-27T12:00:30Z",
  "state": "running",
  "budget_scope": "stable-message-and-attachment-scope",
  "attachments": [{
    "schema": "cf-inbound-read/v1",
    "message_id": 3,
    "attachment_id": 5,
    "thread_id": "authoritative-logical-thread",
    "enterprise_identity_id": "authoritative-identity",
    "url": "https://gateway.example.invalid/inbound-media/7/content",
    "authorization": "Bearer SYNTHETIC_EXAMPLE_ONLY",
    "expires_at": "2026-09-27T12:01:00Z",
    "size": 1234,
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "mime_type": "application/pdf",
    "filename": "example.pdf",
    "declared_quality": null,
    "original_comparison": "not_checked",
    "formal_archive": false,
    "download_policy": {
      "max_attempts": 4,
      "total_timeout_seconds": 30,
      "retryable_status_codes": [503],
      "retry_after_seconds": 1
    }
  }]
}
~~~

示例中的域名、摘要和 Authorization 全部是非生产占位值。实现必须返回既有契约的完整 descriptor，包括该附件短期 Authorization；它只能从后台响应进入受控宿主内存和现有 worker stdin，不能进入模型提示或工具结果。响应不暴露可操作队列的原始 claim token；claim_epoch 只是可比较代次。

Gateway 必须安排一次性的 grant 交接：该 claim 的 grant 只生成一次；重试返回同一 grant，不能再调用 grant_read 重新发凭据。当前实现只持久化读 token 的哈希，不能从哈希恢复完整 Authorization。本方案要求 Gateway 配套在 **claim 预登记时生成一次 grant，并在受保护的短期交接状态中保留原值**，供同一已认领绑定幂等取得，最终到期或终止时销毁；交接状态丢失则失败关闭，不重新签发。

宿主确认所有回显 binding 字段与实际上下文完全相同，才构造现有 HostBridge 输入。本地工作目录来自实际 task 的受控分配，Gateway origin/CA、二进制摘要和大小上限来自宿主配置；后台响应不能扩大本地目录或网络权限。

## 5. 权威撤销流与调用时机

本方案采用**经过服务认证的撤销事件流**，不把普通状态轮询或一次 RUNNING 响应当成不可撤销 lease。拟新增：

- GET /internal/hermes/inbound-bindings/{binding_id}/events。
- POST /internal/hermes/inbound-bindings/{binding_id}/closed，供宿主确认关闭；不是模型工具。

事件绑定 binding_id、claim_epoch、host_instance_id、host_nonce，含单调递增序号、有效截止和明确的 cancel/end/revoke 状态，不含凭据。监听不能重定向到响应提供的任意地址；路由固定在配置的 Gateway origin。

时序要求：

1. Middleware 取得真实 session/task，以服务认证 resolve；权威响应通过且撤销监听建立后，调用 HostBridge.start_dispatch。
2. 在实际工具执行 callback 周围激活同一绑定。所有重复和并发调用复用 worker；模型只选择已授权 attachment_id。
3. 任务结束、异常、取消、claim 变化、事件丢序/断连或任一期限到达时，立即关闭 worker 和下游流，阻止新工具调用，再确认 closed。官方 session-end hook 只能辅助清理，不能替代该权威机制。
4. Gateway 正常完成当前 chat 后及任何提前撤销时，应先终止该宿主绑定；换 claim/完成终态必须经过宿主关闭确认，或等待已授予的有限 lease 到期屏障。不能先结束 Dispatch、任由宿主继续落盘，再以迟到通知宣称严格生命周期已经成立。
5. 无法建立监听、无法确定 lease、服务认证失败或后台状态不匹配时失败关闭，不能使用 descriptor 的 3660 秒凭据期限代替 Dispatch lease。

首版可以保守使用首次响应给出的有效截止，不要求给现有 worker 动态延长期限。即使 Gateway 后续续租，宿主也不能靠新建 worker 延长既有下载预算；较晚调用可能被保守拒绝。允许延长生命周期的后续实现也必须保留每附件首次起算的 4 次/30 秒预算和全部终局状态。

## 6. 重放、历史任务与跨进程预算

每个 claim 专用 session 只能预绑定一次，永不重新分配给新 claim。旧 session、已结束 session 或未知 session 的 middleware lookup 均不得拿到另一任务的附件。若执行中出现未预登记的会话压缩/旋转 ID，首版拒绝该附件调用，不自行追踪 tip、模糊匹配逻辑 thread 或重新绑定；支持旋转需要另外的权威映射验收。

[build_hermes_dispatch_idempotency_key](https://github.com/Tangbohu09527/CF_agent-gateway/blob/a26f234fbe60f9a3212bf6bd3471bba3f5802997/src/cf_agent_gateway/task/model/store.py) 按 message 生成稳定键，它既不是 claim 代次，也不是授权凭据。Gateway 本身必须用内部真实 claim fence 判断代次，不能把该键变成可重置预算的借口。

- 同进程相同 session/task 固定使用同一个 nonce、绑定和 worker；并发首次 lookup 必须合并。
- worker 崩溃后保持终局；不得重新启动而获得新的 4 次/30 秒。
- Gateway 的绑定登记须持久拒绝其他 host_instance_id/nonce 接管同一 claim。首版明确不支持跨进程恢复旧 claim；宿主重启后该旧绑定失败关闭。
- 本轮不增加自动重派。需要新的 claim 或人工恢复时由 Gateway 既有流程另行决定，附件工具不申请凭据续期。
- 专用认证入口是本节成立的前提。不能在公开共享 Key 入口上仅靠 session_id == task_id 宣称排除了另一 HTTP 请求。

## 7. 凭据与模型输入

Gateway 当前 _dispatch 还把完整 descriptor 拼入 messages[0].content。**配套必须删除这个凭据副本，不能把剥离责任交给根本拿不到原始 HTTP 请求的工具 middleware。**

配套后的模型正文只包含原始用户文本、附件 ID、必要非敏感说明及专用工具名称。descriptor 和 Authorization 只通过上节私有后台响应交付；模型不生成 curl/PowerShell 等命令替代下载。filename 和文件内容依然只是待处理数据，不能成为权限来源或可执行指令。

下载工具继续仅接受 attachment_id，返回已验证句柄和摘要；声明质量和原图比较结果原样保留，不因落盘成功提升结论。

## 8. 配套验收及当前阻塞

Gateway 对应项目须实现并分别证明：

- 现有公开 create/fork API 的真实响应、认证和错误路径；父子 lineage、消息历史、profile/model 配置和会话推进保持预期，首次或失败场景不静默丢历史。
- 专用 Gateway 执行入口阻止普通共享 Key 调用方；公开 middleware 的实际 session/task 与预登记 session 完全一致。
- 服务认证 lookup 的未知/旧 session、错误身份/Profile、过期 claim、不同 task/nonce/宿主实例、并发重放和进程重启拒绝。
- 首次一次性完整 grant 交接、重复返回同一授权、故障不重签；无 Authorization 进入模型输入、会话历史或普通日志。
- 撤销流、丢序/断连、任务结束、lease 到期、读取中撤销及关闭确认屏障；旧任务不能领到新任务 grant，预算不因进程或 claim 重放刷新。
- 真实 HTTP 请求 → 官方实际 session/task → 本插件公开 middleware → 认证后台交接 → 现有下载器落盘的完整组合测试。

当前阻塞已定位为这些明确的 Gateway 配套能力，而不是笼统认定所有 metadata 不可信。它们实现并验收前，本项目只能声称已实现的下载器、模拟后台/宿主测试以及真实插件加载或 middleware 探针分别通过，不能声称真实 Gateway 宿主桥已经接通。本轮不在当前运行环境安装启用。
