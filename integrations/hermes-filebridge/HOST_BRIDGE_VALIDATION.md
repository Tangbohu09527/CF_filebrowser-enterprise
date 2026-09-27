# 真实宿主边界复核（2026-09-27）

本轮起点 `0bf082c65091c38874932a3b3d7a9f66be8df6be`，工作树
`C:\Users\Admin\.codex\worktrees\6330\CF_filebrowser-enterprise`，分支
`feat/filebridge-hermes-crud`。检查 branch/status/remote/HEAD/log/diff 后 fetch，
本地与远端一致、工作树干净；包含 `6ba8f71fb0ba270420419618c1e07150b0b8b742`，
没有回退、清理或覆盖既有内容。PR #2 保持 Draft / Open。

**还未接通。具体阻塞是 Gateway 缺少权威 Dispatch 交接与撤销契约，
不是官方 Hermes 缺少 tool_execution middleware。**
[可执行的配套要求](GATEWAY_HOST_BINDING_REQUIREMENTS.md) 规定调用时机、来源认证、
实际会话关联、claim/lease、单次认领与撤销语义；其中新增端点尚不存在，不能伪造成功。

## 调用链及证据边界

固定官方 Hermes `4d55ca91656ac5f83e1506679b7f81e0238e5e16` 的公开接线见
[INBOUND_CONTEXT.md](INBOUND_CONTEXT.md)。没有改动上游源码、monkey patch 或使用固定行号补丁。

| 层次 | 实际执行的路径 | 可以证明 / 不能证明 |
| --- | --- | --- |
| 原有组件 | Python HostBridge → 当前原生 worker → 实际 HTTPS → NTFS → handle → read stream | 合成 binding 下的字节、预算、权限与回收；不证明 Gateway 请求身份 |
| 官方 middleware | 真实 loader / PluginContext → register_middleware → 官方工具分派 → activate → 当前 worker / 下游读取 | 公开扩展点可承载执行范围；测试宿主构造 binding，不能算权威请求交接 |
| 真实 HTTP 请求 | 官方 APIServerAdapter.connect → HTTP POST /v1/chat/completions → 官方 AIAgent → 官方工具 middleware / registry → 当前 handler | 模型服务仅为回环 HTTP 替身；真实请求/加载/工具/结束路径保留。未绑定调用应拒绝，没有“正常下载已接通”的成功声明 |
| 实际 AI 主机 | 未执行 | 没有访问当前安装、配置、凭据或生产 Gateway，不是现场验收 |

HTTP 请求探针使用另一个临时 Profile 和空 bundled 插件目录。额外 observer 是由官方
loader 加载的测试插件，只记录关联字段名称、合成 ID 和固定结果，不替换请求、agent、
dispatcher 或生命周期。对外网络、DNS 和子进程执行由 audit guard 拒绝；模型 stub 仅监听
loopback。middleware 组件测试另行允许固定 worker，使用公开测试证书及私有临时 NTFS 目录。

## 要求逐项对应

| 用户要求 | 本轮证明范围 / 剩余项 |
| --- | --- |
| 正常附件请求到落盘、下游消费 | middleware 组件层验证现有 worker；完整认证请求成功仍受外部契约阻塞 |
| 两个并发会话 | 真实请求检查框架 session/task 隔离；已授权身份/附件/目录隔离在组件层验证，不能扩大为实际 Gateway 已验证 |
| 重复工具不刷新预算 | 原有真实 worker 预算测试保留；middleware 重复调用复用已有 worker。完整认证请求无绑定，不能声称已测试其授权预算 |
| 正常、取消、异常后撤销 | 原有 worker/HostBridge 关闭及 lease 测试保留；真实请求生命周期事件按实测记录，不把单个 on_session_end 当成全路径保证 |
| 伪造任务、错误来源、缺少绑定 | 真实请求边界拒绝与框架实际分派分开核验；无来源认证不建立 binding |
| 原只读/受控新建 | 原 13 项 Python 断言与独立 Go 模块回归保留 |

## 本轮文件及原因

所有路径相对于本项目，没有修改下载器、Windows 存储、原工具实现或依赖锁文件。

| 文件 | 原因 |
| --- | --- |
| `tests/test_hermes_request_probe.py` | 独立官方请求/agent/分派探针；模型替身不能代替这些边界 |
| `tests/test_hermes_middleware.py` | 官方 middleware 与当前 worker 的组件接线证据，明确标记合成 binding |
| `tests/test_hermes_loader.py` | 固定源码校验扩展到本轮实际调用的官方边界 |
| `tests/hermes-probe-requirements.txt` | 仅隔离探针的固定运行依赖，不安装到用户 Hermes |
| `.github/workflows/filebridge-client.yaml` | 沿用现有 Linux/Windows 客户端回归入口，补真实官方探针 |
| `GATEWAY_HOST_BINDING_REQUIREMENTS.md` | 具体外部配套契约、权威来源、反重放及撤销要求 |
| `INBOUND_CONTEXT.md` | 更正先前对公开扩展点的遗漏，记录实际调用范围 |
| `INBOUND_DOWNLOAD.md` / `README.md` | 下载组件与尚未实现的权威交接分开说明 |
| `INBOUND_VALIDATION.md` | 保留既有下载验收记录并链接本轮复核 |
| `plugin/inbound.py` | 仅更正模块说明；未添加第二套桥接或改变已有工具 |
| `HOST_BRIDGE_VALIDATION.md` | 本记录及后续验收步骤 |

## 测试命令与结果

下列命令在隔离环境运行。Go 使用临时 Go 1.25.0，Python 使用独立测试 venv，
`CF_FILEBRIDGE_INBOUND_TEST_EXE` 指向临时编译的当前 worker。

| 命令 | 结果 |
| --- | --- |
| `go test -count=1 ./...`（`tools/filebrowser-agentctl`） | 通过，包含 Windows NTFS / 真实 HTTPS / 实际 30 秒预算及原客户端 |
| `go vet ./...`（同目录） | 通过 |
| `python -B -m unittest discover -s integrations/hermes-filebridge/tests -v` | 22 项通过，包含原 13 项只读/受控新建 |
| `<venv-python> -I -B integrations/hermes-filebridge/tests/test_hermes_loader.py --hermes-source <source>` | 默认关闭/显式注册两场景通过，新增 8 个官方请求/执行边界文件的 Git blob 校验通过 |
| `<venv-python> -I -B integrations/hermes-filebridge/tests/test_hermes_middleware.py --hermes-source <source> --worker <native-worker>` | Windows 6 项通过；真实 model_tools → 官方 middleware → 当前 worker → 下游读取。包括重复/并发、4 次耗尽不重置、身份/线程/目录及 handle 隔离、取消/结束和 ContextVar 恢复；合成 binding，认证请求交接仍为 false |
| `<venv-python> -I -B integrations/hermes-filebridge/tests/test_hermes_request_probe.py --hermes-source <source>` | Windows 真实 HTTP 探针通过：两个并发会话、每会话连续两轮，共 4 次官方工具执行；缺绑定均拒绝；2 次正常结束 hook；无/错误 Bearer 两次 401 且无模型或工具事件 |

真实请求实测 `task_id == session_id`，middleware 收到 `api_request_id`、
`middleware_schema_version`、`original_args`、`session_id`、`task_id`、
`telemetry_schema_version`、`tool_call_id`、`turn_id`，没有 `session_metadata`。
原始消息中合成的附件描述确实到达模型替身，证明“放进提示正文”不能当作私有授权通道。
这不是泄露生产凭据；所有 marker / Authorization 都是公开、无效的测试值。

开发过程如实保留的失败：隔离环境最初缺少官方 Windows 日志依赖；补齐官方固定依赖后
进入真实 agent。首次请求测试把同批两个相同调用预期为两次执行，但官方去重为一次，现改为
连续两轮真实调用，未关闭去重。middleware 新测试最初误要求成功文件在结束后消失；
既有 Store.Close 保留已发布文件，正确要求是撤销句柄/关闭流并保留完整文件和未知内容，
失败未发布文件仍不得残留半文件。没有修改下载器或既有安全断言来迎合新测试。

真实生命周期另发现固定上游缺口：模型服务返回不可重试 HTTP 400 后，Hermes HTTP
响应为 200、`hermes.failed=true`，但没有对应 `on_session_end`；SSE 断开则观察到
`interrupted=true`，同一事件的 `completed` 仍为 true。因此不能只看 completed，
也不能把该 hook 当作所有异常出口的撤销保证。后续探针明确记录这个缺口，不制造结束事件。

未重新执行本地后端/前端/E2E/产品构建：没有对应实现改动。未运行当前安装的 Hermes、
真实 Gateway、微信或 CFserver：本轮明确禁止。没有为规避历史 backend Lint 红项修改
`backend`、Makefile 或 `regular-tests.yaml`。

## 后续一次性实机验收（本轮不执行）

1. Gateway 独立项目实现并测试上述权威交接契约，提供固定提交与测试证据，尤其是
   会话历史保留、claim/lease、旧执行拒绝重绑、撤销屏障及模型前移除授权副本。
2. 本项目依据已定版契约在公开 middleware 内接上现有 HostBridge；来源、字段、
   TLS 或监听失败直接返回固定失败值，handler 仍保留无绑定拒绝。补全真实请求成功、
   两会话、重复预算、取消/正常/异常退出全链测试后，再生成候选制品。
3. 另行授权的隔离 AI 主机使用新 Profile、新测试身份和私有任务目录；先用现有
   Stage/Resume/Check 校验成功 CI 的源码 SHA、inventory SHA 与 NTFS ACL，保留配置/凭据。
4. 通过实际 Gateway 请求各发 PDF/JPEG，工具实际落盘，下游用 handle 读完整字节，
   检查摘要、`verified=true`、`formal_archive=false` 及原质量结论；记录两端版本与关联 ID。
5. 同一轮依次验证并发隔离、503 预算、重复调用、claim 到期、取消/正常/异常结束、
   进程退出与旧任务重放；随后检查原工具回归、未知文件未变化和日志/模型输入无授权值。
   任何一项失败保持下载门禁关闭，不自动重签或续凭据。
