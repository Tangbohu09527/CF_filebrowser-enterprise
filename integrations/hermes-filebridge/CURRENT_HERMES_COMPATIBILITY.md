# 当前 Hermes 兼容性核验记录（2026-09-28）

**新版官方 Hermes `0f4a98f` 与独立 Python 3.14.7 的 Windows 原生请求链、Linux 双运行时完整组合链已通过；旧版参考回归保留并通过。** 原始七项 payload 在短任务目录通过九场景，但真实长路径消费失败。产品仅修复插件的 Windows 工作副本长路径读取；修后十场景包含278字符路径消费和撤销，必须使用新候选，不能把旧暂存版本当作修复版。

代码验证提交为 [`3386c6d2cee396ca595fac3f5f319570d6e61fc0`](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/commit/3386c6d2cee396ca595fac3f5f319570d6e61fc0)，对应 [push run 36394311219](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36394311219) 四组全部通过。本页后续仅文档提交的最终 HEAD、对应 CI 及 Windows 制品/inventory 摘要在 PR #2 交付记录中核验，避免在文档中自引用尚未生成的提交或制品摘要。此结果受下文隔离范围约束，不是用户当前安装、生产双机或真实微信验收。

本项目起始基线为 [`8faff6a0bd627ca5a8ffa1110ea1b1f1919354a8`](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/commit/8faff6a0bd627ca5a8ffa1110ea1b1f1919354a8)，PR 为 [#2](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/pull/2)。既有隔离组合证据见 [JOINT_HOST_VALIDATION.md](JOINT_HOST_VALIDATION.md)，其通过记录不代表本轮新版本已通过。生产服务器、现有 Hermes 安装及其依赖/Profile/凭据、既有 acceptance 暂存与工作目录均不作为本轮测试输入。

## 固定源码与独立运行时

| 输入 | 固定提交 | 完整源码 ZIP SHA-256 |
| --- | --- | --- |
| [旧 Hermes 参考](https://github.com/NousResearch/hermes-agent/tree/4d55ca91656ac5f83e1506679b7f81e0238e5e16) | `4d55ca91656ac5f83e1506679b7f81e0238e5e16` | `3c04b108ae0fcf0e84524ce31b1ea1a739a087a15c0c1382af86260dc84c3979` |
| [新版官方 Hermes](https://github.com/NousResearch/hermes-agent/tree/0f4a98f87c17007b81500239d0bd5b9574027b73) | `0f4a98f87c17007b81500239d0bd5b9574027b73` | `0607677d5e9b3e30c93af2285bbc83108a85adca4596584f471befcdd9e6b453` |
| [Gateway 固定契约](https://github.com/Tangbohu09527/CF_agent-gateway/tree/0ec54bf0f25f421e37e16e11bd098a814beca258) | `0ec54bf0f25f421e37e16e11bd098a814beca258` | `c0ad44618fcd7c640c640f921e8910b8292dcadc24dd2c03cc03a34c2761c445` |

Hermes ZIP 来自官方仓库对应提交的 `codeload.github.com/NousResearch/hermes-agent/zip/<完整提交>`；Gateway 同样使用上表固定仓库与提交。版本目录为 [tests/hermes_versions.json](tests/hermes_versions.json)，默认参考仍是旧版 `4d55ca9`。

新版 Python 使用 [Astral python-build-standalone 官方 20260924 发布](https://github.com/astral-sh/python-build-standalone/releases/tag/20260924)，不读取已安装 Hermes 随附的 Python。以下文件名与摘要同时固定，不能混用 stripped 和非 stripped 的摘要。

| 平台 | 官方资产 | SHA-256 |
| --- | --- | --- |
| Windows x86_64 | [`cpython-3.14.7+20260924-x86_64-pc-windows-msvc-install_only_stripped.tar.gz`](https://github.com/astral-sh/python-build-standalone/releases/download/20260924/cpython-3.14.7%2B20260924-x86_64-pc-windows-msvc-install_only_stripped.tar.gz) | `1493fc4185edf84bbd4305c15c5fbac2d4fcd4ddd7eb6273903669a5d3106178` |
| Linux x86_64 | [`cpython-3.14.7+20260924-x86_64-unknown-linux-gnu-install_only.tar.gz`](https://github.com/astral-sh/python-build-standalone/releases/download/20260924/cpython-3.14.7%2B20260924-x86_64-unknown-linux-gnu-install_only.tar.gz) | `5539eaf1de20bd9b5f43ea11c3c1f84cbac74fe927ac050318a9210c022618cb` |

Windows 本地运行时实际报告 `3.14.7 (main, Sep 24 2026, 17:57:14) [MSC v.1944 64 bit (AMD64)]`。CI 下载后先校验摘要，再执行该解释器断言 `sys.version_info[:3] == (3, 14, 7)`。本地准备使用仓库内新建的 `.compat-20260928`；依赖仅安装到其独立 venv，未修改产品依赖清单或已运行的安装。

| 回归线路 | Hermes / Gateway 运行时安排 |
| --- | --- |
| 旧参考 loader、middleware、HTTP 探针 | 保留原 CI Python 3.11（本轮Windows实际3.11.9）与 `4d55ca9`。 |
| 旧参考 Linux 组合链和退出探针 | 保留 Python 3.12 与 `4d55ca9` / Gateway `0ec54bf`。 |
| 新版两平台 loader、middleware、HTTP 探针 | 独立官方 Python 3.14.7 与 `0f4a98f`。 |
| 新版 Linux 组合链和退出探针 | Gateway 独立 Python 3.12 venv；`--hermes-python` 指向独立 Python 3.14.7 venv，真正启动另一个 Hermes 进程。 |
| 新版 Windows native 请求链 | Python 3.14.7、真实官方 Hermes 与原生 worker；Gateway HTTPS 服务和模型为明确的合成替身。 |

## 来源与隔离方法

[hermes_probe_support.py](tests/hermes_probe_support.py) 先校验完整 ZIP 摘要，再核对解压目录的全部文件/目录集合和每个文件的原始字节，拒绝额外、缺失、变更文件及 reparse/symlink；随后校验关键入口的 Git blob。准备时还核对了官方完整 Git 树：新版 16,383 个文件、旧版 13,138 个文件。官方 `.gitattributes` 对 PowerShell 的 CRLF 导出规则仅用于 Git blob 比较，未改写解压文件；实际解压字节仍与 ZIP 一致。

解释器环境不继承调用者的 PATH、HOME、Profile 或凭据。HOME/USERPROFILE/AppData/HERMES_HOME/TEMP/TMP 均指向本次新目录，PATH 只含独立运行时与固定系统目录；需要旧测试 fixture 时仅追加 Windows 自带 PowerShell 目录。sandbox 内建立并验证独有空 `.git` 目录，阻止官方上下文发现向父项目查找。该目录不是另建 checkout，也不执行 Git 操作。

[hermes_joint_host.py](tests/hermes_joint_host.py) 在官方导入之前验证隔离环境和源码、安装 audit guard，然后才导入真实 loader/API。guard 限制回环网络、固定 worker 命令、sandbox 写入、固定源码/解释器/测试文件读取及少量明确的只读 OS 元数据。SQLite 只允许 sandbox 内普通数据库及经过同样路径/reparse 校验的只读 URI。没有关闭 guard、放行真实 Profile 或使用管理员权限绕过失败。Python audit 结果不是完整原生系统调用沙箱的证明。

新版提示词的本机环境块会调用 scratch 清扫；固定官方实现即使空目录也可能枚举进程，并可清理孤儿进程/工作树。没有发现公开配置可只关闭此模块。测试在导入前精确禁止可选 `hermes_constants_scratch` 模块，另列 `expected_denied_housekeeping`；模块若在 guard 之前已加载则直接失败。官方既有异常处理继续实际请求，不修改源码、monkey patch 或伪造 `.last_prune`。scratch 全局清扫明确不在通过范围，其他未批准操作仍是失败。

早期本地 native 九/十场景的 audit=0 未覆盖这段 Windows 原生进程元数据扫描，故只保留为功能与失败演进证据；最终严格隔离结果使用 `native-strict-final.stdout`：十场景全通过，每个真实宿主均记录一次精确导入阻断、其他审计违规为0、scratch清扫未验证。未据此宣称所有 Windows 原生调用都被 Python audit 拦截。

## 真实调用链与替身边界

```text
真实 HTTP 请求（API key + X-Hermes-Session-Id）
  -> 固定官方 APIServerAdapter / AIAgent
  -> 真实 plugin loader / tool_execution middleware / tool registry
  -> 本项目 HostAdapter：resolve、events 首个有效 running 快照
  -> 当前工具线程内 HostBridge.activate
  -> 原生 worker -> HTTPS 下载 -> 私有任务目录 -> 大小/摘要验证
  -> opaque handle -> 已登记下游工具 open_workcopy
```

| 证据 | 真实部分 | 不能据此宣称的事项 |
| --- | --- | --- |
| loader | 官方 loader、PluginContext、registry，默认关闭及无绑定拒绝 | 加载成功不等于授权请求已接通。 |
| middleware 六场景 | 官方 `model_tools.handle_function_call`、middleware、实际 HTTPS/worker/下游读取 | binding 为合成组件输入，输出 `authenticated_request_binding=false`。 |
| HTTP request/lifecycle | 真实 HTTP 认证、AIAgent、工具分派及 hook；模型只用回环替身 | 无后台绑定时仍应返回 `trusted_context_unavailable`，不能用正文或 metadata 当授权。 |
| Windows native | 真实官方 HTTP/Agent/loader、产品适配器和 worker、NTFS 文件 | Gateway 控制/附件服务与模型是合成 HTTPS/HTTP fixture；`real_gateway_joint=false`、`production_host_acceptance=false`。 |
| Linux joint/host-exit | 固定 Gateway admission/claim/control/lease、官方 Hermes、产品 worker | 模型 HTTP 和微信原始取件为替身；不是 CFserver 到实际 Windows AI 主机的现场验收。 |

测试 observer 只经公开扩展点注册下游工具并观察已创建的真实实例/进程，不签发或注入产品 binding。模型仍只提交 `attachment_id`，不提供身份、路径、origin 或凭据。

## 原 payload 先测结果与失败证据

下列证据保存在本轮本地 `.compat-20260928/evidence/`；该目录为被忽略的测试证据，不是已经发布的 CI artifact。早期 PASS 只适用于当时记录的输入，不能覆盖随后修复或新增用例。

| 证据文件 | 已观察到的结果 |
| --- | --- |
| `first-new-product-hashes.json`、`first-new-loader-314.*` | 在产品文件摘要未变化时，新版官方 loader 的关闭/开启两场景通过，audit 0，仍无 host binding。 |
| `first-new-middleware-314.*` | 原产品下六项 middleware 组件通过，audit 0；仍明确是合成 binding。 |
| `first-new-request_probe-314.*` | 首次真实请求探针失败；guard 拒绝官方 SQLite 只读 URI，随后结果解析失败。保留此失败，不记为首次全链通过；后续 helper 仅补精确 sandbox URI 验证。 |
| `native-original-first.stderr` | 原 artifact 的七项 payload 首次真实 native parallel 场景失败：两次下载及重复复用成功，两个下游消费均 `workcopy_unavailable`。同时 guard 拒绝官方 prompt discovery 向父仓库读取 `AGENTS.md`，该隔离问题通过 sandbox 独有发现边界处理。 |
| `native-original-fourth.stderr` | 后续运行遇到 helper 读取 `external-host-ready.json` 的 Windows `PermissionError`；这是测试 IPC 读写竞争，后续有界处理后重跑结果单独记录。 |
| `native-original-fifth.stdout` / `.stderr` | 保持原七项 payload，在短任务目录完成九场景，输出 `ok=true`、Python 3.14.7、Hermes `0f4a98f`；stderr 为空。这个正面结果不覆盖长路径负例。 |
| `long-workcopy-before-314.*` | 在修复前新增的 `test_native_long_workcopy_opens_and_revokes_without_new_download` 真实失败：`open_workcopy` 抛 `BridgeError("invalid_handle")`；退出码 1。 |

原候选来自 [run 36375973284](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36375973284) 的 artifact `10950234368`，源码为本页起始基线。ZIP SHA-256 为 `6ab41939ba0dfe10eade4b5ef053d7ddec660c3a67e3f1c7d04adae1f08f476a`，inventory 原始字节 SHA-256 为 `bfc4e8acef5e8cf332922e34f5ce5167eebc34f086990e6acde66e431b130af1`，worker SHA-256 为 `b416b4a706c613f71b3f2e6dee19c3881bf429bd4154a82a001599142eb8fa30`。

初始本地产品与旧 artifact 比较：worker、`__init__.py`、`plugin.yaml` 三项原始字节相同；四个 `inbound*.py` 仅有 CRLF/LF 差异，不能称为七项 byte-identical。因此另从已核验 ZIP 以 CreateNew 解压完整七项及 inventory 到全新的 `.compat-20260928/original-bundle`，逐项验摘要和原始字节，再以显式 `--plugin-source` 使用原 payload。没有读取或改写既有 acceptance/stage/work 目录。`--plugin-source` 参数本身不替代调用前的 artifact/inventory 来源验证。

对原始失败现场仅作只读诊断：两个已发布工作副本均为 414 字节，普通绝对路径长度 270；Python 3.14.7 的 `os.stat/lstat` 返回 errno 2、winerror 3，`os.open` 返回 errno 2。同一路径加 `\\?\` 后 stat/lstat/open+fstat 成功，`st_dev/st_ino` 一致且 `samestat=True`，大小与 mtime 一致。另一个 278 字符路径的专项回归也实际失败，见 `long-workcopy-before-314.*`。这是普通长路径访问限制的直接证据，不是文件身份被替换。改用短目录通过不能证明长路径支持。

`native-original-fifth` 的九场景分别为：两身份并发 2 GET / 2 closed；JPEG 1 / 1；一次 503 后成功 2 / 1；首个 running 快照门槛 1 / 1；错误身份 0 GET / 0 closed；模型错误 1 / 1 且 `end_events=[]`；取消和 events 断连各 1 / 1；最后在真实半文件已出现后终止实际 Hermes 宿主，worker 因管道 EOF 以退出码 0 在 0.014 秒内完成回收。该退出场景的宿主快照 audit 0，测试断言无 closed ACK、无半文件残留；正常场景也保留完整文件、摘要、handle 消费、重放拒绝与最终 audit 检查。该结果证明所测短目录链路可行，不能表述为原候选在任意 Windows 路径下完整兼容。

首轮原请求失败日志 SHA-256：`aed098f15f8ebb673e33dfbe66363704a494dca545118a99d8099303394d6fe5`；修前真实长路径失败日志：`7269ae3091c349d7036f46422b8471865f436b7ff351cfc31c9a2138bd7c7982`；原七载荷九场景通过报告：`fd5439214c933c04b2859666c29a609a1f8675e6314df59ea3ea5eafc921afdb`。

本轮长路径产品修复范围限定在插件 `plugin/inbound.py` 的工作副本读取；原生 worker、Gateway 契约和 Hermes 核心不因此改动。必须保留身份、路径、reparse、摘要、任务撤销和不重新下载的约束，修复结果以新增失败回归及完整回归为准。修后专项插件 11/11、来源/隔离 14/14 通过；完整 Windows discovery 83 项中 82 通过、1 项 Linux 专属跳过（44.967 秒）。随后新增真实 HTTP 长路径场景发现联合探针的独立 guard 尚未接上扩展路径等价判断，`native-fixed-first.stderr` 保留该拒绝；修正共享判定后，`native-fixed-second.stdout` 的真实官方请求十场景全部通过，包含278字符路径实际消费、同句柄复用、终局拒绝，worker EOF 退出为0.015秒，审计违规为0。 修复后插件字节变化，需要由新提交构建新 artifact 并取得新的 inventory pin；旧候选不能直接当作已修复版本，也不覆盖、迁移或清理旧 stage/work。

## CI 准备失败与修正记录

- `25ee0e6f` / run 36391420264：Windows Python 归档摘要正确，GNU tar 把归档参数里的 `D:` 当远程主机。改为从 stdin 读取；随后 `634dbaf2` 的 `-C` 原生盘符路径仍被 GNU tar 拒绝，因此仅该参数转换为 Git Bash 路径，传给Python/worker的原生路径不变。两次都还没进入新版产品测试。
- 首轮旧 Windows 的四个来源审计junction fixture在PowerShell子进程超时15秒，内部原因不能从日志确定。测试改用与本项目Go fixture相同的原生NTFS junction创建调用，不提权、不改Token、不延时；新增实际reparse-tag和目标身份断言。`634dbaf2` 旧Windows全86项通过（1项Linux专属未运行），随后固定源码HTTP429导致后续loader步骤失败；只为不可变依赖下载增加有界重试，摘要核验保持。
- 新 Linux 首轮 request 在额外 `/proc/<pid>/stat` 读取被审计拒绝；五帧日志不足以唯一归属。源代码发现可选scratch清扫包含祖先进程/全局进程扫描，因此阻断整个可选模块导入而非放宽`/proc`。诊断现保留数字PID/PPID及12层代码位置，不记录局部变量、请求字段或环境。
- 双运行时入口保留 venv 的解释器路径；不能对Linux `venv/bin/python`调用`resolve()`后改跑基础解释器。回归验证真实符号链接入口保留，Gateway继续3.12，实际Hermes子进程版本单独报告。

## 新版生命周期实测的精确含义

`final-new-request_probe-314.*` 已记录：新版 `0f4a98f` + Python 3.14.7 的真实请求/lifecycle 探针退出 0；两个并发请求、四次官方工具执行、两次未授权 HTTP 拒绝，正常结束事件两次，audit 0。它是无后台 binding 的边界探针，下载结果仍为 `trusted_context_unavailable`。

具体负例是**回环模型 HTTP 返回 400**：官方 Hermes 外层 HTTP 返回 200，响应 `hermes.failed=true`，该错误任务的 `on_session_end` 事件为 0；取消/断连负例观察到一次 `interrupted=true` 的结束事件。因此只能得出“此固定版本的模型 HTTP 400 路径仍缺结束 hook”，不能概括所有异常、所有调用路径或未来版本。`lifecycle_complete=false` 和 `exception_end_hook_missing=true` 是如实记录限制，不是删除失败断言。

旧版 `4d55ca9` 额外尝试 Python 3.14.7 的 `reference-second-request_probe-314.*` 独立失败，真实工具结果为 `'DaemonThreadPoolExecutor' object has no attribute '_initializer'`，退出码 1。它不替代原 Python 3.11/3.12 参考门禁，也不证明新版 `0f4a98f` 有同一问题；没有为此修改官方源码或强行升级旧参考运行时。

## 本轮真实 Linux 组合证据

代码 `634dbaf2e45ec9cedf541581519dcbe436ac8e5b` 的 [push run 36393600685](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36393600685) 与 [PR run 36393606447](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36393606447) 中，旧版和新版 Linux job 均已通过；这两次run整体因Windows准备问题未全绿，不能将单job通过写成整轮通过。

新版实际 JSON 均确认 Gateway Python 3.12.14 / Hermes Python 3.14.7，`separate_hermes_runtime=true`。真实Gateway数据库、admission/claim/prebinding及HTTPS resolve/events/closed，官方Hermes HTTP/Agent/loader/middleware，原worker和实际文件/handle消费均通过。两身份PDF/JPEG并发验证2份，4次工具调用只有2次内容GET；真实暂存锁503分别第2次成功及第4次耗尽，历史文本/附件/文本顺序、create/fork/model-lock/session tip和FIFO断言保留。取消、实际30秒租约、缺结束hook模型错误、未接events/断连等均撤销；丢失closed时本地先收口，Gateway屏障分别30.99/30.69秒。

两个host-exit JSON均确认实际独立Hermes被SIGKILL、退出前下游正持有已验证流，worker因EOF正常退出并被回收（均0.018秒）；Gateway实际events断连、closed ACK为0、固定lease屏障后uncertain、三次旧owner/新nonce重放403、同线程FIFO均通过。实际宿主和Gateway审计违规均0；可选scratch导入被拒绝1次且明确未验证清扫功能。模型HTTP和微信原始取件为测试替身，其余上述链路没有替换。

同SHA的旧Windows PR job已通过86项回归（1项Linux专属未执行）、真实旧loader/6项middleware/HTTP探针。push旧Windows在单元通过后遇到固定源码下载429；新Windows在解包步骤失败。这些是历史准备失败，不与后续成功混写。

`3386c6d2` 的 push run 36394311219 已完成新旧四组全部门禁：新版 Windows 实际3.14.7执行 loader、六项 middleware、HTTP lifecycle 和 native 十场景；新版 Linux 实际3.12.14 Gateway与3.14.7 Hermes完成完整joint及独立宿主退出；旧版Linux/Windows回归均通过。相同代码的 PR run 36394316811 首轮新Windows和旧版两组通过，新Linux仅在固定源码下载连续HTTP429后失败，未进入探针；该任务单独重跑，不关闭来源验证或门禁。最终文档提交仍需核验其自己的CI。

该提交每个 Windows job 的单元回归为86项、85通过、1项Linux专属跳过；每个已执行Linux job为86项、80通过、6项Windows专属跳过。新版Windows push/PR两个native报告均 `ok=true`，实际半文件后终止宿主，worker分别0.013/0.015秒退出；新版Linux push的丢失closed屏障为30.44秒，host-exit的worker退出0.024秒，三项重放均403。报告的非预期审计违规为0，可选scratch清扫仍单独拒绝且不在验证范围。

## 结果状态与仍保留的边界

| 检查 | 已核验状态 |
| --- | --- |
| 独立 Python 3.14.7、固定源码与原候选来源核验 | 已完成；来源摘要如上。 |
| 早期 Python 3.14.7 单元 discover | `unit-314-20260928-070523-43f8f7c0.*`：73 项，72 通过、1 项 Linux 专属跳过，36.200 秒，退出 0。这是新增长路径回归及最终修复前的结果。 |
| 首次 discover 的环境失败 | `unit-314-20260928-070346-8e9722d5.*`：9 项 fixture 找不到 `powershell.exe`；仅给清空后的 PATH 补固定系统 PowerShell 目录，未改测试/产品后重跑如上。 |
| 新版原 payload 的 Windows native 九场景 | `native-original-fifth.stdout`：短目录九场景通过，含真实半文件后宿主终止/worker EOF；长路径专项仍失败，不能认定旧候选完整兼容。 |
| 长路径修复、原工具/权限/TLS/撤销回归 | 专项插件 11/11、隔离 support 14/14；`unit-fixed-final-314.stderr`：83 项中 82 通过，1 项 Linux 专属跳过。联合 guard 修正后，`native-fixed-second.stdout` 的真实 Windows 十场景全通过，包括278字符路径；新增隔离定向17/17通过；加入可选清扫阻断后 `native-strict-final.stdout` 的十场景再通过，宿主被强杀后worker EOF退出0.014秒。 |
| 旧参考两平台、新版两平台、Linux joint 与真实 host-exit CI | `3386c6d2` / push run 36394311219 四组全通过。首轮失败及修正保留在上文，未删除安全断言。 |
| 新 artifact / inventory / 最终 PR 状态 | 产品 `inbound.py` 已变化，需要最终 push 的新 Windows artifact；交付时核对完整 ZIP、七项载荷与 inventory，摘要记录在 PR #2。旧候选和既有工作根不访问、不覆盖、不重新 Stage/Check。PR 保持 Draft/Open。 |
| 实际 Windows AI 主机、CFserver、真实微信取件与用户 Profile | 本轮未验收、未安装启用、未替换客户端或凭据。 |

30 秒下载总预算、最多四次尝试、503 重试与不可续期 lease 的既有要求保持；等序 events 只保活，不延长预算或恢复终局 binding。不能把等待后台 PDF 完成的长期 pending 变成增加下载尝试或延长原预算。PDF 上游长期 pending 仍独立未解决。

历史 backend Lint 112 项仍保留（errcheck 8、govet 84、ineffassign 1、staticcheck 13、unused 6）；本轮不修改规则、版本或依赖消除无关红项。代码提交 `3386c6d2` 的 [常规 CI 36394316809](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36394316809) 仅 backend Lint 失败，format-backend、test-backend、test-frontend、lint-frontend、translations、docs 六项通过；最终交付仍核对最终 HEAD 的对应门禁。未在本地运行无关 FileBrowser backend/frontend、Playwright、业务构建或部署；对应源码不在本轮修复范围。

## 本轮文件范围与原因

本轮产品载荷只改 `plugin/inbound.py`；原 worker 和其下载/存储/预算实现没有修改。以下路径相对本集成目录，CI路径相对仓库根。

| 文件 | 原因 |
| --- | --- |
| `plugin/inbound.py` | 在保留原授权、reparse、identity/hash/撤销检查的前提下，对规范Windows长路径使用扩展表示。 |
| `tests/hermes_versions.json` | 并列保存新旧固定SHA、完整ZIP摘要和关键入口blob。 |
| `tests/hermes_probe_support.py` | 复用完整来源核验、导入前隔离和严格访问审计，明确拒绝可选全局清扫。 |
| `tests/test_hermes_probe_support.py` | 防伪来源、sandbox/SQLite/扩展路径、真实双guard、venv入口和导入拒绝回归；junction直接用原生NTFS，不提权。 |
| `tests/test_hermes_loader.py` | 两版真实loader注册、原只读与受控创建拒绝测试、来源与隔离报告。 |
| `tests/test_hermes_middleware.py` | 复用两版官方工具分派及原六项组件回归，继续标注合成binding。 |
| `tests/test_hermes_request_probe.py` | 保留真实HTTP/Agent/生命周期边界，按固定版本记录实际hook行为。 |
| `tests/hermes_joint_host.py` | 以独立解释器启动真实官方API/loader，安全的只读观测和有界IPC，不注入binding。 |
| `tests/test_hermes_joint_host.py` | Windows真实文件共享冲突、持续失败、坏JSON和超时回归。 |
| `tests/test_hermes_native_host.py` | 可重复Windows真实请求到NTFS/句柄/撤销十场景，Gateway与模型替身显式标注。 |
| `tests/test_gateway_hermes_joint.py` | 原真实Gateway组合入口增加版本选择和双Python进程；保留原history/model-lock/claim/budget等断言。 |
| `tests/test_gateway_hermes_host_exit.py` | 在独立Hermes解释器下复用原SIGKILL/EOF/lease/FIFO退出证明。 |
| `tests/test_inbound_host.py` | 复用合成HTTPS fixture但允许不手动建立adapter；新增已发送半文件的同步信号。 |
| `tests/test_inbound_plugin.py` | 先失败后修复的278字符真实工作副本、junction拒绝及结束闭流回归。 |
| `.github/workflows/filebridge-client.yaml` | 保留旧矩阵；新增独立准确3.14.7和两端分进程门禁、来源摘要及报告制品。 |
| `README.md`、`JOINT_HOST_VALIDATION.md` | 链接当前版本记录并保留带日期历史事实。 |
| `CURRENT_HERMES_COMPATIBILITY.md` | 来源、首次失败、逐层证据、候选差异和未验收边界。 |

## 可重复的现有入口

以下是已纳入CI的可重复入口，变量均须指向来源已核验的独立绝对路径；从清空继承环境、私有 HOME/Profile/TMP 的测试进程执行。不要指向运行中安装、现有 acceptance 或生产目录。每种运行时的实测边界分别见上文，不把入口本身当作通过证据。

```bash
# HERMES_PY 是已校验 Python 3.14.7 venv；SOURCE/ARCHIVE 是同一固定提交。
COMMIT=0f4a98f87c17007b81500239d0bd5b9574027b73
TESTS=integrations/hermes-filebridge/tests
"$HERMES_PY" -I -B -X utf8 "$TESTS/test_hermes_loader.py" \
  --hermes-source "$SOURCE" --hermes-commit "$COMMIT" --hermes-archive "$ARCHIVE"
"$HERMES_PY" -I -B -X utf8 "$TESTS/test_hermes_middleware.py" \
  --hermes-source "$SOURCE" --hermes-commit "$COMMIT" --hermes-archive "$ARCHIVE" --worker "$WORKER"
"$HERMES_PY" -I -B -X utf8 "$TESTS/test_hermes_request_probe.py" \
  --hermes-source "$SOURCE" --hermes-commit "$COMMIT" --hermes-archive "$ARCHIVE" --lifecycle

# Windows 显式 native 入口；默认执行当前插件和额外长路径场景。
# 比较旧制品时另加 --plugin-source <独立核验的 artifact/plugin>，只计九场景参考。
"$HERMES_PY" -I -B -X utf8 "$TESTS/test_hermes_native_host.py" \
  --hermes-source "$SOURCE" --hermes-commit "$COMMIT" --hermes-archive "$ARCHIVE" \
  --worker "$WORKER"

# Linux：Gateway Python 3.12 与 Hermes Python 3.14.7 真正分进程。
"$GATEWAY_PY" -I -B -X utf8 "$TESTS/test_gateway_hermes_joint.py" \
  --gateway-source "$GATEWAY_SOURCE" --gateway-archive "$GATEWAY_ARCHIVE" \
  --hermes-source "$SOURCE" --hermes-commit "$COMMIT" --hermes-archive "$ARCHIVE" \
  --hermes-python "$HERMES_PY" --worker "$WORKER"
"$GATEWAY_PY" -I -B -X utf8 "$TESTS/test_gateway_hermes_host_exit.py" \
  --gateway-source "$GATEWAY_SOURCE" --gateway-archive "$GATEWAY_ARCHIVE" \
  --hermes-source "$SOURCE" --hermes-commit "$COMMIT" --hermes-archive "$ARCHIVE" \
  --hermes-python "$HERMES_PY" --worker "$WORKER"

CF_FILEBRIDGE_INBOUND_TEST_EXE="$WORKER" "$HERMES_PY" -B -X utf8 \
  -m unittest discover -s "$TESTS" -v
```

旧参考使用旧固定提交、对应 archive 及原 CI 运行时，不把 `COMMIT` 替换后继续用 Python 3.14.7 就称为旧参考门禁。完整两平台执行顺序见 [filebridge-client.yaml](../../.github/workflows/filebridge-client.yaml)。
