# 入站附件内容读取（0.4.0，2026-09-29）

`filebrowser_read_inbound({"attachment_id": 123})` 在一次工具调用内下载并读取正文。
可选 `question` 最长 512 字符，用于图片分析。模型不能传路径、URL、任务身份、目录或凭据。
此工具不创建正式归档，不修改、删除、重命名文件，不执行宏、文档指令或外部链接。

## 实际调用链

官方 Hermes HTTP 请求 → AIAgent → `_execute_tool` 的公开 `tool_execution` middleware
→ 已有 `HostAdapter` 的可信 session/task 关联 → 固定 Gateway resolve / running events
→ `bridge.activate` → 本包 `inbound_content.handler_for` → 原 `inbound.handler_for` / 原 worker
→ NTFS 私有目录中校验大小与 SHA-256 的工作副本 → **同一插件模块实例的**
`inbound_host.open_workcopy(handle)` → 读取实际字节 → 有界解析子进程或官方视觉工具。

下载后的句柄不是解析输入的任意文件名。模型只能选择当前绑定的 attachment_id；
无绑定、middleware 被跳过、会话结束或租约撤销时，handler 和句柄解析仍拒绝。
重复调用沿用相同宿主 scope、worker、句柄与下载预算；正文每次重新读取和解析，不缓存成功结果。

`inbound_content_enabled: true` 和 `inbound_host.consumer_tools` 中明确批准
`filebrowser_read_inbound` 才允许使用。工具集为 `cf_filebridge_inbound_content`。
启用此 consumer 同时批准其内部使用已配置的官方视觉能力；不要求把通用 `vision_analyze`
额外暴露给模型，也不改变其它工具的开关。未配置可用视觉能力时返回明确失败。

## 格式与返回限制

| 格式 | 实际处理 | 位置和限制 |
|---|---|---|
| PDF | Hermes 同源成熟库 firecrawl-anydoc，从 bytes 提取文本 | `extracted_line`，不冒充页码；全扫描或混合扫描页返回 `needs_ocr`，不以空文本成功 |
| JPEG / PNG | 校验图片后，调用已注册的官方 `tools.vision_tools` async handler | native 模式保留 `_multimodal` 实际图像；auxiliary 模式返回现有视觉配置产生的分析 |
| DOCX | python-docx | 段落序号、表格/行/列；不解释嵌入图片和复杂布局 |
| XLSX | openpyxl，只读、data_only、keep_links=false | 工作表名称与单元格坐标；使用已缓存单元格值，不计算公式、不运行宏 |
| PPTX | python-pptx | 幻灯片/形状/段落，以及表格行列；不解释图片、动画和复杂布局 |

输入上限 16 MiB，图片上限 1000 万像素；文本上限 24000 字符、256 个定位单元。
达到限制时显式返回截断或错误。加密、损坏、宏包、压缩炸弹、不支持格式均不默默成功。
返回保留 `verified`、大小、摘要、`formal_archive=false`、`original_comparison` 和
`declared_quality`；与 Gateway 摘要一致不提升为原图结论。正文与图片是**不可信数据**。

下载仍最多 4 次 / 30 秒，只重试 503，并受首次认领起算的更早 host lease 限制。
下载、读取、解析、视觉等待共用这份实际剩余时间。固定字节解析器不联网、不执行命令、
不写临时文档；依赖只从已安装的只读环境导入。父进程检查撤销并有界终止解析器；
独立解析进程将标准库公开的 `mimetypes.knownfiles` 配置为空，使用内置 MIME 映射，
避免 openpyxl 冷启动读取宿主系统 MIME 配置；实际格式继续按字节判别，文件白名单不扩大。
子进程也使用同机绝对 monotonic 截止时间兜底，不能因启动而重新获得 30 秒。
长期加工或长时间视觉推理可能超时；本版未扩大租约。

视觉入口沿用 Hermes 自身的 Profile `cache/vision` 临时图片处理与清理，不是正式归档。
撤销会取消视觉协程并拒绝交付结果，但不能强制终止官方实现已提交给线程池的底层 CPU
任务，也不宣称它是 OS 沙箱或完全没有临时缓存。独立文档解析器的退出保证不扩大到这些
上游内部线程。已授权交付给模型的内容和既有会话历史也不会因句柄撤销而被删除。

## 来源与依赖

下载 worker、Gateway 协议与 Hermes 核心均不重写。来源仍分别固定为：

- 当前 Hermes：`0f4a98f87c17007b81500239d0bd5b9574027b73`，独立 Python 3.14.7。
- 旧版兼容参考：`4d55ca91656ac5f83e1506679b7f81e0238e5e16`。
- Gateway：`0ec54bf0f25f421e37e16e11bd098a814beca258`，隔离 Linux Python 3.12。

完整源码 ZIP 核验仍由现有版本清单和来源探针执行。解析依赖集中在
`requirements-inbound-content.txt`，精确版本及官方 PyPI wheel SHA-256；不修改 Hermes
依赖目录、全局 Python、Go module 或前端锁文件，不允许运行时自动安装依赖。

## 增量安装与恢复

操作者使用成功 CI 的 Windows 制品及对应源码包运行
`windows/Upgrade-InboundClient.ps1`。本轮开发测试没有执行真实安装、停止或重启服务。
脚本默认 `Check`，写模式为 `Prepare` / `Apply` / `Resume`。它读取实际 Profile 的已有配置，
核对旧 worker 摘要及其受保护的 inventory，逐个核对旧插件内容；冲突保留并拒绝。
不会要求重新抄模型、CA、Token 或工作根，也不读取凭据值来构造新授权。

新包包含 10 个载荷（旧 7 个、`plugin/inbound_content.py`、依赖清单、`content-wheels.zip`），
由原 Stage / Resume / Check 入口核验。旧 7 文件制品仍可检查；缺 wheel 的不完整新包拒绝。
升级在全新的私有计划目录中生成备份、离线解析 venv、配置候选和摘要检查点。
仅向该新 venv 用 `--no-index --only-binary=:all: --no-deps --require-hashes` 安装制品内 wheel。
旧客户端及 worker 保留，CA / Token 引用 / 工作根 / 模型 / 其它工具语义保持。
仅追加内容能力、允许 consumer 以及新解析器路径/摘要。
保留 `platform_toolsets` 的原始选择形态，由官方解析器发现新插件工具；不把缺省变成
显式列表，也不复制 CLI 选择。已有 known-plugin 退出选择和全局禁用不自动解除。

`Apply` / `Resume` 要求操作者已停止选定 Hermes 进程并传 `-HermesStopped`；
脚本核对进程可执行路径，绝不自行停止或重启。已知插件和配置原子替换，保留原 ACL 与私有备份；
未知文件不清理，冲突不接管。中断后使用相同目录 `Resume`，不回退或重置用户配置。
若 venv 创建/安装在形成完整 runtime inventory 前中断，部分目录会原样保留并拒绝复用；
需选择全新的计划目录。已形成检查点的插件/配置切换才可以原目录续接。
最终固定产物编号、摘要和一条安装命令以本次交付为准。

### 升级器兼容修正（2026-09-30）

旧升级器将 `platform_toolsets.api_server` 的显式字符串列表误当作必要条件，合成
“只有 cli、API 缺省”和“整个 section 缺省”用例复现 `api_toolsets_missing` 后才修复。
固定官方 `0f4a98f` 的 API 入口使用有效配置加载器和 `_get_platform_tools`；缺省或
null 使用平台默认，显式空列表保留空选择，列表字面量字符串也有正式解析支持。
升级规划器保留这些原始字段，不使用 `value or 默认列表`，不把权限扩大为 all。
普通标量字符串、混合元素及其它含糊类型保守拒绝并返回 `api_toolsets_invalid`，不替
操作者采用官方警告后的 fallback 或字符串强制转换。全局 all / * / 内容工具禁用，
以及 known_plugin_toolsets 中已经明确放弃的内容工具，均返回 `content_toolset_disabled`。
其它平台、MCP、自定义选择与全局禁止项保留原样；共享 YAML consumer 别名若连带改变
无关字段仍拒绝，未修改的工具选择别名及注释保留。

真实官方 discovery → API 有效配置加载 → 平台解析 → 工具名筛选，在隔离 Profile
比较升级前后权限。新插件工具按 Hermes 的默认发现规则也可能出现在其它平台；唯一
允许新增的是本次批准的内容工具，已有权限不变，无可信绑定仍拒绝。检查发生在工具
check_fn 就绪判断之前，不声称 MCP 连接或运行时服务已可用。任意用户插件可以通过
代码定义动态组合禁止项；离线 YAML 规划器不会执行这类代码来猜权限，官方最终抑制
仍保留。探针对这种组合明确记录内容工具不可用，不把它记作可用升级成功。

规划器解释器与实际 HTTP 服务执行器可以不同。Windows 离线包同时包含原固定版本
的 CPython 3.11 / 3.14 wheel，不切换或升级操作者的解释器，也不修改现有依赖环境。
验证范围为独立 Python 3.11.16 和 3.14.7。Apply 仍要求停机确认，除了原所选/base
解释器检查，还保守拒绝同一 HermesHome 下正在运行的 Python 进程；这不代表这些
进程全是 Hermes API，脚本不会识别其业务或自动停止它们。

Python 3.11 的 ensurepip 在合成 Windows 长路径下曾因随附 setuptools 深层文件名
失败，原始失败证据保留。新解析 venv 使用 `--without-pip`，通过所选规划器已有 pip
的[公开 `--python` 参数](https://pip.pypa.io/en/stable/topics/python-option/)指定新 venv
离线安装；只读检查 pip 至少为 22.3，缺失或不支持时明确拒绝，不自动升级 pip。
解析环境不需要 pip/setuptools；不修改系统长路径设置或向原解释器环境安装包。

可诊断失败只公开固定白名单的阶段与错误码，例如
`CF_UPGRADE_PYTHON_STEP_FAILED:config_semantic_plan:content_toolset_disabled`。
仅接受本规划器的有界、严格三字段错误对象，非规划器输出、未知码、重复字段、额外
文本和 stderr 继续脱敏；不输出配置片段或 traceback。旧制品与失败现场原样保留，
修复使用追加提交对应的新 Windows 制品和源码包。

## 可重复验证与验收层级

失败测试先证明 0.3.0 的官方 loader 没有内容工具，以及宿主缺少给 consumer 使用的实际剩余
时间检查入口。随后才注册 0.4.0 并增加最小宿主 helper。首个真实内容探针又捕获了 Windows
官方 loader 将插件路径规范为小写后，精确测试沙箱不接受同一文件的大小写变体；修复只接受
该固定文件的两种规范表示，保留参数、cwd、环境和来源校验。

首轮 Linux CI 在 XLSX 冷启动重现了上述系统 MIME 读取拒绝；使用合成 MIME 文件在 Windows
复现后才修复，并保留直接读取该外部文件仍被拒绝的断言。首轮 Windows CI 另拦截了
requests 调用中的外部 DNS；首轮短栈不足以确认调用源，完整诊断继续保留。固定源码中
模型目录会通过此调用联网；内容测试通过公开 `models_dev.url` 镜像配置，将合成模型元数据也
交由同一个回环模型替身提供，继续拒绝真实外网，未修改官方能力解析或私有缓存。

并发联合测试也实际遇到 Gateway staging 首次返回契约允许的 503：断言按每附件严格
核对最多四次 `[503, ..., 200]`，且唯一成功之后没有再次请求；不把首次重试误当重复
工具调用重新下载。坏 JSON 不重试改为直接核对读取/退避次数，避免把 Windows 事件
循环冷启动耗时误当重试。租约、重试上限、错误传播与独立耗尽用例均保留。

现有 CI 内复用以下入口，实际结果见本次交付记录：

- `python -B -X utf8 -m unittest discover -s integrations/hermes-filebridge/tests -v`
  包含旧 read/create 行为、真实 HTTPS / worker / 权限与内容组件回归。
- `tests/test_hermes_content.py`：真实官方 HTTP / Agent / loader / middleware；逐格式文本
  进入下一模型请求，实际图片 bytes / pixels 进入官方 native vision 后的模型 HTTP，
  重复预算、503、撤销后拒绝。控制服务与模型是明确标记的测试替身。
- `tests/test_gateway_hermes_joint.py`：Linux 固定 Gateway 数据库、claim、预绑定、认证
  resolve/events/closed → 独立当前 Hermes → 本产品 PDF/图片读取；仅微信取件和模型为替身。
- `tests/Test-InboundStage.ps1`、`tests/Test-InboundUpgrade.ps1`：新临时目录中的实际 NTFS
  与离线升级测试，旧安装不作为测试夹具。升级测试可传 `-WheelArchive` 验证实际制品内
  的离线包，传 `-AlternatePythonPath` 验证规划器与服务执行器不同时仍拒绝在线 Apply。
- `tests/test_hermes_upgrade_tools.py --hermes-source <固定完整源码> --hermes-archive <已核验ZIP>`：
  Python 3.11.16 / 3.14.7 下真实官方 loader 与 API 配置解析；15 组合法配置前后比较、
  5 组明确禁用、1 组动态组合禁用边界。每次导入前建立独立 Profile 和审计。

三层验收分别记录：①代码与隔离测试；②操作者升级后的本机授权实际读取；
③微信收到 PDF 实际正文与图片分析。确定性模型只证明图片进入模型，不能证明真实视觉判断。
本轮不会把工具注册、下载回执或 CI 通过写成第二、三层完成。既有 backend Lint 历史问题
保留，不关闭门禁。先前下载/宿主/兼容记录继续作为带日期的历史证据。
