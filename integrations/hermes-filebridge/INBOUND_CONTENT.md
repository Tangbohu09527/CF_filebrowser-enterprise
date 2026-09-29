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
仅追加内容能力、允许 consumer、工具集以及新解析器路径/摘要。

`Apply` / `Resume` 要求操作者已停止选定 Hermes 进程并传 `-HermesStopped`；
脚本核对进程可执行路径，绝不自行停止或重启。已知插件和配置原子替换，保留原 ACL 与私有备份；
未知文件不清理，冲突不接管。中断后使用相同目录 `Resume`，不回退或重置用户配置。
若 venv 创建/安装在形成完整 runtime inventory 前中断，部分目录会原样保留并拒绝复用；
需选择全新的计划目录。已形成检查点的插件/配置切换才可以原目录续接。
最终固定产物编号、摘要和一条安装命令以本次交付为准。

## 可重复验证与验收层级

失败测试先证明 0.3.0 的官方 loader 没有内容工具，以及宿主缺少给 consumer 使用的实际剩余
时间检查入口。随后才注册 0.4.0 并增加最小宿主 helper。首个真实内容探针又捕获了 Windows
官方 loader 将插件路径规范为小写后，精确测试沙箱不接受同一文件的大小写变体；修复只接受
该固定文件的两种规范表示，保留参数、cwd、环境和来源校验。

现有 CI 内复用以下入口，实际结果见本次交付记录：

- `python -B -X utf8 -m unittest discover -s integrations/hermes-filebridge/tests -v`
  包含旧 read/create 行为、真实 HTTPS / worker / 权限与内容组件回归。
- `tests/test_hermes_content.py`：真实官方 HTTP / Agent / loader / middleware；逐格式文本
  进入下一模型请求，实际图片 bytes / pixels 进入官方 native vision 后的模型 HTTP，
  重复预算、503、撤销后拒绝。控制服务与模型是明确标记的测试替身。
- `tests/test_gateway_hermes_joint.py`：Linux 固定 Gateway 数据库、claim、预绑定、认证
  resolve/events/closed → 独立当前 Hermes → 本产品 PDF/图片读取；仅微信取件和模型为替身。
- `tests/Test-InboundStage.ps1`、`tests/Test-InboundUpgrade.ps1`：新临时目录中的实际 NTFS
  与离线升级测试，旧安装不作为测试夹具。

三层验收分别记录：①代码与隔离测试；②操作者升级后的本机授权实际读取；
③微信收到 PDF 实际正文与图片分析。确定性模型只证明图片进入模型，不能证明真实视觉判断。
本轮不会把工具注册、下载回执或 CI 通过写成第二、三层完成。既有 backend Lint 历史问题
保留，不关闭门禁。先前下载/宿主/兼容记录继续作为带日期的历史证据。
