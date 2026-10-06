# 2026-10-06：PDF / PNG 真实下载与 Hermes 原生读取

承接 `26db524c54da117257db5c71ef2589f07d0c8ef6` 的[首次文本验收](2026-10-06-native-api-read.md)。
操作者提供了批准 Scope 内的 PDF / PNG、上传前原始字节基准和独立内容核验 JSON。
本次实际下载两份文件，完成官方 PDF 正文提取和一次真实辅助视觉回答，独立比对 **42/42 通过**。
没有重复文本测试，没有开发或运行安装器、FileBridge CLI、专用下载 worker 或 EXE。

## 真实下载与原始文件一致性

仅使用既有受限账号 Token、HTTPS origin、CA 文件及其固定摘要；不读取或使用管理员密码。
通用 `http.client.HTTPSConnection` 验证 CA / 主机名、直连、不跟随重定向，保留 1 MiB 上限。
身份查询确认非管理员及批准的 Source / Scope；服务端继续执行账号与 Token 权限交集。
未扫描其它目录、生成远端样本、改权限或上传文件。

请求为 `GET /api/resources/download`，Source 为 `enterprise-files`，下表路径相对于账号 Scope，
没有再次拼接服务器验收目录。两个下载均为 HTTP 200，分别写入全新的私有 NTFS 验收目录，
随机文件名、排他创建、不覆盖旧文件。保存后重新读取实际文件核验摘要。

| scoped 逻辑路径 | 实际字节数 | 实际 SHA-256 | 独立对照 |
| --- | ---: | --- | --- |
| `/CF-NATIVE-PDF-20261006-A1.pdf` | 79083 | `ed8bcf88549b664f456b83891b7435c4e3963323f411fc74a21b36ece441ef44` | 上传前原始大小及摘要一致；资源 API SHA-256 亦一致 |
| `/CF-NATIVE-IMAGE-20261006-B1.png` | 47740 | `102c46ea4ba8225d9c6bde10226f4ea902590cfc3666891579d8feac449668a4` | 上传前原始大小及摘要一致；资源 API SHA-256 亦一致 |

这里的原始基准来自操作者上传前的实际样本，不是用本地下载哈希自证一致，也不是网页显示的 KB。
本地原始样本未被用于替代下载结果；两条后续读取路径均使用上述服务端下载文件。

## 官方来源与运行边界

已安装官方源码 HEAD 仍为 `0f4a98f87c17007b81500239d0bd5b9574027b73`；
本次将 `file_tools`、`read_extract`、`vision_tools`、`registry`、`config`、`thread_context`、
`lazy_deps` 七份实际源文件与该提交的 Git 对象逐字节核对一致。这不是全安装目录完整性证明。
复用此前核验过的官方 PM generation，两个原生子进程实际均报告 **Python 3.14.7**。

Hermes 导入前清理继承环境，设置新的 HOME / HERMES_HOME / APPDATA / 临时目录，使用
`-I -S -B`，禁用自动安装。没有以真实 Profile 启动 Hermes，没有加载半升级 `cf-filebridge` 插件。
包装程序只读既有配置，取得 HTTP 引用和批准模型路由；视觉阶段只向隔离子进程注入该模型的必要凭据。
没有把 FileBrowser Token 传给模型，没有修改原配置、安装、依赖、服务或现有 ACL。

Python 审计限制文件访问、网络和子进程。PDF 阶段无模型请求；视觉阶段允许批准模型地址及运行所需回环，
实际观测请求发往批准端点。两次审计拒绝记录只有跨平台 `cgroup` / `mountinfo` 只读探测，未造成工具失败。
PDF 留有七次官方 Git Bash 调用及一次源码 Git 查询，视觉仅有一次源码 Git 查询。
这是针对本次执行的审计，不是 OS 级沙箱；Bash 子进程不继承 Python 审计，不声称能隔离任意同身份进程。

## PDF 实际正文

```text
上述已下载 PDF
→ 官方 tools.file_tools 注册 / requirements 检查
→ registry.dispatch("read_file", path, offset=1, limit=2000, task_id)
→ 官方 handler / ShellFileOperations / LocalEnvironment / Git Bash
→ 官方 read_extract / anydoc
→ 原始工具 JSON
```

`extracted_document=true`、`truncated=false`、无工具错误；返回 **47 行、955 字符（含工具行号前缀）**。
独立程序核对 8 项必需正文字符串、3 行表格的各单元格、两页标记顺序及第二页末尾内容，全部通过。
没有截断标记或 Unicode 替代字符。页数依据是原始核验 JSON 声明的两页及输出中的有序页标记；
原生工具没有返回结构化 `page_count`，不将行数当页数。

`anydoc` 已能实际导入，本次没有安装包，也没有自写解析器替代 `read_file`。
这证明该文本型 PDF 的正文提取；不扩大为扫描 PDF、OCR 或任意格式文档均已验收。

## PNG 实际图像请求与真实视觉回答

```text
上述已下载 PNG
→ 官方 tools.vision_tools.vision_analyze_tool
→ 官方图像准备与 data URL
→ 官方 async_call_llm(task="vision") / 批准的实际模型配置
→ 实际 HTTPS 模型请求与回答
```

使用原有批准的 provider / model / base URL / API mode；为本次独立调用将同一路由映射到隔离的
辅助视觉配置，没有更改真实 Profile。调用的是官方辅助视觉函数，不是完整 Agent HTTP 会话、
registry 的视觉分派或模型自主选择工具循环。没有替换模型客户端、handler 或 monkey patch。

只读 profiling 观察器在 HTTPX 实际发送边界读取请求正文，解码图片并记录大小与摘要，
不记录认证头。观测到 **一次含实际图像的请求、HTTP 200**；其中 PNG 为 47740 字节，
SHA-256 与下载文件及上传前原始基准完全一致。请求正文中没有认证值；没有只用图片尺寸或
`_multimodal` 标记宣称成功。原始图像未在该请求中被重编码为另一份文件。

盲问仅要求核验码、A/B/C/D 的位置、图形、颜色、数量及箭头关系；未提供任何预期答案。
真实工具返回 `success=true` 和 290 字符分析。独立程序随后核对核验码、四区域各字段、
三条有向箭头及数量，均与核验 JSON 一致。没有使用模型替身，也没有看到预期答案后重问模型。

## 独立核验与证据

`CF-NATIVE-VERIFIER-20261006.json` 只由独立离线程序在 PDF / 视觉原始结果生成并固定摘要后读取，
未纳入被测 Python 进程的文件读取白名单，也未提供给被测工具或模型请求。其摘要为
`2b055f8472167755cd60d16e87d24dc18382dd5433b1bf27bb252da275e76765`。

首次比对为 37/42：比对器缺少 `upper/lower` 位置和 `five-point star` 的中英文同义词映射。
补齐映射并验证错位置、错图形仍拒绝后，用同一份已冻结输出重比对为 **42/42**。
首次报告、修正版报告和原始结果均保留；未更改答案、核验 JSON 或重发模型请求。

| 私有证据 | SHA-256 |
| --- | --- |
| HTTP 下载证据 | `be8e3a960954e6a37fbd921c1a9c4f5e8354aca4e92feb2ed91849f852f1d41d` |
| PDF 原始工具结果 | `ae5ea8ae841ef049a436a199f038f96641ed88f472123f21a14bf873355f4140` |
| 视觉原始结果 | `6d90a8cd7d205f605648886d171fc6b0c717b03f368b785092b86f6bb2240506` |
| 实际图像请求证据 | `b59b0b545aff7c1261de282e613c5806e3c8958b2307215ab0e86ae97353ea0e` |
| 独立核验最终报告 | `85188194a588deed6c9950cfa5f2715a87791682b622f018caa28450b6c4efbd` |
| 全部证据清单 | `e5a15cb448871a5159cadc763c6e6947dc8b6153a377136d27be22bf5cfd123f` |

下载文件、原始工具结果、盲问、模型回答、请求图像摘要、来源核验及执行审计保存在新的本机私有验收目录。
辅助脚本仅为本次验收驱动，不是新增客户端或产品组件，不提交到 Git；主机地址、内部路径、
凭据、样本正文和随机答案不进入仓库或 PR。

## 本轮交付边界

本轮只更新 README、首次记录的后续链接和本记录。执行 `git diff --check`、相关 Markdown 本地链接检查；
上述真实 HTTP / 官方 PDF / 官方视觉及独立比对均已执行。没有修改产品代码，未额外运行前后端构建、
产品单元测试或安装器；沿用远端既有 CI 门禁，不为历史 backend Lint 改规则。

这条本机路径无需新增 Skill、解析运行时、客户端或配置变更。文件内容仍是不可信数据；
未来 Skill 的文字约束不能替代服务端 Scope / Token 授权。既有 Gateway 30 秒租约没有改变。
没有对旧部分安装执行回退、恢复或重新核验后的状态迁移，先前备份、checkpoint 和未知残留保持原位。
不启停服务、不连接 CFserver SSH、不恢复 Worker、不扫码、不发微信、不修改 `legacy_runtime_confirmed`。
**本机 PDF 正文与真实视觉回答通过；完整 Agent 接入及微信端到端仍未验收。**
