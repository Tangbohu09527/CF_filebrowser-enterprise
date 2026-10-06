# 2026-10-06：既有 FileBrowser API → Hermes 原生读取实证

按 [PR #2 交接留言](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/pull/2#issuecomment-6006915789)
停止推进专用安装器路线。本次只有受限 HTTP 文本下载和同一文件的原生正文读取通过；
PDF、图片及微信端到端未验收。没有运行安装器、FileBridge CLI、专用下载 worker 或生产服务入口。

## 实际下载

在 AI 主机从既有受限配置中读取 HTTPS origin、已固定摘要的 CA 文件和 Token 引用。
秘密仅在 HTTP 请求进程内使用，没有进入 argv、模型、证据或本仓库。使用 Python 标准库
`http.client.HTTPSConnection`，启用 CA / 主机名校验、直连、不跟随重定向。
`GET /api/users?id=self` 确认当前账号非管理员，Source Scope 为已批准的验收目录；
它返回账号权限，不将其误称为 Token 的全部有效权限。服务端仍负责账号与 Token 权限交集。

| 项目 | 实际结果 |
| --- | --- |
| Source / scoped 逻辑路径 | `enterprise-files` / `/CF-FB-FILE-20260926-01.txt` |
| 下载 | `GET /api/resources/download?source=enterprise-files&file=…`，HTTP 200 |
| 实际字节数 | 122 |
| 本地 SHA-256 | `3de35378fe2ca21ed663c0751040d5fa69496a2996af420ffa4c0ba763b1663b` |
| 独立对照 | 另一次资源 API 的 `checksum=sha256` 响应与本地摘要、大小一致 |
| 原始样本基准 | 历史记录只有双方校验 PASS，没有保存可再次独立核对的原始样本摘要 |
| 保存 | 全新的私有 NTFS 验收目录，随机文件名，排他创建、限长、落盘后发布，不覆盖已有文件 |

资源 API 的摘要是独立于本地计算的服务端对照，**不是微信原始文件一致性证明**。
请求中的 `/` 是账号 scoped root，不再次拼接服务器 Scope。
本次保留既有配置的 1 MiB 下载上限，没有放宽权限或改动远端文件。

在该批准目录只做了一次非递归列表：两个历史验收 `.txt`、零子目录。
没有 PDF、PNG 或 JPEG，因此没有尝试这些格式的下载，没有扫描其它业务目录，也没有上传或生成远端替代样本。
本地测试夹具不计为现场样本。

## 官方原生读取

已安装官方源码 HEAD 为 `0f4a98f87c17007b81500239d0bd5b9574027b73`。
只读核对七个相关来源文件与先前固定快照的 SHA-256 一致；这不是整个安装目录完整性证明。
从官方 PM 的安装级元数据读取选中的 generation，并核对其 `pyvenv.cfg`：Python **3.14.7**。
没有运行 bootstrap / activate / repair，没有借用旧 3.11 环境的扩展模块。

实际链路为：

```text
上面的 122 字节下载文件（同一路径、同一 SHA-256）
→ tools.file_tools 的原生注册和 requirements 检查
→ tools.registry.registry.dispatch("read_file", path, task_id)
→ 官方 handler → ShellFileOperations → LocalEnvironment / Git Bash
→ 官方工具 JSON 原始结果 → 4 行实际正文逐行核对一致
```

`truncated=false`、无工具错误、未加载 `cf-filebridge` 插件。
这证明本机原生工具读取正文，**不是 Agent HTTP 会话、真实模型回答或微信实收证明**。
没有替换 handler / backend、monkey patch，或另写解析器代替原生读取。

任何 Hermes import 前清空继承环境，设置独立 HOME / HERMES_HOME / APPDATA / 临时目录，
禁用 lazy install；`-I -S -B` 避免真实 Profile 初始化、site 启动钩子及安装目录 pycache 写入。
只加入已核验官方源码和其选中的依赖目录。Python 审计限制读写、网络和子进程；
原生 backend 的五次 Git Bash 调用和一次源码 `git rev-parse HEAD` 留有私有记录。
跨平台探测对 `cgroup` / `mountinfo` 的尝试被审计拒绝，不影响正文读取。
该审计不是 OS 级沙箱，也不宣称能隔离任意同身份进程。

首次裸 3.14 解释器运行没有加载 PM generation，报 `ModuleNotFoundError`；
选中正确依赖目录后成功。另一次测试审计器未处理 Windows `executable=None`，修正测试记录器后重跑通过。
这些失败及成功证据均保留，没有据此修改已安装 Hermes 或安装依赖。

## PDF / 视觉与最小下一步

选中环境内 `anydoc` 和 `PIL.Image` 均完成隔离实际导入。当前没有证据要求安装 PDF 依赖；
此前裸解释器的缺包不能归结为服务 Runtime 缺包。
官方 PDF 路径为 `read_file → read_extract → anydoc`；缺包环境的官方入口是
`hermes pm install --extra doc-extract`，本轮未执行，也不建议在本次已可导入环境重复安装。
扫描 PDF 是否需额外 OCR 路由必须用实际样本判定，空文本不算阅读成功。

图片原生入口 `vision_analyze` 已做源码定位，但没有获批远端图片，
**实际图片输入接线未执行，真实视觉理解未执行**；Pillow 可导入不能替代这两项。
没有为凑结果发起模型请求或使用替身。

当前明确的下一步输入是：批准 Scope 中已有 PDF 与 PNG/JPEG 的明确路径，以及可取得的独立样本基准。
若当前目录确无样本，由有权限的操作者另行准备并批准；本任务不自动上传。
取得样本后沿用同一 HTTP 方法及原生工具，视觉仅用原有批准模型配置；
仍须实际验证 PDF 提取和视觉链路，依赖导入成功不能排除后续运行条件缺口。
已通过的文本链无需新客户端、worker、EXE、服务或 Skill；本轮不修改真实配置。
日后若把操作固化为轻量 Skill，它只能指导现有 HTTP / 原生工具，不能将文字约束当作服务端授权。

## 部分安装复核与未执行的回退方案

本次重新读取原事务的 checkpoint、inventory、备份和七个插件文件；没有沿用旧 PID。
2026-10-06 只读快照发现四个归属 Hermes 安装路径的 Python 进程、8642 / 9119 两个监听；
**不能沿用此前“服务停止”的结论**。本任务没有启停任何服务。

| 文件 | 当前状态 | 原备份 |
| --- | --- | --- |
| `__init__.py` | 旧版 | 摘要匹配 |
| `inbound.py` | 新旧相同 | 摘要匹配 |
| `inbound_control.py` | 新旧相同 | 摘要匹配 |
| `inbound_directory.py` | 新旧相同 | 摘要匹配 |
| `inbound_host.py` | 旧版 | 摘要匹配 |
| `inbound_content.py` | 新增版本 | 旧版原本不存在 |
| `plugin.yaml` | 旧版 | 摘要匹配 |

当前配置仍与事务 `config.before.yaml` 相同；before / after、staged inventory 和解析环境收据摘要匹配。
一个 `.cf-config-*.tmp` 仍保留。文件摘要相同并不能证明临时文件属于本次事务，不能自动认领或清除。

最小回退方案：先取得明确的现场变更授权，再重新核验文件摘要和进程归属、受控停机。
六个原有插件文件及旧配置有已核验备份，但本次它们已经是旧版或新旧相同，**无需盲目覆盖**。
新增 `inbound_content.py` 只有在重新证明归属且批准后才可隔离保留，不能直接删除。
未知临时文件继续保留。备份、checkpoint、候选、解析环境和旧客户端全部保留。
出现新变更即停止接管；不能把当前混合现场称为已回退的干净旧安装。
**本轮未执行回退、恢复、安装或 ACL 修改，新路线不以修复旧安装为前提。**

## 证据与仓库验证

实际本地下载路径、原始工具 JSON、脱敏 HTTP 结果、来源摘要及执行审计只保存在任务私有目录；
正文、随机验收标记、配置、主机地址和凭据不提交。
原始工具结果 SHA-256：`b36336cbc7267913f214e0aa1b842f11cf76d3f591785268b2108cfec7c37d5d`。
HTTP 证据 SHA-256：`71ec2ff914dd1a39d66068b149d403486ff8fc7bbe57d41da74b84a038de93cc`。

本次仓库仅修改说明，执行 `git diff --check` 和相关 Markdown 本地链接检查。
实际 HTTP 请求及原生读取是上述现场实证，不是模拟单元测试。
未运行业务构建、前后端测试或安装器回归：产品、工具和安装器源码均未修改。
历史 backend Lint 不变；旧 Gateway 宿主 30 秒租约限制不变，也不能迁移为这次 API 的授权结论。
不恢复 CFserver Worker、不操作微信、不修改 `legacy_runtime_confirmed`；微信端到端继续未验收。
