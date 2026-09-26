# 2026-09-26 微信文件只读现场验收

## 证据等级

来源：操作者在本次协作中回传的 Windows/CFserver 终端输出与微信截图。本文记录这些现场结果，不声称维护者另行登录生产系统或直接取得原始日志。验收范围仅限下述身份、目录及单一测试文件的读取闭环。

## 部署与加载

- FileBrowser 服务端固定源码：`8ff37ef0da322aa2194d9ef37e26eb7f7035cbb2`。
- 独立客户端/插件制品源码：`04c7e717d856d8bf451fc18d7f5ae8cd04fc0c40`；实际 Windows ZIP 摘要已由操作者核对。
- HTTPS 内部 CA、服务器名称及指纹通过；错误 CA 与名称拒绝通过，系统全局信任未修改。
- 受限账号 userid2，Source `enterprise-files`，服务端 Scope `/wechat-acceptance`。原运行 Token 无 admin/api/share/realtime/preview；保留原 browse/download/create/modify/delete 签发边界。客户端/插件当前配置只读，不据此开放写工具。
- 2026-09-26 受控 Hermes 重载后，`cf_filebridge` enabled/configured=true，工具包含 `filebrowser_files`；已有工具集合保留。
- 之前身份和空目录查询已收到微信回复。该项目仍为联调阶段，不等于全生产退出条件满足。

## 真实文件内容回传

测试编号 `CF-FB-FILE-20260926-01`，资源路径 `/CF-FB-FILE-20260926-01.txt`，大小122字节。测试文件由操作者脚本通过现有 FileBrowser API 新建并完整回读；**不是微信创建**。

| 请求 | 时间（UTC） | 客户端 request_id | 操作者核验结果 |
| --- | --- | --- | --- |
| read | 2026-09-26T07:54:11.6168564Z | req-c1542963baf98d3781c3d6b6 | result=ok，122字节 |
| checksum | 2026-09-26T07:54:15.1856445Z | req-02c1bdd19593da0b524a8cb7 | result=ok，SHA-256匹配 |

操作者的校验程序给出 `WECHAT_REPLY_CONTENT_MATCH=PASS`、`BOTH_SHA256_MATCH=PASS`、`CLIENT_AUDIT_CORRELATION=PASS`、`WECHAT_FILE_CONTENT_ACCEPTANCE=PASS`。消息原文通过剪贴板输入校验，未手动改写回复。包含随机标记的完整内容没有提前作为答案发送给 Agent。

私人现场证据 basename：`wechat-verified-f266262f78a04bc09197269beb86692a.json`，仍在操作者安装目录内；不将凭据、完整配置、测试正文/随机值或整个日志提交到本仓库。

## 尚未核验或未交付

- 原始 Hermes 工具轨迹和 FileBrowser 持久审计的逐请求关联仍未复核；不把客户端审计当成服务器审计。
- 微信新建、修改、删除，完整 CRUD 尚未验收；操作者上传不能充当微信创建证据。
- 新建功能后续代码不因本记录而算已安装；旧的只读基线仍保持可用。
- 单次读取不证明跨会话身份隔离、并发写入、断线/掉电恢复、Token轮换或所有插件升级兼容。
- 两个相关 PR 的合并、后端 Lint 红项、统一新环境安装入口、备份恢复与正式发布均单独跟踪。不要为补证重新执行已发生的有副作用请求。
