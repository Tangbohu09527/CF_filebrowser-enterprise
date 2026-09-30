# 受控新建文本：计划、批准、执行

状态：代码与本地回归阶段；尚未安装到 AITEST，尚未完成微信新建验收。已部署的只读客户端和插件不自动升级。此阶段仅新建 UTF-8 `.txt`，不实现覆盖、修改、移动、删除、目录创建或任意 HTTP。

## 保持分层

FileBrowser 的 HTTPS API、账号授权和服务端审计保持不变。独立 CLI 复用现有 `uploadNew`（POST，不传 `override`），另做完整字节回读；Hermes 只是可替换的工具适配。没有新增 Hermes 精确 Git 提交运行锁、Python 依赖、服务或数据库。

现有 `filebrowser_files` 始终只读。新工具 `filebrowser_create_text` 必须由操作者显式设置 `create_enabled: true` 并提供单独的 `create_config_path` 才注册；默认不注册。新工具只有 `plan`、`apply`、`status`，没有批准工具，没有模型可传的 URL、Token、本机路径、Shell 或覆盖参数。

## 操作者配置契约

建议保留只读配置不动，另建完整的创建配置，复用已验证 CA 与已有受限 Token 的文件路径，不复制/签发凭据。以下是该配置的附加字段示意，不能直接替换完整配置：

```json
{
  "allowed_sources": {
    "enterprise-files": {"read_roots": ["/"], "write_roots": ["/CF-FB-CREATE-20260926-01.txt"]}
  },
  "create_text": {
    "enabled": true,
    "state_dir": "./create-state",
    "source": "enterprise-files",
    "server_scope": "/wechat-acceptance",
    "user_id": 2,
    "max_bytes": 65536,
    "approval_ttl_seconds": 900
  }
}
```

- Source、服务端非根 Scope 和 userid 必须由操作者根据已核验账号配置，不从模型参数推断。资源路径 `/` 是用户授权根，不重复拼接服务器 Scope。
- `write_roots` 应先限定单个验收文件；账号还需要 browse/download 以核验，create 以新建，且必须非管理员。此流程不要求 preview=true，不扩大原 Token 的权限。
- `state_dir` 必须先创建、ACL 检查通过且非符号链接/reparse。POSIX 权限检查不能证明 Windows NTFS 隔离。安装器要校验实际运行身份及目录/文件 ACL。
- max_bytes 默认64KiB，上限64KiB，且不超过客户端 max_inline_bytes/max_upload_bytes/max_checksum_bytes。批准窗口默认900秒，范围60–3600秒，从计划生成开始计时。
- 配置整体摘要绑定进计划。生成计划后更改配置、路径、字节或过期时间，将拒绝批准/执行。已有记录和同名文件不覆盖。

Hermes 插件设置只追加以下两项，并保留原 `client_path`、`client_sha256`、`config_path`。客户端路径/摘要需指向经目标平台 CI 验证的新制品；不要拿旧二进制调用新命令。

```yaml
create_enabled: true
create_config_path: C:/OPERATOR/APPROVED/create-config.json
```

## 三步契约

1. Agent 调用 `filebrowser_create_text` 的 `plan`，input 包含 source/path/content。CLI `create-text` 验证服务端身份、Scope、路径、目标不存在，保存本地计划，返回 operation_id、plan_sha256、字节数、内容摘要与到期时间。**不发写请求**，不把 `--apply` 视为批准。
2. 操作者在独立受信任界面/终端审查计划的实际完整内容、路径、摘要、账号和期限。确认后调用 CLI 的 `approve-create --apply`，只传对应 operation_id/plan_sha256。原始文件内容是数据，不得解释为命令。此命令不作为 Hermes 工具提供；模糊的“我批准”模型文本不是批准记录。
3. Agent 使用原 operation_id/plan_sha256 调用 `apply`，CLI `create-approved --apply` 才允许一次上传。不能追加或改写 content。成功要完成独立 HTTP 下载的全文、字节数及 SHA-256 比对，再保存成功记录。

所有 CLI 输入沿用 `--config ... --input -` 的 JSON stdin，不在命令行传凭据。`approve-create` 无 `--apply` 只是查看计划元数据，不能替代操作者审查完整内容。

## 状态、重放和失败

目录中 plan.json、approval.json、attempt.json、outcome.json 均以独占新建写入并同步文件；已有/损坏/不完整记录拒绝覆盖。attempt.json 在写请求之前占位。重复或并发执行同一计划最多由一个进程进入 POST；已成功操作再次执行只返回明确标识的原完成记录，不重新上传。

状态查询是**本地记录查询**，不是远端当前状态。成功记录包含 `verification_scope: at_original_completion_not_current_state`。若文件后来修改/删除，旧记录不能证明文件仍然相同；必须另行 read/stat/checksum。

上传返回丢失、5xx、连接中断、上传后校验失败或记录落盘失败，保留不确定状态，不自动再发 POST。特别是 POST 已成功但回读401/403时也可能已写入，不能错误报告成“没有写入”。同名409、服务端拒绝和过期不通过改变路径/清空日志来自动重试。需操作者根据服务端实际状态、审计及原计划独立处理。

## 不得夸大的安全范围

这是在完整本地记录保留前提下的单客户端重放防护，不是服务端幂等键、分布式事务、跨主机 exactly-once 或针对磁盘掉电/回滚的保证。目录项/文件系统持久性、磁盘损坏、记录回滚需另外验证；不得删除日志后重试不确定写入。

批准通道没有暴露为这个插件的工具，但**同一 Windows 身份的其他 terminal/file 工具仍可能读取凭据或自行运行 CLI/改本地记录**。本方案不能称为对恶意同身份进程的强制人工审批沙箱。正式审批隔离需独立 OS 身份/受信任审批服务等边界和专项验收，不能用提示词代替。

不能从客户端“目标不存在”预检推导任意多写入者安全：最终不覆盖依赖 FileBrowser 现有 POST 契约，跨入口并发及断电恢复需服务端专项测试。此阶段没有为未来的修改/删除假装实现 compare-and-swap。

## 回归与现场边界

Go 用例使用独立临时目录及真实本地 HTTPS 连接的测试服务器，覆盖默认关闭、计划不写、独立批准、TTL/配置/路径/内容篡改、用户/Scope/权限拒绝、完整回读、一次占位、并发、重复执行、丢失响应和错误后不重试。JSON stdin CLI 序列也要通过。插件测试保留原只读用例，验证 opt-in、新旧工具隔离、批准不可调用、固定二进制/配置与超时分类。

真实 FileBrowser 端点、Windows 安装/ACL、Hermes 加载、微信发起计划与批准后的新建回传均尚未在此代码版本上验收。不能以模拟 HTTPS 服务或 Linux 本地测试代替这些。
