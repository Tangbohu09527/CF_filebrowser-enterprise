# API 契约

本文档定义 FileBrowser Enterprise `v1.0-beta` 的企业 API 基线。调用方不得依赖未在本契约中声明的兼容行为。

## Authorization Header

API 客户端必须使用 Bearer Token：

```http
Authorization: Bearer <token>
```

- `Bearer` 方案名称不区分大小写；客户端应使用上述标准写法。
- Header 缺失、格式错误或 Token 无效时，服务端返回 `401 Unauthorized`。
- 新集成不得通过 URL 查询参数传递 Token，避免 Token 被浏览器历史、代理或访问日志记录。
- 浏览器会话 Cookie 和 WebDAV 兼容认证属于各自协议入口，不改变企业 API 的 Bearer Header 约定。

## Token 规则

- Token 必须绑定用户身份，包含或关联签发时间、过期时间，并支持服务端撤销。
- 有权限快照的 Token 按“用户当前权限 ∩ Token 权限”计算有效权限；签发时请求的权限不得超过用户权限。
- 使用当前用户权限的状态型 Token 在每次请求时读取用户现有权限，用户权限撤销立即生效。
- Token 过期、被撤销、签名无效、找不到所属用户或权限版本不兼容时必须失败关闭，并返回 `401 Unauthorized`。
- Token 仅在创建时返回完整值。调用方必须按密钥管理，禁止写入源码、URL、普通日志或错误消息。

## 权限模型

有效授权由以下约束共同决定：

```text
有效权限 = 用户当前权限 ∩ Token 权限 ∩ Source/路径范围 ∩ Share/协议约束
```

权限项包括：

| 权限 | 约束 |
| --- | --- |
| `api` | 创建、查看和撤销 API Token |
| `admin` | 管理操作；不得授予 Agent 或自动化身份 |
| `create` | 新建文件、目录或上传新资源 |
| `modify` | 覆盖或修改已有资源 |
| `delete` | 删除已有资源 |
| `share` | 创建和管理 Share |
| `browse` | 浏览目录、发现资源和读取元数据 |
| `preview` | 缩略图和在线预览；同时要求 `browse` |
| `download` | 读取或导出原始文件内容；同时要求 `browse` |
| `realtime` | 接收实时更新 |

所有入口必须按目标资源的实际状态检查权限。例如，新建资源检查 `create`，覆盖已有资源检查 `modify`，不能用其中一项替代另一项。管理员之外的调用仍须满足 Source、路径和 Share 边界。

## 错误码规范

错误响应使用 HTTP 状态码表达类别，并返回 JSON：

```json
{
  "status": 403,
  "message": "permission denied"
}
```

| HTTP 状态码 | 含义 |
| --- | --- |
| `400 Bad Request` | 参数、Header 或请求体格式无效 |
| `401 Unauthorized` | 未认证，或 Token 缺失、无效、过期、撤销或版本不兼容 |
| `403 Forbidden` | 已识别身份，但有效权限、Scope、Share 或协议约束不允许操作 |
| `404 Not Found` | 资源不存在，或为避免越权枚举而不公开资源状态 |
| `405 Method Not Allowed` | 资源存在，但请求方法不受支持 |
| `409 Conflict` | 资源状态、并发操作或目标名称发生冲突 |
| `413 Content Too Large` | 请求体或上传内容超过允许大小 |
| `429 Too Many Requests` | 请求频率或认证失败次数限制已触发；客户端应遵循 `Retry-After` |
| `500 Internal Server Error` | 未预期的服务端错误 |

- `status` 必须与 HTTP 响应状态码一致。
- `message` 用于诊断，不作为稳定的程序分支标识；客户端必须按 HTTP 状态码处理错误。
- 错误响应不得包含 Token、密码、密钥、内部路径、堆栈或其他敏感实现细节。
