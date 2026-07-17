# v1.0-beta 发布前 P0 任务

本文档定义 FileBrowser Enterprise `v1.0-beta` 进入公司内部生产环境前必须完成的 P0 工作。所有任务均为发布阻断项，必须在独立测试环境完成验收并保留测试、配置审查或演练记录；任一项未通过时不得上线。

## P0-001 服务端 Browse / Preview / Download 权限闭环

**目标**

在服务端统一落实 Browse、Preview、Download 三项读权限，确保任何入口都不能依赖前端隐藏或通过替代协议绕过。有效权限必须同时受用户当前权限、Token 权限、Source/路径范围以及 Share/协议约束限制。

**涉及模块**

- `backend/http/resource.go`、`search.go`、`preview.go`、`media.go`、`download.go`、`archive.go`
- `backend/http/middleware.go` 与 `backend/database/access/`
- `backend/database/users/` 中的用户权限模型
- `backend/http/permission_contract_test.go`、`permission_read_security_test.go`、`permission_preview_security_test.go`

**验收标准**

- 普通用户在 Browse、Preview、Download 的允许与拒绝组合下均有服务端自动化测试；管理员身份不得意外绕过显式读权限约束。
- 列表、搜索、固定项、实时订阅和资源元数据接口在缺少 Browse 时不返回资源名称、存在性、大小、时间或路径等可枚举信息。
- 缩略图和在线预览同时要求 Browse 与 Preview；会返回原始文件内容的预览还必须要求 Download。
- 原文件、Raw、`content=true`、校验和、`HEAD`/Range/条件请求、归档和导出下载同时要求 Browse 与 Download，并在请求执行和缓存复用时重新校验当前权限。
- 浏览器会话与 API Token 均按相同语义执行；用户或 Token 任一侧撤销权限后，下一次请求立即失败。
- 拒绝响应符合 `docs/API_CONTRACT.md`，且不泄露内部路径、堆栈或目标资源是否存在。

**风险**

- 新增或遗漏的旁路入口可能直接读取文件，形成权限绕过。
- 权限、索引或预览缓存失效不及时，可能在撤权后继续返回旧内容。
- Preview 与 Download 的边界不清可能导致原始内容被低权限预览接口返回。
- 权限检查散落在处理器中会提高后续上游同步时的回归风险。

## P0-002 Token 安全

**目标**

完成 API Token 从签发、使用、权限收敛、过期、轮换到撤销的安全闭环。Token 只能缩小用户权限，不能成为长期管理员凭据或扩大用户、Source 和路径边界。

**涉及模块**

- `backend/auth/` 中的 Token 生成、验证与签名逻辑
- `backend/http/auth.go`、`api.go`、`middleware.go`、`users.go`
- `backend/database/users/` 与 `backend/database/access/` 中的 Token 元数据、权限和撤销状态
- Token 管理前端以及 `docs/API_CONTRACT.md`、`docs/SECURITY.md`
- `backend/auth/*_test.go`、`backend/http/permission_contract_test.go`、`resource_test.go`

**验收标准**

- 普通用户只能签发不超过自身当前权限的 Token；有效权限始终为用户当前权限与 Token 授权范围的交集。
- 用户权限撤销、Token 撤销、用户禁用或删除后立即失效；过期、签名错误、未知用户和不兼容权限版本均失败关闭并返回 `401`。
- Token 具有明确有效期、唯一标识和可审计的签发/撤销记录；轮换完成后旧 Token 不可继续使用。
- 完整 Token 仅在创建时返回，不以明文写入数据库可读字段、URL、普通日志、错误响应或审计记录；界面列表只显示受控摘要或标识。
- Bearer Header、浏览器会话和 WebDAV 兼容认证边界清晰，禁止通过查询参数为新增集成传递 Token。
- 覆盖签发时越权、使用时权限交集、撤权、过期、撤销、并发使用和多实例一致性的自动化测试全部通过。

**风险**

- 当前实现与兼容旧 Token 时可能保留可持久化或查询的完整 Token、无有效期凭据或过宽权限，必须作为发布关闭项处理。
- 多实例缓存或持久化延迟可能造成撤销窗口。
- Token 出现在 URL、代理日志或错误消息中会扩大泄露范围。
- 时钟漂移和轮换顺序错误可能造成误拒绝或旧 Token 延迟失效。

## P0-003 Public Share 安全

**目标**

将 Public Share 限制为只作用于已授权 Source、根路径和操作集合的受限能力，确保匿名、密码保护和已认证访问均不能越过分享边界探测或操作其他资源。

**涉及模块**

- `backend/http/public.go`、`share.go`、`middleware.go`、`resource.go`、`download.go`、`chunk_upload.go`
- `backend/database/share/` 与分享持久化实现
- Public Share 前端访问与管理界面
- `backend/http/permission_share_security_test.go`、`resource_test.go`、`chunk_upload_security_test.go`

**验收标准**

- 普通用户创建的 Share 不能超过其当前 Share 权限、Source/路径范围和读写权限；权限撤销后已有 Share 不得继续放大访问能力。
- 匿名、密码保护和已认证三类访问分别验证 Browse、Preview、Download、Upload、Modify、Delete 的允许与拒绝边界。
- 仅上传 Share 不得获得 Browse、Preview 或 Download；新建、覆盖、重命名和删除分别按 Create、Modify、Delete 校验，不能互相替代。
- 密码、有效期、下载次数和访问限制在每次请求时校验；计数更新具备并发一致性，过期或耗尽后立即拒绝。
- `GET`、`HEAD`、上传、分片上传、覆盖、重命名和删除等入口均固定在 Share 根路径内，并覆盖编码路径、路径穿越、符号链接和跨 Source 场景。
- 越权请求不形成资源存在性探针，响应不返回宿主绝对路径、Share 密钥、Token 或内部错误细节。
- 历史 Public Share 安全回归测试及新增边界测试全部通过，且未弱化既有关键断言。

**风险**

- 路径标准化差异、符号链接和二次 URL 解码可能突破 Share 根目录。
- 并发下载或上传可能绕过次数、配额和覆盖权限检查。
- 分享直链中的凭据可能通过浏览器历史、Referer 或代理日志泄露。
- Share 创建后所有者权限变化若未重新计算，可能形成长期越权入口。

## P0-004 WebDAV 权限矩阵

**目标**

固化 WebDAV 方法到 FileBrowser 权限的服务端映射，使 WebDAV 与 HTTP API 使用相同的普通用户、Token、Source 和路径边界，并对源路径和目标路径分别授权。

**涉及模块**

- `backend/http/webdav.go`、`middleware.go` 与路由注册
- `backend/database/access/`、`backend/database/users/`
- `backend/http/webdav_test.go`、`permission_webdav_security_test.go` 及其测试辅助文件
- WebDAV 客户端兼容说明和 `docs/API_CONTRACT.md`

**验收标准**

- 权限矩阵至少覆盖 `OPTIONS`、`PROPFIND`、`GET`、`HEAD`、`POST`、`PUT`、`MKCOL`、`DELETE`、`COPY`、`MOVE`、`LOCK`、`UNLOCK` 和 `PROPPATCH`。
- `PROPFIND` 要求 Browse，`GET`/Range/`HEAD`/`POST` 要求 Browse 与 Download；无 Browse 时不得通过已知路径、别名或元数据响应判断资源是否存在。
- `PUT` 明确区分新建所需的 Create 与覆盖所需的 Modify；目录创建、属性修改、锁定和删除分别验证对应权限。
- `COPY`、`MOVE` 同时检查源资源读取/修改/删除能力与目标位置 Create/Modify 能力，禁止跨越 Source、用户 Scope 或授权根路径。
- Source 配置为只读时，所有改变内容、目录、属性或锁状态的方法均拒绝；`Destination`、编码路径和符号链接不能逃逸授权根路径。
- 普通用户使用会话和最小权限 Token 执行完整允许/拒绝矩阵；用户或 Token 权限撤销后下一次请求立即失败。
- 主流内部 WebDAV 客户端完成互操作验证，HTTP 状态和 XML 错误响应不泄露服务器文件系统信息。

**风险**

- WebDAV 库的内部回调和方法降级可能绕过顶层处理器检查。
- `COPY`、`MOVE` 等双路径操作只检查一侧时会造成跨目录越权。
- 未执行 Source 只读配置，或未区分新建与覆盖，会破坏存储只读承诺并混淆 Create/Modify 权限。
- 目标在检查后被并发创建会混淆 Create 与 Modify 判定。
- 为客户端兼容放宽状态码或路径规则可能重新引入存在性探测和权限绕过。

## P0-005 Hermes Agent 接入基础

**目标**

建立 Hermes Agent 访问 FileBrowser Enterprise 的最小可用、安全接入基线。当前仓库没有 Hermes 专用实现，本任务只开放稳定、受限、可撤销且可审计的 API 能力，不授予管理员会话或直接文件系统访问。

**涉及模块**

- `docs/API_CONTRACT.md`、`docs/SECURITY.md` 中的 Agent 与 Token 契约
- `backend/http/middleware.go`、`auth.go`、`api.go`、`resource.go`、`search.go`
- `backend/auth/`、`backend/database/users/`、`backend/database/access/`
- 部署系统中的 Hermes 服务账号、Secret 注入和轮换配置；Hermes 侧配置不在本仓库保存生产凭据
- P0-007 定义的审计链路

**验收标准**

- Hermes 使用独立普通用户和专用短期 Token，`admin=false`，权限仅覆盖经批准的 Source、路径和操作。
- 仅通过 HTTPS 和 `Authorization: Bearer` 接入，不复用人工管理员 Cookie、会话或 Token，也不直接挂载业务存储。
- 选定的最小业务流程完成端到端验收，至少包含资源发现/读取以及一个经批准的写入动作，并验证所有非授权动作返回 `403`。
- Token 撤销、到期、用户停用和权限收缩立即生效；Hermes 对 `401`、`403`、`409`、`429` 和 `5xx` 采用有界重试或停止策略。
- 写入请求具备去重或幂等约束，避免超时重试生成重复文件；请求标识可贯穿应用日志和审计记录。
- 生产凭据由 Secret 系统注入并完成一次轮换演练，Hermes 日志和任务上下文中不存在完整 Token 或文件敏感内容。

**风险**

- Agent 身份权限过宽会放大提示注入、任务配置错误或凭据泄露的影响。
- 无界重试和缺少幂等约束可能导致重复写入或资源耗尽。
- API 行为未固定时，上游升级可能破坏 Hermes 工作流。
- Agent 输入、输出和日志可能意外复制敏感文件内容或访问凭据。

## P0-006 文件目录规范和资料库初始化

**目标**

明确程序、配置、数据库、业务文件、临时文件、日志和备份的物理目录边界，并按业务确认的 Source 与一级目录初始化内部资料库，确保所有权、访问范围和生命周期可管理、可备份、可恢复。

**涉及模块**

- `backend/common/settings/` 与 `backend/config.yaml` 所描述的 Source、数据库和临时目录配置结构
- `backend/database/storage/`、`backend/database/sql/`、`backend/database/dbindex/`、`backend/indexing/`
- `backend/database/access/` 与用户 Scope/权限配置
- `docs/DEPLOYMENT.md` 以及部署系统管理的持久化挂载、目录初始化和迁移清单

**验收标准**

- 形成经评审的目录清单，分别定义程序、只读配置、状态数据库、业务资料、临时区、审计日志和备份的位置、所有者、权限模式、容量与保留策略。
- 生产数据库和业务文件使用独立持久化存储；临时目录不可与正式资料或备份混用，生产路径和凭据不提交到仓库。
- 业务负责人确认 Source、一级目录、目录责任人和访问组；初始化脚本或清单可重复执行且不会覆盖已有文件。
- 使用普通用户验证每个 Source 的允许/拒绝边界、索引状态和目录可见性，并覆盖中文名、长文件名、空目录和大文件等基础场景。
- 初始资料迁移保留文件数量、总大小、时间属性和校验结果，迁移后完成索引重建或一致性校验。
- P0-008 的备份与恢复演练覆盖该目录布局，恢复后权限、索引和资料校验结果一致。

**风险**

- 挂载点、容器路径和 Source 配置不一致可能把数据写入临时层或错误目录。
- Source 名称或路径变化可能使既有用户 Scope、侧边栏引用和索引失效；Source 不存在但服务继续启动会造成带病运行。
- 目录所有权和继承权限配置错误可能导致服务不可用或普通用户越权。
- 绕过应用直接修改文件系统可能造成索引、审计和权限状态不一致。
- 初始化或迁移脚本若不具备幂等性，重复执行可能覆盖、重复或遗漏资料。

## P0-007 基础审计

**目标**

建立面向内部生产的持久化结构化审计，覆盖身份、授权和关键文件操作，能够回答“谁在何时以何种身份对哪个资源执行了什么操作以及结果如何”，同时不记录秘密或文件内容。

**涉及模块**

- `backend/http/middleware.go` 及认证、Token、Share、资源、下载、WebDAV 和用户管理处理器
- `backend/auth/`、`backend/database/access/`、`backend/database/share/`
- 新的持久化审计存储/输出边界；`backend/events/` 仅用于实时事件，不能作为唯一审计记录
- 日志配置、集中采集、访问控制与保留策略
- `docs/SECURITY.md` 和部署运维文档

**验收标准**

- 审计事件至少包含 UTC 时间、请求标识、操作者、认证方式、受控 Token/Share 标识、客户端地址、动作、Source/目标路径、有效权限、结果和状态码。
- 覆盖登录成功/失败、Token 签发/撤销、权限变更、Share 变更、Browse/Preview/Download、上传/覆盖、重命名、删除、WebDAV 和管理操作的成功与拒绝事件。
- 密码、完整 Token、Cookie、密钥、请求正文和文件内容不得进入审计；路径等敏感字段按内部规范访问控制或脱敏。
- 审计记录只允许授权审计人员读取，具备明确保留期、轮转、容量告警和防篡改措施；应用普通用户不能修改或删除。
- 能按操作者、Token、Share、资源、请求标识和时间范围检索并关联一次操作链路，代理后的客户端地址只信任受控转发头。
- 自动化测试验证关键事件存在、拒绝事件存在、字段完整和秘密脱敏，并完成一次审计查询与留存演练。

**风险**

- 现有通用请求日志包含原始查询串；未先脱敏即作为审计输入，可能记录 Token 或 Share 凭据。
- 分散处理器遗漏事件会形成无法追责的操作盲区。
- 记录完整路径、请求体或凭据可能使审计系统成为新的敏感数据源。
- 同步写审计可能影响大文件吞吐；异步写入则存在崩溃丢失和乱序风险。
- 磁盘耗尽、采集故障或不可信代理头会降低审计可用性和证据可信度。

## P0-008 部署和备份

**目标**

形成可重复、最小权限、可观测且可回滚的 Debian/Docker Compose/Nginx 生产部署流程，并用实际恢复演练证明应用数据库、业务文件、关键配置和审计记录可以在目标时间内恢复。

**涉及模块**

- `docs/DEPLOYMENT.md`、`_docker/Dockerfile`、`_docker/docker-compose.yaml`
- `makefile`、`.github/workflows/` 与发布构建产物
- `backend/common/settings/`、`backend/database/storage/` 和 `/health` 服务检查
- 部署系统管理的 Nginx、TLS、Secret、持久化挂载、监控、备份与恢复流程
- P0-006 的目录和资料清单、P0-007 的审计存储

**验收标准**

- 使用固定版本或镜像摘要部署，服务以独立非登录、非 root 身份运行；配置、数据库、业务文件、日志和临时目录挂载符合 P0-006。
- Nginx 是唯一对外入口，完成 HTTPS、可信代理头、上传大小、流式传输、超时和管理/诊断端点隔离验证。
- 健康检查、启动就绪、优雅停止、自动重启、资源限制、磁盘容量和证书到期监控均有明确阈值与告警接收人。
- 备份覆盖应用数据库、业务文件、部署配置、认证/加密关键材料和审计记录，采用一致性快照或停写窗口，并加密保存到独立故障域。
- 明确并经业务确认 RPO、RTO、保留周期和责任人；在隔离环境完成一次从备份重建服务的全量恢复演练，校验文件、权限、Token/Share 状态、索引和审计记录。
- 上线前完成构建、核心回归、升级与回滚演练；回滚使用兼容版本和已验证备份，不对已迁移数据库直接原地降级。

**风险**

- 仓库现有 Compose 主要服务于测试场景，未经独立生产审查不得直接部署；现有健康检查也不能替代数据库、Source 和索引就绪验证。
- 数据库与业务文件非一致时间点备份可能在恢复后产生悬空索引、Share 或权限状态。
- 未加密或与生产同故障域的备份无法抵御凭据泄露、误删和主机故障。
- 未固定镜像、配置或迁移版本会导致部署不可复现和回滚失败。
- 只验证“备份成功”而不执行恢复演练，可能在事故时才发现备份不可用。
