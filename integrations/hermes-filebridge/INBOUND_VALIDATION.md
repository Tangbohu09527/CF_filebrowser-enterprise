# 入站工作副本下载：本轮交付与验证记录

本页保留截至 `0bf082c65091c38874932a3b3d7a9f66be8df6be` 的下载组件交付记录。
后续官方 middleware / 真实请求审查见 [HOST_BRIDGE_VALIDATION.md](HOST_BRIDGE_VALIDATION.md)；
该页为带日期的历史证据；Gateway 配套现已实现，当前接线与测试见 [JOINT_HOST_VALIDATION.md](JOINT_HOST_VALIDATION.md)。

日期：2026-09-27。工作树：`C:\Users\Admin\.codex\worktrees\6330\CF_filebrowser-enterprise`。
分支：`feat/filebridge-hermes-crud`；起始基线 `6ba8f71fb0ba270420419618c1e07150b0b8b742`。
起始工作树干净，fetch 后没有分叉；保留原有提交，未重置、强推或清理未知文件。
[PR #2](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/pull/2) 保持 Draft / Open。

结论：下载代码、原生安全落盘、受控句柄和可续接暂存入口已实现。实际 Hermes 可信
Dispatch 桥接缺失，真实 AI 主机尚未验收；不能宣称已安装可用或本项目 CI 全绿。

## 本轮修改文件与原因

以下路径相对于仓库根，未改 FileBrowser 后端/前端实现、依赖清单、锁文件或原安全断言。

| 文件 | 修改原因 |
| --- | --- |
| `.gitattributes` | 将 PDF/JPEG 测试夹具按二进制保留，避免 Windows 换行转换破坏 PDF xref。 |
| `.github/workflows/filebridge-client.yaml` | 现有 Linux/Windows CI 增加真实 worker 插件测试、固定 Hermes loader 检查和可校验 bundle。 |
| `.github/workflows/filebridge-windows-config.yaml` | 保留原回归并增加原生入站暂存检查。 |
| `tools/filebrowser-agentctl/cmd/filebridge-inbound/main.go` | 专用 stdin 管道 worker；当前 Dispatch 生命周期及内部 handle 解析。 |
| `tools/filebrowser-agentctl/cmd/filebridge-inbound/main_test.go` | 验证严格协议、超长输入和初始化失败不泄露原输入。 |
| `tools/filebrowser-agentctl/internal/inbound/download.go` | 严格 Gateway 契约、独立 HTTPS 授权、共享预算、完整性校验及可解析句柄。 |
| `tools/filebrowser-agentctl/internal/inbound/download_test.go` | 真实 HTTPS、并发预算、实际 30 秒截止、TLS/重定向/内容边界。 |
| `tools/filebrowser-agentctl/internal/inbound/store.go` | 唯一暂存对象、安全发布、已知对象解析及取消清理。 |
| `tools/filebrowser-agentctl/internal/inbound/store_windows.go` | Win32 原生 NTFS DACL、祖先锁、对象身份、按句柄原子发布和清理。 |
| `tools/filebrowser-agentctl/internal/inbound/store_windows_test.go` | 实际 DACL、祖先重命名锁、junction、ADS、发布后权限验证。 |
| `tools/filebrowser-agentctl/internal/inbound/store_linux.go` | Linux 匿名临时 inode 发布；清理不删除未知路径。 |
| `tools/filebrowser-agentctl/internal/inbound/store_linux_test.go` | Linux 私有目录、symlink 和匿名暂存隔离。 |
| `tools/filebrowser-agentctl/internal/inbound/store_other.go` | 未支持的系统明确拒绝，避免不安全兼容回退。 |
| `tools/filebrowser-agentctl/internal/inbound/store_test.go` | 通用无覆盖、未知文件保护、取消、篡改及句柄测试。 |
| `integrations/hermes-filebridge/plugin/__init__.py` | 增加入站工具的显式 opt-in 注册入口，保留原两工具。 |
| `integrations/hermes-filebridge/plugin/inbound.py` | 可信宿主专用绑定、单 worker 生命周期、模型参数约束及下游只读流。 |
| `integrations/hermes-filebridge/plugin/plugin.yaml` | 声明新工具和插件版本，默认开关仍关闭。 |
| `integrations/hermes-filebridge/tests/test_inbound_plugin.py` | 实际 worker→HTTPS→NTFS→句柄消费；模拟宿主明确标注，不冒充真实 Dispatch。 |
| `integrations/hermes-filebridge/tests/test_hermes_loader.py` | 固定官方真实 loader / PluginContext / registry 的默认关闭与缺桥接拒绝检查。 |
| `integrations/hermes-filebridge/tests/Test-InboundStage.ps1` | 18 项原生暂存、续接、未知文件、ACL 及 reparse 回归。 |
| `integrations/hermes-filebridge/tests/fixtures/cert.pem` | 仅回环测试的公开 CA，不安装全局信任。 |
| `integrations/hermes-filebridge/tests/fixtures/key.pem` | 上述非秘密测试证书的测试私钥，不是运行环境凭据。 |
| `integrations/hermes-filebridge/tests/fixtures/sample.pdf` | 无业务内容的有效最小 PDF。 |
| `integrations/hermes-filebridge/tests/fixtures/sample.jpg` | 无业务内容的有效 2×2 JPEG。 |
| `integrations/hermes-filebridge/tests/fixtures/README.md` | 记录测试夹具来源及禁止部署边界。 |
| `integrations/hermes-filebridge/windows/Manage-InboundClient.ps1` | 独立 Stage / Resume / Check / SelfTest；不改当前安装及凭据。 |
| `integrations/hermes-filebridge/README.md` | 提供新增开发入口并明确未启用。 |
| `integrations/hermes-filebridge/INBOUND_CONTEXT.md` | 固定上游源码证据、真实接口缺口及最小宿主接线要求。 |
| `integrations/hermes-filebridge/INBOUND_DOWNLOAD.md` | 固定契约、调用接线、预算、文件边界及后续一次性实机验收步骤。 |
| `integrations/hermes-filebridge/INBOUND_VALIDATION.md` | 本记录：文件原因、测试结果和剩余验证边界。 |

## 实际执行的本地检查

Go 1.25.0 为独立临时便携工具链，未安装到系统；官方 Windows ZIP SHA-256：
`89efb4f9b30812eee083cc1770fdd2913c14d301064f6454851428f9707d190b`。
以下 Go 命令在 `tools/filebrowser-agentctl` 目录执行，`GOTOOLCHAIN=local`，缓存位于任务临时目录。

| 命令 / 检查 | 结果 |
| --- | --- |
| `go test -count=1 ./internal/filebridge` | 修改前独立客户端基线通过。 |
| `python -B -m unittest discover -s integrations/hermes-filebridge/tests -v` | 修改前 13 项既有插件回归通过。 |
| `gofmt -l cmd internal` | 输出为空，保留现有格式门禁。 |
| `go test -count=1 ./...` | 原客户端、新 worker、下载及 Windows 存储测试通过。 |
| `go vet ./...` | 通过；开发中发现的 WinAPI unsafe.Pointer 警告已修复，未关闭检查。 |
| `go test -count=1 -timeout=45s -run 'TestDownloadThirtySecondBudgetShared\|TestDownloadHTTPSCrossOriginRedirects' -v ./internal/inbound` | 新增补充测试通过；30 秒测试实测 30.01 秒。两个并发共享 1 次请求，重复失败不重新计时/请求。五种 HTTPS 跨源重定向目标均为 0 请求。 |
| `go build -trimpath -mod=readonly -o <独立临时目录>/filebridge-inbound.exe ./cmd/filebridge-inbound` | 测试 worker 编译通过；未替换已安装客户端。 |
| `python -B -m unittest discover -s integrations/hermes-filebridge/tests -v` | 设置 `CF_FILEBRIDGE_INBOUND_TEST_EXE` 指向上述原生 worker 后 22 项通过，包含原 13 项。 |
| `<独立venv-python> -I -B integrations/hermes-filebridge/tests/test_hermes_loader.py --hermes-source <固定源码目录>` | 真实 Hermes 两个配置场景通过，输出 `host_bridge_connected=false`。 |
| `powershell.exe -NoProfile -NonInteractive -File integrations/hermes-filebridge/windows/Stage-CreateClient.ps1 -Mode SelfTest` | 原受控新建暂存回归通过。 |
| `powershell.exe -NoProfile -NonInteractive -File integrations/hermes-filebridge/windows/Manage-CreateStage.ps1 -Mode SelfTest` | Python700 / ACL / 跨语言原回归通过。 |
| `powershell.exe -NoProfile -NonInteractive -File integrations/hermes-filebridge/tests/Test-InboundStage.ps1` | 新增 18 项通过。祖先锁测试曾在 READ_ATTRIBUTES-only 实现上失败，增加 FILE_LIST_DIRECTORY 后通过。 |
| CI YAML 解析、`git diff --check`、`git diff --stat`、`git status --short` | 通过；提交后工作树无未提交改动。 |

既有 `Test-WindowsConfigReplace.ps1` 的本地完整运行**未通过**：先在 PowerShell 7 中因
旧 .NET API 不兼容失败；改用 CI 规定的 Windows PowerShell 5.1 后，前 8 个场景通过，
创建 SymbolicLink 时因本机权限限制中止。未使用管理员权限、未跳过/修改断言。
其原始脚本在本轮 Windows 2022/2025 CI 中均通过；本地中止结果仍保留。

## CI 证据与既有阻塞

功能提交 `a0c1a3f4dd20cfa9fb9f13388847d761571a28ef`：
[FileBridge client](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36309817279)、
[FileBridge Windows config](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36309817273)、
[deployment-assets](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36309817345) 通过。
最后补充测试提交对应的检查需以 [PR 当前 checks](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/pull/2/checks)
及交付回复中的完整 HEAD 为准，不将旧提交成功冒充新 HEAD 结果。

[regular tests](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36309817288)
在 lint-backend 失败：112 项（errcheck 8、govet 84、ineffassign 1、staticcheck 13、unused 6）。
[起始基线同一检查](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/36232492548)
已是相同分类/数量的失败。本轮前后 backend Git tree 均为
`91b213a5bca4ca34c40a991faefccbc75a3eb881`；backend、regular-tests 工作流与 Makefile 均未更改。
没有为清理这些无关问题而修改 Lint 版本、依赖或安全测试；因此 PR 仍非全绿。

## 未执行及剩余限制

- 实际 AI 主机的有效 Dispatch 下载、真实 Gateway 身份/claim 撤销、真实 PDF 上游取件：
  可信宿主桥接未提供，且本轮明确禁止安装启用和生产连接。
- 在真实固定 loader 内的成功 Dispatch：目前只验证真实加载/拒绝；成功下载使用明确标注
  的合成可信宿主，加真实 HTTPS 与原生 worker。两者不能拼称真实端到端已接通。
- 慢磁盘 Write/Sync/rename 跨期限故障注入：未执行。正常落盘、取消前拒绝和真实网络总限
  已测试，跨不可中断文件系统调用的期限保护另由代码审阅；不宣称测过慢磁盘故障。
- 64 MiB 实际边界大文件传输：未执行。使用较小宿主上限验证超限/截断，配置超过硬上限拒绝。
- 第二个普通 OS 用户跨账户读取：未创建第二账号；测试核对实际 NTFS DACL、SID 和 ACL 弱化拒绝。
- 本地 FileBrowser 后端/前端全套、Playwright、业务构建/部署：这些实现未改，未在本机运行。
  自动触发的远端 regular tests 结果如上；没有借任务扩大本地测试/部署范围。

后续一次性实机验收顺序及不覆盖现有配置的暂存命令见 [INBOUND_DOWNLOAD.md](INBOUND_DOWNLOAD.md)。
