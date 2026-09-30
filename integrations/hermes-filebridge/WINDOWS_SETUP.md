# Windows 统一安装与中断恢复（2026-09-30）

操作者从本次固定 GitHub Actions 制品下载并解压后，**双击
`windows-setup/FileBridge-Setup.exe`，确认一次操作授权**。不需要选择解释器、复制摘要、
编辑 YAML 或判断 Check / Apply / Resume。下述内部阶段是维护说明，不是操作清单。

本入口只处理本机 FileBridge；不安装 Hermes、不连接 CFserver、不恢复 Gateway Worker、
不扫码或发送微信。跨主机编排仍属于 Gateway 部署工作流。

## 当前部分升级现场与恢复策略

2026-09-30 的只读核对确认：原 6f59267c 计划、六个旧插件备份、配置前后候选、
清单与运行时收据均匹配；进一步逐文件核对了计划的 10 个载荷和解析运行时 829 个文件。
已安装源码提交为官方 `0f4a98f87c17007b81500239d0bd5b9574027b73`，三个生命周期
公开源码摘要与隔离参考相同。没有导入真实 Hermes、读取会话正文或写入安装。

| 目标 | 核对时状态 |
|---|---|
| inbound_content.py | 新版，已新增 |
| inbound.py / inbound_control.py / inbound_directory.py | 旧新版字节相同 |
| inbound_host.py / __init__.py / plugin.yaml | 旧版 |
| config.yaml | 仍为旧版 |

失败目标为 `plugin/inbound_host.py`。唯一 `.cf-config-*.tmp` 残留的字节匹配其旧版本；
所有者、组、ACE 顺序与掩码相同，但 Windows 为候选增加了 `DACL_AUTO_INHERITED`。
原目标为 protected-at-create、无该标志；原严格比较因此拒绝，原目标没有替换。
核对时相关 Python 和两个已知监听端口均为零。现场敏感身份、完整 SDDL、路径和配置
保留在本机私有证据中，没有写入仓库。

新入口对这个固定旧计划执行：核验新包 → 核验旧 checkpoint、旧清单全部载荷、备份、
运行时、配置语义及当前八个目标 → 确认实例仍停止 → 按 journal 接续未完成文件 →
再次核验完整安装。原本停止的服务保持停止。**本轮开发没有实际执行这些现场恢复步骤。**

跨包续接只允许 `6f59267-installer-only-repair-v1`：旧清单摘要必须为
`c0210fe182748e45be7f446e3f5b78b86935fe984910106f4d9be54bc605f3d0`，来源必须为
`6f59267ccdfe004ac10777a0be84a0526d6aaab5`；新旧七个插件和 requirements 必须逐字节
相同。继续使用已准备的旧 stage、旧 worker、旧离线 wheels 和解析运行时；不把新 worker
或新 ZIP 悄悄替换进去，不改旧 checkpoint。测试故意改变新 worker/wheels 以证明此约束。

旧未记账残留只在上述固定兼容状态下、唯一文件、固定旧 host 字节、相同所有者/组/ACE
且仅该 AI 标志差异时可**原位保留**。其所有权仍记为未证明，绝不删除、复用、执行或认领。
第二个残留、不同内容/权限或任何未知变更都拒绝接管。

## 组件与事务边界

- `FileBridge-Setup.exe` 内嵌 CI 的完整发布清单，校验源码包、所有脚本、inventory 和
  载荷；将核验字节复制到新建私有 NTFS 缓存，锁定目录和输入文件后调用原生 PS 5.1。
  不信任旁边可编辑 JSON 自报的摘要，不使用 PowerShell ExecutionPolicy Bypass，
  不调整现有文件 ACL。企业 AllSigned 策略仍会拒绝未签名脚本，入口不会绕过。
- `Setup-FileBridge.ps1` 自动读取本机 HOME/Profile、既有 worker 清单与规划解释器，
  识别 fresh / unprepared / prepared / partial / complete，复用现有 Stage 与 Upgrade。
  规划器和服务执行器是两个不同概念；不因机器存在 Python 3.14 而切换 3.11 规划器。
- `ConfigFile.ps1` 仅在自己的候选上使用 Win32 DACL setter 保持原描述符，最终仍做完整
  owner/group/DACL 精确比较。每个目标有不可变 intent 和 owned 记录，绑定源/候选文件身份、
  原后摘要、安全描述符及相对目标。配置和七个插件组成可恢复事务，**不是整体原子交换**。
- `Setup-Fresh.ps1` 只为已存在 Hermes 的全新 FileBridge 安装复用 Stage 和 CREATE_NEW
  journal。配置不变，若存在旧的启用意图则拒绝；结果明确为 installed_disabled，仍需
  Gateway 提供授权配置。不会把“默认关闭的文件已安装”当作真实内容能力可用。

中断后重新运行同一个入口会重新核验磁盘事实。未知修改、不完整身份日志、创建候选与
写入 owned 记录之间无法证明归属的窗口，都保留现场并停止。不会用“同名且摘要相同”
接管未知文件。恢复原运行状态前先记录 restore-intent，完成后写终态凭据；重复点击已完成
安装不会重新播放旧 running 状态。恢复调用结果不确定时拒绝自动重复启动。

## 实例归属与停启限制

官方 `gateway stop` 可能扫描默认 Profile 的其他进程，`gateway start` 可能修复计划任务，
而 dashboard stop 在 Windows 是强制终止已识别 PID。因此包装层先核归属及活动任务，
不批量结束 Python，不按监听端口猜归属，不改变自启策略。停止后至少观察十秒稳定退出，
成功升级及完整核验后才恢复先前运行的组件；失败不会启动混合版本。

当前已核验适配范围是 default Profile、无计划任务/服务/多 Profile 共用进程、可证明归属
的直接 gateway。启动器严格核官方公开模板及固定源码行为，再经官方机器接口确定执行器。
停止路径不导入 Hermes。运行中的 dashboard、桌面管理实例、未知同名计划任务、不可证明
HOME 的进程或未核验生命周期实现会明确拒绝自动接管。不会要求用户降级或关闭默认工具。
现场当前已停止的路径不依赖这些运行中实例的推断。此限制不应写成“所有 Hermes 启动方式
均已自动停启验收”。

## 来源与验证

信任起点是本仓库固定提交的 GitHub Actions 制品下载渠道；不是本地自签名证书。
CI 为 EXE 和内嵌发布清单生成 GitHub OIDC build-provenance，附带 Sigstore 证明，支持
独立用官方 `gh attestation verify` 审计。没有生成生产签名密钥或伪称 Authenticode 签名。
操作者不需要安装 gh、提供 GitHub Token 或手工抄摘要。具体 run、artifact 与 ZIP/source/
inventory/manifest/EXE 摘要由对应提交的交付记录给出；旧失败制品保持不变。

回归包括三种现场合法 ACL 的完整 SDDL、真实 NTFS rename 阻断的七个文件边界、
未知/篡改拒绝、旧 6f 真实包接续、全新安装七处中断、统一入口原 action 构造及重复运行。
生命周期状态机使用明确的测试替身；进程元数据解析和锁文件检查使用独立临时目录。
没有将替身测试写成已停止/恢复真实 Hermes。原内容读取、read/create、HTTPS/NTFS、
Stage、新旧官方 Hermes 与 Linux Gateway 联合测试继续由原 CI 门禁运行。

旧包兼容 CI 当前依赖固定 artifact `11075196992`，下载后先验证 ZIP/source 摘要。
制品过期会使该检查明确失败，不能跳过或伪造旧 inventory；届时应从受信归档恢复同字节
制品并更新其获取位置，保持摘要不变。

仍独立记录：历史 backend Lint 红项、30 秒 host lease 对长时间内容处理的限制、PDF 上游
长期 pending，以及生产 CFserver→Windows / 微信内容端到端未验收。代码与隔离验证、现场
恢复、现场安装、微信内容验收是四个不同状态。
