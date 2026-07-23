# PortProxy GUI — 计划、竞品分析与进度

## 当前状态
- Web 版（server.py + index.html）与桌面版（portproxy_gui.pyw → PortProxy.exe）均已实现 v1 核心功能：规则增删、列表、实时刷新、结果反馈、管理员检测、GBK 解码、前端双重校验。
- 已合并的增强：
  - **P0 自动提权**：非管理员时通过 `ShellExecute(runas)` 重启自身请求 UAC 提权；Web 版提供 `/api/elevate` 与前端"以管理员重启"按钮兜底。
  - **P0 多类型下拉**：v4tov4 / v4tov6 / v6tov4 / v6tov6 四种类型，前端与桌面端均可选择，`do_netsh` 按类型拼接 add/delete/show。
  - **P1 JSON 导入/导出**：`/api/export`、`/api/import`（Web）与导出/导入按钮（桌面），逐条 add 并去重、跳过无效项。
  - **P1 防火墙联动**：添加/编辑规则时可勾选"放行防火墙入站"，调用 `netsh advfirewall firewall add rule`。
  - **P1 规则编辑**：编辑 = 删除原监听点（按**原始**监听地址）后按新参数 add；编辑同一监听点时跳过重复校验。
  - **P2 系统托盘**：桌面版最小化/关闭按钮隐入系统托盘（ctypes `Shell_NotifyIcon`，零依赖），托盘图标支持左/右键菜单（显示 / 刷新 / 退出）。
  - **P2 开机自启**：桌面版"设置 → 开机自启"勾选写入当前用户注册表 `Run` 键（零依赖），启动时自动反映状态。
- 桌面版额外具备：清空全部、浅色主题、占位符提示、右键菜单编辑/删除。
- 版本：本地按功能推进，Release 由用户手动发布；推送由用户手动完成。

## 竞品分析结论
- **coderskyking/PortProxyGUI**（C#/WPF，最完整）：系统托盘、自动提权、四种类型、IPv6、JSON 导入导出、防火墙放行、WSL 自动检测、开机自启、深色主题、多语言。
- **aizvorski/Windows-Port-Forwarding-Manager**（Python + wxPython）：IPv6、CSV/JSON 批量导入、防火墙检测按钮、备份恢复。
- **smiley/netsh-portproxy-gui**（Python + Flask + Vue，Web 直接竞品）：增/改/删、多类型、配置导入导出、Windows 服务自启、日志面板。

## 与竞品的差距 & 优先级
- ✅ P0 自动提权（已做）
- ✅ P0 多类型（已做）
- ✅ P1 JSON 导入/导出（已做）
- ✅ P1 防火墙联动（已做）
- ✅ P1 规则编辑（已做）
- ✅ P2 系统托盘（已做，零依赖）
- ✅ P2 开机自启（已做，零依赖）
- ✅ P3 原始日志面板：展示每次执行的 netsh 命令与输出，便于排查。
- ✅ P3 深色模式 / 国际化：UI 主题切换与中英文界面。
- ✅ P3 WSL / 容器转发自动检测（coderskyking 特有，非必需）。
- ✅ P3 CSV 批量导入（aizvorski 支持，可作为 JSON 之外的补充）。

## 改进实施进度
1. P0 自动提权 — ✅ 完成（uac runas + Web 兜底）
2. P0 多类型下拉 — ✅ 完成（四种类型）
3. P1 JSON 导入/导出 — ✅ 完成
4. P1 防火墙联动 — ✅ 完成
5. P1 规则编辑 — ✅ 完成
6. P2 系统托盘 — ✅ 完成（ctypes Shell_NotifyIcon，零依赖）
7. P2 开机自启 — ✅ 完成（注册表 Run 键，零依赖）
8. P3 日志面板 / 深色模式 / 国际化 / WSL检测 / CSV导入 — ✅ 完成

## 测试与验收
- 非管理员启动 → 自动提权或明确提示。
- 切换四种类型增删，列表与 netsh 一致。
- 导出 JSON → 清空 → 导入 → 规则完全还原。
- 启用防火墙联动后端口入站可通。
- 编辑规则后监听点参数更新（含修改监听地址时旧规则被清理）。
- 点击关闭/最小化 → 隐入托盘；托盘菜单可显示/刷新/退出。
- "设置 → 开机自启"勾选后注册表 Run 键出现，重启后自动启动（netsh 规则本身已持久）。
- 发布 Release：桌面 EXE（dist/PortProxy.exe，已 gitignore）由用户手动上传到 GitHub Release。

## 假设
- 仍以 TCP 为主（netsh 仅支持 TCP，不做 UDP）。
- Web 版与桌面版同步增强；本次 Release 以桌面版（PortProxy.exe）为主交付对象。
- 自动提权可能受组策略限制，需保留手动管理员入口作为兜底。