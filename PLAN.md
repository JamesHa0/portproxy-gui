# PortProxy GUI — 竞品分析与改进路线图

## 1. 当前状态（已完成，v1.0.0）
- Web 版（server.py + index.html）与桌面版（portproxy_gui.pyw → PortProxy.exe）均已实现 v1 核心：规则增删、列表、实时刷新、结果反馈、管理员检测、GBK 解码、前端双重校验。
- 桌面版额外具备：清空全部、clam 主题、占位符提示。
- 已打本地 tag v1.0.0，尚未推送远程（由用户手动推送）。

## 2. 竞品分析结论
- **coderskyking/PortProxyGUI**（C#/WPF，最完整）：系统托盘、自动提权(runas)、四种类型(v4tov4/v4tov6/v6tov4/v6tov6)、IPv6、JSON 导入导出、防火墙放行、WSL 自动检测、开机自启、深色主题、多语言。
- **aizvorski/Windows-Port-Forwarding-Manager**（Python + wxPython）：IPv6、CSV/JSON 批量导入、防火墙检测按钮、备份恢复。
- **smiley/netsh-portproxy-gui**（Python + Flask + Vue，Web 直接竞品）：增/改/删、多类型、配置导入导出、Windows 服务自启、日志面板。

## 3. 关键差距（按竞争压力排序）
- 自动提权（runas）：竞品普遍自动请求管理员，当前仅弹窗警告（最高优先级）。
- 多类型支持（v4tov6/v6tov4/v6tov6）：主要竞品均支持，当前 v4tov4 硬编码。
- 配置导入/导出（JSON）：两个 Python 竞品均支持，便于备份迁移。
- 防火墙联动放行：竞品均提供，避免"加了转发仍连不通"的困惑。
- 开机自启持久化：竞品通过注册表 Run 键 / Windows 服务实现。
- 规则编辑（先删后增）、系统托盘、原始日志面板、深色模式 / 国际化：打磨项。

## 4. 改进实施计划（建议优先级）
1. P0 自动提权：非管理员时通过 ShellExecute(runas) 重启自身请求提权；Web 版提供管理员启动脚本。
2. P0 多类型下拉：前端/桌面增加类型选择，do_netsh 按类型拼接 add/delete/show。
3. P1 JSON 导入导出：导出当前规则为 JSON，导入时逐条 add 并去重（两套 UI 均实现）。
4. P1 防火墙联动：添加规则时可选项"放行对应入站端口"，调用 netsh advfirewall firewall add rule。
5. P1 规则编辑：编辑 = 删除同一监听点后按新参数 add。
6. P2 开机自启：桌面版写入注册表 HKCU\...\Run 启动项。
7. P2 系统托盘：最小化到托盘 + 托盘菜单。
8. P3 日志面板 / 深色模式 / 国际化：展示原始 netsh 命令与输出；主题切换；中英界面。

## 5. 测试与验收
- 非管理员启动 → 自动提权或明确提示。
- 切换四种类型增删，列表与 netsh 一致。
- 导出 JSON → 清空 → 导入 → 规则完全还原。
- 启用防火墙联动后端口入站可通。
- 编辑规则后监听点参数更新。
- 开机自启后规则重启仍在（netsh 规则本身持久）。

## 6. 假设
- 仍以 TCP 为主（netsh 仅支持 TCP，不做 UDP）。
- Web 版与桌面版同步增强；若先做一个，优先桌面版（本次 Release 对象）。
- 自动提权可能受组策略限制，需保留手动管理员入口作为兜底。
