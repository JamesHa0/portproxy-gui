# PortProxy GUI

基于 Windows 自带 `netsh interface portproxy` 的图形化管理工具，告别繁琐的命令行。零第三方依赖，纯 Python + Tkinter（桌面版）或 http.server（Web 版）。

## 功能

- 可视化查看 / 添加 / 删除端口转发规则（实时刷新）
- **四种转发类型**：v4tov4 / v4tov6 / v6tov4 / v6tov6
- **JSON 导入 / 导出**：一键备份与迁移全部规则
- **防火墙联动**：添加规则时可一键放行对应入站端口
- **规则编辑**：编辑 = 删除原监听点后按新参数重建
- **自动提权**：非管理员启动时自动请求 UAC 提权（桌面版 runas；Web 版提供"以管理员重启"按钮兜底）
- **系统托盘**：关闭/最小化隐入托盘，托盘菜单可显示 / 刷新 / 退出（桌面版，零依赖）
- **开机自启**：设置中勾选后写入当前用户注册表 `Run` 键（桌面版，零依赖）
- 实时反馈 netsh 执行结果，失败时展示原始错误信息
- 中文系统 GBK 输出自动解码，避免乱码

## 两种界面

- **桌面版（推荐）**：运行 `portproxy_gui.pyw`（Tkinter），或双击 `run.bat` 启动已构建的 `dist/PortProxy.exe`
- **Web 版**：运行 `python server.py`，浏览器打开 http://127.0.0.1:8765

## 快速开始（桌面版）

1. 从 [Releases](https://github.com/JamesHa0/portproxy-gui/releases) 下载 `PortProxy.exe`，或直接双击仓库内的 `run.bat`
2. 首次运行会请求管理员（UAC）权限 —— 端口转发必须由 netsh 以管理员身份执行
3. 在表单中填写 监听地址 / 监听端口 / 目标地址 / 目标端口，选择转发类型，点击"添加"
4. 表格实时刷新；右键行可编辑 / 删除，顶部按钮可清空全部、导入 / 导出 JSON

> 若被组策略禁止自动提权，请右键 `PortProxy.exe` / `run.bat` 选择"以管理员身份运行"。

## 运行要求

- Windows 系统
- 端口转发需要管理员权限：程序会自动请求 UAC 提权；若被组策略禁止，请右键"以管理员身份运行"
- 仅支持 TCP（netsh portproxy 的限制）

## 从源码构建（桌面版 EXE）

需要 Python 3.8+ 与 PyInstaller：

```bash
pip install pyinstaller
python -m PyInstaller PortProxy.spec --noconfirm
# 产物位于 dist/PortProxy.exe
```

## 已知限制

- 仅支持 TCP 协议（netsh portproxy 的固有限制）
- 主要面向 Windows 环境
- 规则本身由 netsh 持久化，重启后依然生效；桌面版的"开机自启"仅控制程序自启动

## 版本

- 功能按 P0/P1/P2 推进；Release 与代码推送均由用户手动完成。
- 本仓库 `dist/` 已 gitignore，发布用的 `PortProxy.exe` 在 GitHub Release 附件中提供。
