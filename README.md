# PortProxy GUI

基于 Windows 自带 `netsh interface portproxy` 的图形化管理工具，告别繁琐的命令行。

## 功能

- 可视化查看 / 添加 / 删除端口转发规则（实时刷新）
- **四种转发类型**：v4tov4 / v4tov6 / v6tov4 / v6tov6
- **JSON 导入 / 导出**：一键备份与迁移全部规则
- **防火墙联动**：添加规则时可一键放行对应入站端口
- **规则编辑**：编辑 = 删除原监听点后按新参数重建
- **自动提权**：非管理员启动时自动请求 UAC 提权（Web 版提供"以管理员重启"按钮兜底）
- 实时反馈 netsh 执行结果，失败时展示原始错误信息
- 中文系统 GBK 输出自动解码，避免乱码

## 两种界面

- Web 版：运行 `python server.py`，浏览器打开 http://127.0.0.1:8765
- 桌面版：运行 `portproxy_gui.pyw`（Tkinter），或双击 `run.bat` 启动已构建的 `dist/PortProxy.exe`

## 运行要求

- Windows 系统
- 端口转发需要管理员权限：程序会自动请求 UAC 提权；若被组策略禁止，请右键"以管理员身份运行"
- 仅支持 TCP（netsh portproxy 的限制）