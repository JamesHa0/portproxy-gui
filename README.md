# PortProxy GUI

基于 Windows 自带 `netsh interface portproxy` 的图形化管理工具，告别繁琐的命令行。

## 功能

- 可视化查看 / 添加 / 删除端口转发规则
- 实时反馈 netsh 执行结果

## 两种界面

- Web 版：运行 `python server.py`，浏览器打开 http://127.0.0.1:8765
- 桌面版：运行 `portproxy_gui.pyw`（Tkinter）

## 运行要求

- Windows 系统
- 必须以管理员身份运行（netsh interface portproxy 需要管理员权限）
