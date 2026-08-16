@echo off
title PortProxy - 端口转发管理器
echo ================================================
echo   PortProxy - 端口转发管理器
echo ================================================
echo.
echo   正在启动...
echo   提示: 请以管理员身份运行此程序
echo.
if exist "%~dp0dist\PortProxy.exe" (
    echo   已找到 dist\PortProxy.exe，启动构建版本...
    start "" "%~dp0dist\PortProxy.exe"
) else (
    echo   未找到 dist\PortProxy.exe，改为从源码启动（需已安装 Python）...
    start "" "%~dp0portproxy_gui.pyw"
)
