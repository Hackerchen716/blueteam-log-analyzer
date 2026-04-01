@echo off
:: BlueTeam Log Analyzer - Windows 快捷启动脚本
:: 将此文件所在目录加入 PATH 即可全局使用 bla 命令
python "%~dp0bla_cli.py" %*
