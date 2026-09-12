@echo off
rem Source checkout launcher. For a reproducible installation, use the venv
rem instructions in README.md and invoke its sentinel.exe entry point.
py -3.12 "%~dp0sentinel.py" %*
