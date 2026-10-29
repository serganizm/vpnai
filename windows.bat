@echo off
chcp 65001 >nul
cd /d "%~dp0app"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" app.py
) else (
  py -3 app.py
  if errorlevel 9009 python app.py
)
pause
