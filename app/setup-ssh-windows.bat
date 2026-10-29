@echo off
chcp 65001 >nul
cd /d "%~dp0"
py -3 -m venv .venv
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo Готово. Запустите ..\windows.bat.
pause
exit /b 0
:failed
echo Не удалось установить SSH-компонент. Проверьте Python и доступ к интернету.
pause
exit /b 1
