@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (echo ERROR: Virtual environment .venv was not found.& pause& exit /b 1)
set "PYTHONUTF8=1"
set "PYTHONDONTWRITEBYTECODE=1"
echo Starting local AI operations safety console.
echo Open http://127.0.0.1:8765 if the browser does not open automatically.
echo Press Ctrl+C in this window to stop.
echo.
".venv\Scripts\python.exe" -B scripts\launch_console.py
endlocal
