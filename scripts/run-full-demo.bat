@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
    echo ERROR: Virtual environment .venv was not found.
    pause
    exit /b 1
)

set "PYTHONUTF8=1"
set "PYTHONDONTWRITEBYTECODE=1"

echo Running the complete AI operations safety demo.
echo All execution is simulated inside a temporary sandbox.
echo.
".venv\Scripts\python.exe" -B full_safety_demo.py

echo.
if errorlevel 1 (
    echo FAILED: Full safety demo did not complete.
) else (
    echo SUCCESS: Full safety demo completed.
)
echo.
pause
endlocal

