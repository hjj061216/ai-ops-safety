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

echo Running the complete project test suite.
echo No real service or system configuration will be changed.
echo.
".venv\Scripts\python.exe" -B -m unittest discover -v -s tests -p "test_*.py"

echo.
if errorlevel 1 (
    echo FAILED: One or more tests did not pass.
) else (
    echo SUCCESS: All project tests passed.
)
echo.
pause
endlocal

