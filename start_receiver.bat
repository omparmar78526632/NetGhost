@echo off
REM NetGhost Dedicated Receiver Node Launcher (Port 5001)
REM Run as Administrator for raw packet steganography

echo ===============================================================
echo   NETGHOST - DEDICATED RECEIVER NODE (PORT 5001)
echo ===============================================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Not running as Administrator!
    echo Packet sniffing and capture require Administrator privileges.
    echo.
)

if exist .venv\Scripts\activate.bat (
    set "PY_EXE=.venv\Scripts\python.exe"
) else (
    set "PY_EXE=python"
)

echo Starting Receiver Node on http://127.0.0.1:5001/receiver ...
start http://127.0.0.1:5001/receiver

%PY_EXE% receiver/receiver_app.py
pause
