@echo off
REM NetGhost Dual-Node Multi-Host Launcher
REM Runs Dedicated Sender on port 5000 and Dedicated Receiver on port 5001
REM Run as Administrator for raw packet steganography

echo ===============================================================
echo   NETGHOST - DUAL-NODE MULTI-HOST LAUNCHER
echo ===============================================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Not running as Administrator!
    echo Packet capture and raw transmission require Administrator privileges.
    echo.
)

REM Activate virtual environment
if exist .venv\Scripts\activate.bat (
    set "PY_EXE=.venv\Scripts\python.exe"
) else (
    set "PY_EXE=python"
)

echo [1/2] Launching Dedicated Receiver Node on http://127.0.0.1:5001 ...
start "NetGhost Receiver (Port 5001)" cmd /k "%PY_EXE% receiver/receiver_app.py"

echo [2/2] Launching Dedicated Sender Node on http://127.0.0.1:5000 ...
start "NetGhost Sender (Port 5000)" cmd /k "%PY_EXE% sender/sender_app.py"

echo.
echo Waiting 3 seconds for servers to initialize...
timeout /t 3 /nobreak >nul

echo Opening Receiver in browser: http://127.0.0.1:5001/receiver
start http://127.0.0.1:5001/receiver

echo Opening Sender in browser:   http://127.0.0.1:5000/sender
start http://127.0.0.1:5000/sender

echo.
echo ===============================================================
echo   [✓] Both nodes are running in separate terminal windows!
echo   • Sender Node:   http://127.0.0.1:5000/sender
echo   • Receiver Node: http://127.0.0.1:5001/receiver
echo ===============================================================
echo.
pause
