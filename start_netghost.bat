@echo off
REM NetGhost Master Launcher
REM Run as Administrator for raw packet steganography

echo.
echo ===============================================================
echo   NETGHOST - NETWORK STEGANOGRAPHY LABORATORY
echo ===============================================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Not running as Administrator!
    echo Packet capture and raw transmission require Administrator privileges.
    echo.
)

if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
    set "PY_EXE=.venv\Scripts\python.exe"
) else (
    set "PY_EXE=python"
)

echo Please choose an execution mode:
echo.
echo   [1] Dual Nodes (Recommended)
echo       - Sender on http://127.0.0.1:5000/sender
echo       - Receiver on http://127.0.0.1:5001/receiver
echo.
echo   [2] Dedicated Sender Node Only (Port 5000)
echo   [3] Dedicated Receiver Node Only (Port 5001)
echo   [4] Unified Lab Console (Port 5000)
echo.

set /p choice="Enter choice (1-4) [default: 1]: "

if "%choice%"=="2" goto opt_sender
if "%choice%"=="3" goto opt_receiver
if "%choice%"=="4" goto opt_unified
goto opt_dual

:opt_dual
echo.
echo Launching Dual Nodes...
call start_dual_nodes.bat
exit /b

:opt_sender
echo.
echo Launching Dedicated Sender Node...
call start_sender.bat
exit /b

:opt_receiver
echo.
echo Launching Dedicated Receiver Node...
call start_receiver.bat
exit /b

:opt_unified
echo.
echo Starting Unified Console on http://127.0.0.1:5000 ...
start http://127.0.0.1:5000
%PY_EXE% app.py
pause
exit /b
