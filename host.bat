@echo off
setlocal EnableExtensions
cd /d "%~dp0" || exit /b 1

if exist ".venv\Scripts\python.exe" (
  set "MCS_PYTHON=%CD%\.venv\Scripts\python.exe"
) else (
  set "MCS_PYTHON=python"
)

if not exist "dashboard\app.py" (
  echo ERROR: dashboard\app.py was not found. Run host.bat from the project folder.
  pause
  exit /b 1
)

"%MCS_PYTHON%" -c "import flask, flask_wtf, waitress, webauthn, boto3, meraki, azure.identity, azure.mgmt.storage, cloudflare, argon2, cryptography"
if errorlevel 1 (
  echo Required dashboard packages are missing. Installing requirements.txt...
  if not exist "requirements.txt" (
    echo ERROR: requirements.txt was not found.
    pause
    exit /b 1
  )
  "%MCS_PYTHON%" -m pip install -r requirements.txt
  if errorlevel 1 (
    echo ERROR: Package installation failed. Check your internet connection and Python installation.
    pause
    exit /b 1
  )
)

echo.
echo Starting the complete MultiCloudSecurity project...
echo The dashboard includes the built-in Cloud Security Assistant.
echo.
powershell -NoProfile -Command "try{$c=New-Object Net.Sockets.TcpClient;$c.Connect('127.0.0.1',8000);$c.Close();exit 0}catch{exit 1}"
if not errorlevel 1 goto :open_dashboard

echo Starting the server at http://localhost:8000 ...
start "MultiCloudSecurity Server" "%MCS_PYTHON%" -m dashboard.app
powershell -NoProfile -Command "$ready=$false; for($i=0;$i -lt 30;$i++){try{$client=New-Object Net.Sockets.TcpClient;$client.Connect('127.0.0.1',8000);$client.Close();$ready=$true;break}catch{Start-Sleep -Milliseconds 500}}; if($ready){exit 0}else{exit 1}"
if errorlevel 1 goto :host_error

:open_dashboard
start "" "http://localhost:8000"
echo Dashboard is ready. Keep the MultiCloudSecurity Server window open if this script started it.
echo This host is available on this computer at http://localhost:8000.
goto :finish

:host_error
echo ERROR: The server did not start. Check the MultiCloudSecurity Server window for details.

:finish
echo.
echo Hosting continues while the dashboard server is running.
echo Press any key to close this launcher window.
pause >nul
endlocal
