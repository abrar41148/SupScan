@echo off
cd /d "%~dp0"
start "" /min cmd /c "ping -n 3 127.0.0.1 >nul & start http://127.0.0.1:8765/"
python -m supply_scan.serve --port 8765
