@echo off
cd /d "%~dp0"
echo supply-scan page at http://127.0.0.1:8765/
python -m supply_scan.serve --port 8765
