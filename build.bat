@echo off
REM Build single-file exe for Windows.
REM Requires: Python 3.10+ with PyInstaller installed (pip install pyinstaller).

python -m PyInstaller --onefile --windowed ^
  --name KeeneticFqdnManager ^
  --add-data "services.json;." ^
  --clean ^
  kn_router_gui.py

IF %ERRORLEVEL% NEQ 0 (
  echo Build failed.
  exit /b 1
)
echo.
echo Build OK: dist\KeeneticFqdnManager.exe
