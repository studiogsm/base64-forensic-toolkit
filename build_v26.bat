@echo off
REM ============================================================
REM  Base64 Forensic Toolkit v2.7 — build.bat
REM  Laboratorium Elektroniki / Krystian Zarzecki
REM
REM  Wymagane pliki w jednym folderze:
REM    base64_forensic_toolkit_v2_5.py
REM    b64toolkit_v26_extension.py
REM    b64toolkit_layout_b.py
REM    b64toolkit_v27_extension.py
REM    base64_forensic_toolkit_v2_6.py  (main)
REM    app_icon.ico
REM ============================================================

echo.
echo  [1/4] Sprawdzam Python...
python --version
if errorlevel 1 ( echo  BLAD: Python nie znaleziony. & pause & exit /b 1 )

echo.
echo  [2/4] Sprawdzam PyInstaller...
python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 ( python -m pip install pyinstaller )
echo  PyInstaller OK.

echo.
echo  [3/4] Czyszcze poprzednie buildy...
if exist build        rmdir /s /q build
if exist dist         rmdir /s /q dist
if exist __pycache__  rmdir /s /q __pycache__
if exist "base64_forensic_toolkit_v2_6.spec" del /f "base64_forensic_toolkit_v2_6.spec"

echo.
echo  [4/4] Kompiluje EXE...
pyinstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --name "base64_forensic_toolkit_v2_7" ^
    --icon "app_icon.ico" ^
    --add-data "base64_forensic_toolkit_v2_5.py;." ^
    --add-data "b64toolkit_v26_extension.py;." ^
    --add-data "b64toolkit_layout_b.py;." ^
    --add-data "b64toolkit_v27_extension.py;." ^
    --add-data "app_icon.ico;." ^
    base64_forensic_toolkit_v2_6.py

if errorlevel 1 (
    echo.
    echo  BLAD kompilacji!
    pause & exit /b 1
)

echo.
echo  ============================================================
echo   SUKCES! Plik: dist\base64_forensic_toolkit_v2_7.exe
echo  ============================================================
explorer dist
pause
