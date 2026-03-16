@echo off
echo ============================================
echo   HuddleTracker — Setup and Run
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install from https://python.org
    pause
    exit /b 1
)

:: Delete old venv if it exists to avoid conflicts
if exist venv (
    echo Removing old virtual environment...
    rmdir /s /q venv
)

:: Create fresh venv
echo [1/3] Creating virtual environment...
python -m venv venv

:: Activate and install
echo [2/3] Installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo ERROR: Installation failed. Try running manually:
    echo   pip install -r requirements.txt --no-deps
    pause
    exit /b 1
)

:: Run app
echo [3/3] Starting HuddleTracker...
echo.
echo  Open your browser at: http://127.0.0.1:5000
echo  Login: admin / Admin@1234
echo  Press Ctrl+C to stop the server
echo.
python app.py
pause
