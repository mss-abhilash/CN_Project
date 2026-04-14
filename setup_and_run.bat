@echo off
SETLOCAL EnableDelayedExpansion
title IoT VPN + 2FA — Dev Environment Setup
color 0A

echo.
echo ============================================================
echo   IoT VPN + 2FA — Complete Development Environment Setup
echo ============================================================
echo.

:: ── Step 1: Check Python Version ─────────────────────────────
echo [1/6] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo    [ERROR] Python is not installed or not in PATH.
    echo    Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo    Found Python %PYVER%
echo.

:: ── Step 2: Create Virtual Environment ───────────────────────
echo [2/6] Creating virtual environment...
if exist "venv\Scripts\activate.bat" (
    echo    Virtual environment already exists — skipping creation.
) else (
    python -m venv venv
    if errorlevel 1 (
        echo    [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo    Virtual environment created.
)
echo.

:: ── Step 3: Activate Virtual Environment ─────────────────────
echo [3/6] Activating virtual environment...
call venv\Scripts\activate.bat
echo    Activated: %VIRTUAL_ENV%
echo.

:: ── Step 4: Upgrade pip ──────────────────────────────────────
echo [4/6] Upgrading pip...
python -m pip install --upgrade pip --quiet
echo    pip upgraded.
echo.

:: ── Step 5: Install Dependencies ─────────────────────────────
echo [5/6] Installing dependencies from requirements.txt...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo    [ERROR] Dependency installation failed.
    echo    Try running: pip install -r requirements.txt
    pause
    exit /b 1
)
echo    All dependencies installed successfully.
echo.

:: ── Step 6: Verify Installation ──────────────────────────────
echo [6/6] Verifying key packages...
python -c "import fastapi; print(f'    FastAPI      {fastapi.__version__}')"
python -c "import uvicorn; print(f'    Uvicorn      {uvicorn.__version__}')"
python -c "import pyotp; print(f'    PyOTP        {pyotp.__version__}')"
python -c "import cryptography; print(f'    Cryptography {cryptography.__version__}')"
python -c "import sqlalchemy; print(f'    SQLAlchemy   {sqlalchemy.__version__}')"
echo.

:: ── Launch ───────────────────────────────────────────────────
echo ============================================================
echo   Setup Complete — Starting FastAPI Server...
echo ============================================================
echo.
echo   Server  : http://127.0.0.1:8000
echo   API Docs: http://127.0.0.1:8000/docs
echo   Press Ctrl+C to stop the server.
echo.

python main.py

pause
ENDLOCAL
