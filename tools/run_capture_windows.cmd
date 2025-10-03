@echo off
setlocal ENABLEDELAYEDEXPANSION

set SCRIPT_KEY=
set OUT_DIR=out
set INIT=initv4.lua
set JSON=Obfuscated.json
set EXTRA=

:parse
if "%~1"=="" goto run
if "%~1"=="--key" (
    set SCRIPT_KEY=%~2
    shift
    shift
    goto parse
)
if "%~1"=="--out" (
    set OUT_DIR=%~2
    shift
    shift
    goto parse
)
set EXTRA=%EXTRA% %~1
shift
goto parse

:run
if "%SCRIPT_KEY%"=="" (
    echo Usage: %~n0 --key ^<script_key^> [--out out] [extra args]
    exit /b 1
)

python -m venv .venv >nul 2>&1
if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
)

python -m pip install --quiet -r requirements.txt
python src\sandbox_runner.py --init %INIT% --json %JSON% --key %SCRIPT_KEY% --out %OUT_DIR% --run-lifter %EXTRA%

endlocal
