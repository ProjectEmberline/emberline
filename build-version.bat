@echo off
REM ─────────────────────────────────────────────────────────────────────────────
REM Emberline — pre-deploy: write current git commit hash to BUILD_VERSION
REM ─────────────────────────────────────────────────────────────────────────────
REM Run this from C:\emberline before the scp-to-Pi step. It writes the
REM current HEAD commit hash to BUILD_VERSION, which server.js reads at
REM startup and displays in the page footer linked to GitHub.
REM
REM The deploy workflow becomes:
REM   1. git push origin main     (so the commit is actually on GitHub)
REM   2. build-version.bat        (this script — writes BUILD_VERSION)
REM   3. scp the files to the Pi  (include BUILD_VERSION)
REM   4. docker compose build && docker compose up -d on the Pi
REM
REM Guardrails:
REM   - Refuses to run if the working tree is dirty (uncommitted changes)
REM   - Refuses to run if HEAD is not pushed to origin/main
REM Both conditions mean the footer would link to a commit GitHub doesn't
REM have, which would 404 for any auditor clicking the hash.

setlocal

cd /d "%~dp0"

REM --- Guardrail 1: working tree must be clean ---
git diff-index --quiet HEAD --
if errorlevel 1 (
  echo.
  echo ERROR: working tree has uncommitted changes.
  echo Commit or stash them before deploying — the footer must point to
  echo a commit that actually exists on GitHub.
  echo.
  git status --short
  exit /b 1
)

REM --- Guardrail 2: HEAD must match origin/main ---
git fetch origin main --quiet
for /f "delims=" %%i in ('git rev-parse HEAD') do set LOCAL_SHA=%%i
for /f "delims=" %%i in ('git rev-parse origin/main') do set REMOTE_SHA=%%i
if not "%LOCAL_SHA%"=="%REMOTE_SHA%" (
  echo.
  echo ERROR: local HEAD does not match origin/main.
  echo Local:  %LOCAL_SHA%
  echo Remote: %REMOTE_SHA%
  echo.
  echo Push your changes first so the footer link resolves on GitHub:
  echo   git push origin main
  exit /b 1
)

REM --- Write BUILD_VERSION ---
git rev-parse HEAD > BUILD_VERSION
for /f "delims=" %%i in ('git rev-parse --short HEAD') do set SHORT_SHA=%%i
echo.
echo BUILD_VERSION written: %SHORT_SHA%
echo.
echo Next step: scp the updated files to the Pi, including BUILD_VERSION.

endlocal
