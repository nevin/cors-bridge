@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js 18 or newer is required. Download it from https://nodejs.org and run this again.
  pause
  exit /b 1
)
rem Let Node trust the certificates your company has installed in Windows (for the real server).
set NODE_USE_SYSTEM_CA=1
node server.js
pause
