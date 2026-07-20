@echo off
title GrowthLock AI Site
cd /d "%~dp0"
echo Installing dependencies if needed...
call npm install
echo.
echo Starting GrowthLock on http://localhost:3000
echo Do not close this window while using the site.
echo.
start http://localhost:3000
call npm start
pause
