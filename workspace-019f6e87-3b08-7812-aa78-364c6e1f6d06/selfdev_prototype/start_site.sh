#!/usr/bin/env bash
cd "$(dirname "$0")"
echo "Installing dependencies if needed..."
npm install
echo "Starting GrowthLock on http://localhost:3000"
echo "Do not close this terminal while using the site."
if command -v xdg-open >/dev/null 2>&1; then xdg-open http://localhost:3000 >/dev/null 2>&1 & fi
if command -v open >/dev/null 2>&1; then open http://localhost:3000 >/dev/null 2>&1 & fi
npm start
