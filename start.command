#!/bin/bash
cd "$(dirname "$0")"
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 18 or newer is required. Download it from https://nodejs.org and run this again."
  read -n 1 -s -r -p "Press any key to close"
  exit 1
fi
# Let Node trust the certificates your company has installed in the macOS keychain (for the real server).
export NODE_USE_SYSTEM_CA=1
node server.js
