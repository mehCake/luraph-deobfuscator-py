#!/usr/bin/env bash
set -euo pipefail

# Installs LuaJIT + luarocks + lua-cjson on Linux/macOS (best-effort).
# Usage: bash scripts/setup_lua.sh

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y luajit libluajit-5.1-dev luarocks
elif command -v brew >/dev/null 2>&1; then
  brew update
  brew install luajit luarocks
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -Sy --noconfirm luajit luarocks
else
  echo "Please install LuaJIT + luarocks manually for your distro."
fi

# lua-cjson (fast JSON in Lua; optional but nice)
if command -v luarocks >/dev/null 2>&1; then
  sudo luarocks install lua-cjson || luarocks install lua-cjson || true
fi

echo "Done. luajit path: $(command -v luajit || echo 'not found')"
