# Installs LuaJIT + luarocks on Windows (best-effort).
# Usage: powershell -ExecutionPolicy Bypass -File scripts\setup_lua.ps1
$ErrorActionPreference = "Stop"

function Exists($cmd) {
  $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)
}

if (Exists "choco") {
  choco install -y luajit luarocks
} elseif (Exists "winget") {
  Write-Host "winget available; please install LuaJIT and LuaRocks via winget or download releases."
  Write-Host "Example: winget install LuaJIT.LuaJIT"
} else {
  Write-Warning "Neither Chocolatey nor winget found. Install LuaJIT + LuaRocks manually."
}

Write-Host "If you have LuaRocks, install lua-cjson:"
Write-Host "  luarocks install lua-cjson"
