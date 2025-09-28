# run_all.ps1
# Usage:
#   ./run_all.ps1 -ScriptKey "ppcg208ty9nze5wcoldxh" [-LuaJit "C:\path\to\luajit.exe"]
param(
  [string]$ScriptKey = $env:SCRIPT_KEY,
  [string]$LuaJit = "luajit"
)

if (-not $ScriptKey) {
  Write-Error "Please provide -ScriptKey or set SCRIPT_KEY env var."
  exit 1
}

if (-not (Test-Path ".\initv4.lua")) { Write-Error "initv4.lua not found."; exit 1 }
if (-not (Test-Path ".\Obfuscated.json")) { Write-Error "Obfuscated.json not found."; exit 1 }

Write-Host "Running devirtualizer..."
& $LuaJit ".\tools\user_env\devirtualize.lua" $ScriptKey
if ($LASTEXITCODE -ne 0) {
  Write-Error "Devirtualizer failed. Inspect output above."
  exit $LASTEXITCODE
}

# Prefer single decoded_output.lua; otherwise reformat all decoded_chunk_*.lua
if (Test-Path ".\decoded_output.lua") {
  Write-Host "Reformatting decoded_output.lua..."
  & $LuaJit ".\tools\user_env\reformat.lua" ".\decoded_output.lua" | Out-File -Encoding utf8 ".\readable.lua"
  Write-Host "Wrote readable.lua"
} else {
  $chunks = Get-ChildItem -File -Filter "decoded_chunk_*.lua" | Sort-Object Name
  if ($chunks.Count -eq 0) {
    Write-Warning "No decoded_output.lua or decoded_chunk_*.lua found; nothing to reformat."
    exit 0
  }
  $i = 1
  foreach ($c in $chunks) {
    $out = ".\chunk$($i)_readable.lua"
    Write-Host "Reformatting $($c.Name) -> $out"
    & $LuaJit ".\tools\user_env\reformat.lua" $c.FullName | Out-File -Encoding utf8 $out
    $i++
  }
  Write-Host "Done."
}
