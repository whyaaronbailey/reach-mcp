# Kill switch: while PAUSED exists, every input tool (click, type, keys, drag, ...) refuses.
# Screenshots and other read-only tools keep working. Undo with resume.ps1.
$root = if ($env:REACH_MCP_HOME) { [Environment]::ExpandEnvironmentVariables($env:REACH_MCP_HOME) } else { Split-Path $PSScriptRoot -Parent }
$flag = Join-Path $root 'PAUSED'
New-Item -ItemType Directory -Force -Path $root | Out-Null
Set-Content -LiteralPath $flag -Value "paused $(Get-Date -Format o)" -Encoding utf8
Write-Output "Desktop control paused ($flag)."
