$root = if ($env:REACH_MCP_HOME) { [Environment]::ExpandEnvironmentVariables($env:REACH_MCP_HOME) } else { Split-Path $PSScriptRoot -Parent }
$flag = Join-Path $root 'PAUSED'
if (Test-Path -LiteralPath $flag) { Remove-Item -LiteralPath $flag }
Write-Output 'Desktop control resumed.'
