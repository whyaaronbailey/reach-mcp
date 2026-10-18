# Open a running server's private approval panel without printing its URL token.
param([int]$ProcessId, [string]$StateDirectory)
$ErrorActionPreference = 'Stop'
$root = if ($env:REACH_MCP_HOME) { [Environment]::ExpandEnvironmentVariables($env:REACH_MCP_HOME) } else { Split-Path $PSScriptRoot -Parent }
$state = if ($StateDirectory) { $StateDirectory } else { Join-Path $root '.state' }
$pattern = if ($PSBoundParameters.ContainsKey('ProcessId')) { "control-panel-$ProcessId.url" } else { 'control-panel-*.url' }
$files = @(Get-ChildItem -LiteralPath $state -Filter $pattern -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
foreach ($file in $files) {
    try {
        $url = [Uri](Get-Content -Raw -LiteralPath $file.FullName).Trim()
        if ($url.Scheme -ne 'http' -or $url.Host -ne '127.0.0.1' -or -not $url.Fragment -or $url.UserInfo) { continue }
        $health = Invoke-WebRequest -UseBasicParsing -Uri ("http://127.0.0.1:{0}/health" -f $url.Port) -TimeoutSec 2
        if ($health.StatusCode -ne 200) { continue }
    } catch { continue }
    Start-Process -FilePath $url.AbsoluteUri
    Write-Output 'Opened the local approval controls.'
    return
}
throw 'No running control panel found. Start the native server first.'
