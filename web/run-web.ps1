param([ValidateSet('local','client')][string]$ApprovalPolicy = 'local')

# Run the loopback native server and OAuth relay as the logged-in desktop user.
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ([Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Use the normal non-elevated desktop user.'
}
$web = $PSScriptRoot
$root = Split-Path $web -Parent
$cfg = Get-Content -Raw (Join-Path $web 'secrets\github-oauth.json') | ConvertFrom-Json
$pin = Get-Content -Raw (Join-Path $web 'secrets\deployment.json') | ConvertFrom-Json
if ($pin.machine_name -ine $env:COMPUTERNAME) { throw 'Deployment belongs to a different machine; configure it locally first.' }
if ($cfg.public_url -ne $pin.public_url -or $cfg.native_url -ne $pin.native_url) { throw 'Relay addresses do not match the local deployment.' }
$owners = @($cfg.allowed_github_user_ids)
if ($owners.Count -ne 1 -or $owners[0] -ne $pin.owner_github_user_id -or $pin.owner_github_user_id -le 0) { throw 'The owner-only GitHub lock does not match the local deployment.' }
$origin = [Uri]$cfg.public_url
if ($origin.Scheme -ne 'https' -or $origin.AbsolutePath -ne '/' -or $origin.Query -or $origin.Fragment -or $origin.UserInfo) { throw 'Public URL must be an HTTPS origin.' }
if ($cfg.native_url -notmatch '^http://127\.0\.0\.1:(\d+)/mcp$') { throw 'Native server must use IPv4 loopback HTTP.' }
$nativePort = [int]$Matches[1]
if ($nativePort -lt 1 -or $nativePort -gt 65535 -or $nativePort -in @(8766,8891)) { throw 'Invalid or conflicting native port.' }
foreach ($key in @('client_id','client_secret','native_token','jwt_signing_key')) {
    if (-not ($cfg.$key -is [string]) -or -not $cfg.$key -or $cfg.$key.StartsWith('PASTE')) { throw 'Configure credentials with web\configure-github.ps1 first.' }
}
. (Join-Path $web 'process-lifetime.ps1')
$server = $null
$relay = $null
try {
    $env:REACH_MCP_TOKEN = $cfg.native_token
    try {
        $server = Start-Process -FilePath (Join-Path $root '.venv\Scripts\pythonw.exe') `
            -ArgumentList @('-m','reach_mcp','--transport','http','--port',"$nativePort",'--client','web-relay','--approval-policy',$ApprovalPolicy) `
            -WorkingDirectory $root -WindowStyle Hidden -PassThru `
            -RedirectStandardError (Join-Path $web 'server-stderr.log')
    } finally {
        Remove-Item Env:REACH_MCP_TOKEN -ErrorAction SilentlyContinue
    }
    $relay = Start-Process -FilePath (Join-Path $web '.venv\Scripts\pythonw.exe') `
        -ArgumentList @('-u', ('"{0}"' -f (Join-Path $web 'relay.py'))) `
        -WorkingDirectory $web -WindowStyle Hidden -PassThru `
        -RedirectStandardError (Join-Path $web 'relay-launcher-stderr.log')
    while (-not $relay.WaitForExit(1000)) {
        if ($server.HasExited) { throw 'Native server exited; stopping relay.' }
    }
    exit $relay.ExitCode
} finally {
    foreach ($child in @($relay,$server)) {
        if ($null -ne $child -and -not $child.HasExited) { Stop-Process -Id $child.Id -Force }
    }
}
