# Create or rotate local credentials without printing their values.
# Prefer configure-github.ps1 for masked interactive credential entry.
param(
    [string]$ClientId,
    [string]$ClientSecret,
    [string]$PublicUrl,
    [long[]]$AllowedGitHubUserIds,
    [ValidateRange(1,65535)][int]$NativePort
)
$ErrorActionPreference = 'Stop'
$dir = Join-Path $PSScriptRoot 'secrets'
$file = Join-Path $dir 'github-oauth.json'
New-Item -ItemType Directory -Force $dir | Out-Null
$ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls $dir /inheritance:r /grant:r "*${ownerSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to secure secrets folder.' }
$allowedSids = @($ownerSid,'S-1-5-18','S-1-5-32-544')
foreach ($path in @($dir,$file,(Join-Path $dir 'deployment.json'))) {
    if (Test-Path -LiteralPath $path) {
        $unexpected = @((Get-Acl -LiteralPath $path).Access | Where-Object {
            $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowedSids
        })
        if ($unexpected.Count) { throw 'Unexpected secrets ACL entries; refusing to write credentials.' }
    }
}
function New-Secret([int]$bytes) {
    $buffer = New-Object byte[] $bytes
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+','-').Replace('/','_')
}
$cfg = [ordered]@{}
if (Test-Path -LiteralPath $file) {
    (Get-Content -Raw -LiteralPath $file | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }
}
if ($PublicUrl) { $cfg['public_url'] = $PublicUrl.TrimEnd('/') }
if (-not $cfg['public_url']) { throw 'Supply -PublicUrl for a new deployment.' }
$origin = [Uri]$cfg['public_url']
if (-not $origin.IsAbsoluteUri -or $origin.Scheme -ne 'https' -or $origin.AbsolutePath -ne '/' -or $origin.Query -or $origin.Fragment -or $origin.UserInfo) {
    throw 'PublicUrl must be an HTTPS origin without a path, credentials, query, or fragment.'
}
if ($PSBoundParameters.ContainsKey('AllowedGitHubUserIds')) { $cfg['allowed_github_user_ids'] = @($AllowedGitHubUserIds) }
$owners = @($cfg['allowed_github_user_ids'])
if ($owners.Count -ne 1 -or -not ($owners[0] -is [int] -or $owners[0] -is [long]) -or $owners[0] -le 0) {
    throw 'Supply exactly one positive immutable GitHub user ID with -AllowedGitHubUserIds.'
}
if ($PSBoundParameters.ContainsKey('NativePort')) { $cfg['native_url'] = "http://127.0.0.1:$NativePort/mcp" }
if (-not $cfg['native_url']) { $cfg['native_url'] = 'http://127.0.0.1:8765/mcp' }
if ($cfg['native_url'] -notmatch '^http://127\.0\.0\.1:(\d+)/mcp$' -or [int]$Matches[1] -lt 1 -or [int]$Matches[1] -gt 65535 -or [int]$Matches[1] -in @(8766,8891)) {
    throw 'Native URL must be loopback HTTP on an available port distinct from the panel and relay ports.'
}
if ($ClientId) { $cfg['client_id'] = $ClientId } elseif (-not $cfg['client_id']) { $cfg['client_id'] = 'PASTE_GITHUB_OAUTH_CLIENT_ID' }
if ($ClientSecret) { $cfg['client_secret'] = $ClientSecret } elseif (-not $cfg['client_secret']) { $cfg['client_secret'] = 'PASTE_GITHUB_OAUTH_CLIENT_SECRET' }
if (-not $cfg['jwt_signing_key']) { $cfg['jwt_signing_key'] = New-Secret 48 }
if (-not $cfg['native_token']) { $cfg['native_token'] = New-Secret 32 }
$deployment = [ordered]@{
    machine_name = $env:COMPUTERNAME
    public_url = $cfg['public_url']
    native_url = $cfg['native_url']
    owner_github_user_id = $owners[0]
}
$utf8 = New-Object Text.UTF8Encoding $false
[IO.File]::WriteAllText($file, ($cfg | ConvertTo-Json -Depth 4), $utf8)
[IO.File]::WriteAllText((Join-Path $dir 'deployment.json'), ($deployment | ConvertTo-Json), $utf8)
Write-Output 'Saved local relay credentials and deployment identity (values not shown).'
