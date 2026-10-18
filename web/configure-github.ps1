# Masked credential entry. Existing local keys and owner are preserved unless supplied.
param(
    [string]$PublicUrl,
    [long]$OwnerGitHubUserId,
    [ValidateRange(1,65535)][int]$NativePort
)
$ErrorActionPreference = 'Stop'
$setup = @{}
if ($PublicUrl) { $setup.PublicUrl = $PublicUrl }
if ($PSBoundParameters.ContainsKey('OwnerGitHubUserId')) { $setup.AllowedGitHubUserIds = @($OwnerGitHubUserId) }
if ($PSBoundParameters.ContainsKey('NativePort')) { $setup.NativePort = $NativePort }
$clientId = Read-Host 'GitHub OAuth Client ID'
$secure = Read-Host 'GitHub OAuth Client Secret' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    & (Join-Path $PSScriptRoot 'setup-secrets.ps1') -ClientId $clientId -ClientSecret $plain @setup
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    $plain = $null
    $secure.Dispose()
}
Write-Host 'Saved locally. Never paste credentials into a chat or log.'
