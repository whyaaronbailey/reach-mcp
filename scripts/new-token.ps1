# Print a cryptographically random bearer token for the HTTP transport.
# Use it for this shell:   $env:REACH_MCP_TOKEN = & .\scripts\new-token.ps1
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
