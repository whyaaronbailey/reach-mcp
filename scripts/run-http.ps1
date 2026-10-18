# Serve Streamable HTTP on loopback for clients that connect to a running server.
# Requires REACH_MCP_TOKEN (>= 24 chars). Generate one with:
#   $env:REACH_MCP_TOKEN = & .\scripts\new-token.ps1
# Clients then send:  Authorization: Bearer <token>   to   http://127.0.0.1:8765/mcp
param([int]$Port = 8765, [string]$Client = 'http')
$root = Split-Path $PSScriptRoot -Parent
if (-not $env:REACH_MCP_TOKEN) { throw 'Set $env:REACH_MCP_TOKEN first: $env:REACH_MCP_TOKEN = & .\scripts\new-token.ps1' }
& (Join-Path $root '.venv\Scripts\reach-mcp.exe') --transport http --port $Port --client $Client
