# Create the native Python 3.12 environment, then install and test.
param([string]$Python = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe")
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    if (-not (Test-Path -LiteralPath $Python)) { throw 'Supply -Python with a Python 3.12 executable.' }
    & $Python -m venv .venv
    if ($LASTEXITCODE) { throw 'Native venv creation failed.' }
}
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
if ($LASTEXITCODE) { throw 'pip upgrade failed.' }
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
if ($LASTEXITCODE) { throw 'Project installation failed.' }
& .\.venv\Scripts\python.exe -m pytest -q
if ($LASTEXITCODE) { throw 'Unit tests failed.' }
