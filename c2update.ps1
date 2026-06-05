# c2update.ps1 — Wrapper script to update C2IntelFeeds JSON feed (Windows).
#
# Usage:
#   .\c2update.ps1                              # update all feeds
#   .\c2update.ps1 -30day                       # update only 30-day active IPs
#   .\c2update.ps1 -domain                      # update only domain feed
#   .\c2update.ps1 -output "C:\feeds\feed.json" # custom output path
#   .\c2update.ps1 -timeout 30                  # custom HTTP timeout
#
# Schedule with Task Scheduler:
#   schtasks /create /tn "C2IntelFeedsUpdate" /tr "powershell -ExecutionPolicy Bypass -File C:\path\to\c2update.ps1" /sc daily /st 02:00

param(
    [string]$Output = "c2intel_feeds.json",
    [switch]$ThreeDay,
    [switch]$Domain,
    [switch]$IPPort,
    [int]$Timeout = 10
)

# Resolve script directory robustly (works when run via -File, Invoke-Expression, or Task Scheduler)
$ScriptDir = $null
if ($MyInvocation.MyCommand.Path) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
} elseif ($PSScriptRoot) {
    $ScriptDir = $PSScriptRoot
} else {
    $ScriptDir = (Get-Location).Path
}

$Binary = Join-Path $ScriptDir "c2update\c2update.exe"
$LogFile = Join-Path $ScriptDir "c2update.log"

# Build arguments for the binary
$CmdArgs = @("-output", $Output, "-timeout", $Timeout.ToString())
if ($ThreeDay) { $CmdArgs += @("-30day") }
if ($Domain)   { $CmdArgs += @("-domain") }
if ($IPPort)   { $CmdArgs += @("-ipport") }

$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "[$Timestamp] Starting C2IntelFeeds update..."
$Timestamp | Out-File -Append -FilePath $LogFile

if (-not (Test-Path $Binary)) {
    Write-Host "ERROR: c2update.exe not found at $Binary" -ForegroundColor Red
    Write-Host "Build it with: cd c2update && go build -o c2update.exe ." -ForegroundColor Red
    $Timestamp | Out-File -Append -FilePath $LogFile
    exit 1
}

# Execute the binary directly (no Invoke-Expression)
Write-Host "  Running: $Binary $($CmdArgs -join ' ')"
$exitCode = 0
& $Binary @CmdArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    $exitCode = $LASTEXITCODE
}

if ($exitCode -eq 0) {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] Update complete."
    $Timestamp | Out-File -Append -FilePath $LogFile
} else {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] Update FAILED (exit code $exitCode)." -ForegroundColor Red
    $Timestamp | Out-File -Append -FilePath $LogFile
    exit 1
}
