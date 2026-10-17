param(
    [ValidateSet("rs")]
    [string]$Engine = "rs"
)

$ErrorActionPreference = "Continue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   KHOI DONG ADBLOCK MONOREPO (WINDIVERT) " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Kiem tra va yeu cau quyen Administrator (UAC)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[UAC] Dang yeu cau quyen Administrator..." -ForegroundColor Yellow
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`" -Engine $Engine" -WorkingDirectory $PSScriptRoot -Verb RunAs
        exit 0
    } catch {
        Write-Host "[Loi] Ban da tu choi cap quyen Administrator. Khong the khoi dong." -ForegroundColor Red
        exit 1
    }
}

# 2. Kiem tra xem Engine da dang chay chua qua Named Pipe
$legacyEngine = Get-Process -Name "adblock-engine-cs" -ErrorAction SilentlyContinue
if ($legacyEngine) {
    Write-Host "[Loi] C# engine legacy van dang chay. Hay dung no truoc khi khoi dong Rust." -ForegroundColor Red
    exit 1
}

$pipeExists = $false
try {
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", "adblock.engine", [System.IO.Pipes.PipeDirection]::InOut)
    $client.Connect(300)
    $client.Dispose()
    $pipeExists = $true
} catch {
    try {
        $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", "adblock-engine", [System.IO.Pipes.PipeDirection]::InOut)
        $client.Connect(300)
        $client.Dispose()
        $pipeExists = $true
    } catch {}
}

if ($pipeExists) {
    Write-Host "[Engine] Phat hien Rust engine dang chay san tren Named Pipe!" -ForegroundColor Green
} else {
    Write-Host "[Engine] Dang build Rust Release..." -ForegroundColor Cyan
    $engineDir = "$PSScriptRoot\engine-rs\target\standalone\release"
    cargo build --release --manifest-path "$PSScriptRoot\engine-rs\Cargo.toml" --target-dir "$PSScriptRoot\engine-rs\target\standalone"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[Loi] Build engine-rs that bai." -ForegroundColor Red
        exit $LASTEXITCODE
    }
    $engineExe = "$engineDir\adblock-engine-rs.exe"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "title AdblockEngine (Rust) && `"$engineExe`" --rules `"$PSScriptRoot\spec\test-data\rules.txt`""
    Start-Sleep -Milliseconds 1500
}

# 3. Tim va khoi dong WinUI 3 App
Write-Host "[App] Dang khoi dong WinUI 3 UI (AdblockApp)..." -ForegroundColor Cyan
$candidates = @(
    "$PSScriptRoot\app\bin\x64\Release\net10.0-windows10.0.26100.0\win-x64\AdblockApp.exe",
    "$PSScriptRoot\app\bin\Release\net10.0-windows10.0.26100.0\win-x64\AdblockApp.exe",
    "$PSScriptRoot\app\bin\x64\Debug\net10.0-windows10.0.26100.0\win-x64\AdblockApp.exe",
    "$PSScriptRoot\app\bin\Debug\net10.0-windows10.0.26100.0\win-x64\AdblockApp.exe"
) | Where-Object { Test-Path $_ } | Sort-Object { (Get-Item $_).LastWriteTimeUtc } -Descending

$appExe = $candidates | Select-Object -First 1
if (-not $appExe) {
    Write-Host "Building AdblockApp..." -ForegroundColor Yellow
    dotnet build "$PSScriptRoot\app\AdblockApp.csproj" -c Release -p:Platform=x64
    $appExe = "$PSScriptRoot\app\bin\x64\Release\net10.0-windows10.0.26100.0\win-x64\AdblockApp.exe"
}

if (Test-Path $appExe) {
    Start-Process -FilePath $appExe
    Write-Host "[OK] Da khoi dong Engine va App thanh cong! ($appExe)" -ForegroundColor Green
} else {
    Write-Host "[Loi] Khong tim thay file thuc thi AdblockApp.exe tai $appExe" -ForegroundColor Red
}

