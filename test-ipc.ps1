param(
    [string]$Engine = "all" # "rs", "cs", or "all"
)

$ErrorActionPreference = "Stop"

function Test-EngineIpc {
    param(
        [string]$EngineName,
        [string]$ExePath,
        [string[]]$CommandLineArgs = @()
    )

    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host " TESTING ENGINE: $EngineName" -ForegroundColor Cyan
    Write-Host " Exe: $ExePath" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan

    if (-not (Test-Path $ExePath)) {
        throw "Engine executable not found at: $ExePath"
    }

    if ($CommandLineArgs -and $CommandLineArgs.Length -gt 0) {
        $proc = Start-Process -FilePath $ExePath -ArgumentList $CommandLineArgs -PassThru -NoNewWindow
    } else {
        $proc = Start-Process -FilePath $ExePath -PassThru -NoNewWindow
    }
    Start-Sleep -Milliseconds 1200

    try {
        $pipeName = "adblock-engine"
        $pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
        Write-Host "Connecting to \\.\pipe\$pipeName..." -NoNewline
        $pipeClient.Connect(4000)
        Write-Host " CONNECTED!" -ForegroundColor Green

        $reader = New-Object System.IO.StreamReader($pipeClient, [System.Text.Encoding]::UTF8)
        $writer = New-Object System.IO.StreamWriter($pipeClient, (New-Object System.Text.UTF8Encoding($false)))
        $writer.AutoFlush = $true

        function Invoke-Rpc {
            param([string]$Method, [object]$Params = @{}, [object]$Id = 1)
            $req = @{ id = $Id; method = $Method; params = $Params } | ConvertTo-Json -Compress
            $writer.WriteLine($req)
            while ($true) {
                $respLine = $reader.ReadLine()
                if (-not $respLine) { break }
                $parsed = $respLine | ConvertFrom-Json
                if ($null -ne $parsed.event) {
                    continue
                }
                return $parsed
            }
        }

        # 1. Ping
        Write-Host "1. Testing engine.ping... " -NoNewline
        $r1 = Invoke-Rpc -Method "engine.ping" -Id 101
        if ($r1.result.status -eq "ok" -and $r1.id -eq 101) {
            Write-Host "PASSED [timestamp: $($r1.result.timestamp)]" -ForegroundColor Green
        } else {
            throw "Failed engine.ping: $($r1 | ConvertTo-Json -Compress)"
        }

        # 2. Get Status
        Write-Host "2. Testing engine.get_status... " -NoNewline
        $r2 = Invoke-Rpc -Method "engine.get_status" -Id 102
        if ($r2.result.state -in @("running", "paused") -and $null -ne $r2.result.stats) {
            Write-Host "PASSED [state: $($r2.result.state), active rules: $($r2.result.active_rules_count)]" -ForegroundColor Green
        } else {
            throw "Failed engine.get_status: $($r2 | ConvertTo-Json -Compress)"
        }

        # 3. Add Rules
        Write-Host "3. Testing rules.add... " -NoNewline
        $r3 = Invoke-Rpc -Method "rules.add" -Params @{ rules = @("test-ad-1.com", "*.test-network.org") } -Id 103
        if ($r3.result.added -eq 2) {
            Write-Host "PASSED [added: $($r3.result.added), total: $($r3.result.active_rules_count)]" -ForegroundColor Green
        } else {
            throw "Failed rules.add: $($r3 | ConvertTo-Json -Compress)"
        }

        # 4. List Rules
        Write-Host "4. Testing rules.list... " -NoNewline
        $r4 = Invoke-Rpc -Method "rules.list" -Params @{ offset = 0; limit = 100 } -Id 104
        if ($r4.result.rules.Count -ge 2 -and ($r4.result.rules -contains "test-ad-1.com")) {
            Write-Host "PASSED [total: $($r4.result.total), returned: $($r4.result.rules.Count)]" -ForegroundColor Green
        } else {
            throw "Failed rules.list: $($r4 | ConvertTo-Json -Compress)"
        }

        # 5. Remove Rules
        Write-Host "5. Testing rules.remove... " -NoNewline
        $r5 = Invoke-Rpc -Method "rules.remove" -Params @{ rules = @("test-ad-1.com") } -Id 105
        if ($r5.result.removed -eq 1) {
            Write-Host "PASSED [removed: 1]" -ForegroundColor Green
        } else {
            throw "Failed rules.remove: $($r5 | ConvertTo-Json -Compress)"
        }

        # 6. Set State (Pause / Resume)
        Write-Host "6. Testing engine.set_state... " -NoNewline
        $r6a = Invoke-Rpc -Method "engine.set_state" -Params @{ state = "paused" } -Id 106
        $r6b = Invoke-Rpc -Method "engine.set_state" -Params @{ state = "running" } -Id 107
        if ($r6a.result.state -eq "paused" -and $r6b.result.state -eq "running") {
            Write-Host "PASSED [paused -> running]" -ForegroundColor Green
        } else {
            throw "Failed engine.set_state"
        }

        # 7. Stats Get & Reset
        Write-Host "7. Testing stats.get and stats.reset... " -NoNewline
        $r7a = Invoke-Rpc -Method "stats.get" -Id 108
        $r7b = Invoke-Rpc -Method "stats.reset" -Id 109
        if ($null -ne $r7a.result.dns_queries -and $r7b.result.reset -eq $true) {
            Write-Host "PASSED" -ForegroundColor Green
        } else {
            throw "Failed stats operations"
        }

        # 8. Error handling: Method Not Found
        Write-Host "8. Testing unknown method error handling... " -NoNewline
        $r8 = Invoke-Rpc -Method "invalid.method.call" -Id 110
        if ($r8.error.code -eq -32601) {
            Write-Host "PASSED [code: -32601]" -ForegroundColor Green
        } else {
            throw "Failed unknown method handling: $($r8 | ConvertTo-Json -Compress)"
        }

        # 9. IPC.md Command: get_status (with name/version/RAM)
        Write-Host "9. Testing IPC.md get_status (name/version)... " -NoNewline
        $r9 = Invoke-Rpc -Method "get_status" -Id 111
        if ($r9.result.name -and $r9.result.version -and $null -ne $r9.result.uptime_seconds) {
            Write-Host "PASSED [name: $($r9.result.name), v: $($r9.result.version)]" -ForegroundColor Green
        } else {
            throw "Failed get_status command"
        }

        # 10. IPC.md Command: get_stats (allowed/blocked counters, RAM)
        Write-Host "10. Testing IPC.md get_stats (allowed/blocked/RAM)... " -NoNewline
        $r10 = Invoke-Rpc -Method "get_stats" -Id 112
        if ($null -ne $r10.result.allowed_count -and $null -ne $r10.result.blocked_count -and $r10.result.ram_bytes -ge 0) {
            Write-Host "PASSED [ram: $($r10.result.ram_mb) MB, ram_bytes: $($r10.result.ram_bytes)]" -ForegroundColor Green
        } else {
            throw "Failed get_stats command"
        }

        # 11. IPC.md Command: set_lists (spec/testdata/sample_list.txt)
        Write-Host "11. Testing IPC.md set_lists... " -NoNewline
        $sampleListPath = "D:\adblock\spec\testdata\sample_list.txt"
        $r11 = Invoke-Rpc -Method "set_lists" -Params @{ paths = @($sampleListPath) } -Id 113
        if ($r11.result.status -eq "ok" -and $r11.result.loaded_lists -ge 1) {
            Write-Host "PASSED [loaded: $($r11.result.loaded_lists), rules: $($r11.result.active_rules_count)]" -ForegroundColor Green
        } else {
            throw "Failed set_lists command: $($r11 | ConvertTo-Json -Compress)"
        }

        # 12. IPC.md Command: set_allowlist
        Write-Host "12. Testing IPC.md set_allowlist... " -NoNewline
        $r12 = Invoke-Rpc -Method "set_allowlist" -Params @{ rules = @("@@||custom-safe.org^", "safe.mycorp.net") } -Id 114
        if ($r12.result.status -eq "ok" -and $r12.result.allowlist_count -ge 2) {
            Write-Host "PASSED [allowlist_count: $($r12.result.allowlist_count)]" -ForegroundColor Green
        } else {
            throw "Failed set_allowlist command: $($r12 | ConvertTo-Json -Compress)"
        }

        # 13. IPC.md Command: reload
        Write-Host "13. Testing IPC.md reload... " -NoNewline
        $r13 = Invoke-Rpc -Method "reload" -Id 115
        if ($r13.result.status -eq "ok" -and $r13.result.active_rules_count -ge 1) {
            Write-Host "PASSED [active_rules: $($r13.result.active_rules_count), allowlist: $($r13.result.allowlist_count)]" -ForegroundColor Green
        } else {
            throw "Failed reload command"
        }

        # 14. IPC.md Command: get_recent_blocked
        Write-Host "14. Testing IPC.md get_recent_blocked... " -NoNewline
        $r14 = Invoke-Rpc -Method "get_recent_blocked" -Params @{ limit = 10 } -Id 116
        if ($null -ne $r14.result.items) {
            Write-Host "PASSED [items returned: $($r14.result.items.Count)]" -ForegroundColor Green
        } else {
            throw "Failed get_recent_blocked command"
        }

        # 15. IPC.md Commands: stop and start
        Write-Host "15. Testing IPC.md stop and start... " -NoNewline
        $r15a = Invoke-Rpc -Method "stop" -Id 117
        $r15b = Invoke-Rpc -Method "start" -Id 118
        if ($r15a.result.state -eq "stopped" -and $r15b.result.state -eq "running") {
            Write-Host "PASSED [stopped -> running]" -ForegroundColor Green
        } else {
            throw "Failed stop/start commands"
        }

        Write-Host "`n>>> ${EngineName}: ALL IPC & IPC.MD TESTS PASSED! Spec fully validated." -ForegroundColor Green

        $pipeClient.Dispose()
    }
    finally {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
        }
    }
}

if ($Engine -in @("rs", "all")) {
    Test-EngineIpc -EngineName "engine-rs (Rust)" `
                   -ExePath "D:\adblock\engine-rs\target\debug\adblock-engine-rs.exe" `
                   -CommandLineArgs @("--rules", "D:\adblock\spec\test-data\rules.txt")
}

if ($Engine -in @("cs", "all")) {
    Test-EngineIpc -EngineName "engine-cs (C# .NET 10)" `
                   -ExePath "D:\adblock\engine-cs\bin\Debug\net10.0\adblock-engine-cs.exe" `
                   -CommandLineArgs @("--rules", "D:\adblock\spec\test-data\rules.txt")
}
