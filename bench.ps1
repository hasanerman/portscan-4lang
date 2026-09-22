param(
    [int]$Runs = 7,
    [string]$Ports = "1-1024",
    [int]$Timeout = 800,
    [int]$Concurrency = 500
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

$targets = @(
    @{ Name = "C";    Path = Join-Path $root "c\build\portscan.exe" }
    @{ Name = "C++";  Path = Join-Path $root "cpp\build\Release\portscan.exe" }
    @{ Name = "Rust"; Path = Join-Path $root "rust\target\release\portscan.exe" }
    @{ Name = "C#";   Path = Join-Path $root "csharp\src\PortScan\bin\Release\net10.0\portscan.exe" }
)

$arguments = @("127.0.0.1", "--ports", $Ports, "--timeout", $Timeout, "--concurrency", $Concurrency)

$results = foreach ($target in $targets) {
    if (-not (Test-Path $target.Path)) {
        Write-Warning "$($target.Name): binary not found -> $($target.Path)"
        continue
    }

    $durations = @()
    $peak = 0
    $openCount = 0

    for ($i = 0; $i -lt $Runs; $i++) {
        $output = [System.IO.Path]::GetTempFileName()
        $start = [System.Diagnostics.Stopwatch]::StartNew()
        $process = Start-Process -FilePath $target.Path -ArgumentList $arguments -PassThru -NoNewWindow -RedirectStandardOutput $output
        while (-not $process.HasExited) {
            $process.Refresh()
            try { $peak = [Math]::Max($peak, $process.PeakWorkingSet64) } catch { }
            Start-Sleep -Milliseconds 1
        }
        $start.Stop()
        try { $peak = [Math]::Max($peak, $process.PeakWorkingSet64) } catch { }
        if ($i -eq $Runs - 1) {
            $openCount = (Get-Content $output | Select-String "^\d+\s+open").Count
        }
        Remove-Item $output -ErrorAction SilentlyContinue

        if ($i -gt 0) { $durations += $start.Elapsed.TotalMilliseconds }
    }

    [pscustomobject]@{
        Dil             = $target.Name
        "Sure (ms)"     = [Math]::Round(($durations | Measure-Object -Average).Average, 1)
        "Min (ms)"      = [Math]::Round(($durations | Measure-Object -Minimum).Minimum, 1)
        "Ikili (KB)"    = [Math]::Round((Get-Item $target.Path).Length / 1KB, 1)
        "Peak RAM (MB)" = [Math]::Round($peak / 1MB, 1)
        "Acik port"     = $openCount
    }
}

$results | Format-Table -AutoSize
