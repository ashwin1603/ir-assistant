<#
  IR Assistant - stop the backend and frontend started by run.ps1.
    powershell -ExecutionPolicy Bypass -File .\stop.ps1
#>
$PidFile = Join-Path $env:TEMP "ir-assistant-pids.txt"

# 1. The two windows run.ps1 opened (and everything they started).
if (Test-Path $PidFile) {
    foreach ($procId in Get-Content $PidFile) {
        if (Get-Process -Id $procId -ErrorAction SilentlyContinue) {
            & taskkill /PID $procId /T /F | Out-Null
            Write-Host "Stopped window PID $procId"
        }
    }
    Remove-Item $PidFile -ErrorAction SilentlyContinue
}

# 2. Any python/node still listening on the app ports.
foreach ($port in 8000, 5173) {
    $owners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($procId in $owners) {
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -in @("python", "pythonw", "node", "uvicorn")) {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped $($p.ProcessName) on port $port (PID $procId)"
        } elseif ($p) {
            Write-Host "Port $port is used by $($p.ProcessName) (PID $procId); not touching it." -ForegroundColor Yellow
        }
    }
}
Write-Host "Done."
