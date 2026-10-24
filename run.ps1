<#
  IR Assistant - start backend (port 8000) and frontend (port 5173) in two new windows.
    powershell -ExecutionPolicy Bypass -File .\run.ps1
  Stop them with .\stop.ps1 (or close both windows).
#>
$Root = $PSScriptRoot
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"
$VenvPy = Join-Path $Backend ".venv\Scripts\python.exe"
$PidFile = Join-Path $env:TEMP "ir-assistant-pids.txt"

if (-not (Test-Path $VenvPy)) { Write-Host "backend\.venv missing - run setup.ps1 first." -ForegroundColor Red; exit 1 }
if (-not (Test-Path (Join-Path $Backend ".env"))) { Write-Host "backend\.env missing - run setup.ps1 first." -ForegroundColor Red; exit 1 }
if (-not (Test-Path (Join-Path $Frontend "node_modules"))) { Write-Host "frontend\node_modules missing - run setup.ps1 first." -ForegroundColor Red; exit 1 }

# Free the ports if a previous run left python/node behind. Anything else is left alone.
foreach ($port in 8000, 5173) {
    $owners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($procId in $owners) {
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        if ($p.ProcessName -in @("python", "pythonw", "node", "uvicorn")) {
            Write-Host "Port $port held by leftover $($p.ProcessName) (PID $procId) - stopping it."
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "Port $port is used by $($p.ProcessName) (PID $procId). Close it and re-run." -ForegroundColor Red
            exit 1
        }
    }
}

$backendCmd = "Set-Location '$Backend'; `$host.UI.RawUI.WindowTitle = 'IR Assistant backend'; & '$VenvPy' -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
$frontendCmd = "Set-Location '$Frontend'; `$host.UI.RawUI.WindowTitle = 'IR Assistant frontend'; npm run dev"

$b = Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd -PassThru
$f = Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd -PassThru
Set-Content -Path $PidFile -Value @($b.Id, $f.Id)

Write-Host "Waiting for backend health check..."
$healthy = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/health" -UseBasicParsing -TimeoutSec 2
        if ($r.StatusCode -eq 200) { $healthy = $true; break }
    } catch { }
    Start-Sleep -Seconds 1
}

if ($healthy) { Write-Host "Backend is up." -ForegroundColor Green }
else { Write-Host "Backend did not answer /api/health within 60s - check the backend window." -ForegroundColor Yellow }

Write-Host ""
Write-Host "  App:      http://localhost:5173   (use 'localhost', CORS only allows this origin)"
Write-Host "  API:      http://127.0.0.1:8000/api/health"
Write-Host "  Stop:     powershell -ExecutionPolicy Bypass -File .\stop.ps1"
