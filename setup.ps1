<#
  IR Assistant - one-time setup for a fresh clone (Windows, PowerShell 5.1+).
  Safe to run again: every step skips work that is already done.

  Run from the repo root:
    powershell -ExecutionPolicy Bypass -File .\setup.ps1                   # install + configure
    powershell -ExecutionPolicy Bypass -File .\setup.ps1 -Check            # verify only, change nothing
    powershell -ExecutionPolicy Bypass -File .\setup.ps1 -EnableAuditing   # (elevated terminal) turn on Windows auditing

  Secrets are written to backend\.env only; this script never prints them.
#>
param(
    [switch]$EnableAuditing,
    [switch]$Check
)

$Root = $PSScriptRoot
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"
$VenvPy = Join-Path $Backend ".venv\Scripts\python.exe"
$EnvFile = Join-Path $Backend ".env"
$EnvExample = Join-Path $Root ".env.example"

# Versions the original dev machine uses (backend\.venv was built with these).
$PythonVersion = "3.14.4"
$NodeVersion = "24.16.0"

$script:Problems = 0

function Step($msg) { Write-Host ""; Write-Host "== $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "   [ok]   $msg" -ForegroundColor Green }
function Info($msg) { Write-Host "   [..]   $msg" }
function Warn($msg) { Write-Host "   [warn] $msg" -ForegroundColor Yellow }
function Bad($msg)  { Write-Host "   [fail] $msg" -ForegroundColor Red; $script:Problems++ }

function Test-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Update-PathFromRegistry {
    # winget installs update PATH in the registry, not in this session.
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user"
}

function Install-WithWinget($id, $version) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Bad "winget not found. Install '$id' manually, then re-run this script."
        return
    }
    $wingetArgs = @("install", "--id", $id, "--exact", "--silent",
              "--accept-package-agreements", "--accept-source-agreements")
    if ($version) { $wingetArgs += @("--version", $version) }
    Info "winget $($wingetArgs -join ' ')"
    & winget @wingetArgs
    if ($LASTEXITCODE -ne 0) { Bad "winget install $id failed (exit $LASTEXITCODE)" } else { Ok "installed $id" }
    Update-PathFromRegistry
}

function New-RandomSecret([int]$bytes) {
    $buf = New-Object byte[] $bytes
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($buf)
    $rng.Dispose()
    # URL-safe base64 without padding: no characters that need quoting in .env
    return [Convert]::ToBase64String($buf).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Find-Python314 {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python314\python.exe"),
        (Join-Path $env:ProgramFiles "Python314\python.exe")
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $exe = & py -3.14 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $exe) { return $exe.Trim() }
    }
    return $null
}

if ($Check) { Write-Host "Check mode: nothing will be installed or changed." -ForegroundColor Cyan }

# ---------------------------------------------------------------- 1. tools
Step "1/7 Tools (Git, Python $PythonVersion, Node $NodeVersion LTS, Ollama)"

if (Get-Command git -ErrorAction SilentlyContinue) { Ok (& git --version) }
elseif ($Check) { Bad "Git not installed" }
else { Install-WithWinget "Git.Git" $null }

$Python = Find-Python314
if (-not $Python -and -not $Check) {
    Install-WithWinget "Python.Python.3.14" $PythonVersion
    $Python = Find-Python314
}
if ($Python) {
    $pv = (& $Python -c "import platform; print(platform.python_version())").Trim()
    if ($pv -eq $PythonVersion) { Ok "Python $pv ($Python)" }
    else { Warn "Python $pv found; the project was built on $PythonVersion (should still work)" }
} else { Bad "Python 3.14 not found" }

if (Get-Command node -ErrorAction SilentlyContinue) {
    $nv = (& node --version).TrimStart("v")
    if ($nv -eq $NodeVersion) { Ok "Node $nv" } else { Warn "Node $nv found; the project uses $NodeVersion" }
} elseif ($Check) { Bad "Node.js not installed" }
else { Install-WithWinget "OpenJS.NodeJS.LTS" $NodeVersion }

if (Get-Command ollama -ErrorAction SilentlyContinue) { Ok (& ollama --version 2>$null | Select-Object -First 1) }
elseif ($Check) { Warn "Ollama not installed (only needed for LLM_PROVIDER=ollama)" }
else { Install-WithWinget "Ollama.Ollama" $null }

# ---------------------------------------------------------------- 2. venv + packages
Step "2/7 Backend virtual environment and packages"
if (Test-Path $VenvPy) { Ok "backend\.venv exists" }
elseif ($Check) { Bad "backend\.venv missing" }
elseif ($Python) {
    & $Python -m venv (Join-Path $Backend ".venv")
    if ($LASTEXITCODE -eq 0) { Ok "created backend\.venv" } else { Bad "venv creation failed" }
} else { Bad "cannot create venv without Python" }

if (Test-Path $VenvPy) {
    if ($Check) {
        $missing = & $VenvPy -m pip install --dry-run --disable-pip-version-check -r (Join-Path $Backend "requirements.txt") 2>$null | Select-String "^Would install"
        if ($missing) { Bad "packages missing or wrong version: $missing" } else { Ok "all pinned packages installed" }
    } else {
        & $VenvPy -m pip install --quiet --disable-pip-version-check -r (Join-Path $Backend "requirements.txt")
        if ($LASTEXITCODE -eq 0) { Ok "pip install -r requirements.txt" } else { Bad "pip install failed (exit $LASTEXITCODE)" }
    }
}

# ---------------------------------------------------------------- 3. smoke import
Step "3/7 Backend smoke import (import app.main)"
if (Test-Path $VenvPy) {
    Push-Location $Backend
    $out = & $VenvPy -c "import app.main; print('import ok')" 2>&1 | Out-String
    $code = $LASTEXITCODE
    Pop-Location
    if ($code -eq 0) { Ok "backend imports cleanly" }
    elseif ($out -match "Application Control policy") {
        Warn "Windows Application Control blocked SQLAlchemy's compiled speed-up (.pyd)."
        Write-Host "   Documented fix (docs\windows_setup.md): reinstall the SAME SQLAlchemy version as pure Python:"
        Write-Host '     $env:DISABLE_SQLALCHEMY_CEXT = "1"'
        Write-Host '     backend\.venv\Scripts\python.exe -m pip install --force-reinstall --no-deps --no-binary sqlalchemy sqlalchemy==2.1.6'
        if ($Check) { Bad "import blocked (run setup without -Check to apply the fix)" }
        else {
            $answer = Read-Host "   Apply this fix now? (y/N)"
            if ($answer -match "^[yY]") {
                $env:DISABLE_SQLALCHEMY_CEXT = "1"
                & $VenvPy -m pip install --force-reinstall --no-deps --no-binary sqlalchemy sqlalchemy==2.1.6
                Push-Location $Backend
                & $VenvPy -c "import app.main" 2>&1 | Out-Null
                $code = $LASTEXITCODE
                Pop-Location
                if ($code -eq 0) { Ok "backend imports cleanly (pure-Python SQLAlchemy)" } else { Bad "import still failing" }
            } else { Bad "import blocked; fix not applied" }
        }
    } else {
        Bad "import failed:"
        Write-Host $out
    }
}

# ---------------------------------------------------------------- 4. frontend
Step "4/7 Frontend packages (npm ci)"
$installedLock = Join-Path $Frontend "node_modules\.package-lock.json"
$lock = Join-Path $Frontend "package-lock.json"
$upToDate = (Test-Path $installedLock) -and ((Get-Item $installedLock).LastWriteTime -ge (Get-Item $lock).LastWriteTime)
if ($upToDate) { Ok "frontend\node_modules up to date" }
elseif ($Check) { Bad "frontend\node_modules missing or older than package-lock.json" }
elseif (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location $Frontend
    & npm ci --no-audit --no-fund
    $code = $LASTEXITCODE
    Pop-Location
    if ($code -eq 0) { Ok "npm ci" } else { Bad "npm ci failed (exit $code). Close any running dev server and retry." }
} else { Bad "npm not found (open a new terminal after installing Node)" }

# ---------------------------------------------------------------- 5. .env
Step "5/7 backend\.env (secrets)"
if (Test-Path $EnvFile) { Ok "backend\.env exists (left untouched)" }
elseif ($Check) { Bad "backend\.env missing" }
else {
    $values = @{
        "JWT_SECRET"        = (New-RandomSecret 48)
        "COLLECTOR_API_KEY" = (New-RandomSecret 32)
        "ADMIN_PASSWORD"    = (New-RandomSecret 18)
    }
    $lines = Get-Content $EnvExample | ForEach-Object {
        $key = ($_ -split "=", 2)[0]
        if ($values.ContainsKey($key)) { "$key=$($values[$key])" } else { $_ }
    }
    # UTF-8 without BOM so pydantic-settings reads the first key correctly
    [IO.File]::WriteAllLines($EnvFile, $lines, (New-Object Text.UTF8Encoding $false))
    $values = $null
    Ok "created backend\.env with random JWT_SECRET, COLLECTOR_API_KEY, ADMIN_PASSWORD"
    Info "Open backend\.env to read the admin password (ADMIN_USERNAME / ADMIN_PASSWORD)."
}

# ---------------------------------------------------------------- 6. ollama model
Step "6/7 Ollama model"
$model = "qwen2.5:3b"
$m = Select-String -Path $EnvExample -Pattern "^LLM_MODEL=(.+)$" | Select-Object -First 1
if ($m) { $model = $m.Matches[0].Groups[1].Value.Trim() }
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) { Warn "Ollama not on PATH; skipping model (open a new terminal after installing)" }
else {
    $list = & ollama list 2>$null | Out-String
    if ($LASTEXITCODE -ne 0) { Warn "Ollama is not running. Start the Ollama app, then re-run." }
    elseif ($list -match [regex]::Escape($model)) { Ok "model $model present" }
    elseif ($Check) { Warn "model $model not pulled" }
    else {
        & ollama pull $model
        if ($LASTEXITCODE -eq 0) { Ok "pulled $model" } else { Bad "ollama pull $model failed" }
    }
}

# ---------------------------------------------------------------- 7. auditing
Step "7/7 Windows auditing (for live collection)"
$cmdLineKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$sbKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$subcategories = @("Process Creation", "Logon", "User Account Management",
                   "Security Group Management", "Other Object Access Events")

if ($EnableAuditing -and -not $Check) {
    if (-not (Test-Admin)) {
        Bad "-EnableAuditing needs an elevated terminal (Run as administrator)."
    } else {
        foreach ($s in $subcategories) {
            & auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
            if ($LASTEXITCODE -eq 0) { Ok "auditpol: $s" } else { Bad "auditpol failed for '$s'" }
        }
        # 4688 events include the full command line
        & reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
        # PowerShell 4104 script block logging
        & reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
        Ok "registry: command-line auditing + script block logging enabled"
    }
} else {
    $cl = (Get-ItemProperty $cmdLineKey -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    $sb = (Get-ItemProperty $sbKey -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($cl -eq 1) { Ok "command-line auditing on" } else { Warn "command-line auditing off" }
    if ($sb -eq 1) { Ok "script block logging on" } else { Warn "script block logging off" }
    if (Test-Admin) {
        foreach ($s in $subcategories) {
            $line = & auditpol /get /subcategory:"$s" 2>$null | Select-String $s
            if ($line -match "Success") { Ok "auditpol: $s" } else { Warn "auditpol: $s not audited" }
        }
    } else { Info "auditpol state needs admin to read; skipped" }
    Info "To enable: elevated terminal -> powershell -ExecutionPolicy Bypass -File .\setup.ps1 -EnableAuditing"
}

# ---------------------------------------------------------------- summary
Write-Host ""
if ($script:Problems -eq 0) { Write-Host "Setup OK." -ForegroundColor Green }
else { Write-Host "$($script:Problems) problem(s) above need attention." -ForegroundColor Red }
Write-Host @"

Next steps:
  1. Open backend\.env to read the admin password (do not share or commit it).
  2. Optional local AI: set LLM_PROVIDER=ollama in backend\.env (default 'template' needs no model).
  3. Start the app:   powershell -ExecutionPolicy Bypass -File .\run.ps1
  4. Browse to        http://localhost:5173   and log in as the admin user.
  5. Demo data:       backend\.venv\Scripts\python.exe scripts\seed_simulated_events.py  (backend must be running)
  6. Stop the app:    powershell -ExecutionPolicy Bypass -File .\stop.ps1
See HANDOFF.md for details and pitfalls.
"@
if ($script:Problems -gt 0) { exit 1 }
