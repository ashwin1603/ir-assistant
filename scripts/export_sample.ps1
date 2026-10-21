# Export the last 500 Security events to JSON for the Upload page.
# Reading the Security log needs admin rights: run from an ELEVATED PowerShell:
#   powershell -ExecutionPolicy Bypass -File scripts\export_sample.ps1
# Read-only: this never modifies or clears any event log.
param(
    [int]$MaxEvents = 500,
    [string]$OutFile = "security_sample.json"
)

$events = Get-WinEvent -LogName Security -MaxEvents $MaxEvents -ErrorAction Stop |
    ForEach-Object {
        # Same shape as the collector, so upload_parser can normalize it.
        [PSCustomObject]@{
            RecordId     = $_.RecordId
            TimeCreated  = $_.TimeCreated.ToUniversalTime().ToString('o')
            Id           = $_.Id
            LogName      = $_.LogName
            ProviderName = $_.ProviderName
            MachineName  = $_.MachineName
            Message      = $_.Message
            Properties   = @($_.Properties | ForEach-Object { $_.Value })
        }
    }

$events | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "Exported $(@($events).Count) events to $((Resolve-Path $OutFile).Path)"
