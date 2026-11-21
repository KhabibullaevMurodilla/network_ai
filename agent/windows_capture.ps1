<#
Live capture for Windows: records the traffic of one network adapter in
short windows with Wireshark's dumpcap, uploads each window to
POST /ingest/pcap, deletes the file, repeats. Stop with Ctrl+C.

NOT TESTED on a real Windows machine (written without a Windows host).

Prerequisite: install Wireshark (https://www.wireshark.org) and keep the
"Npcap" option ticked during setup.

Usage (PowerShell):
  .\windows_capture.ps1 -ApiKey "YOUR_INGEST_KEY" -List
  .\windows_capture.ps1 -ApiKey "YOUR_INGEST_KEY" -Interface 4
#>
param(
  [Parameter(Mandatory=$true)][string]$ApiKey,
  [string]$Interface = "",
  [int]$Seconds = 30,
  [string]$ApiUrl = "http://localhost:8000",
  [switch]$List
)

$dumpcap = "C:\Program Files\Wireshark\dumpcap.exe"
if (-not (Test-Path $dumpcap)) { Write-Error "dumpcap not found at $dumpcap. Install Wireshark first."; exit 1 }

if ($List -or -not $Interface) {
  Write-Host "Available interfaces (use the number as -Interface):"
  & $dumpcap -D
  exit 0
}

$tmp = Join-Path $env:TEMP "netai_window.pcapng"
Write-Host "Capturing interface $Interface in $Seconds-second windows -> $ApiUrl. Ctrl+C to stop."
while ($true) {
  if (Test-Path $tmp) { Remove-Item $tmp -Force }
  & $dumpcap -i $Interface -a "duration:$Seconds" -w $tmp -q
  if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -lt 100) {
    Write-Warning "Nothing captured (wrong interface, or run PowerShell as Administrator). Retrying in 10s."
    Start-Sleep -Seconds 10; continue
  }
  $out = & curl.exe -s -S -X POST "$ApiUrl/ingest/pcap" -H "X-API-Key: $ApiKey" -F "file=@$tmp"
  Write-Host ("{0}  {1}" -f (Get-Date -Format "HH:mm:ss"), $out)
  Remove-Item $tmp -Force
}
