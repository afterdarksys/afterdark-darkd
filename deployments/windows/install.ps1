# Native Windows service registration scaffold; run from elevated PowerShell.
# Supply reviewed configuration and built binaries. This does not sign artifacts.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BinaryDirectory,
    [Parameter(Mandatory=$true)][string]$ConfigFile
)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from elevated PowerShell.' }
if (Get-Service -Name 'afterdark-darkd' -ErrorAction SilentlyContinue) { throw 'Service already exists; stop and upgrade it using a reviewed upgrade procedure.' }
$BinaryDirectory = (Resolve-Path $BinaryDirectory).Path
$ConfigFile = (Resolve-Path $ConfigFile).Path
foreach ($binary in @('afterdark-darkd.exe','afterdark-darkdadm.exe','darkapi.exe')) {
    if (-not (Test-Path (Join-Path $BinaryDirectory $binary) -PathType Leaf)) { throw "Missing $binary" }
}
$installDirectory = Join-Path $env:ProgramFiles 'AfterDark'
$dataDirectory = Join-Path $env:ProgramData 'AfterDark'
foreach ($directory in @($installDirectory,$dataDirectory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    & icacls.exe $directory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not secure $directory" }
}
foreach ($binary in @('afterdark-darkd.exe','afterdark-darkdadm.exe','darkapi.exe')) {
    Copy-Item (Join-Path $BinaryDirectory $binary) $installDirectory
}
$destinationConfig = Join-Path $dataDirectory 'darkd.yaml'
if (Test-Path $destinationConfig) { throw 'Existing configuration will not be overwritten.' }
Copy-Item $ConfigFile $destinationConfig
$eventSource = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\afterdark-darkd'
New-Item $eventSource -Force | Out-Null
New-ItemProperty $eventSource -Name EventMessageFile -Value "$env:SystemRoot\System32\EventCreate.exe" -PropertyType ExpandString -Force | Out-Null
New-ItemProperty $eventSource -Name TypesSupported -Value 7 -PropertyType DWord -Force | Out-Null
$binaryPath = '"' + (Join-Path $installDirectory 'afterdark-darkd.exe') + '" run --config "' + $destinationConfig + '"'
New-Service -Name 'afterdark-darkd' -DisplayName 'AfterDark Endpoint Agent' -BinaryPathName $binaryPath -StartupType Automatic | Out-Null
& sc.exe failure afterdark-darkd reset= 86400 actions= restart/10000/restart/30000/none/0 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service created, but recovery settings failed.' }
Write-Output 'Service registered. Review configuration and credentials, then run Start-Service afterdark-darkd.'
