# AfterDark Security Suite - Windows Service Installer
# Must be run as Administrator

$ServiceName = "afterdark-darkd"
$DisplayName = "After Dark Systems Endpoint Security Daemon"
$Description = "Provides patch compliance monitoring, threat intelligence integration, and baseline security assessments."
$BinPath = "C:\Program Files\AfterDark\afterdark-darkd.exe"
$ConfigPath = "C:\ProgramData\AfterDark\darkd.yaml"
$LogPath = "C:\ProgramData\AfterDark\Logs"

# Check for Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script. Please re-run this script as an Administrator."
    Break
}

# Create directories
New-Item -ItemType Directory -Force -Path "C:\Program Files\AfterDark" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\ProgramData\AfterDark" | Out-Null
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

# Check if binary exists
if (-Not (Test-Path $BinPath)) {
    Write-Warning "Binary not found at $BinPath. Please copy afterdark-darkd.exe to this location."
}

# Stop existing service if running
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping existing service..."
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    
    Write-Host "Removing existing service..."
    # Config is preserved, but service definition is recreated
    & sc.exe delete $ServiceName
    Start-Sleep -Seconds 2
}

# Install Service
Write-Host "Installing service..."
$ServiceCmd = "`"$BinPath`" --config `"$ConfigPath`""

# Use sc.exe for robust service creation
$scArgs = @(
    "create", $ServiceName,
    "binPath=", $ServiceCmd,
    "start=", "auto",
    "obj=", "LocalSystem",
    "DisplayName=", $DisplayName
)
& sc.exe $scArgs

& sc.exe description $ServiceName $Description
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/10000/restart/10000

# Start Service
Write-Host "Starting service..."
Start-Service $ServiceName

Write-Host "Installation complete."
Get-Service $ServiceName
