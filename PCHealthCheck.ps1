# Advanced PC Health Check Script
# Version: 2.0
# Description: Comprehensive system diagnostics tool compatible with PowerShell 5

param (
    [switch]$LogToFile = $false,
    [string]$LogPath = "$env:USERPROFILE\Documents\PCHealthChecks",
    [switch]$Silent = $false
)

# Create log directory if it doesn't exist
if ($LogToFile -and -not (Test-Path $LogPath)) {
    try {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        Write-Host "Created log directory: $LogPath" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error creating log directory: $_" -ForegroundColor Red
        $LogToFile = $false
    }
}

# Log file setup
$logFileName = "PCHealthCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logFilePath = Join-Path -Path $LogPath -ChildPath $logFileName

# Function to write to both console and log file
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$ForegroundColor = "White"
    )
    
    if (-not $Silent) {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    
    if ($LogToFile) {
        $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timeStamp - $Message" | Out-File -FilePath $logFilePath -Append
    }
}

# Error handling wrapper
function Invoke-WithErrorHandling {
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage
    )
    
    try {
        & $ScriptBlock
        return $true
    }
    catch {
        Write-Log "ERROR: $ErrorMessage - $_" -ForegroundColor Red
        return $false
    }
}

function Show-Banner {
    Clear-Host
    Write-Log "===============================================" -ForegroundColor Cyan
    Write-Log "           ADVANCED PC HEALTH CHECK            " -ForegroundColor Cyan
    Write-Log "===============================================" -ForegroundColor Cyan
    Write-Log "System: $($env:COMPUTERNAME)" -ForegroundColor Cyan
    Write-Log "User: $($env:USERNAME)" -ForegroundColor Cyan
    Write-Log "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Log "===============================================" -ForegroundColor Cyan
    if ($LogToFile) {
        Write-Log "Logging to: $logFilePath" -ForegroundColor Cyan
    }
}

function Show-Menu {
    Write-Log "`nSelect an option:" -ForegroundColor Yellow
    Write-Log "1. Check Disk Space" -ForegroundColor White
    Write-Log "2. Check CPU Usage (Multiple Samples)" -ForegroundColor White
    Write-Log "3. Check Memory Usage" -ForegroundColor White
    Write-Log "4. Test Network Connectivity" -ForegroundColor White
    Write-Log "5. Check for Port Exhaustion" -ForegroundColor White
    Write-Log "6. Check System Uptime" -ForegroundColor White
    Write-Log "7. List Top Processes by Memory" -ForegroundColor White
    Write-Log "8. List Top Processes by CPU" -ForegroundColor White
    Write-Log "9. Check Windows Services Status" -ForegroundColor White
    Write-Log "10. Run All Checks" -ForegroundColor Green
    Write-Log "H. Help" -ForegroundColor Magenta
    Write-Log "Q. Quit" -ForegroundColor Red
}

function Get-DiskSpace {
    Write-Log "`nChecking Disk Space..." -ForegroundColor Yellow
    
    Invoke-WithErrorHandling -ScriptBlock {
        $disks = Get-PSDrive -PSProvider FileSystem | 
                Select-Object Name, @{Name="FreeSpace(GB)";Expression={[math]::Round($_.Free/1GB,2)}}, 
                @{Name="TotalSpace(GB)";Expression={[math]::Round(($_.Used/1GB + $_.Free/1GB),2)}},
                @{Name="UsedSpace(GB)";Expression={[math]::Round($_.Used/1GB,2)}},
                @{Name="PercentFree";Expression={[math]::Round(($_.Free/($_.Used + $_.Free))*100,2)}}
        
        foreach ($disk in $disks) {
            $color = "Green"
            if ($disk."PercentFree" -lt 20) { $color = "Yellow" }
            if ($disk."PercentFree" -lt 10) { $color = "Red" }
            
            Write-Log "Drive $($disk.Name): $($disk.'FreeSpace(GB)') GB free of $($disk.'TotalSpace(GB)') GB ($($disk.PercentFree)% free)" -ForegroundColor $color
        }
        
        return $disks
    } -ErrorMessage "Failed to retrieve disk space information"
}

function Get-CPUUsage {
    Write-Log "`nChecking CPU Usage (5 samples over 10 seconds)..." -ForegroundColor Yellow
    
    Invoke-WithErrorHandling -ScriptBlock {
        $samples = @()
        $totalSamples = 5
        $sampleDelay = 2
        
        for ($i = 0; $i -lt $totalSamples; $i++) {
            $counterData = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -ErrorAction Stop
            $cpuValue = [math]::Round($counterData.CounterSamples.CookedValue, 2)
            $samples += $cpuValue
            
            if ($i -lt ($totalSamples - 1)) {
                Write-Log "Sample $($i+1) of $totalSamples : $cpuValue% CPU usage" -ForegroundColor Gray
                Start-Sleep -Seconds $sampleDelay
            }
            else {
                Write-Log "Sample $($i+1) of $totalSamples : $cpuValue% CPU usage" -ForegroundColor Gray
            }
        }
        
        $avgCPU = [math]::Round(($samples | Measure-Object -Average).Average, 2)
        $maxCPU = [math]::Round(($samples | Measure-Object -Maximum).Maximum, 2)
        
        $color = "Green"
        if ($avgCPU -gt 70) { $color = "Yellow" }
        if ($avgCPU -gt 90) { $color = "Red" }
        
        Write-Log "Average CPU Usage: $avgCPU% (Max: $maxCPU%)" -ForegroundColor $color
        
        return [PSCustomObject]@{
            AverageCPU = $avgCPU
            MaximumCPU = $maxCPU
            Samples = $samples
        }
    } -ErrorMessage "Failed to retrieve CPU usage information"
}

function Get-MemoryUsage {
    Write-Log "`nChecking Memory Usage..." -ForegroundColor Yellow
    
    Invoke-WithErrorHandling -ScriptBlock {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $totalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeMemoryGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedMemoryGB = [math]::Round($totalMemoryGB - $freeMemoryGB, 2)
        $percentUsed = [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 2)
        
        $color = "Green"
        if ($percentUsed -gt 70) { $color = "Yellow" }
        if ($percentUsed -gt 90) { $color = "Red" }
        
        Write-Log "Total Memory: $totalMemoryGB GB" -ForegroundColor White
        Write-Log "Used Memory: $usedMemoryGB GB ($percentUsed%)" -ForegroundColor $color
        Write-Log "Free Memory: $freeMemoryGB GB" -ForegroundColor White
        
        return [PSCustomObject]@{
            TotalMemoryGB = $totalMemoryGB
            FreeMemoryGB = $freeMemoryGB
            UsedMemoryGB = $usedMemoryGB
            PercentUsed = $percentUsed
        }
    } -ErrorMessage "Failed to retrieve memory usage information"
}

function Test-NetworkConnectivity {
    Write-Log "`nTesting Network Connectivity..." -ForegroundColor Yellow
    
    $hosts = @("google.com", "microsoft.com", "1.1.1.1")
    $results = @()
    
    foreach ($targetHost in $hosts) {
        Write-Log "Testing connection to $targetHost..." -ForegroundColor Gray
        
        $pingResult = Invoke-WithErrorHandling -ScriptBlock {
            $ping = Test-Connection -ComputerName $targetHost -Count 4 -ErrorAction Stop
            $avgTime = [math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average, 2)
            $packetLoss = 100 - ([math]::Round(($ping.Count / 4) * 100, 0))
            
            $color = "Green"
            if ($avgTime -gt 100) { $color = "Yellow" }
            if ($avgTime -gt 200 -or $packetLoss -gt 0) { $color = "Red" }
            
            Write-Log "  Response from $targetHost - Avg time: $avgTime ms, Packet Loss: $packetLoss%" -ForegroundColor $color
            
            return [PSCustomObject]@{
                Target = $targetHost
                AverageResponseTime = $avgTime
                PacketLoss = $packetLoss
                Success = $true
            }
        } -ErrorMessage "Failed to ping $targetHost"
        
        if (-not $pingResult) {
            $results += [PSCustomObject]@{
                Target = $targetHost
                AverageResponseTime = 0
                PacketLoss = 100
                Success = $false
            }
        }
        else {
            $results += $pingResult
        }
    }
    
    # Internet connectivity summary
    $successfulPings = ($results | Where-Object { $_.Success -eq $true }).Count
    if ($successfulPings -eq $hosts.Count) {
        Write-Log "Network Status: ONLINE (All hosts reachable)" -ForegroundColor Green
    }
    elseif ($successfulPings -gt 0) {
        Write-Log "Network Status: DEGRADED (Some hosts unreachable)" -ForegroundColor Yellow
    }
    else {
        Write-Log "Network Status: OFFLINE (No hosts reachable)" -ForegroundColor Red
    }
    
    return $results
}

function Test-PortExhaustion {
    Write-Log "`nChecking for Port Exhaustion..." -ForegroundColor Yellow
    
    Invoke-WithErrorHandling -ScriptBlock {
        # PS5 compatible way to get TCP connections
        $establishedCount = 0
        $timeWaitCount = 0
        $totalConnections = 0
        
        # Using netstat as it's available on all Windows versions with PS5
        $netstat = netstat -ano | Out-String
        $connections = $netstat -split "`r`n" | Where-Object { $_ -match "(TCP|UDP)" }
        $totalConnections = $connections.Count
        
        # Count established connections
        $establishedCount = ($connections | Where-Object { $_ -match "ESTABLISHED" }).Count
        $timeWaitCount = ($connections | Where-Object { $_ -match "TIME_WAIT" }).Count
        
        $color = "Green"
        if ($establishedCount -gt 8000) { $color = "Yellow" }
        if ($establishedCount -gt 16000) { $color = "Red" }
        
        Write-Log "Established connections: $establishedCount" -ForegroundColor $color
        Write-Log "Time Wait connections: $timeWaitCount" -ForegroundColor White
        Write-Log "Total connections: $totalConnections" -ForegroundColor White
        
        if ($establishedCount -gt 16000) {
            Write-Log "WARNING: High number of connections detected. Port exhaustion may occur!" -ForegroundColor Red
        }
        
        return [PSCustomObject]@{
            EstablishedConnections = $establishedCount
            TimeWaitConnections = $timeWaitCount
            TotalConnections = $totalConnections
        }
    } -ErrorMessage "Failed to retrieve network connection information"
}

function Get-SystemUptime {
    Write-Log "`nChecking System Uptime..." -ForegroundColor Yellow
    
    Invoke-WithErrorHandling -ScriptBlock {
        # PowerShell 5 compatible uptime calculation
        $bootUpTime = (Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
        
        # Parse WMI datetime format (yyyyMMddHHmmss.mmmmmm+UUU)
        $year = [int]$bootUpTime.Substring(0, 4)
        $month = [int]$bootUpTime.Substring(4, 2)
        $day = [int]$bootUpTime.Substring(6, 2)
        $hour = [int]$bootUpTime.Substring(8, 2)
        $minute = [int]$bootUpTime.Substring(10, 2)
        $second = [int]$bootUpTime.Substring(12, 2)
        
        $lastBootTime = New-Object DateTime($year, $month, $day, $hour, $minute, $second)
        $uptime = (Get-Date) - $lastBootTime
        
        $formattedUptime = "{0} days, {1} hours, {2} minutes, {3} seconds" -f `
            $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds
        
        Write-Log "System Last Boot: $($lastBootTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
        Write-Log "System Uptime: $formattedUptime" -ForegroundColor White
        
        return [PSCustomObject]@{
            LastBootTime = $lastBootTime
            UptimeDays = $uptime.Days
            UptimeHours = $uptime.Hours
            UptimeMinutes = $uptime.Minutes
            UptimeSeconds = $uptime.Seconds
            FormattedUptime = $formattedUptime
        }
    } -ErrorMessage "Failed to retrieve system uptime information"
}

function Get-TopProcessesByMemory {
    Write-Log "`nGetting Top Processes by Memory Usage..." -ForegroundColor Yellow
    
    Invoke-WithErrorHandling -ScriptBlock {
        $processes = Get-Process | 
                    Sort-Object -Property WorkingSet -Descending | 
                    Select-Object -First 10 -Property Id, ProcessName, @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet / 1MB, 2)}}
        
        $counter = 1
        foreach ($process in $processes) {
            Write-Log "$counter. $($process.ProcessName) (PID: $($process.Id)) - $($process.'Memory(MB)') MB" -ForegroundColor White
            $counter++
        }
        
        return $processes
    } -ErrorMessage "Failed to retrieve top memory consuming processes"
}

function Get-TopProcessesByCPU {
    Write-Log "`nGetting Top Processes by CPU Usage..." -ForegroundColor Yellow
    
    Invoke-WithErrorHandling -ScriptBlock {
        $processes = Get-Process | 
                    Sort-Object -Property CPU -Descending | 
                    Select-Object -First 10 -Property Id, ProcessName, @{Name="CPU(s)";Expression={[math]::Round($_.CPU, 2)}}
        
        $counter = 1
        foreach ($process in $processes) {
            Write-Log "$counter. $($process.ProcessName) (PID: $($process.Id)) - $($process.'CPU(s)') CPU seconds" -ForegroundColor White
            $counter++
        }
        
        return $processes
    } -ErrorMessage "Failed to retrieve top CPU consuming processes"
}

function Get-ServicesStatus {
    Write-Log "`nChecking Critical Windows Services..." -ForegroundColor Yellow
    
    $criticalServices = @(
        "wuauserv",      # Windows Update
        "WinDefend",     # Windows Defender
        "wscsvc",        # Security Center
        "Dhcp",          # DHCP Client
        "Dnscache",      # DNS Client
        "LanmanServer",  # Server
        "LanmanWorkstation", # Workstation
        "nsi",           # Network Store Interface Service
        "W32Time",       # Windows Time
        "eventlog"       # Windows Event Log
    )
    
    $results = @()
    
    foreach ($serviceName in $criticalServices) {
        Invoke-WithErrorHandling -ScriptBlock {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            
            $color = "Green"
            if ($service.Status -ne "Running") { $color = "Red" }
            
            Write-Log "$($service.DisplayName): $($service.Status)" -ForegroundColor $color
            
            $results += [PSCustomObject]@{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
            }
        } -ErrorMessage "Failed to retrieve status for service $serviceName"
    }
    
    return $results
}

function Run-AllChecks {
    Write-Log "`n===== Running All System Checks =====" -ForegroundColor Cyan
    
    # Run all check functions
    $diskSpace = Get-DiskSpace
    Start-Sleep -Seconds 1
    
    $memoryUsage = Get-MemoryUsage
    Start-Sleep -Seconds 1
    
    $cpuUsage = Get-CPUUsage
    Start-Sleep -Seconds 1
    
    $networkStatus = Test-NetworkConnectivity
    Start-Sleep -Seconds 1
    
    $portStatus = Test-PortExhaustion
    Start-Sleep -Seconds 1
    
    $uptime = Get-SystemUptime
    Start-Sleep -Seconds 1
    
    $servicesStatus = Get-ServicesStatus
    
    # Generate system health summary
    Write-Log "`n===== System Health Summary =====" -ForegroundColor Cyan
    
    # Disk space check
    $lowDiskDrives = $diskSpace | Where-Object { $_.PercentFree -lt 15 }
    if ($lowDiskDrives) {
        $driveList = ($lowDiskDrives | ForEach-Object { $_.Name }) -join ", "
        Write-Log "! LOW DISK SPACE: Drives $driveList have less than 15% free space" -ForegroundColor Red
    }
    else {
        Write-Log "+ Disk Space: All drives have sufficient free space" -ForegroundColor Green
    }
    
    # Memory check
    if ($memoryUsage.PercentUsed -gt 90) {
        Write-Log "! HIGH MEMORY USAGE: $($memoryUsage.PercentUsed)% of memory is in use" -ForegroundColor Red
    }
    else {
        Write-Log "+ Memory Usage: $($memoryUsage.PercentUsed)% (Normal)" -ForegroundColor Green
    }
    
    # CPU check
    if ($cpuUsage.AverageCPU -gt 90) {
        Write-Log "! HIGH CPU USAGE: $($cpuUsage.AverageCPU)% average CPU utilization" -ForegroundColor Red
    }
    else {
        Write-Log "+ CPU Usage: $($cpuUsage.AverageCPU)% average (Normal)" -ForegroundColor Green
    }
    
    # Network check
    $failedConnections = $networkStatus | Where-Object { $_.Success -eq $false }
    if ($failedConnections) {
        $hostList = ($failedConnections | ForEach-Object { $_.Target }) -join ", "
        Write-Log "! NETWORK ISSUES: Failed to connect to: $hostList" -ForegroundColor Red
    }
    else {
        Write-Log "+ Network Connectivity: All tested hosts are reachable" -ForegroundColor Green
    }
    
    # Port check
    if ($portStatus.EstablishedConnections -gt 16000) {
        Write-Log "! PORT EXHAUSTION RISK: $($portStatus.EstablishedConnections) established connections" -ForegroundColor Red
    }
    else {
        Write-Log "+ TCP Connections: $($portStatus.EstablishedConnections) established connections (Normal)" -ForegroundColor Green
    }
    
    # Service check
    $stoppedServices = $servicesStatus | Where-Object { $_.Status -ne "Running" }
    if ($stoppedServices) {
        $serviceList = ($stoppedServices | ForEach-Object { $_.DisplayName }) -join ", "
        Write-Log "! CRITICAL SERVICES STOPPED: $serviceList" -ForegroundColor Red
    }
    else {
        Write-Log "+ Services: All critical services are running" -ForegroundColor Green
    }
    
    Write-Log "`nSystem Check Complete!" -ForegroundColor Cyan
    if ($LogToFile) {
        Write-Log "Results saved to: $logFilePath" -ForegroundColor Cyan
    }
}

function Show-Help {
    Write-Log "`n===== HELP =====" -ForegroundColor Magenta
    Write-Log "This script performs various system health checks to diagnose performance issues." -ForegroundColor White
    Write-Log "`nAvailable Command-line Parameters:" -ForegroundColor Cyan
    Write-Log "  -LogToFile      Saves results to a log file" -ForegroundColor White
    Write-Log "  -LogPath        Specifies custom log directory (default: Documents\PCHealthChecks)" -ForegroundColor White
    Write-Log "  -Silent         Suppresses console output (only applicable with -LogToFile)" -ForegroundColor White
    Write-Log "`nExample Usage:" -ForegroundColor Cyan
    Write-Log "  .\PCHealthCheck.ps1 -LogToFile" -ForegroundColor White
    Write-Log "  .\PCHealthCheck.ps1 -LogToFile -LogPath 'C:\Logs'" -ForegroundColor White
    Write-Log "  .\PCHealthCheck.ps1 -LogToFile -Silent" -ForegroundColor White
    Write-Log "`nPress any key to return to the menu..." -ForegroundColor Yellow
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
}

# Main program
Show-Banner

if ($LogToFile) {
    Write-Log "Logging enabled. Log will be saved to: $logFilePath" -ForegroundColor Green
}

$exitRequested = $false

while (-not $exitRequested) {
    Show-Menu
    $choice = Read-Host "Enter your choice"
    
    switch ($choice.ToUpper()) {
        "1" { Get-DiskSpace }
        "2" { Get-CPUUsage }
        "3" { Get-MemoryUsage }
        "4" { Test-NetworkConnectivity }
        "5" { Test-PortExhaustion }
        "6" { Get-SystemUptime }
        "7" { Get-TopProcessesByMemory }
        "8" { Get-TopProcessesByCPU }
        "9" { Get-ServicesStatus }
        "10" { Run-AllChecks }
        "H" { Show-Help }
        "Q" { 
            Write-Log "Exiting script..." -ForegroundColor Cyan
            if ($LogToFile) {
                Write-Log "Log saved to: $logFilePath" -ForegroundColor Green
            }
            $exitRequested = $true 
        }
        default { Write-Log "Invalid choice. Please try again." -ForegroundColor Red }
    }
    
    if (-not $exitRequested) {
        Write-Log "`nPress any key to continue..." -ForegroundColor Yellow
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
        Clear-Host
    }
}