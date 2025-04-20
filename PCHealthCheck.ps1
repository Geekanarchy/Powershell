# Enhanced PC Health Check Script
# Compatible with PowerShell 5.x

# Define log file path
$logFilePath = "$([Environment]::GetFolderPath('Desktop'))\PCHealthChecks"
$logFile = "$logFilePath\PCHealthCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Define functions first
function Write-ColorOutput {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$ForegroundColor = "White"
    )
    
    Write-Host $Message -ForegroundColor $ForegroundColor
    Add-ToLog $Message
}

function Add-ToLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    # Ensure log directory exists
    if (-not (Test-Path -Path $logFilePath)) {
        New-Item -Path $logFilePath -ItemType Directory -Force | Out-Null
    }
    
    # Add timestamp and append message to log file
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
}

function Show-Banner {
    Clear-Host
    Write-ColorOutput "=======================================" "Cyan"
    Write-ColorOutput "        ENHANCED PC HEALTH CHECK       " "Cyan"
    Write-ColorOutput "=======================================" "Cyan"
    Write-ColorOutput "System: $($env:COMPUTERNAME)" "Cyan"
    Write-ColorOutput "User: $($env:USERNAME)" "Cyan"
    Write-ColorOutput "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Cyan"
    Write-ColorOutput "Log File: $logFile" "Cyan"
    Write-ColorOutput "=======================================" "Cyan"
}

function Show-Menu {
    Write-ColorOutput "`nSelect an option:" "Yellow"
    Write-ColorOutput "1. Check Disk Space" "White"
    Write-ColorOutput "2. Check CPU Usage" "White"
    Write-ColorOutput "3. Check Memory Usage" "White"
    Write-ColorOutput "4. Test Network Connectivity" "White"
    Write-ColorOutput "5. Check for Port Exhaustion" "White"
    Write-ColorOutput "6. Check System Uptime" "White"
    Write-ColorOutput "7. List Top Processes by Memory" "White"
    Write-ColorOutput "8. List Top Processes by CPU" "White"
    Write-ColorOutput "9. Check Windows Services Status" "White"
    Write-ColorOutput "10. Scan Windows Event Logs" "White"
    Write-ColorOutput "11. Check Windows Update Status" "White"
    Write-ColorOutput "12. Run All Checks" "Green"
    Write-ColorOutput "H. Help" "Cyan"
    Write-ColorOutput "Q. Quit" "Red"
}

function Get-DiskSpace {
    Write-ColorOutput "`nChecking Disk Space..." "Yellow"
    
    try {
        $disks = Get-PSDrive -PSProvider FileSystem | 
                Select-Object Name, @{Name="FreeSpace(GB)";Expression={[math]::Round($_.Free/1GB, 2)}}, 
                @{Name="TotalSpace(GB)";Expression={[math]::Round(($_.Used/1GB + $_.Free/1GB), 2)}},
                @{Name="PercentFree";Expression={[math]::Round(($_.Free/($_.Used + $_.Free))*100, 2)}}
        
        foreach ($disk in $disks) {
            $color = "Green"
            if ($disk."PercentFree" -lt 20) { $color = "Yellow" }
            if ($disk."PercentFree" -lt 10) { $color = "Red" }
            
            Write-ColorOutput "Drive $($disk.Name): $($disk.'FreeSpace(GB)') GB free of $($disk.'TotalSpace(GB)') GB ($($disk.PercentFree)% free)" $color
        }
    }
    catch {
        Write-ColorOutput "Error checking disk space: $_" "Red"
    }
}

function Get-CPUUsage {
    Write-ColorOutput "`nChecking CPU Usage..." "Yellow"
    
    try {
        Write-ColorOutput "Taking 5 CPU utilization samples..." "Gray"
        $samples = @()
        
        for ($i = 1; $i -le 5; $i++) {
            $counterData = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -ErrorAction Stop
            $cpuValue = [math]::Round($counterData.CounterSamples.CookedValue, 2)
            $samples += $cpuValue
            
            Write-ColorOutput "  Sample $i of 5: $cpuValue%" "Gray"
            Start-Sleep -Seconds 1
        }
        
        # Calculate average CPU usage
        $avgCpu = ($samples | Measure-Object -Average).Average
        $avgCpu = [math]::Round($avgCpu, 2)
        
        # Calculate min and max values
        $minCpu = ($samples | Measure-Object -Minimum).Minimum
        $maxCpu = ($samples | Measure-Object -Maximum).Maximum
        
        # Set color based on average CPU usage
        $color = "Green"
        if ($avgCpu -gt 70) { $color = "Yellow" }
        if ($avgCpu -gt 90) { $color = "Red" }
        
        Write-ColorOutput "`nCPU Usage Results:" "White"
        Write-ColorOutput "  Average: $avgCpu%" $color
        Write-ColorOutput "  Minimum: $minCpu%" "Gray"
        Write-ColorOutput "  Maximum: $maxCpu%" "Gray"
    }
    catch {
        Write-ColorOutput "Error checking CPU usage: $_" "Red"
    }
}

function Get-MemoryUsage {
    Write-ColorOutput "`nChecking Memory Usage..." "Yellow"
    
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $totalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeMemoryGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedMemoryGB = [math]::Round($totalMemoryGB - $freeMemoryGB, 2)
        $percentUsed = [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 2)
        
        $color = "Green"
        if ($percentUsed -gt 70) { $color = "Yellow" }
        if ($percentUsed -gt 90) { $color = "Red" }
        
        Write-ColorOutput "Total Memory: $totalMemoryGB GB" "White"
        Write-ColorOutput "Used Memory: $usedMemoryGB GB ($percentUsed%)" $color
        Write-ColorOutput "Free Memory: $freeMemoryGB GB" "White"
    }
    catch {
        Write-ColorOutput "Error checking memory usage: $_" "Red"
    }
}

function Test-NetworkConnectivity {
    Write-ColorOutput "`nTesting Network Connectivity..." "Yellow"
    
    $hosts = @("google.com", "microsoft.com", "1.1.1.1")
    
    foreach ($targetHost in $hosts) {
        Write-ColorOutput "Testing connection to $targetHost..." "Gray"
        
        try {
            $ping = Test-Connection -ComputerName $targetHost -Count 4 -ErrorAction Stop
            $pingStats = $ping | Measure-Object -Property ResponseTime -Average -Maximum -Minimum
            $avgTime = [math]::Round($pingStats.Average, 2)
            
            $color = "Green"
            if ($avgTime -gt 100) { $color = "Yellow" }
            if ($avgTime -gt 200) { $color = "Red" }
            
            Write-ColorOutput "  Response from $targetHost - Avg time: $avgTime ms" $color
        }
        catch {
            Write-ColorOutput "  Failed to ping $targetHost`: $_" "Red"
        }
    }
}

function Test-PortExhaustion {
    Write-ColorOutput "`nChecking for Port Exhaustion..." "Yellow"
    
    try {
        # Using netstat as it's available on all Windows versions with PS5
        $netstatOutput = netstat -ano | Out-String
        $connections = $netstatOutput -split "`r`n" | Where-Object { $_ -match "(TCP|UDP)" }
        
        # Count established connections
        $establishedConnections = @($connections | Where-Object { $_ -match "ESTABLISHED" })
        $establishedCount = $establishedConnections.Count
        
        $color = "Green"
        if ($establishedCount -gt 8000) { $color = "Yellow" }
        if ($establishedCount -gt 16000) { $color = "Red" }
        
        Write-ColorOutput "Established connections: $establishedCount" $color
        Write-ColorOutput "Total connections: $($connections.Count)" "White"
        
        if ($establishedCount -gt 16000) {
            Write-ColorOutput "WARNING: High number of connections detected. Port exhaustion may occur!" "Red"
        }
    }
    catch {
        Write-ColorOutput "Error checking port exhaustion: $_" "Red"
    }
}

function Get-SystemUptime {
    Write-ColorOutput "`nChecking System Uptime..." "Yellow"
    
    try {
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
        
        Write-ColorOutput "System Last Boot: $($lastBootTime.ToString('yyyy-MM-dd HH:mm:ss'))" "White"
        Write-ColorOutput "System Uptime: $formattedUptime" "White"
    }
    catch {
        Write-ColorOutput "Error checking system uptime: $_" "Red"
    }
}

function Get-TopProcessesByMemory {
    Write-ColorOutput "`nGetting Top Processes by Memory Usage..." "Yellow"
    
    try {
        $processes = Get-Process | 
                    Sort-Object -Property WorkingSet -Descending | 
                    Select-Object -First 10 -Property Id, ProcessName, @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet / 1MB, 2)}}
        
        $counter = 1
        foreach ($process in $processes) {
            Write-ColorOutput "$counter. $($process.ProcessName) (PID: $($process.Id)) - $($process.'Memory(MB)') MB" "White"
            $counter++
        }
    }
    catch {
        Write-ColorOutput "Error getting top memory processes: $_" "Red"
    }
}

function Get-TopProcessesByCPU {
    Write-ColorOutput "`nGetting Top Processes by CPU Usage..." "Yellow"
    
    try {
        $processes = Get-Process | 
                    Sort-Object -Property CPU -Descending | 
                    Select-Object -First 10 -Property Id, ProcessName, @{Name="CPU(s)";Expression={[math]::Round($_.CPU, 2)}}
        
        $counter = 1
        foreach ($process in $processes) {
            Write-ColorOutput "$counter. $($process.ProcessName) (PID: $($process.Id)) - $($process.'CPU(s)') CPU seconds" "White"
            $counter++
        }
    }
    catch {
        Write-ColorOutput "Error getting top CPU processes: $_" "Red"
    }
}

function Get-ServicesStatus {
    Write-ColorOutput "`nChecking Critical Windows Services..." "Yellow"
    
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
    
    foreach ($serviceName in $criticalServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            
            $color = "Green"
            if ($service.Status -ne "Running") { $color = "Red" }
            
            Write-ColorOutput "$($service.DisplayName): $($service.Status)" $color
        }
        catch {
            Write-ColorOutput "Error checking service $serviceName" "Red"
        }
    }
}

function Get-EventLogErrors {
    Write-ColorOutput "`nScanning Windows Event Logs for errors (past 24 hours)..." "Yellow"
    
    $startTime = (Get-Date).AddHours(-24)
    $criticalLogs = @("System", "Application")
    $errorCount = 0
    
    foreach ($logName in $criticalLogs) {
        Write-ColorOutput "Scanning $logName log..." "Gray"
        
        try {
            $errors = Get-EventLog -LogName $logName -EntryType Error -After $startTime -ErrorAction SilentlyContinue
            if ($errors -and $errors.Count -gt 0) {
                $errorCount += $errors.Count
                $topErrors = $errors | Group-Object -Property Source | Sort-Object -Property Count -Descending | Select-Object -First 3
                
                foreach ($errorGroup in $topErrors) {
                    $latestError = $errors | Where-Object { $_.Source -eq $errorGroup.Name } | Sort-Object -Property TimeGenerated -Descending | Select-Object -First 1
                    $messagePreview = if ($latestError.Message.Length -gt 100) { $latestError.Message.Substring(0, 97) + "..." } else { $latestError.Message }
                    
                    Write-ColorOutput "[$logName] $($errorGroup.Name) (EventID: $($latestError.EventID)): $($errorGroup.Count) occurrences" "Red"
                    Write-ColorOutput "   Last occurred: $($latestError.TimeGenerated)" "Gray"
                    Write-ColorOutput "   $messagePreview" "Gray"
                }
            }
        }
        catch {
            Write-ColorOutput "  Unable to retrieve events from $logName log: $_" "Yellow"
        }
    }
    
    # Display summary count
    if ($errorCount -gt 0) {
        Write-ColorOutput "Found $errorCount Error events in the past 24 hours" "Red"
    }
    else {
        Write-ColorOutput "No Error events found in the past 24 hours" "Green"
    }
}

function Get-WindowsUpdateStatus {
    Write-ColorOutput "`nChecking Windows Update Status..." "Yellow"
    
    # Get update service status
    try {
        $wuauserv = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        
        if ($wuauserv) {
            $color = "Green"
            if ($wuauserv.Status -ne "Running") { $color = "Red" }
            
            Write-ColorOutput "Windows Update Service: $($wuauserv.Status)" $color
            
            if ($wuauserv.Status -ne "Running") {
                Write-ColorOutput "WARNING: Windows Update service is not running!" "Red"
            }
        }
        else {
            Write-ColorOutput "Windows Update Service: Status unknown" "Red"
        }
        
        # Try COM object approach for more detailed update info
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            
            # Check for pending updates
            $pendingUpdates = $updateSearcher.Search("IsInstalled=0")
            
            # Display Pending Updates
            if ($pendingUpdates.Updates.Count -gt 0) {
                Write-ColorOutput "`nPending Updates: $($pendingUpdates.Updates.Count)" "Yellow"
                
                $count = 1
                foreach ($update in $pendingUpdates.Updates) {
                    Write-ColorOutput "$count. $($update.Title)" "White"
                    $count++
                    
                    # Limit to top 5 to avoid flooding console
                    if ($count -gt 5 -and $pendingUpdates.Updates.Count -gt 5) {
                        Write-ColorOutput "   (and $($pendingUpdates.Updates.Count - 5) more...)" "Gray"
                        break
                    }
                }
            }
            else {
                Write-ColorOutput "`nNo pending Windows updates found." "Green"
            }
        }
        catch {
            Write-ColorOutput "Limited Windows Update information available: $_" "Yellow"
        }
    }
    catch {
        Write-ColorOutput "Error checking Windows Update status: $_" "Red"
    }
}

function Show-Help {
    Write-ColorOutput "`n===== HELP =====" "Magenta"
    Write-ColorOutput "This script performs various system health checks to diagnose performance issues." "White"
    Write-ColorOutput "`nAvailable Command-line Parameters:" "Cyan"
    Write-ColorOutput "  -LogToFile      Saves results to a log file" "White"
    Write-ColorOutput "  -LogPath        Specifies custom log directory (default: Documents\PCHealthChecks)" "White"
    Write-ColorOutput "  -Silent         Suppresses console output (only applicable with -LogToFile)" "White"
    Write-ColorOutput "`nExample Usage:" "Cyan"
    Write-ColorOutput "  .\PCHealthCheck.ps1 -LogToFile" "White"
    Write-ColorOutput "  .\PCHealthCheck.ps1 -LogToFile -LogPath 'C:\Logs'" "White"
    Write-ColorOutput "  .\PCHealthCheck.ps1 -LogToFile -Silent" "White"
    Write-ColorOutput "`nPress any key to return to the menu..." "Yellow"
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
}

function Show-LogFiles {
    Write-ColorOutput "`nAvailable Log Files:" "Yellow"
    
    try {
        if (Test-Path -Path $logFilePath) {
            $logs = Get-ChildItem -Path $logFilePath -Filter "PCHealthCheck_*.log" | 
                    Sort-Object -Property LastWriteTime -Descending
            
            if ($logs.Count -gt 0) {
                $counter = 1
                foreach ($log in $logs) {
                    Write-Host "$counter. $($log.Name) - $($log.LastWriteTime)" -ForegroundColor White
                    $counter++
                    
                    # Limit to top 10 to avoid flooding console
                    if ($counter -gt 10 -and $logs.Count -gt 10) {
                        Write-Host "   (and $($logs.Count - 10) more...)" -ForegroundColor Gray
                        break
                    }
                }
                
                Write-ColorOutput "`nLog location: $logFilePath" "Cyan"
            }
            else {
                Write-ColorOutput "No log files found." "Yellow"
            }
        }
        else {
            Write-ColorOutput "Log directory does not exist yet. Run some checks first." "Yellow"
        }
    }
    catch {
        Write-ColorOutput "Error listing log files: $_" "Red"
    }
}

function Run-AllChecks {
    Write-ColorOutput "`n===== Running All System Checks =====" "Cyan"
    
    # Run all check functions
    Get-DiskSpace
    Get-MemoryUsage
    Get-CPUUsage
    Test-NetworkConnectivity
    Test-PortExhaustion
    Get-SystemUptime
    Get-ServicesStatus
    Get-EventLogErrors
    Get-WindowsUpdateStatus
    
    Write-ColorOutput "`nSystem Check Complete!" "Cyan"
    Write-ColorOutput "Results saved to: $logFile" "Cyan"
}

# Main program
Show-Banner

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
        "10" { Get-EventLogErrors }
        "11" { Get-WindowsUpdateStatus }
        "12" { Run-AllChecks }
        "H" { Show-Help }
        "L" { Show-LogFiles }
        "Q" { 
            Write-ColorOutput "Exiting script..." "Cyan"
            $exitRequested = $true 
        }
        default { Write-ColorOutput "Invalid choice. Please try again." "Red" }
    }
    
    if (-not $exitRequested) {
        Write-ColorOutput "`nPress any key to continue..." "Yellow"
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Clear-Host
        Show-Banner
    }
}