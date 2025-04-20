# Main program
# Run command-line mode if switches are used
if ($RunAllChecks -or $Silent) {
    if ($LogToFile -or $ExportHTML) {
        Show-Banner
        Run-AllChecks
        exit
    }
}

# Otherwise run in interactive mode
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
        "E" { 
            # Generate and open HTML report
            $ExportHTML = $true
            Run-AllChecks
            $ExportHTML = $false
        }
        "Q" { 
            Write-ColorOutput "Exiting script..." "Cyan"
            $exitRequested = $true 
        }
        default { Write-ColorOutput "Invalid choice. Please try again." "Red" "Critical" }
    }
    
    if (-not $exitRequested) {
        Write-ColorOutput "`nPress any key to continue..." "Yellow"
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Clear-Host
        Show-Banner
    }
}# Enhanced PC Health Check Script
# Compatible with PowerShell 5.x

# Command-line parameters
param (
    [Parameter(Mandatory=$false)]
    [switch]$LogToFile,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$Silent,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportHTML,
    
    [Parameter(Mandatory=$false)]
    [switch]$RunAllChecks,
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Show help if requested
if ($Help) {
    Write-Host "`n===== HELP =====" -ForegroundColor Magenta
    Write-Host "This script performs various system health checks to diagnose performance issues." -ForegroundColor White
    Write-Host "`nAvailable Command-line Parameters:" -ForegroundColor Cyan
    Write-Host "  -LogToFile      Saves results to a log file" -ForegroundColor White
    Write-Host "  -LogPath        Specifies custom log directory (default: Desktop\PCHealthChecks)" -ForegroundColor White
    Write-Host "  -Silent         Suppresses console output (only applicable with -LogToFile)" -ForegroundColor White
    Write-Host "  -ExportHTML     Creates an HTML report of the results" -ForegroundColor White
    Write-Host "  -RunAllChecks   Runs all checks automatically without user interaction" -ForegroundColor White
    Write-Host "  -Help           Displays this help information" -ForegroundColor White
    Write-Host "`nExample Usage:" -ForegroundColor Cyan
    Write-Host "  .\PCHealthCheck.ps1 -LogToFile" -ForegroundColor White
    Write-Host "  .\PCHealthCheck.ps1 -LogToFile -LogPath 'C:\Logs'" -ForegroundColor White
    Write-Host "  .\PCHealthCheck.ps1 -LogToFile -Silent" -ForegroundColor White
    Write-Host "  .\PCHealthCheck.ps1 -ExportHTML" -ForegroundColor White
    Write-Host "  .\PCHealthCheck.ps1 -RunAllChecks -ExportHTML" -ForegroundColor White
    exit
}

# Define default log file path if not specified
if (-not $LogPath) {
    $LogPath = "$([Environment]::GetFolderPath('Desktop'))\PCHealthChecks"
}

# Create HTML report file name
$htmlReportFile = "$LogPath\PCHealthCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

# Create log file name
$logFile = "$LogPath\PCHealthCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Initialize HTML report content if export is requested
$htmlReport = $null
if ($ExportHTML) {
    $htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PC Health Check Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 {
            color: #0066cc;
            padding-bottom: 10px;
            border-bottom: 1px solid #ccc;
        }
        h2 {
            color: #0066cc;
            margin-top: 25px;
        }
        .report-meta {
            background-color: #f0f7ff;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .section {
            margin-bottom: 30px;
            border-left: 4px solid #0066cc;
            padding-left: 15px;
        }
        .good {
            color: #2e8b57;
            font-weight: bold;
        }
        .warning {
            color: #ff9900;
            font-weight: bold;
        }
        .critical {
            color: #cc3300;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>PC Health Check Report</h1>
        <div class="report-meta">
            <p><strong>System:</strong> $($env:COMPUTERNAME)</p>
            <p><strong>User:</strong> $($env:USERNAME)</p>
            <p><strong>Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
"@
}

# Define functions first
function Write-ColorOutput {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$ForegroundColor = "White",
        
        [Parameter(Mandatory=$false)]
        [string]$StatusLevel = "Info"
    )
    
    # Only output to console if not in silent mode
    if (-not $Silent) {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    
    # Log to file if requested
    if ($LogToFile) {
        Add-ToLog $Message
    }
    
    # Add to HTML report if requested
    if ($ExportHTML) {
        Add-ToHtmlReport $Message $StatusLevel
    }
}

function Add-ToLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    # Ensure log directory exists
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    # Add timestamp and append message to log file
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
}

function Add-ToHtmlReport {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$StatusLevel = "Info"
    )
    
    # Determine CSS class based on status level
    $cssClass = "info"
    if ($StatusLevel -eq "Warning") { $cssClass = "warning" }
    if ($StatusLevel -eq "Critical") { $cssClass = "critical" }
    if ($StatusLevel -eq "Good") { $cssClass = "good" }
    
    # Format content based on caller function
    $callerName = (Get-PSCallStack)[1].Command
    
    # Start a new section if this is a function header
    if ($Message -match "^Checking|^Getting|^Testing|^Scanning") {
        $sectionTitle = $Message -replace "\.\.\..*", ""
        $script:htmlReport += "<div class='section'><h2>$sectionTitle</h2>"
        $script:currentSection = $callerName
        $script:htmlReport += "<p>$Message</p>"
    }
    elseif ($callerName -ne $script:currentSection -and $callerName -ne "Write-ColorOutput" -and $callerName -ne "Show-Banner") {
        # If we've switched functions, close current section and start new one
        if ($script:currentSection) {
            $script:htmlReport += "</div>"
        }
        $script:htmlReport += "<div class='section'><h2>$callerName</h2>"
        $script:currentSection = $callerName
        $script:htmlReport += "<p>$Message</p>"
    }
    else {
        # Regular message within current section
        if ($cssClass -ne "info") {
            $script:htmlReport += "<p class='$cssClass'>$Message</p>"
        } else {
            $script:htmlReport += "<p>$Message</p>"
        }
    }
}

function Start-HtmlTable {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$Headers
    )
    
    if ($ExportHTML) {
        $headerRow = $Headers | ForEach-Object { "<th>$_</th>" }
        $script:htmlReport += "<table><tr>$headerRow</tr>"
    }
}

function Add-HtmlTableRow {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$Cells,
        
        [Parameter(Mandatory=$false)]
        [string]$StatusLevel = "Info"
    )
    
    if ($ExportHTML) {
        $cssClass = "info"
        if ($StatusLevel -eq "Warning") { $cssClass = "warning" }
        if ($StatusLevel -eq "Critical") { $cssClass = "critical" }
        if ($StatusLevel -eq "Good") { $cssClass = "good" }
        
        $cellRows = $Cells | ForEach-Object { "<td>$_</td>" }
        $script:htmlReport += "<tr class='$cssClass'>$cellRows</tr>"
    }
}

function End-HtmlTable {
    if ($ExportHTML) {
        $script:htmlReport += "</table>"
    }
}

function Save-HtmlReport {
    if ($ExportHTML) {
        # Close any open section
        if ($script:currentSection) {
            $script:htmlReport += "</div>"
        }
        
        # Add footer and close HTML
        $script:htmlReport += @"
        <div class="section">
            <h2>Report Summary</h2>
            <p>PC Health Check completed on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
    </div>
</body>
</html>
"@
        
        # Ensure directory exists
        if (-not (Test-Path -Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        }
        
        # Save HTML to file
        $script:htmlReport | Out-File -FilePath $htmlReportFile -Encoding utf8
        
        # Return the file path for display
        return $htmlReportFile
    }
    
    return $null
}

function Show-Banner {
    if (-not $Silent) {
        Clear-Host
        Write-Host "=======================================" -ForegroundColor Cyan
        Write-Host "        ENHANCED PC HEALTH CHECK       " -ForegroundColor Cyan
        Write-Host "=======================================" -ForegroundColor Cyan
        Write-Host "System: $($env:COMPUTERNAME)" -ForegroundColor Cyan
        Write-Host "User: $($env:USERNAME)" -ForegroundColor Cyan
        Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
        if ($LogToFile) {
            Write-Host "Log File: $logFile" -ForegroundColor Cyan
        }
        if ($ExportHTML) {
            Write-Host "HTML Report: $htmlReportFile" -ForegroundColor Cyan
        }
        Write-Host "=======================================" -ForegroundColor Cyan
    }
}

function Show-Menu {
    if (-not $Silent) {
        Write-Host "`nSelect an option:" -ForegroundColor Yellow
        Write-Host "1. Check Disk Space" -ForegroundColor White
        Write-Host "2. Check CPU Usage" -ForegroundColor White
        Write-Host "3. Check Memory Usage" -ForegroundColor White
        Write-Host "4. Test Network Connectivity" -ForegroundColor White
        Write-Host "5. Check for Port Exhaustion" -ForegroundColor White
        Write-Host "6. Check System Uptime" -ForegroundColor White
        Write-Host "7. List Top Processes by Memory" -ForegroundColor White
        Write-Host "8. List Top Processes by CPU" -ForegroundColor White
        Write-Host "9. Check Windows Services Status" -ForegroundColor White
        Write-Host "10. Scan Windows Event Logs" -ForegroundColor White
        Write-Host "11. Check Windows Update Status" -ForegroundColor White
        Write-Host "12. Run All Checks" -ForegroundColor Green
        Write-Host "E. Export HTML Report" -ForegroundColor Cyan 
        Write-Host "H. Help" -ForegroundColor Cyan
        Write-Host "L. View Log Files" -ForegroundColor Cyan
        Write-Host "Q. Quit" -ForegroundColor Red
    }
}

function Get-DiskSpace {
    Write-ColorOutput "`nChecking Disk Space..." "Yellow"
    
    try {
        $disks = Get-PSDrive -PSProvider FileSystem | 
                Select-Object Name, @{Name="FreeSpace(GB)";Expression={[math]::Round($_.Free/1GB, 2)}}, 
                @{Name="TotalSpace(GB)";Expression={[math]::Round(($_.Used/1GB + $_.Free/1GB), 2)}},
                @{Name="PercentFree";Expression={[math]::Round(($_.Free/($_.Used + $_.Free))*100, 2)}}
        
        if ($ExportHTML) {
            Start-HtmlTable @("Drive", "Free Space (GB)", "Total Space (GB)", "Percent Free")
        }
        
        foreach ($disk in $disks) {
            $color = "Green"
            $status = "Good"
            if ($disk."PercentFree" -lt 20) { $color = "Yellow"; $status = "Warning" }
            if ($disk."PercentFree" -lt 10) { $color = "Red"; $status = "Critical" }
            
            Write-ColorOutput "Drive $($disk.Name): $($disk.'FreeSpace(GB)') GB free of $($disk.'TotalSpace(GB)') GB ($($disk.PercentFree)% free)" $color $status
            
            if ($ExportHTML) {
                Add-HtmlTableRow @($disk.Name, $disk.'FreeSpace(GB)', $disk.'TotalSpace(GB)', "$($disk.PercentFree)%") $status
            }
        }
        
        if ($ExportHTML) {
            End-HtmlTable
        }
    }
    catch {
        Write-ColorOutput "Error checking disk space: $_" "Red" "Critical"
    }
}

function Get-CPUUsage {
    Write-ColorOutput "`nChecking CPU Usage..." "Yellow"
    
    try {
        Write-ColorOutput "Taking 5 CPU utilization samples..." "Gray"
        $samples = @()
        
        if ($ExportHTML) {
            Start-HtmlTable @("Sample", "CPU Usage (%)")
        }
        
        for ($i = 1; $i -le 5; $i++) {
            $counterData = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -ErrorAction Stop
            $cpuValue = [math]::Round($counterData.CounterSamples.CookedValue, 2)
            $samples += $cpuValue
            
            Write-ColorOutput "  Sample $i of 5: $cpuValue%" "Gray"
            
            if ($ExportHTML) {
                Add-HtmlTableRow @("Sample $i", "$cpuValue%")
            }
            
            Start-Sleep -Seconds 1
        }
        
        if ($ExportHTML) {
            End-HtmlTable
        }
        
        # Calculate average CPU usage
        $avgCpu = ($samples | Measure-Object -Average).Average
        $avgCpu = [math]::Round($avgCpu, 2)
        
        # Calculate min and max values
        $minCpu = ($samples | Measure-Object -Minimum).Minimum
        $maxCpu = ($samples | Measure-Object -Maximum).Maximum
        
        # Set color based on average CPU usage
        $color = "Green"
        $status = "Good"
        if ($avgCpu -gt 70) { $color = "Yellow"; $status = "Warning" }
        if ($avgCpu -gt 90) { $color = "Red"; $status = "Critical" }
        
        Write-ColorOutput "`nCPU Usage Results:" "White"
        Write-ColorOutput "  Average: $avgCpu%" $color $status
        Write-ColorOutput "  Minimum: $minCpu%" "Gray"
        Write-ColorOutput "  Maximum: $maxCpu%" "Gray"
        
        if ($ExportHTML) {
            Start-HtmlTable @("Measurement", "Value", "Status")
            Add-HtmlTableRow @("Average CPU Usage", "$avgCpu%", $(if($avgCpu -gt 90){"Critical"}elseif($avgCpu -gt 70){"Warning"}else{"Good"})) $status
            Add-HtmlTableRow @("Minimum CPU Usage", "$minCpu%", "Info")
            Add-HtmlTableRow @("Maximum CPU Usage", "$maxCpu%", "Info")
            End-HtmlTable
        }
    }
    catch {
        Write-ColorOutput "Error checking CPU usage: $_" "Red" "Critical"
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
        $status = "Good"
        if ($percentUsed -gt 70) { $color = "Yellow"; $status = "Warning" }
        if ($percentUsed -gt 90) { $color = "Red"; $status = "Critical" }
        
        Write-ColorOutput "Total Memory: $totalMemoryGB GB" "White"
        Write-ColorOutput "Used Memory: $usedMemoryGB GB ($percentUsed%)" $color $status
        Write-ColorOutput "Free Memory: $freeMemoryGB GB" "White"
        
        if ($ExportHTML) {
            Start-HtmlTable @("Measurement", "Value", "Status")
            Add-HtmlTableRow @("Total Memory", "$totalMemoryGB GB", "Info")
            Add-HtmlTableRow @("Used Memory", "$usedMemoryGB GB ($percentUsed%)", $(if($percentUsed -gt 90){"Critical"}elseif($percentUsed -gt 70){"Warning"}else{"Good"})) $status
            Add-HtmlTableRow @("Free Memory", "$freeMemoryGB GB", "Info")
            End-HtmlTable
            
            # Add a simple memory usage visualization
            $script:htmlReport += @"
            <div style="margin-top: 15px; margin-bottom: 15px;">
                <div style="background-color: #f0f0f0; border-radius: 5px; height: 30px; width: 100%; overflow: hidden;">
                    <div style="background-color: $(if($percentUsed -gt 90){"#cc3300"}elseif($percentUsed -gt 70){"#ff9900"}else{"#2e8b57"}); height: 100%; width: $percentUsed%; text-align: center; color: white; line-height: 30px;">
                        $percentUsed%
                    </div>
                </div>
                <div style="font-size: 12px; text-align: center; margin-top: 5px;">Memory Usage</div>
            </div>
"@
        }
    }
    catch {
        Write-ColorOutput "Error checking memory usage: $_" "Red" "Critical"
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
    Write-ColorOutput "  -LogPath        Specifies custom log directory (default: Desktop\PCHealthChecks)" "White"
    Write-ColorOutput "  -Silent         Suppresses console output (only applicable with -LogToFile)" "White"
    Write-ColorOutput "  -ExportHTML     Creates an HTML report of the results" "White" 
    Write-ColorOutput "  -RunAllChecks   Runs all checks automatically without user interaction" "White"
    Write-ColorOutput "`nExample Usage:" "Cyan"
    Write-ColorOutput "  .\PCHealthCheck.ps1 -LogToFile" "White"
    Write-ColorOutput "  .\PCHealthCheck.ps1 -LogToFile -LogPath 'C:\Logs'" "White"
    Write-ColorOutput "  .\PCHealthCheck.ps1 -LogToFile -Silent" "White"
    Write-ColorOutput "  .\PCHealthCheck.ps1 -ExportHTML" "White"
    Write-ColorOutput "  .\PCHealthCheck.ps1 -RunAllChecks -ExportHTML" "White"
    Write-ColorOutput "`nPress any key to return to the menu..." "Yellow"
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
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
    Get-TopProcessesByMemory
    Get-TopProcessesByCPU
    
    Write-ColorOutput "`nSystem Check Complete!" "Cyan"
    
    if ($LogToFile) {
        Write-ColorOutput "Results saved to: $logFile" "Cyan"
    }
    
    if ($ExportHTML) {
        $reportPath = Save-HtmlReport
        if (-not $Silent) {
            Write-Host "`nHTML report generated: $reportPath" -ForegroundColor Green
            Write-Host "Would you like to open the report now? (Y/N)" -ForegroundColor Yellow
            $openReport = Read-Host
            if ($openReport -like "Y*") {
                Start-Process $reportPath
            }
        }
    }
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