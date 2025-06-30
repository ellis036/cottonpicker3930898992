# Intel 13th/14th Gen DPC/ISR Optimization Script
$RWE_PATH = "C:\Program Files (x86)\RW-Everything\Rw.exe"
$WINRING0_PATH = Join-Path $PSScriptRoot "WinRing0x64.dll"
$WINRING0_SYS = Join-Path $PSScriptRoot "WinRing0x64.sys"

# Registry optimization paths
$NVME_PATH = "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"
$STORPORT_PATH = "HKLM:\SYSTEM\CurrentControlSet\Services\storport\Parameters"
$GRAPHICS_PATH = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
$ETW_PATH = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
$MITIGATION_PATH = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
$SYSTEM_PROFILE = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"

function Is-Admin() {
    $current_principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $current_principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function GetValueFromAddress($address) {
    $address = "0x" + $address.ToString("X2")
    $stdout = & $RWE_PATH /Min /NoLogo /Stdout /Command="R32 $address" | Out-String
    $split_string = $stdout -split " "
    return [int]$split_string[-1]
}

function RunMsrCommand($command) {
    $msrPath = Join-Path $PSScriptRoot "msr-cmd.exe"
    if (-not (Test-Path $msrPath)) {
        Write-Host "Error: msr-cmd.exe not found in script directory" -ForegroundColor Red
        return $null
    }
    $result = & $msrPath $command | Out-String
    Start-Sleep -Milliseconds 50
    return $result.Trim()
}

function ReadMsr($address) {
    $result = RunMsrCommand "read $address"
    if ($result -match "EDX:\s*(\w+)\s+EAX:\s*(\w+)") {
        return @{
            EDX = $matches[1]
            EAX = $matches[2]
        }
    }
    return $null
}

function WriteMsr($address, $edx, $eax, $allCores = $false) {
    $coreFlag = if ($allCores) { "-a" } else { "" }
    RunMsrCommand "$coreFlag write $address $edx $eax"
}

function OptimizeInterruptHandling() {
    Write-Host "`n=== Optimizing Interrupt Handling ===" -ForegroundColor Cyan
    
    # Get all PCI devices
    $pciDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object {
        $_.DeviceID -like "*PCI\VEN_*"
    }
    
    foreach ($device in $pciDevices) {
        if ($device.DeviceID -match "PCI\\VEN_(\w+)&DEV_(\w+)\\(\d+)&(\w+)") {
            $bus = [Convert]::ToInt32($matches[3])
            
            # MSI Mode and Interrupt Priority
            Write-Host "Optimizing interrupt handling for device: $($device.Name)" -ForegroundColor Yellow
            
            # Enable MSI mode and set maximum priority
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/04 0x00000147" # Command register (MSI enable)
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/D0 0x00000001" # MSI control (single message)
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/D4 0x00000000" # MSI mask bits (no masking)
            
            # Optimize interrupt moderation
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/E0 0x00000000" # Disable interrupt throttling
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/E4 0x00000000" # Clear throttle parameters
            
            # Registry optimization for the device
            if ($device.DeviceID -match "PCI\\VEN_(\w+)&DEV_(\w+)") {
                $devicePath = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI\VEN_$($matches[1])&DEV_$($matches[2])*\*\Device Parameters\Interrupt Management"
                
                # MSI Settings
                $msiPath = "$devicePath\MessageSignaledInterruptProperties"
                if (-not (Test-Path $msiPath)) { New-Item -Path $msiPath -Force | Out-Null }
                reg.exe add $msiPath /v "MSISupported" /t REG_DWORD /d 1 /f | Out-Null
                
                # Affinity Policy
                $affinityPath = "$devicePath\Affinity Policy"
                if (-not (Test-Path $affinityPath)) { New-Item -Path $affinityPath -Force | Out-Null }
                reg.exe add $affinityPath /v "DevicePriority" /t REG_DWORD /d 3 /f | Out-Null # High priority
            }
        }
    }
    
    # Global interrupt optimization
    Write-Host "Applying global interrupt optimizations..." -ForegroundColor Yellow
    
    # Disable Dynamic Tick
    bcdedit /set disabledynamictick yes | Out-Null
    
    # Set platform timer resolution
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d 1 /f | Out-Null
    
    # Optimize DPC settings
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MinimumDpcRate" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d 0 /f | Out-Null
    
    # Optimize HAL settings for low latency
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ForceClockResolution" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcQueueDepth" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcRate" /t REG_DWORD /d 0 /f | Out-Null
}

function OptimizeCPUSettings() {
    Write-Host "`n=== Optimizing CPU Settings for 13th/14th Gen Intel ===" -ForegroundColor Cyan

    # Set processor capabilities for optimal performance
    Write-Host "Setting processor capabilities..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d 0x0007e066 /f | Out-Null

    # Core Performance Boost and Hardware P-States with focus on latency
    Write-Host "Optimizing Core Performance Settings..." -ForegroundColor Yellow
    WriteMsr "0x771" "0" "1" $true  # HWP_CAPABILITIES - Performance mode
    WriteMsr "0x774" "0" "0" $true  # HWP_REQUEST - Maximum performance request
    WriteMsr "0x770" "0" "1" $true  # HWP_ENABLE - Enable HWP in performance mode

    # Disable C-States completely for lowest latency
    Write-Host "Disabling C-States..." -ForegroundColor Yellow
    WriteMsr "0xE2" "0" "0" $true   # PKG_CST_CONFIG_CONTROL - Disable all C-states
    WriteMsr "0x1FC" "0" "0" $true  # MSR_POWER_CTL - Disable C1E
    WriteMsr "0x1A0" "0" "0" $true  # IA32_MISC_ENABLES - Disable C1E
    
    # Performance and Power Management optimized for latency
    Write-Host "Optimizing Power Management..." -ForegroundColor Yellow
    WriteMsr "0x1AA" "0" "0" $true  # MSR_MISC_PWR_MGMT - Disable Speed Shift
    WriteMsr "0x1AD" "0" "0" $true  # ENERGY_PERF_BIAS_CONFIG - Performance bias
    WriteMsr "0x1B0" "0" "0" $true  # IA32_ENERGY_PERF_BIAS - Maximum performance
    WriteMsr "0x1FC" "0" "0" $true  # MSR_POWER_CTL - Disable power limits
    
    # Cache and Memory Settings for optimal latency
    Write-Host "Optimizing Cache Settings..." -ForegroundColor Yellow
    WriteMsr "0x1A4" "0" "0" $true  # Disable prefetchers for consistent latency
    WriteMsr "0x1CC" "0" "0" $true  # LBR_SELECT - Disable last branch recording
    
    # Interrupt handling optimization
    Write-Host "Optimizing Interrupt Handling..." -ForegroundColor Yellow
    WriteMsr "0x38D" "0" "0" $true  # IA32_FIXED_CTR_CTRL - Disable fixed counters
    WriteMsr "0x38F" "0" "0" $true  # IA32_PERF_GLOBAL_CTRL - Disable global counters
    WriteMsr "0x390" "0" "0" $true  # IA32_PERF_GLOBAL_STATUS - Clear status
    
    # Maximum Power Limits
    Write-Host "Setting Power Limits..." -ForegroundColor Yellow
    WriteMsr "0x610" "0x00FFFFFF" "0x00FFFFFF" $true  # PL1/PL2 Power Limits
    WriteMsr "0x618" "0x00FFFFFF" "0x00FFFFFF" $true  # DRAM Power Limit
    WriteMsr "0x620" "0x00FFFFFF" "0x00FFFFFF" $true  # Platform Power Limit
    
    Write-Host "CPU Optimization Complete" -ForegroundColor Green
}

function OptimizeStorageController() {
    Write-Host "`n=== Optimizing Storage Controllers ===" -ForegroundColor Cyan
    
    # Advanced NVMe Optimizations
    Write-Host "Optimizing NVMe Settings..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "EnableNVMeRuntimeD3" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "EnableIdlePowerManagement" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdleTimerValue" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IntCoalescingTime" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IntCoalescingEntries" /t REG_DWORD /d 0 /f | Out-Null
    
    # Additional NVMe optimizations
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme" /v "IoLatencyCap" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme" /v "EnableQueryAccessAlignment" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme" /v "DisableQueryAccessAlignment" /t REG_DWORD /d 1 /f | Out-Null
    
    # StorPort Optimizations
    Write-Host "Optimizing StorPort Settings..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport\Parameters" /v "EnableIdlePowerManagement" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport\Parameters" /v "IoLatencyCap" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport\Parameters" /v "InterruptThrottleThreshold" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport\Parameters" /v "InterruptThrottleTimeFrameMs" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport\Parameters" /v "MaxRequestHoldTime" /t REG_DWORD /d 0 /f | Out-Null
    
    # Additional StorPort optimizations
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport\Parameters" /v "DpcRedirectBehavior" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport\Parameters" /v "MaxDpcQueueDepth" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport\Parameters" /v "MaxNumberOfIO" /t REG_DWORD /d 0xFFFFFFFF /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport\Parameters" /v "MaxRequestHoldTime" /t REG_DWORD /d 0 /f | Out-Null
    
    # Direct hardware optimizations for NVMe and SATA controllers
    $controllers = Get-WmiObject -Class Win32_PnPEntity | Where-Object {
        $_.DeviceID -like "*PCI\VEN_*" -and 
        ($_.DeviceID -like "*CC_0108*" -or $_.DeviceID -like "*CC_0106*")
    }
    
    foreach ($controller in $controllers) {
        Write-Host "Optimizing controller: $($controller.Name)" -ForegroundColor Yellow
        
        if ($controller.DeviceID -match "PCI\\VEN_(\w+)&DEV_(\w+)\\(\d+)&(\w+)") {
            $bus = [Convert]::ToInt32($matches[3])
            
            # MSI optimization for storage
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/04 0x00000147"  # Enable MSI, disable INTx
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/D0 0x00000001"  # Single MSI vector
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/D4 0x00000000"  # No MSI masking
            
            # Optimize queue settings
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/10 0x00000406"  # Command register optimization
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/14 0x00000000"  # Latency tolerance reporting off
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/18 0x00000007"  # Advanced features
            
            # Power management
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/80 0x00000000"  # Disable power management
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/84 0x00000000"  # Power management status
        }
    }
}

function OptimizeGraphicsSettings() {
    Write-Host "`n=== Optimizing Graphics Settings ===" -ForegroundColor Cyan
    
    # Registry optimizations for graphics
    Write-Host "Optimizing Graphics Driver Settings..." -ForegroundColor Yellow
    
    # General graphics optimizations
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MonitorLatencyTolerance" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "UseGpuTimer" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d 1 /f | Out-Null
    
    # Additional graphics optimizations
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DxgKrnlPerfMon" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PerfAnalyzeModeEnabled" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "EnablePreemption" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "GPUPreemptionLevel" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisableGpuMaximizedWindowDWMSync" /t REG_DWORD /d 1 /f | Out-Null
    
    # AMD-specific optimizations
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableAspmL0s" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableAspmL1" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableComputePreemption" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d 1 /f | Out-Null
    
    # Find and optimize graphics controller
    $graphics = Get-WmiObject -Class Win32_PnPEntity | Where-Object {
        $_.DeviceID -like "*PCI\VEN_*" -and $_.DeviceID -like "*CC_0300*"
    }
    
    foreach ($card in $graphics) {
        Write-Host "Optimizing graphics card: $($card.Name)" -ForegroundColor Yellow
        
        if ($card.DeviceID -match "PCI\\VEN_(\w+)&DEV_(\w+)\\(\d+)&(\w+)") {
            $bus = [Convert]::ToInt32($matches[3])
            
            # PCIe optimizations
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/50 0x00000000"  # Disable ASPM
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/54 0x00000000"  # Disable ASPM L1
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/58 0x00000040"  # Max payload size
            
            # Power and performance
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/B0 0x00000000"  # Disable power throttling
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/B4 0x00000000"  # Clear power limits
            
            # MSI optimizations with specific focus on DPC/ISR
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/04 0x00000147"  # Command register (MSI enable, no INTx)
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/D0 0x00000001"  # MSI control (single message)
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/D4 0x00000000"  # MSI mask (no masking)
            
            # Additional latency optimizations
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/0C 0x00000000"  # Disable cacheline size
            & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$bus/0/0/24 0x00000000"  # Prefetch disable
        }
    }
}

function OptimizeUSBControllers() {
    Write-Host "`n=== Optimizing USB Controllers ===" -ForegroundColor Cyan
    
    # Get all xHCI controllers with their PCI information
    $controllers = Get-WmiObject Win32_PnPEntity | Where-Object {
        ($_.Name -like "*xHCI*" -or $_.Name -like "*eXtensible Host Controller*") -and 
        $_.PNPDeviceID -match "PCI\\VEN_(\w+)&DEV_(\w+)"
    } | ForEach-Object {
        $pnpid = $_.PNPDeviceID
        $location = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\$pnpid").LocationInformation
        if ($location -match "PCI bus (\d+), device (\d+), function (\d+)") {
            @{
                Name = $_.Name
                Bus = [int]$matches[1]
                Device = [int]$matches[2]
                Function = [int]$matches[3]
                PNPID = $pnpid
            }
        }
    }
    
    foreach ($controller in $controllers) {
        Write-Host "Optimizing: $($controller.Name)" -ForegroundColor Yellow
        Write-Host "PCI Location: Bus $($controller.Bus), Device $($controller.Device), Function $($controller.Function)" -ForegroundColor Yellow
        
        # Direct register writes for USB optimization
        Write-Host "Optimizing USB Controller Settings..." -ForegroundColor Yellow
        
        # IMOD - Interrupt Moderation Control (completely disabled)
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/F0 0x00000000" | Out-Null
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/F4 0x00000000" | Out-Null
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/FC 0x00000000" | Out-Null
        
        # Power Management Control (all disabled)
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/74 0x00000000" | Out-Null
        
        # PCIe Link Control (optimized for latency)
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/50 0x00000000" | Out-Null  # Disable ASPM
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/54 0x00000000" | Out-Null  # Disable ASPM L1
        
        # MSI Configuration (optimized for latency)
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/04 0x00000147" | Out-Null  # Enable MSI, disable INTx
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/D0 0x00000001" | Out-Null  # Single MSI vector
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/D4 0x00000000" | Out-Null  # No MSI masking
        
        # Additional USB 3.0 Optimizations
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/40 0x00000000" | Out-Null  # Disable USB3 LPM
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($controller.Bus)/$($controller.Device)/$($controller.Function)/44 0x00000000" | Out-Null  # Disable Port Disable Suspend
        
        # Registry optimizations for the controller
        $deviceParams = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($controller.PNPID)\Device Parameters"
        if (Test-Path $deviceParams) {
            reg.exe add "$deviceParams" /v "EnableSelectiveSuspend" /t REG_DWORD /d 0 /f | Out-Null
            reg.exe add "$deviceParams" /v "SelectiveSuspendTimeout" /t REG_DWORD /d 0 /f | Out-Null
            reg.exe add "$deviceParams" /v "SelectiveSuspendOn" /t REG_DWORD /d 0 /f | Out-Null
            reg.exe add "$deviceParams" /v "DeviceSelectiveSuspended" /t REG_DWORD /d 0 /f | Out-Null
            reg.exe add "$deviceParams" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d 0 /f | Out-Null
            reg.exe add "$deviceParams" /v "AllowIdleIrpInD3" /t REG_DWORD /d 0 /f | Out-Null
            reg.exe add "$deviceParams" /v "DeviceIdleEnabled" /t REG_DWORD /d 0 /f | Out-Null
            reg.exe add "$deviceParams" /v "UserSetDeviceIdleEnabled" /t REG_DWORD /d 0 /f | Out-Null
            reg.exe add "$deviceParams" /v "DefaultIdleState" /t REG_DWORD /d 0 /f | Out-Null
            reg.exe add "$deviceParams" /v "BusIdleExit" /t REG_DWORD /d 0 /f | Out-Null
        }
        
        # USB Hub settings
        reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "u1Timeout" /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "u2Timeout" /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "EnableU1" /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "EnableU2" /t REG_DWORD /d 0 /f | Out-Null
    }
    
    # Global USB settings
    Write-Host "Applying global USB settings..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USB" /v "DisableSelectiveSuspend" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "SelectiveSuspendTimeout" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "InterruptModeration" /t REG_DWORD /d 0 /f | Out-Null
    
    # WDF settings for USB
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wdf01000\Parameters" /v "DpcWatchdogPeriod" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wdf01000\Parameters" /v "MinimumDpcRate" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wdf01000\Parameters" /v "IdleTimeoutType" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wdf01000\Parameters" /v "DefaultIdleTimeout" /t REG_DWORD /d 0 /f | Out-Null
}

function ForceStopEventLog() {
    Write-Host "Force stopping Event Log and dependencies..." -ForegroundColor Yellow
    
    # Disable Event Log at registry level first
    Write-Host "Disabling Event Log at registry level..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
    
    # Get all services that depend on EventLog
    $eventLogDependents = Get-Service -Name "EventLog" -DependentServices
    
    # Stop all dependent services first
    foreach ($service in $eventLogDependents) {
        Write-Host "Stopping dependent service: $($service.Name)" -ForegroundColor Yellow
        Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service.Name -StartupType Disabled
    }
    
    # Stop and disable Event Log
    Stop-Service -Name "EventLog" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "EventLog" -StartupType Disabled
}

function DisableETWTracking() {
    Write-Host "`n=== Disabling ETW and System Tracing ===" -ForegroundColor Cyan
    
    # Use the new function to handle Event Log
    ForceStopEventLog
    
    # Disable diagnostic services
    $diagnosticServices = @(
        "DPS",              # Diagnostic Policy Service
        "WdiServiceHost",   # Diagnostic Service Host
        "WdiSystemHost",    # Diagnostic System Host
        "diagsvc",         # Diagnostic Execution Service
        "diagnosticshub.standardcollector.service", # Diagnostic Hub Standard Collector
        "DiagTrack",       # Connected User Experiences and Telemetry
        "PcaSvc",          # Program Compatibility Assistant
        "dmwappushservice" # Device Management WAP Provider
    )
    
    foreach ($service in $diagnosticServices) {
        Write-Host "Disabling $service..." -ForegroundColor Yellow
        # Check if service exists first
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        } else {
            # Try using sc.exe as fallback
            sc.exe stop $service 2>$null
            sc.exe config $service start= disabled 2>$null
        }
    }
    
    # Disable Performance Counters
    Write-Host "Disabling Performance Counters..." -ForegroundColor Yellow
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" /v "Disable Performance Counters" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PerfHost" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PerfProc" /v "Performance" /t REG_DWORD /d 0 /f | Out-Null
    
    # Optimize kernel settings
    Write-Host "Optimizing kernel settings..." -ForegroundColor Yellow
    # Remove existing DWORDs first
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /f 2>$null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MinimumDpcRate" /f 2>$null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /f 2>$null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ForceClockResolution" /f 2>$null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcQueueDepth" /f 2>$null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcRate" /f 2>$null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeLimit" /f 2>$null
    
    # Add only the specified values
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "TimerCheckFlags" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SerializeTimerExpiration" /t REG_DWORD /d 1 /f | Out-Null
    
    # Disable Windows Event Collector
    Write-Host "Disabling Windows Event Collector..." -ForegroundColor Yellow
    if (Get-Service -Name "Wecsvc" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "Wecsvc" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "Wecsvc" -StartupType Disabled
    }
    
    Write-Host "ETW and System Tracing Optimization Complete!" -ForegroundColor Green
}

function DisableCPUMitigations() {
    Write-Host "`n=== Disabling CPU Mitigations ===" -ForegroundColor Cyan
    
    # Use bcdedit to disable mitigations
    Write-Host "Disabling CPU mitigations via boot configuration..." -ForegroundColor Yellow
    bcdedit /set isolatedcontext off | Out-Null
    bcdedit /set allowedinmemorysettings 0x0 | Out-Null
    bcdedit /set disableelamdrivers Yes | Out-Null
    
    # Disable via registry
    Write-Host "Disabling CPU mitigations via registry..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f | Out-Null
    
    # Disable additional security features
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d 0 /f | Out-Null
    
    Write-Host "CPU Mitigations disabled!" -ForegroundColor Green
}

function OptimizeSystemProfile() {
    Write-Host "`n=== Optimizing System Profile ===" -ForegroundColor Cyan
    
    # System Profile Optimizations
    Set-ItemProperty -Path $SYSTEM_PROFILE -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Type DWord
    Set-ItemProperty -Path $SYSTEM_PROFILE -Name "SystemResponsiveness" -Value 0 -Type DWord
    Set-ItemProperty -Path $SYSTEM_PROFILE -Name "EnableMmcss" -Value 0 -Type DWord
    
    # Gaming Profile Optimizations
    $gaming = "$SYSTEM_PROFILE\Tasks\Games"
    if (-not (Test-Path $gaming)) {
        New-Item -Path $gaming -Force | Out-Null
    }
    Set-ItemProperty -Path $gaming -Name "GPU Priority" -Value 8 -Type DWord
    Set-ItemProperty -Path $gaming -Name "Priority" -Value 6 -Type DWord
    Set-ItemProperty -Path $gaming -Name "Scheduling Category" -Value "High" -Type String
    Set-ItemProperty -Path $gaming -Name "SFIO Priority" -Value "High" -Type String
}

function OptimizeCoreAffinity() {
    Write-Host "`n=== Optimizing Core Affinities ===" -ForegroundColor Cyan
    
    # Get CPU topology
    $cores = (Get-WmiObject -Class Win32_Processor).NumberOfCores
    $p_cores = [math]::Floor($cores / 2)  # Assuming Intel 13th/14th gen with P and E cores
    
    # Calculate optimal masks
    $p_cores_mask = [math]::Pow(2, $p_cores) - 1
    $first_p_core = 1  # First P-core mask
    $second_p_core = 2  # Second P-core mask
    
    Write-Host "Detected $cores total cores, $p_cores performance cores" -ForegroundColor Yellow
    Write-Host "Using first P-core for critical tasks" -ForegroundColor Yellow
    
    try {
        # Use PowerShell jobs to set process affinities with elevated privileges
        $processes = @{
            "dwm" = $first_p_core
            "csrss" = $first_p_core
            "winlogon" = $second_p_core
            "lsass" = $second_p_core
            "audiodg" = $second_p_core
        }
        
        foreach ($proc in $processes.GetEnumerator()) {
            $scriptBlock = {
                param($procName, $affinity)
                $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue
                foreach ($process in $processes) {
                    $WinAPI = Add-Type -Name SetAffinity -Namespace Win32Functions -PassThru -MemberDefinition @"
                        [DllImport("kernel32.dll")]
                        public static extern bool SetProcessAffinityMask(IntPtr hProcess, IntPtr dwProcessAffinityMask);
"@
                    $WinAPI::SetProcessAffinityMask($process.Handle, [IntPtr]$affinity)
                }
            }
            
            Start-Process powershell -ArgumentList "-Command & {$scriptBlock} -procName $($proc.Key) -affinity $($proc.Value)" -Verb RunAs -WindowStyle Hidden
            Write-Host "Set $($proc.Key) affinity to core $($proc.Value)" -ForegroundColor Yellow
        }
        
        # Set device interrupt affinities
        $gpus = Get-WmiObject -Class Win32_VideoController | Where-Object { $_.PNPDeviceID -like "*PCI\VEN_*" }
        foreach ($gpu in $gpus) {
            if ($gpu.PNPDeviceID -match "PCI\\VEN_(\w+)&DEV_(\w+)\\(\d+)&(\w+)") {
                Write-Host "Setting GPU affinity: $($gpu.Name)" -ForegroundColor Yellow
                & $RWE_PATH /NoLogo /Min /Command="W32 PCI/$($matches[3])/0/0/68 $first_p_core"
            }
        }
        
        # Set timer resolution
        Write-Host "Setting Timer Resolution..." -ForegroundColor Yellow
        & $RWE_PATH /NoLogo /Min /Command="W32 PCI/0/0/0/54 0x00000001"
        reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" /v "MaxPollInterval" /t REG_DWORD /d 1 /f | Out-Null
    }
    catch {
        Write-Host "Warning: Some affinity operations required elevated permissions" -ForegroundColor Red
    }
}

function OptimizeBootConfiguration() {
    Write-Host "`n=== Optimizing Boot Configuration ===" -ForegroundColor Cyan
    
    # Disable DMA remapping to reduce storage latency
    Write-Host "Configuring DMA and Interrupt Settings..." -ForegroundColor Yellow
    bcdedit /set dmaremap No | Out-Null
    bcdedit /set vsmlaunchtype Off | Out-Null
    bcdedit /set hypervisorlaunchtype Off | Out-Null
    bcdedit /set integrityservices Disable | Out-Null
    bcdedit /set nx OptOut | Out-Null
    bcdedit /set pae ForceDisable | Out-Null
    bcdedit /set uselegacyapicmode Yes | Out-Null
    bcdedit /set useplatformtick No | Out-Null
    bcdedit /set disabledynamictick Yes | Out-Null
    bcdedit /set tscsyncpolicy Enhanced | Out-Null
    bcdedit /set x2apicpolicy Enable | Out-Null
    bcdedit /set usephysicaldestination No | Out-Null
    bcdedit /set linearaddress57 OptOut | Out-Null
    bcdedit /set firstmegabytepolicy UseAll | Out-Null
    bcdedit /set configaccesspolicy Default | Out-Null
    bcdedit /set usefirmwarepcisettings No | Out-Null
    bcdedit /set msi Default | Out-Null
    bcdedit /set perfmem 0 | Out-Null
    
    # MSI mode for storage controllers
    Write-Host "Enabling MSI Mode for Storage Controllers..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_8086&DEV_7A60\3&11583659&0&A0\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_8086&DEV_7A60\3&11583659&0&A0\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d 3 /f | Out-Null
    
    # Optimize storage class driver parameters
    Write-Host "Optimizing Storage Class Drivers..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storahci" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storport" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\iaStorAC" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
    
    # Disable storage power management
    Write-Host "Disabling Storage Power Management..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Storage" /v "StorageD3InModernStandby" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Storage\StoragePolicies" /v "StoragePolicyIdleDisabled" /t REG_DWORD /d 1 /f | Out-Null
    
    # Optimize AHCI settings
    Write-Host "Optimizing AHCI Settings..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "EnableHIPM" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "EnableDIPM" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "EnableHDDParking" /t REG_DWORD /d 0 /f | Out-Null
}

function OptimizeServices() {
    Write-Host "`n=== Optimizing Services ===" -ForegroundColor Cyan
    
    # Critical network services to keep
    $network_services_to_keep = @(
        "Dnscache",                      # DNS Client
        "NlaSvc",                        # Network Location Awareness
        "nsi",                           # Network Store Interface Service
        "netprofm",                      # Network List Service
        "NetSetupSvc",                   # Network Setup Service
        "Dhcp",                          # DHCP Client
        "BFE",                           # Base Filtering Engine (required for network stack)
        "NetBIOS",                       # NetBIOS Service
        "NetBT",                         # NetBT Service
        "Tcpip",                         # TCP/IP Protocol Driver
        "Tcpip6",                        # IPv6 Protocol Driver
        "tdx",                           # TDX Driver
        "vwififlt",                      # Virtual WiFi Filter Driver
        "AFD",                           # Ancillary Function Driver
        "NetAdapterCx",                  # Network Adapter Framework
        "msquic",                        # Microsoft QUIC Protocol Driver
        "HTTP"                           # HTTP Protocol Stack
    )
    
    # Services to keep for Xbox and Store
    $system_services_to_keep = @(
        "XblGameSave",                   # Xbox Live Game Save
        "XboxNetApiSvc",                 # Xbox Live Networking Service
        "AppXSvc",                       # AppX Deployment Service
        "ClipSVC",                       # Client License Service
        "TokenBroker",                   # Web Account Manager
        "InstallService",                # Microsoft Store Install Service
        "LicenseManager",                # Windows License Manager Service
        "wuauserv",                      # Windows Update
        "StorSvc",                       # Storage Service
        "StateRepository",               # State Repository Service
        "crypt32",                       # Cryptographic Services
        "AppIDSvc",                      # Application Identity
        "msiserver"                      # Windows Installer
    )
    
    # AMD Services that need special handling
    $amd_protected_services = @(
        "amdfendr",                      # AMD system defense
        "amdfendrmgr",                   # AMD system defense manager
        "amdlog",                        # AMD logging
        "AMDSAFD",                       # AMD storage driver
        "AMD External Events Utility"     # AMD external events
    )
    
    # Force stop protected AMD services first
    foreach ($service in $amd_protected_services) {
        ForceStopService $service
    }
    
    # Services to disable
    $services_to_disable = @(
        # AMD Services
        "AMD External Events Utility",      # AMD external events
        "AMD Log Utility",                  # AMD logging
        "amdfendr",                        # AMD system defense
        "amdgpio2",                        # AMD GPIO
        "amdfendrmgr",                     # AMD system defense manager
        "AMDRyzenMasterDriverV19",         # Ryzen Master
        "AMDRyzenMasterDriver",            # Ryzen Master
        
        # Telemetry & Diagnostics
        "DiagTrack",                       # Connected User Experiences and Telemetry
        "dmwappushservice",                # Device Management Wireless Application Protocol
        "diagnosticshub.standardcollector.service", # Microsoft diagnostics hub
        "diagsvc",                         # Diagnostic Execution Service
        "DPS",                             # Diagnostic Policy Service
        "WdiServiceHost",                  # Diagnostic Service Host
        "WdiSystemHost",                   # Diagnostic System Host
        
        # Windows Bloat
        "RetailDemo",                      # Retail Demo Service
        "WbioSrvc",                        # Windows Biometric Service
        "FontCache",                       # Windows Font Cache
        "GraphicsPerfSvc",                 # Graphics performance monitor
        "WSearch",                         # Windows Search
        "SysMain",                         # Superfetch
        "TrkWks",                          # Distributed Link Tracking
        "defragsvc",                       # Optimize drives
        "HomeGroupListener",               # HomeGroup Listener
        "HomeGroupProvider",               # HomeGroup Provider
        "lfsvc",                           # Geolocation Service
        "MapsBroker",                      # Downloaded Maps Manager
        "PcaSvc",                          # Program Compatibility Assistant
        "RemoteRegistry",                  # Remote Registry
        "SharedAccess",                    # Internet Connection Sharing
        "SNMPTRAP",                        # SNMP Trap
        "WerSvc",                          # Windows Error Reporting
        "WMPNetworkSvc",                   # Windows Media Player Network
        
        # Print Services (if not needed)
        "Spooler",                         # Print Spooler
        "PrintNotify",                     # Printer Extensions
        
        # Remote Desktop (if not needed)
        "SessionEnv",                      # Remote Desktop Configuration
        "TermService",                     # Remote Desktop Services
        "UmRdpService",                    # Remote Desktop Services UserMode Port Redirector
        
        # Other Performance Impact Services
        "SCardSvr",                        # Smart Card
        "ScDeviceEnum",                    # Smart Card Device Enumeration
        "SCPolicySvc",                     # Smart Card Removal Policy
        "TabletInputService",              # Touch Keyboard and Handwriting
        "WebClient",                       # WebClient
        "WwanSvc",                         # WWAN AutoConfig
        "XboxGipSvc",                      # Xbox Accessory Management Service
        "SEMgrSvc",                        # Payments and NFC
        "PhoneSvc",                        # Phone Service
        "WpcMonSvc",                       # Parental Controls
        "wisvc",                           # Windows Insider Service
        "RasAuto",                         # Remote Access Auto Connection
        "RemoteAccess",                    # Routing and Remote Access
        "SensorDataService",               # Sensor Data Service
        "SensorService",                   # Sensor Service
        "SensrSvc",                        # Sensor Monitoring Service
        "ShellHWDetection",                # Shell Hardware Detection
        
        # Additional Telemetry
        "TapiSrv",                         # Telephony
        "Themes",                          # Themes
        "DeviceAssociationService",        # Device Association Service
        "DeviceInstall",                   # Device Install Service
        "DevicePickerUserSvc",             # Device Picker
        "DevicesFlowUserSvc",              # Devices Flow
        "DusmSvc",                         # Data Usage
        "BthAvctpSvc",                     # AVCTP service
        "BTAGService",                     # Bluetooth Audio Gateway Service
        "bthserv",                         # Bluetooth Support Service
        "BluetoothUserService",            # Bluetooth User Support Service
        "CDPSvc",                          # Connected Devices Platform Service
        "CDPUserSvc",                      # Connected Devices Platform User Service
        "DevQueryBroker",                  # DevQuery Background Discovery Broker
        "WpnService",                      # Windows Push Notifications System Service
        "WpnUserService",                  # Windows Push Notifications User Service
        "cbdhsvc"                          # Clipboard User Service
    )
    
    Write-Host "Disabling unnecessary services..." -ForegroundColor Yellow
    foreach ($service in $services_to_disable) {
        # Skip if service is in the keep lists
        if (($network_services_to_keep -notcontains $service) -and 
            ($system_services_to_keep -notcontains $service)) {
            try {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    Write-Host "Disabling $service..." -ForegroundColor Yellow
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Host "Could not disable $service" -ForegroundColor Red
            }
        }
    }
    
    # Disable AMD services via registry as well
    Write-Host "Disabling AMD services via registry..." -ForegroundColor Yellow
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\amdlog" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\amdfendr" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\amdfendrmgr" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AMDSAFD" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AMD External Events Utility" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
    
    # Disable telemetry via registry
    Write-Host "Disabling telemetry via registry..." -ForegroundColor Yellow
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableWizard" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f | Out-Null
    
    # Additional AMD registry cleanup
    Write-Host "Cleaning up AMD registry entries..." -ForegroundColor Yellow
    $amd_reg_keys = @(
        "HKLM\SYSTEM\CurrentControlSet\Services\amdfendr",
        "HKLM\SYSTEM\CurrentControlSet\Services\amdfendrmgr",
        "HKLM\SYSTEM\CurrentControlSet\Services\amdlog",
        "HKLM\SYSTEM\CurrentControlSet\Services\AMDSAFD",
        "HKLM\SOFTWARE\AMD",
        "HKLM\SOFTWARE\AMD Global",
        "HKLM\SOFTWARE\AMD Performance Profile"
    )
    
    foreach ($key in $amd_reg_keys) {
        reg.exe delete $key /f 2>$null
    }
    
    # Block AMD services from starting
    Write-Host "Blocking AMD services from starting..." -ForegroundColor Yellow
    foreach ($service in $amd_protected_services) {
        # Create dummy service entry that prevents the real service from starting
        sc.exe create "$service`_dummy" binPath= "C:\Windows\System32\cmd.exe /c exit" type= own start= disabled error= ignore | Out-Null
        sc.exe description "$service`_dummy" "Dummy service to prevent $service from starting" | Out-Null
    }
    
    Write-Host "Service optimization complete!" -ForegroundColor Green
}

function DisableDefender() {
    Write-Host "`n=== Disabling Windows Defender ===" -ForegroundColor Cyan
    
    # Disable Defender services
    $defender_services = @(
        "WdNisSvc",                      # Network Inspection Service
        "WinDefend",                     # Main Defender service
        "Sense",                         # Advanced Protection Service
        "wscsvc",                        # Security Center
        "SecurityHealthService",         # Security Health Service
        "WdNisDrv",                     # Network Inspection Driver
        "WdFilter",                     # Mini-Filter Driver
        "WdBoot",                       # Boot Driver
        "mpssvc",                       # Windows Firewall
        "mspft",                        # Microsoft Protection Service
        "MsMpSvc"                       # Microsoft Malware Protection
    )
    
    Write-Host "Disabling Defender services..." -ForegroundColor Yellow
    foreach ($service in $defender_services) {
        try {
            Write-Host "Stopping and disabling $service..." -ForegroundColor Yellow
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            sc.exe config $service start= disabled | Out-Null
        }
        catch {
            Write-Host "Could not disable $service" -ForegroundColor Red
        }
    }
    
    # Disable via Registry
    Write-Host "Disabling Defender via Registry..." -ForegroundColor Yellow
    
    # Main Defender settings
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 0 /f | Out-Null
    
    # Real-time protection
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 1 /f | Out-Null
    
    # Reporting and notifications
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center" /v "DisableAppBrowserUI" /t REG_DWORD /d 1 /f | Out-Null
    
    # Disable Tamper Protection via registry
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 1 /f | Out-Null
    
    # Disable Windows Defender Security Center
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
    
    # Disable Smart Screen
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f | Out-Null
    
    # Remove Windows Defender context menu
    reg.exe delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f | Out-Null
    reg.exe delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f | Out-Null
    reg.exe delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f | Out-Null
    
    # Disable Windows Defender in Local Group Policy
    Write-Host "Disabling Defender in Local Group Policy..." -ForegroundColor Yellow
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecurityCenter" /t REG_DWORD /d 0 /f | Out-Null
    
    # Disable Windows Defender Firewall
    Write-Host "Disabling Windows Defender Firewall..." -ForegroundColor Yellow
    netsh advfirewall set allprofiles state off | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
    
    # Remove Defender scheduled tasks
    Write-Host "Removing Defender scheduled tasks..." -ForegroundColor Yellow
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable | Out-Null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable | Out-Null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable | Out-Null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable | Out-Null
    
    Write-Host "Windows Defender has been disabled!" -ForegroundColor Green
}

function DisableUnneededDrivers() {
    Write-Host "`n=== Disabling Unnecessary Drivers ===" -ForegroundColor Cyan
    
    $drivers_to_disable = @(
        # Interface and Protocol Drivers
        "1394ohci",                    # FireWire driver
        "Acpidev",                     # ACPI devices
        "acpipagr",                    # ACPI processor aggregator
        "AcpiPmi",                     # ACPI Power Meter
        "acpitime",                    # ACPI time
        "AppvVemgr",                   # App-V manager
        "bam",                         # Background Activity Moderator
        "beep",                        # Beep device
        "bowser",                      # Browser support
        "cdrom",                       # CD-ROM driver
        "cdfs",                        # CD-ROM file system
        "CSC",                         # Offline files
        "gencounter",                  # Generic performance counter
        "HidIr",                       # HID infrared
        "hvcrash",                     # Hyper-V crashdump
        "hvservice",                   # Hyper-V service
        "i8042prt",                    # PS/2 keyboard/mouse
        "iaStorV",                     # Intel storage driver
        "MEIx64",                      # Intel Management Engine
        "mssmbios",                    # Microsoft BIOS driver
        
        # Network Related
        "NdisCap",                     # Network capture
        "NdisVirtualBus",             # Virtual network adapter
        "Ndu",                         # Windows Network Data Usage
        "pcw",                         # Performance Counter
        "rdpbus",                      # Remote Desktop
        "scfilter",                    # Smart card filter
        "sfloppy",                     # Floppy disk
        "SgrmAgent",                   # System Guard Runtime Monitor
        "udfs",                        # UDF file system
        "UevAgentDriver",             # User Experience Virtualization
        "umbus",                      # UMBus driver
        "Vid",                        # Hyper-V video
        "wanarp",                     # Remote Access IPv4
        "wanarpv6",                   # Remote Access IPv6
        
        # Bluetooth Related
        "b06bdrv",                    # Bluetooth driver
        "BthA2dp",                    # Bluetooth A2DP
        "BthEnum",                    # Bluetooth enumerator
        "BthHFEnum",                  # Bluetooth hands-free
        "BthLEEnum",                  # Bluetooth LE
        "BthMini",                    # Bluetooth miniport
        "BTHMODEM",                   # Bluetooth modem
        "BTHPORT",                    # Bluetooth port
        "BTHUSB",                     # Bluetooth USB
        "HidBth",                     # Bluetooth HID
        "Microsoft_Bluetooth_AvrcpTransport", # Bluetooth AVRCP
        "RFCOMM"                      # Bluetooth RFCOMM
    )
    
    foreach ($driver in $drivers_to_disable) {
        Write-Host "Disabling driver: $driver" -ForegroundColor Yellow
        
        # Try to stop and disable the driver service
        try {
            Stop-Service -Name $driver -Force -ErrorAction SilentlyContinue
            Set-Service -Name $driver -StartupType Disabled -ErrorAction SilentlyContinue
        } catch { }
        
        # Use registry method to ensure driver is disabled
        reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$driver" /v "Start" /t REG_DWORD /d 4 /f | Out-Null
        
        # If it's a driver service, try to unload it
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$driver") {
            $driverInfo = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$driver" -ErrorAction SilentlyContinue
            if ($driverInfo.Type -eq 1) { # Kernel driver
                # Try to unload the driver
                & $RWE_PATH /NoLogo /Min /Command="UNLOAD $driver" 2>$null
                fltmc unload $driver 2>$null
            }
        }
    }
    
    Write-Host "Driver optimization complete!" -ForegroundColor Green
}

function ForceStopService($serviceName) {
    Write-Host "Force stopping $serviceName..." -ForegroundColor Yellow
    
    # Special handling for BAM service
    if ($serviceName -eq "bam") {
        # Kill dependent services first
        $dependentServices = Get-Service -Name $serviceName -DependentServices -ErrorAction SilentlyContinue
        foreach ($depService in $dependentServices) {
            Stop-Service -Name $depService.Name -Force -ErrorAction SilentlyContinue
        }
        
        # Try to stop BAM service with timeout
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($stopWatch.ElapsedMilliseconds -lt 5000) {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service.Status -eq 'Stopped') {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        $stopWatch.Stop()
        
        # If still not stopped, use more aggressive methods
        if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status -ne 'Stopped') {
            # Kill process
            $process = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'" | Select-Object -ExpandProperty ProcessId
            if ($process) {
                taskkill /F /PID $process 2>$null
            }
            
            # Force remove service
            sc.exe delete $serviceName 2>$null
        }
    }
    
    # Get service details
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
    if ($service) {
        # Kill service process if running
        if ($service.ProcessId -gt 0) {
            taskkill /PID $service.ProcessId /F 2>$null
        }
        
        # Force remove service
        sc.exe delete $serviceName 2>$null
    }
    
    # Handle driver services specifically
    $driverKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if (Test-Path $driverKey) {
        try {
            # Get driver info
            $driverInfo = Get-ItemProperty -Path $driverKey -ErrorAction SilentlyContinue
            $imagePath = $driverInfo.ImagePath
            
            # Unload driver using multiple methods
            if ($imagePath -and $imagePath.EndsWith('.sys')) {
                # Method 1: Use RW.exe to unload
                & $RWE_PATH /NoLogo /Min /Command="UNLOAD $serviceName" 2>$null
                Start-Sleep -Milliseconds 500
                
                # Method 2: Use fltmc to unload
                fltmc unload $serviceName 2>$null
                Start-Sleep -Milliseconds 500
                
                # Method 3: Use driverquery and remove
                $driverQuery = driverquery /v /fo csv | ConvertFrom-Csv | Where-Object { $_.Path -like "*$serviceName.sys" }
                if ($driverQuery) {
                    sc.exe delete $serviceName 2>$null
                }
                
                # Get actual file path
                if ($imagePath -match '\\SystemRoot\\') {
                    $imagePath = $imagePath -replace '\\SystemRoot\\', "$env:SystemRoot\"
                }
                if ($imagePath -match '\\\?\?\\') {
                    $imagePath = $imagePath -replace '\\\?\?\\', ''
                }
                
                if (Test-Path $imagePath) {
                    # Take ownership and set permissions
                    $acl = Get-Acl -Path $imagePath
                    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity.Name, "FullControl", "Allow")
                    $acl.SetAccessRule($rule)
                    
                    # Use multiple methods to take ownership
                    takeown /F $imagePath /A | Out-Null
                    icacls $imagePath /grant Administrators:F | Out-Null
                    try { Set-Acl -Path $imagePath -AclObject $acl } catch { }
                    
                    # Try to rename first (sometimes helps with locked files)
                    $backupPath = "$imagePath.bak"
                    try { 
                        Move-Item -Path $imagePath -Destination $backupPath -Force -ErrorAction SilentlyContinue
                        Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
                    } catch { }
                    
                    # Try direct removal
                    Remove-Item -Path $imagePath -Force -ErrorAction SilentlyContinue
                }
            }
            
            # Remove service registry key
            Remove-Item -Path $driverKey -Force -Recurse -ErrorAction SilentlyContinue
            
            # Remove device if exists
            $devicePath = "HKLM:\SYSTEM\CurrentControlSet\Enum\Root\*\*"
            Get-ChildItem -Path $devicePath -ErrorAction SilentlyContinue | ForEach-Object {
                $deviceKey = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($deviceKey.Service -eq $serviceName) {
                    Remove-Item -Path $_.PSPath -Force -Recurse -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            Write-Host "Warning: Could not fully remove driver $serviceName" -ForegroundColor Red
        }
    }
    
    # Disable service with multiple methods
    sc.exe config $serviceName start= disabled 2>$null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$serviceName" /v "Start" /t REG_DWORD /d 4 /f 2>$null
    
    # Create dummy service to prevent restart
    $dummyPath = "$env:SystemRoot\System32\cmd.exe /c exit"
    sc.exe create "$serviceName`_dummy" binPath= $dummyPath type= kernel start= disabled error= ignore | Out-Null
}

function main() {
    if (-not (Is-Admin)) {
        Write-Host "Error: Administrator privileges required" -ForegroundColor Red
        return 1
    }

    if (-not ((Test-Path $WINRING0_PATH) -and (Test-Path $WINRING0_SYS))) {
        Write-Host "Error: WinRing0 files not found in script directory" -ForegroundColor Red
        return 1
    }

    Write-Host "Intel 13th/14th Gen DPC/ISR Latency Optimization" -ForegroundColor Cyan
    Write-Host "WARNING: This script makes low-level hardware changes." -ForegroundColor Red
    Write-Host "Optimizations:"
    Write-Host "- Optimize CPU power states and cache settings" -ForegroundColor Yellow
    Write-Host "- Disable storage controller interrupt coalescing" -ForegroundColor Yellow
    Write-Host "- Optimize graphics driver latency settings" -ForegroundColor Yellow
    Write-Host "- Disable USB interrupt moderation" -ForegroundColor Yellow
    Write-Host "- Disable ETW and system tracing" -ForegroundColor Yellow
    Write-Host "- Disable CPU security mitigations" -ForegroundColor Yellow
    Write-Host "- Optimize core affinities" -ForegroundColor Yellow
    Write-Host "- Configure boot settings for optimal latency" -ForegroundColor Yellow
    Write-Host "- Optimize services" -ForegroundColor Yellow
    Write-Host "- Disable unnecessary drivers" -ForegroundColor Yellow
    Write-Host "- Optimize interrupt handling for all PCI devices" -ForegroundColor Yellow
    Write-Host "Press Enter to continue or Ctrl+C to cancel..."
    $null = Read-Host

    OptimizeCPUSettings
    OptimizeInterruptHandling
    OptimizeStorageController
    OptimizeGraphicsSettings
    OptimizeUSBControllers
    DisableETWTracking
    DisableCPUMitigations
    OptimizeSystemProfile
    OptimizeCoreAffinity
    OptimizeBootConfiguration
    OptimizeServices
    DisableUnneededDrivers

    Write-Host "`nOptimization complete!" -ForegroundColor Green
    Write-Host "Please restart your system for changes to take effect." -ForegroundColor Red
    Write-Host "After restart, run LatencyMon to verify improvements." -ForegroundColor Yellow

    return 0
}

exit main

