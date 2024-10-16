@echo off
setlocal enabledelayedexpansion

:: Check if script is running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    :: Relaunch the script as administrator
    powershell -Command "Start-Process '%~0' -Verb runAs"
    exit /b
)

:: Now the script is running with Administrator privileges
echo Script is running with elevated privileges.
set "batchFile=%~f0"
set "taskName=Run CPU MSR Script"

REM Check if the task already exists
schtasks /query /TN "%taskName%" >nul 2>&1
if %ERRORLEVEL%==0 (
    echo Task "%taskName%" already exists. Skipping creation.
    goto :RunScript
)

REM Create the scheduled task to run this script with highest privileges at startup
schtasks /create /tn "%taskName%" /tr "\"%batchFile%\"" /sc onlogon /rl highest /f >nul 2>&1
if %ERRORLEVEL%==0 (
    echo Task created successfully.
) else (
    
)

:RunScript
REM Start executing the actual MSR writes
cd C:\cpu-msr
echo Writing all successful MSR changes...

msr-cmd.exe -A write 0x1AD 0x99999999 0x99999999
msr-cmd.exe -A write 0x1FC 0x00000000 0x00000000
msr-cmd.exe -A write 0x610 0x00000000 0x0000FFFF
msr-cmd.exe -A write 0xE2 0x00000000 0x00000001
msr-cmd.exe -A write 0x1B1 0x00000000 0x00000000
msr-cmd.exe -A write 0x48 0x00000000 0x00000000
msr-cmd.exe -A write 0x1A4 0x00000000 0x00000000
msr-cmd.exe -A write 0x1C9 0x00000000 0x00000000
msr-cmd.exe -A write 0x150 0x00000000 0x40008500
msr-cmd.exe -A write 0x620 0x00000000 0x00000079
msr-cmd.exe -A write 0x3b 0x00000000 0x00000000
msr-cmd.exe -A write 0x6e0 0x00000000 0x00000000
msr-cmd.exe -A write 0x65c 0x0000FFD0 0x000E0FFD0
msr-cmd.exe -A write 0x1A4 0x00000000 0x00000000
msr-cmd.exe -A write 0x642 0x00000000 0x00000010
msr-cmd.exe -A write 0x33 0x00000000 0x00000000
msr-cmd.exe -A write 0x618 0x00E07FD0 0x00E07FD0
msr-cmd.exe -A write 0x600 0x00000001 0x00000001
msr-cmd.exe -A write 0x63a 0x0 0x0
msr-cmd.exe -A write 0x638 0x0 0x0
msr-cmd.exe -A write 0x19C 0x00000000 0x00000000
msr-cmd.exe -A write 0x1F4 0x00000000 0x00000000

SETLOCAL ENABLEEXTENSIONS

:: Create the directory for the script if it doesn't exist
if not exist "C:\Scripts" mkdir "C:\Scripts"

:: Create the batch script that sets global CPU affinity for all processes
(
    echo @echo off
    echo SETLOCAL ENABLEEXTENSIONS
    echo.
    echo :: Get the number of logical processors
    echo for /f "tokens=2 delims==^" %%%%a in ^('wmic cpu get NumberOfLogicalProcessors /value^' ^) do set /a num_cpus=%%%%a
    echo :: Calculate the affinity mask for all processors
    echo set /a affinity_mask=0
    echo for /l %%%%b in ^(1,1,%%num_cpus%%^) do set /a affinity_mask^|=1^<<%%%%b-1
    echo.
    echo :: Convert affinity_mask to hexadecimal
    echo for /f "tokens=2 delims==^" %%%%c in ^('cmd /c exit /b %%affinity_mask%% ^&^& echo %%^=ExitCodeAscii%%'^) do set hex_mask=%%%%c
    echo.
    echo :: Set affinity for all processes
    echo for /f "skip=1 tokens=2 delims=,^" %%%%p in ^('wmic process get ProcessId^,Name /format:csv^' ^) do ^
    echo PowerShell -Command ^"$Process = Get-Process -Id %%%%p -ErrorAction SilentlyContinue; if ^($Process^) { $Process.ProcessorAffinity=%%affinity_mask%% }^"
) > "C:\Scripts\SetGlobalAffinity.bat"

:: Create a scheduled task to run the script every minute as SYSTEM
schtasks /create /tn "Set Global Affinity" /tr "C:\Scripts\SetGlobalAffinity.bat" /sc minute /mo 1 /ru SYSTEM /rl HIGHEST /f

:: Confirm the task was created
echo Scheduled task created to run every minute as SYSTEM. Check with 'schtasks /query /tn "Set Global Affinity"' to verify.

:: Set ThreadPool Min Threads for Max Throughput
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "ThreadPoolMinThreads" /t REG_DWORD /d 2 /f

:: Set ThreadPool Max Threads for Max Throughput
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "ThreadPoolMaxThreads" /t REG_DWORD /d 4 /f

:: Set IOCP Concurrency for Max Throughput
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IOCPConcurrency" /t REG_DWORD /d 1 /f

:: Notify the user that max throughput settings have been applied
echo Max throughput settings applied successfully.

REM Setting Max Pending values for performance optimization
setx MAX_PENDING_INTERRUPTS 0 /M
setx MAX_PENDING_IO 1 /M
setx MAX_PENDING_DPCS 0 /M
setx MAX_PENDING_DMA 0 /M
setx MAX_PENDING_NETWORK 16 /M
setx MAX_PENDING_STORAGE 16 /M
setx MAX_PENDING_AUDIO_INTERRUPTS 0 /M
setx MAX_PENDING_USB 0 /M
setx MAX_PENDING_GPU 0 /M
setx MAX_PENDING_PCIE 0 /M
setx MAX_PENDING_NVME 8 /M
setx MAX_PENDING_HID 0 /M
setx MAX_PENDING_DISPLAY 0 /M
setx MAX_PENDING_BLUETOOTH 2 /M
setx MAX_PENDING_PAGING 4 /M

echo Max Pending values have been set globally.

SETLOCAL ENABLEDELAYEDEXPANSION

:: Step 1: Create the Mystring.vbs file in C:\
(
    echo mystring = ^(1.7976931348623157E+308^)
) > "C:\Mystring.vbs"

:: Check if Mystring.vbs was created successfully
if exist "C:\Mystring.vbs" (
    echo Mystring.vbs created successfully.
) else (
    echo Failed to create Mystring.vbs.
    
)

:: Step 2: Create the Freemem.vbs file in C:\
(
    echo freemem = Space^(1000000000^)
) > "C:\Freemem.vbs"

:: Check if Freemem.vbs was created successfully
if exist "C:\Freemem.vbs" (
    echo Freemem.vbs created successfully.
) else (
    echo Failed to create Freemem.vbs.
    
)

:: Step 3: Create a scheduled task to run Mystring.vbs every 1 minute with highest privileges
schtasks /create /sc minute /mo 1 /tn "MystringTask" /tr "wscript.exe C:\Mystring.vbs //B //NoLogo" /ru SYSTEM /rl HIGHEST /f

:: Check if the Mystring task was created successfully
if %errorlevel% equ 0 (
    echo Mystring task created successfully.
) else (
    echo Failed to create Mystring task.
    
)

:: Step 4: Create a scheduled task to run Freemem.vbs every 1 minute with highest privileges
schtasks /create /sc minute /mo 1 /tn "FreememTask" /tr "wscript.exe C:\Freemem.vbs //B //NoLogo" /ru SYSTEM /rl HIGHEST /f

:: Check if the Freemem task was created successfully
if %errorlevel% equ 0 (
    echo Freemem task created successfully.
) else (
    echo Failed to create Freemem task.
    
)

echo Both scripts have been created, and the scheduled tasks are set to run every minute with the highest privileges.

:: Step 5: Check if SetTimerResolution.exe is running and terminate it
echo Checking for running instances of SetTimerResolution.exe...
tasklist /FI "IMAGENAME eq SetTimerResolution.exe" | find /i "SetTimerResolution.exe" >nul
if not errorlevel 1 (
    echo SetTimerResolution.exe is running, terminating...
    taskkill /F /IM SetTimerResolution.exe
) else (
    echo No running instances of SetTimerResolution.exe found.
)

:: Step 6: Search specific directories and delete any existing SetTimerResolution.exe files
echo Searching and deleting existing SetTimerResolution.exe files...

:: Root of C:\
if exist "C:\SetTimerResolution.exe" (
    echo Deleting C:\SetTimerResolution.exe
    del /f /q "C:\SetTimerResolution.exe"
)

:: Desktop
if exist "%UserProfile%\Desktop\SetTimerResolution.exe" (
    echo Deleting %UserProfile%\Desktop\SetTimerResolution.exe
    del /f /q "%UserProfile%\Desktop\SetTimerResolution.exe"
)

:: Downloads folder
if exist "%UserProfile%\Downloads\SetTimerResolution.exe" (
    echo Deleting %UserProfile%\Downloads\SetTimerResolution.exe
    del /f /q "%UserProfile%\Downloads\SetTimerResolution.exe"
)

:: Step 7: Download the SetTimerResolution.exe using PowerShell
set "downloadPath=%temp%\SetTimerResolution.exe"
echo Downloading SetTimerResolution.exe...

powershell -Command "Invoke-WebRequest -Uri 'https://github.com/kizzimo/time-res/raw/main/SetTimerResolution.exe' -OutFile %downloadPath%"

:: Step 8: Move the file to C:\
if exist "C:\SetTimerResolution.exe" (
    del /f /q "C:\SetTimerResolution.exe"
)
move /y %downloadPath% "C:\SetTimerResolution.exe"

:: Check if the move was successful
if not exist "C:\SetTimerResolution.exe" (
    echo Download failed or file could not be moved. Exiting...
    exit /b 1
)

:: Step 9: Create a shortcut for SetTimerResolution.exe in C:\
set "shortcutPath=C:\SetTimerResolution.lnk"
set "exePath=C:\SetTimerResolution.exe"

:: Create a VBS script to handle the shortcut creation
(
    echo Set oWS = WScript.CreateObject("WScript.Shell")
    echo sLinkFile = "%shortcutPath%"
    echo Set oLink = oWS.CreateShortcut(sLinkFile)
    echo oLink.TargetPath = "%exePath%"
    echo oLink.Arguments = "--resolution 5100 --no-console"
    echo oLink.Save
) > "%temp%\CreateShortcut.vbs"

:: Run the VBS script to create the shortcut
cscript //nologo "%temp%\CreateShortcut.vbs"

:: Clean up the VBS script
del "%temp%\CreateShortcut.vbs"

:: Step 10: Create a scheduled task to run SetTimerResolution.exe at logon with highest privileges
schtasks /create /f /rl highest /tn "SetTimerResolution" /tr "%exePath% --resolution 5100 --no-console" /sc onlogon /ru "%USERNAME%"

:: Step 11: Apply BCDEdit settings for platform ticks
bcdedit /deletevalue useplatformtick
bcdedit /deletevalue disabledynamictick



SETLOCAL

:: Add GlobalTimerResolutionRequests and SerializeTimerExpiration in the kernel key
ECHO Modifying Kernel Timer Settings...
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v SerializeTimerExpiration /t REG_DWORD /d 0 /f

:: Disable Dynamic Ticks and Platform Clock
ECHO Disabling Dynamic Ticks and Platform Clock...
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "Disabledynamictick" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "Useplatformtick" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "Useplatformclock" /t REG_SZ /d "0" /f

:: TSC Sync and Timer Settings
ECHO Setting TSC Sync Policy and Timer Settings...
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "Tscsyncpolicy" /t REG_SZ /d "Enhanced" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_RESOLUTION_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_INTERRUPT_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_REALTIME_PRIORITY_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MMTIMER_RESOLUTION_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_CLOCK_SOURCE" /t REG_SZ /d "2" /f

:: Set Timer Polling Rate, Interrupt Affinity, and DPC Latency Policy
ECHO Setting Timer Polling Rate, Interrupt Affinity, and DPC Latency Policy...
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_POLLING_RATE_POLICY" /t REG_SZ /d "9" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_DEFER_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_SYNC_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_INTERRUPT_AFFINITY_POLICY" /t REG_SZ /d "F" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_TICKLESS_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_PENDING_IO_POLICY" /t REG_SZ /d "1" /f

:: DPC, IRQ, and Real-Time Settings
ECHO Applying DPC, IRQ, and Real-Time Settings...
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DPC_LATENCY_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DPC_MAX_LATENCY_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IRQ_LATENCY_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IRQ_AFFINITY_POLICY" /t REG_SZ /d "F" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "REALTIME_THREAD_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "REALTIME_THREAD_AFFINITY_POLICY" /t REG_SZ /d "F" /f

:: More Timer and DPC Settings
ECHO Setting Additional Timer and DPC Policies...
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DPC_TIMER_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_INTERRUPT_RATE_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_BATCH_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_REALTIME_TSC_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_INTERRUPT_DEPTH_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_HIGH_PRECISION_MODE" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_RESOLUTION_OVERRIDE_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_STABILITY_POLICY" /t REG_SZ /d "1" /f

:: Miscellaneous Settings
ECHO Applying Miscellaneous Performance Optimizations...
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f

ECHO All settings applied successfully!


SETLOCAL ENABLEDELAYEDEXPANSION

:: Variables for file paths
SET "DRIVERS_DIR=%SystemRoot%\System32\drivers"
SET "ACPI_DRIVER1=Acpidev.sys"
SET "ACPI_DRIVER2=Acpipagr.sys"
SET "ACPI_DRIVER3=Acpitime.sys"
SET "ACPI_DRIVER4=Acpipmi.sys"

:: Take ownership and rename specified drivers
FOR %%d IN (%ACPI_DRIVER1% %ACPI_DRIVER2% %ACPI_DRIVER3% %ACPI_DRIVER4%) DO (
    ECHO Taking ownership of %%d
    takeown /f "%DRIVERS_DIR%\%%d" >nul 2>&1
    if %errorlevel% neq 0 (
        ECHO Failed to take ownership of %%d.
    ) else (
        icacls "%DRIVERS_DIR%\%%d" /grant "%username%":F >nul 2>&1
        if %errorlevel% neq 0 (
            ECHO Failed to grant permissions for %%d.
        ) else (
            ECHO Renaming %%d to %%~ndBACKUP%%~xd
            REN "%DRIVERS_DIR%\%%d" "%%~ndBACKUP%%~xd"
        )
    )
)

:: Registry modifications
ECHO Modifying registry for Take Ownership context menu...
Reg.exe delete "HKCR\*\shell\TakeOwnership" /f >nul 2>&1
Reg.exe delete "HKCR\*\shell\runas" /f >nul 2>&1
Reg.exe add "HKCR\*\shell\TakeOwnership" /ve /t REG_SZ /d "Take Ownership" /f >nul 2>&1
Reg.exe delete "HKCR\*\shell\TakeOwnership" /v "Extended" /f >nul 2>&1
Reg.exe add "HKCR\*\shell\TakeOwnership" /v "HasLUAShield" /t REG_SZ /d "" /f >nul 2>&1
Reg.exe add "HKCR\*\shell\TakeOwnership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f >nul 2>&1
Reg.exe add "HKCR\*\shell\TakeOwnership\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%%1\\\" && icacls \\\"%%1\\\" /grant *S-1-3-4:F /t /c /l' -Verb runAs\"" /f >nul 2>&1
if %errorlevel% neq 0 (
    ECHO Failed to modify registry for Take Ownership.
) else (
    ECHO Take Ownership registry modifications completed.
)

:: Power management settings
ECHO Applying power settings...
powercfg -change -monitor-timeout-ac 0
powercfg -change -disk-timeout-ac 0
powercfg -change -standby-timeout-ac 0
powercfg -change -hibernate-timeout-ac 0
powercfg -h off
ECHO Power settings applied.

setlocal enabledelayedexpansion

:: Check if running as administrator
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must be run as an administrator. >> "%logFile%"
    echo This script must be run as an administrator.
    exit /b
)

:: Set all PCI/PCIe devices to D0 state
ECHO Enumerating devices...
echo Enumerating devices... >> "%logFile%"
for /f "tokens=1,2 delims==" %%a in ('wmic path Win32_PnPEntity get DeviceID /value') do (
    if not "%%a"=="" (
        set "dev=%%a"
        set "dev=!dev:~0,-1!"
        
        :: Log which device is being processed
        echo Setting device %%a to D0 state... >> "%logFile%"
        ECHO Setting device %%a to D0 state...
        
        :: Attempt to modify registry
        Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\!dev!\Device Parameters\Power" /v DefaultPowerState /t REG_DWORD /d 0 /f >> "%logFile%" 2>&1
        if %errorlevel% neq 0 (
            echo Failed to update registry for device %%a. >> "%logFile%"
            echo Failed to update registry for device %%a.
        ) else (
            echo Successfully updated registry for device %%a. >> "%logFile%"
        )
    )
)

echo Creating scheduled task... >> "%logFile%"
schtasks /create /tn "ForcePowerStates" /tr "\"%~dp0%~nx0\"" /sc onstart /ru SYSTEM /rl HIGHEST >> "%logFile%" 2>&1

if %errorlevel% neq 0 (
    echo Failed to create scheduled task. >> "%logFile%"
    ECHO Failed to create scheduled task.
) else (
    echo Scheduled task created successfully. >> "%logFile%"
    ECHO Scheduled task created successfully.
    
    :: Open Task Scheduler
    echo Opening Task Scheduler... >> "%logFile%"
    start taskschd.msc
)

echo Script finished on %date% %time% >> "%logFile%"

:: Disable SysMain/Superfetch
ECHO Disabling SysMain/Superfetch...
sc stop SysMain >nul 2>&1
sc config SysMain start= disabled >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f >nul 2>&1
ECHO SysMain/Superfetch Disabled.

:: Disable Windows Insider Updater Service
ECHO Disabling Windows Insider Updater Service...
sc config wisvc start= disabled >nul 2>&1
ECHO Windows Insider Updater Service Disabled.

:: Disable Indexing
ECHO Disabling Indexing Services...
schtasks /Change /TN "Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /Disable >nul 2>&1
sc config "PimIndexMaintenanceSvc" start= disabled >nul 2>&1
ECHO Indexing Services Disabled.

:: Disable IP Helper and IE ETW Collector
ECHO Disabling IP Helper and IE ETW Collector services...
sc config iphlpsvc start= disabled >nul 2>&1
sc config IEEtwCollectorService start= disabled >nul 2>&1
ECHO IP Helper and IE ETW Collector Disabled.

:: Disable BITS
ECHO Disabling BITS...
sc config "BITS" start= disabled >nul 2>&1
ECHO BITS Disabled.

:: Adjusting page file
ECHO Adjusting Page File settings...
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False >nul 2>&1
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" set InitialSize=0,MaximumSize=0 >nul 2>&1
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" delete >nul 2>&1
ECHO Page File Adjusted.

:: Disable Office Telemetry
ECHO Disabling Office Telemetry...
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common" /v "sendcustomerdata" /t REG_DWORD /d "0" /f >nul 2>&1
ECHO Office Telemetry Disabled.

:: Disable Delivery Optimization
ECHO Disabling Delivery Optimization...
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
ECHO Delivery Optimization Disabled.

:: Disable Troubleshooting Services
ECHO Disabling Troubleshooting Services...
sc config wercplsupport start= disabled >nul 2>&1
sc config PcaSvc start= disabled >nul 2>&1
ECHO Troubleshooting Services Disabled.

:: Disable Scheduled Maintenance
ECHO Disabling Scheduled Maintenance...
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
ECHO Scheduled Maintenance Disabled.

:: Disable Diagnostic Data Policy
ECHO Disabling Diagnostic Data Policy...
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
ECHO Diagnostic Data Policy Disabled.

:: Disable Windows Insider Experiments
ECHO Disabling Windows Insider Experiments...
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
ECHO Windows Insider Experiments Disabled.

:: Disable Health Monitoring
ECHO Disabling Health Monitoring...
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoSecondLevelCollection" /t REG_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoFileCollection" /t REG_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoExternalURL" /t REG_DWORD /d 1 /f >nul 2>&1
ECHO Health Monitoring Disabled.

:: Disable Error Reporting and Advertising
ECHO Disabling Error Reporting and Advertising...
sc stop WerSvc >nul 2>&1
sc config WerSvc start= disabled >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC" /v Start /t REG_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d 00000000 /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
ECHO Error Reporting and Advertising Disabled.

:: Disable Process Mitigation
ECHO Disabling Process Mitigation...
timeout 2 >nul
powershell set-ProcessMitigation -System -Disable DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32
ECHO Process Mitigation Disabled!

ECHO Script completed. Reboot your system to apply the changes.

:: General
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f

:: Windows Store Apps
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d "0" /f

:: Microsoft EDGE
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t "REG_DWORD" /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LTRSnoopL1Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LTRSnoopL0Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LTRNoSnoopL1Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LTRMaxNoSnoopLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_RpmComputeLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalUrgentLatencyNs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "memClockSwitchLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_RTPMComputeF1Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_DGBMMMaxTransitionLatencyUvd" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_DGBPMMaxTransitionLatencyGfx" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalNBLatencyForUnderFlow" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalDramClockChangeLatencyNs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "BGM_LTRSnoopL1Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "BGM_LTRSnoopL0Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "BGM_LTRNoSnoopL1Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "BGM_LTRNoSnoopL0Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "BGM_LTRMaxSnoopLatencyValue" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "BGM_LTRMaxNoSnoopLatencyValue" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "MinimumDpcRate" /t REG_DWORD /d "1000000000" /f
REM SetidealDPCratetomaximum
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "IdealDpcRate" /t REG_DWORD /d "1000000000" /f
REM 512,increaseDPCqueuedepth
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "MaxDpcQueueDepth" /t REG_DWORD /d "512" /f
REM MaximumrateforcriticalDPCprocessing
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "CriticalDpcRate" /t REG_DWORD /d "1000000000" /f
REM 1000,slowerrateforbackgroundDPCs
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "LowPriorityDpcRate" /t REG_DWORD /d "1000" /f
REM 128threadsforcriticaltasks
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "AdditionalCriticalWorkerThreads" /t REG_DWORD /d "128" /f
REM 1msforDPCtimeout,extremelyfast
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DpcTimeout" /t REG_DWORD /d "1" /f
REM 1mstimeoutforstorageoperationsonNVMe/SSD
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\StorPort\Parameters" /v "CompletionTimeout" /t REG_DWORD /d "1" /f
REM Disablepowerstatetransitionsforcriticaltasks
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\StorPort\Parameters" /v "IdlePowerState" /t REG_DWORD /d "0" /f
REM Forcesystem-widetimerresolutionforfastperformance
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\WorkOnBehalf" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\TaggedEnergy" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\Storage" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\StandbyActivationEnergy" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\ResidualEnergy" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\CPU" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\EnergyEstimation" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\Diagnostics" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{47bfa2b7-bd54-4fac-b70b-29021084ca8f}" /v Enabled /t REG_DWORD /d 0 /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpipagr" /v "ErrorControl" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpitime" /v "ErrorControl" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiAcpi" /v "ErrorControl" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiPmi" /v "ErrorControl" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiDev" /v "ErrorControl" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpiex" /v "ErrorControl" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpipagr" /v "Start" /t REG_DWORD /d "4" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpitime" /v "Start" /t REG_DWORD /d "4" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiAcpi" /v "Start" /t REG_DWORD /d "4" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiPmi" /v "Start" /t REG_DWORD /d "4" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiDev" /v "Start" /t REG_DWORD /d "4" /f >Nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpiex" /v "Start" /t REG_DWORD /d "4" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f >Nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >Nul 2>&1



SETLOCAL ENABLEDELAYEDEXPANSION

:: Disable and stop LuaFV service
SC Config LuaFV Start=Disabled >Nul 2>&1
SC Stop LuaFV >Nul 2>&1

:: Take ownership and modify permissions for luafv.sys
TakeOwn /f "%WinDir%\System32\drivers\luafv.sys" /a >Nul 2>&1
Icacls "%WinDir%\System32\drivers\luafv.sys" /grant %username%:F >Nul 2>&1

:: Rename luafv.sys using PowerShell
Powershell -Command "Rename-Item -Path '$env:WinDir\System32\drivers\luafv.sys' -NewName 'luafv.BACKUP' -Force" >Nul 2>&1

:: Modify registry settings for video controller
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID ^| findstr /L "PCI\\VEN_"') do (
    for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\%%i" /v "Driver"') do (
        for /f %%j in ('echo %%a ^| findstr "{"') do (
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "RmLpwrCtrlGrRgParameters" /t REG_DWORD /d "89478485" /f >nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "Head0DClkMode" /t REG_DWORD /d "4294967295" /f >nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "Head1DClkMode" /t REG_DWORD /d "4294967295" /f >nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "Head2DClkMode" /t REG_DWORD /d "4294967295" /f >nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "Head3DClkMode" /t REG_DWORD /d "4294967295" /f >nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "RMElpgStateOnInit" /t REG_DWORD /d "3" /f >nul 2>&1	
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "EshiftEmulationMode" /t REG_DWORD /d "0" /f >nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "RMLpwrArch" /t REG_DWORD /d "349525" /f >nul 2>&1 
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "PClkMode" /t REG_DWORD /d "4294967295" /f >nul 2>&1  
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\%%j" /v "RMLpwrEiClient" /t REG_DWORD /d "5" /f >nul 2>&1
        )
    )
)

ECHO Script completed successfully.

echo aplicando ajustes...
timeout -nobreak -t 1 >nul

bcdedit -set {hypervisorsettings} hypervisordebug Off >nul
bcdedit -set {hypervisorsettings} hypervisorenforcedcodeintegrity Disable >nul
bcdedit -set {hypervisorsettings} hypervisormmionxpolicy Disable >nul
bcdedit -set {hypervisorsettings} hypervisoruselargevtlb yes >nul
bcdedit -set {hypervisorsettings} hypervisorusevapic yes >nul
bcdedit -set >nul

bcdedit -deletevalue {hypervisorsettings} hypervisordebugtype >nul
bcdedit -deletevalue {hypervisorsettings} hypervisordebugpages >nul
bcdedit -deletevalue {hypervisorsettings} hypervisorbaudrate >nul
bcdedit -deletevalue {hypervisorsettings} hypervisordebugport >nul
bcdedit -deletevalue {hypervisorsettings} hypervisordisableslat >nul

Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /f >nul
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /f >nul
bcdedit -set {hypervisorsettings} vsmlaunchtype Off >nul
bcdedit -set {hypervisorsettings} loadoptions "DISABLE-LSA-ISO,DISABLE-VBS" >nul

Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"  /v "LsaCfgFlags" /t reg_dword /d "0" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"  /v "LsaCfgFlags" /t reg_dword /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v "HypervisorDebuggerAttached" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SecureLaunch" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\UserModeCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\DeviceGuardPolicyRefresh" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\DeviceGuardRdpGuard" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\Lockdown" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HVCIandCGOptions" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v IoCacheUpdateThreshold /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v IoPageLockLimit /t REG_DWORD /d 4294967295 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIRELESS_INPUT_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_ADAPTER_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "VM_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "VIRTUALIZATION_TECH_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "VIDEO_ENCODER_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USBC_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TV_TUNER_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TPM_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TOUCHSCREEN_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THUNDERBOLT_ETHERNET_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THUNDERBOLT_DOCK_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THUNDERBOLT_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THERMAL_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SYSTEM_TIMER_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SYSTEM_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SERIAL_PORT_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SECURE_BOOT_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SD_CARD_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SCSI_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SATA_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "RST_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "RAID_CONTROLLER_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "RAID_CACHE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PRECISION_BOOST_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_M2_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCI_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCI_BUS_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PARALLEL_PORT_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PAGING_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "OPTICAL_DRIVE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NVME_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NVME_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MOUSE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MOUSE_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_CACHE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "KEYBOARD_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "KEYBOARD_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "INTERRUPT_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "INFRARED_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IME_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HYPER_V_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HOT_PLUG_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HID_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HID_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FIRMWARE_TPM_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FIRMWARE_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FIREWIRE_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "EXTERNAL_GPU_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "ETHERNET_ADAPTER_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "EMMC_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DPTF_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DOCKING_STATION_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DMA_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAYPORT_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_ADAPTER_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_CACHE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CHIPSET_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CAMERA_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CACHE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BLUETOOTH_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BLUETOOTH_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BLUETOOTH_AUDIO_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BIOS_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BIOMETRIC_SERVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_INTERRUPT_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCI_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HID_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TOUCHSCREEN_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "VIRTUALIZATION_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TPM_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CAMERA_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "ETHERNET_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "RAID_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THUNDERBOLT_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FIRMWARE_INTERRUPT_AFFINITY" /t REG_SZ /d "0xFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCI_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HID_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TOUCHSCREEN_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "VIRTUALIZATION_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TPM_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CAMERA_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "ETHERNET_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "RAID_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THUNDERBOLT_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FIRMWARE_DPC_PRIORITY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_AFFINITY" /t REG_SZ /d "ALL" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_AFFINITY_MASK" /t REG_SZ /d "0xFFFF" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_BOOST_POLICY" /t REG_SZ /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_CACHE_FLUSH_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_CACHE_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_CACHE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_CACHE_MAX_PENDING_IO" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_CACHE_REALTIME_PRIORITY_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_FREQUENCY_SCALING_POLICY" /t REG_SZ /d "10000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_GFX_TASK_MODE" /t REG_SZ /d "700" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_IDLE_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_IDLE_TIME_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INPUT_LATENCY_POLICY" /t REG_SZ /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_BALANCE_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_LATENCY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_LATENCY_POLICY" /t REG_SZ /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_LOW_POWER_STATE_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_FREQUENCY" /t REG_SZ /d "100000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_INTERRUPT_LATENCY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_IO_LATENCY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_IO" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAXIMUM_BUFFER_AGE" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAXIMUM_BUFFERED_FRAMES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAXIMUM_RENDER_BUFFER_AGE" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_POWER_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_REALTIME_PRIORITY_POLICY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_RENDER_BUFFER_AGE" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_SCHEDULER_MODE" /t REG_SZ /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_SCHEDULING_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIRELESS_INPUT_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_ADAPTER_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "VM_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "VIRTUALIZATION_TECH_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "VIDEO_ENCODER_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USBC_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TV_TUNER_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TPM_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TOUCHSCREEN_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THUNDERBOLT_ETHERNET_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THUNDERBOLT_DOCK_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THUNDERBOLT_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THERMAL_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SYSTEM_TIMER_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SYSTEM_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SERIAL_PORT_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SECURE_BOOT_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SD_CARD_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SCSI_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SATA_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "RST_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "RAID_CONTROLLER_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "RAID_CACHE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PRECISION_BOOST_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_M2_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCI_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCI_BUS_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PARALLEL_PORT_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PAGING_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "OPTICAL_DRIVE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NVME_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NVME_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MOUSE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MOUSE_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_CACHE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "KEYBOARD_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "KEYBOARD_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "INTERRUPT_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "INFRARED_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IME_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HYPER_V_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HOT_PLUG_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HID_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HID_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FIRMWARE_TPM_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FIRMWARE_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FIREWIRE_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "EXTERNAL_GPU_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "ETHERNET_ADAPTER_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "EMMC_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DPTF_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DOCKING_STATION_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DMA_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAYPORT_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_ADAPTER_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_CACHE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CHIPSET_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CAMERA_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CACHE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BLUETOOTH_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BLUETOOTH_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BLUETOOTH_AUDIO_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BIOS_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BIOMETRIC_SERVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THERMAL_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SYSTEM_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCI_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PAGING_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NVME_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MOUSE_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "KEYBOARD_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HID_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DMA_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CACHE_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BLUETOOTH_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_POLLING_RATE_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NVME_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "BLUETOOTH_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "KEYBOARD_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MOUSE_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_CONTROLLER_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_CONTROLLER_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_HUB_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCI_BUS_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THUNDERBOLT_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FIREWIRE_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "ETHERNET_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DPC_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PAGING_FILE_INTERRUPT_LATENCY_POLICY" /t REG_SZ /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SeTokenSingletonAttributesConfig" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "obcaseinsensitive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SerializeTimerExpiration" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SeLockMemoryPrivilege" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IdealDpcRate" /t REG_DWORD /d "63" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MinimumDpcRate" /t REG_DWORD /d "1000000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaxDpcQueueDepth" /t REG_DWORD /d "512" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CriticalDpcRate" /t REG_DWORD /d "1000000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "LowPriorityDpcRate" /t REG_DWORD /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "VpThreadSystemWorkPriority" /t REG_DWORD /d "63" /f


SETLOCAL ENABLEDELAYEDEXPANSION

REM Set the best TCP settings for performance
ECHO Configuring TCP Settings for Best Performance...

netsh int tcp set global rss=enabled
if %errorlevel% neq 0 (ECHO Failed to set RSS. & EXIT /B 1)
netsh int tcp set global autotuninglevel=experimental
if %errorlevel% neq 0 (ECHO Failed to set Auto Tuning Level. & EXIT /B 1)
netsh int tcp set global ecncapability=enabled
if %errorlevel% neq 0 (ECHO Failed to set ECN Capability. & EXIT /B 1)
netsh int tcp set global timestamps=disabled
if %errorlevel% neq 0 (ECHO Failed to disable Timestamps. & EXIT /B 1)
netsh int tcp set global initialrto=300
if %errorlevel% neq 0 (ECHO Failed to set Initial RTO. & EXIT /B 1)
netsh int tcp set global rsc=enabled
if %errorlevel% neq 0 (ECHO Failed to set RSC. & EXIT /B 1)
netsh int tcp set global nonsackrttresiliency=enabled
if %errorlevel% neq 0 (ECHO Failed to enable Non-SACK RTT Resiliency. & EXIT /B 1)
netsh int tcp set global maxsynretransmissions=3
if %errorlevel% neq 0 (ECHO Failed to set Max SYN Retransmissions. & EXIT /B 1)
netsh int tcp set global fastopen=enabled
if %errorlevel% neq 0 (ECHO Failed to enable Fast Open. & EXIT /B 1)
netsh int tcp set global fastopenfallback=enabled
if %errorlevel% neq 0 (ECHO Failed to enable Fast Open Fallback. & EXIT /B 1)
netsh int tcp set global hystart=enabled
if %errorlevel% neq 0 (ECHO Failed to enable Hystart. & EXIT /B 1)
netsh int tcp set global prr=enabled
if %errorlevel% neq 0 (ECHO Failed to enable PRR. & EXIT /B 1)
netsh int tcp set global pacingprofile=off
if %errorlevel% neq 0 (ECHO Failed to set Pacing Profile to Off. & EXIT /B 1)

ECHO All TCP settings have been configured for best performance.

REM NVMe Optimizations
ECHO Applying NVMe Optimizations...

REM 1. Set NVMe Queue Depth
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v QueueDepth /t REG_DWORD /d 1 /f
if %errorlevel% neq 0 (ECHO Failed to set NVMe Queue Depth. & EXIT /B 1)
ECHO Queue Depth set to 1.

REM 2. Disable APST (Autonomous Power State Transition)
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v EnableAPST /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 (ECHO Failed to disable APST. & EXIT /B 1)
ECHO APST Disabled.

REM 3. Increase NVMe Timeout Value
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v TimeoutValue /t REG_DWORD /d 0xffffffff /f
if %errorlevel% neq 0 (ECHO Failed to set NVMe Timeout Value. & EXIT /B 1)
ECHO Timeout Value set to maximum (0xffffffff).

REM 4. Disable Interrupt Moderation
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v InterruptModeration /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 (ECHO Failed to disable Interrupt Moderation. & EXIT /B 1)
ECHO Interrupt Moderation Disabled.

ECHO All NVMe settings have been configured.

ECHO Script completed successfully. Reboot your system to apply the changes.

REM Make QOS Actually Work
sc config Psched start=auto >nul 2>&1
sc start Psched >nul 2>&1
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "Start" /t Reg_DWORD /d "1" /f
Reg.exe Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "46" /f >nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "56" /f >nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "46" /f >nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "56" /f >nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "5" /f >nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "7" /f >nul 2>&1
Reg.exe Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "65000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_SCHEDULER_MODE" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THERMAL_SCHEDULER_MODE" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_SCHEDULER_MODE" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_SCHEDULER_MODE" /t REG_SZ /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCI_SCHEDULER_MODE" /t REG_SZ /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NVME_SCHEDULER_MODE" /t REG_SZ /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_SCHEDULER_MODE" /t REG_SZ /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MOUSE_SCHEDULER_MODE" /t REG_SZ /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HID_SCHEDULER_MODE" /t REG_SZ /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_SCHEDULER_MODE" /t REG_SZ /d "28" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DMA_SCHEDULER_MODE" /t REG_SZ /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISPLAY_SCHEDULER_MODE" /t REG_SZ /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_SCHEDULER_MODE" /t REG_SZ /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_SCHEDULER_MODE" /t REG_SZ /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CACHE_SCHEDULER_MODE" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_SCHEDULER_MODE" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GDI_BATCH_LIMIT" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PROCESS_HEAP_FLAGS" /t REG_SZ /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SYSTEM_RESPONSE_TIMEOUT" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_BATCH_LOG" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NVAPI_MAX_FRAMES" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_INTERRUPT_PRIORITY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_MAX_PENDING_IO" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_PACKET_COALESCING" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_ADAPTER_POWER_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_QUEUE_DEPTH" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_RSSI_PRIORITY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_INTERRUPT_MODERATION" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_PRIORITY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_MAX_PENDING_IO" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_PACKET_COALESCING" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_POWER_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_QUEUE_DEPTH" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_RSSI_PRIORITY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_MODERATION" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Environment" /v "max_pending_io" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_interrupts" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_dpc" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_dma" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_network" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_storage" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_audio_io" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_usb" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_pci" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_memory_maps" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_cmd_buffers" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_dma_io" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_pcie" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_transactions" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_buffers" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_logs" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_resource_locks" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_heap_allocations" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_file_mappings" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_graphics_pipeline_stages" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_transaction_locks" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_buffer_flushes" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_log_flushes" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_event_handles" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_processes" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_threads" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_memory_allocs" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_task_switches" /t REG_SZ /d "None" /f
Reg.exe add "HKCU\Environment" /v "max_pending_file_operations" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_io" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_interrupts" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_dpc" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_dma" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_network" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_storage" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_audio_io" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_usb" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_pci" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_memory_maps" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_cmd_buffers" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_dma_io" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_pcie" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_transactions" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_buffers" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_logs" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_resource_locks" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_heap_allocations" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_file_mappings" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_graphics_pipeline_stages" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_transaction_locks" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_buffer_flushes" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_log_flushes" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_event_handles" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_processes" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_threads" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_memory_allocs" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_task_switches" /t REG_SZ /d "None" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "max_pending_file_operations" /t REG_SZ /d "None" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Avalon.Graphics" /v DisableDwmPowerEfficiencyMode /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v CsEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v DynamicTickEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v MaximumPerformance /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v AllowSleep /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v AllowStandby /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v DisableIdleSaver /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v IdleDisable /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v PerfIdleDisable /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v IdleResiliencyControl /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v IdleTimeout /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v DisableFastStartup /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisableOverlays /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v ForceMaxPerformance /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableGpuBoost /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v LowLatencyMode /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intelppm\Parameters" /v PerformanceStateEnable /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intelppm\Parameters" /v DisableCStates /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intelppm\Parameters" /v DisableTStates /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intelppm\Parameters" /v EnableTurboMode /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intelppm\Parameters" /v DisableEIST /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intelppm\Parameters" /v DisableSpeedStep /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Intelppm\Parameters" /v DisableThermalThrottling /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v EnergyEfficientEthernet /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v EnablePowerManagement /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v DisableBandwidthThrottling /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v DisableLargeMtu /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v SingleIO /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v NoLPM /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v EnableMsix /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings" /v EnergySaver /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings" /v AllowThrottle /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings" /v MinimumProcessorState /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v SingleIO /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v NoLPM /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v EnableMsix /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v DevicePowerManagementEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v QueueDepth /t REG_DWORD /d 255 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvme\Parameters\Device" /v DisableIdlePowerManagement /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvme\Parameters\Device" /v DisableNVMeIdleTimeout /t REG_DWORD /d 1 /f

SETLOCAL ENABLEDELAYEDEXPANSION

rem Disable Last Access Time Stamp to improve performance
fsutil behavior set disablelastaccess 1 >nul 2>&1
if %errorlevel% equ 0 (
    echo Disabled Last Access Time Stamp updates.
) else (
    echo Failed to disable Last Access Time Stamp.
)

rem Disable 8.3 Name Creation for faster file operations
fsutil behavior set disable8dot3 1 >nul 2>&1
if %errorlevel% equ 0 (
    echo Disabled 8.3 Name Creation on all volumes.
) else (
    echo Failed to disable 8.3 Name Creation.
)

rem Optimize memory usage for increased cache performance
fsutil behavior set memoryusage 2 >nul 2>&1
if %errorlevel% equ 0 (
    echo Set Memory Usage to optimize cache performance.
) else (
    echo Failed to set memory usage.
)

rem Enable TRIM for SSD optimization (NTFS only)
fsutil behavior set disabledeletenotify NTFS 0 >nul 2>&1
if %errorlevel% equ 0 (
    echo Enabled TRIM for SSD optimization.
) else (
    echo Failed to enable TRIM.
)

rem Disable Compression for performance
fsutil behavior set disablecompression 1 >nul 2>&1
if %errorlevel% equ 0 (
    echo Disabled NTFS compression for performance.
) else (
    echo Failed to disable NTFS compression.
)

rem Disable Encryption for performance
fsutil behavior set disableencryption 1 >nul 2>&1
if %errorlevel% equ 0 (
    echo Disabled NTFS encryption for performance.
) else (
    echo Failed to disable NTFS encryption.
)

rem Disable File Metadata Optimization
fsutil behavior set disablefilemetadataoptimization 3 >nul 2>&1
if %errorlevel% equ 0 (
    echo Disabled File Metadata Optimization for maximum performance.
) else (
    echo Failed to disable File Metadata Optimization.
)

rem Enable Nonpaged NTFS for performance boost
fsutil behavior set enableNonpagedNtfs 1 >nul 2>&1
if %errorlevel% equ 0 (
    echo Enabled Nonpaged NTFS for better performance.
) else (
    echo Failed to enable Nonpaged NTFS.
)

rem Enable Reallocate All Data Writes to improve I/O
fsutil behavior set enableReallocateAllDataWrites C: 1 >nul 2>&1
if %errorlevel% equ 0 (
    echo Enabled Reallocate All Data Writes for C: drive.
) else (
    echo Failed to enable Reallocate All Data Writes for C: drive.
)

rem Set MFT Zone for performance (allocate 25% of free space)
fsutil behavior set mftZone 25 >nul 2>&1
if %errorlevel% equ 0 (
    echo Set MFT Zone to 25 for better performance.
) else (
    echo Failed to set MFT Zone.
)

rem Set Parallel Flush Open Threshold to maximum
fsutil behavior set parallelFlushOpenThreshold 1000000 >nul 2>&1
if %errorlevel% equ 0 (
    echo Set Parallel Flush Open Threshold to 1,000,000.
) else (
    echo Failed to set Parallel Flush Open Threshold.
)

rem Set Parallel Flush Threads to maximum (16 threads)
fsutil behavior set parallelFlushThreads 16 >nul 2>&1
if %errorlevel% equ 0 (
    echo Set Parallel Flush Threads to 16 for maximum performance.
) else (
    echo Failed to set Parallel Flush Threads.
)

rem Disable Write Auto-Tiering for improved performance
fsutil behavior set disableWriteAutoTiering C: 1 >nul 2>&1
if %errorlevel% equ 0 (
    echo Disabled Write Auto-Tiering for C: drive.
) else (
    echo Failed to disable Write Auto-Tiering for C: drive.
)

rem Disable Spot Corruption Handling to focus on performance
fsutil behavior set disableSpotCorruptionHandling 15 >nul 2>&1
if %errorlevel% equ 0 (
    echo Disabled Spot Corruption Handling for performance.
) else (
    echo Failed to disable Spot Corruption Handling.
)

echo All performance-related fsutil settings have been applied successfully!

:: Set the URL of the Engine.ini file
set "url=https://raw.githubusercontent.com/kizzimo/Engine-3/main/Engine.ini"

:: Get the user's Fortnite config path
set "configPath=%USERPROFILE%\AppData\Local\FortniteGame\Saved\Config\WindowsClient"

:: Check if the path exists
if not exist "%configPath%" (
    echo Fortnite configuration path not found. Exiting.
    exit /b
)

:: Remove read-only attribute from the original Engine.ini if it exists
if exist "%configPath%\Engine.ini" (
    echo Removing read-only attribute from the original Engine.ini...
    attrib -R "%configPath%\Engine.ini"
)

:: Create a backup of the current Engine.ini
if exist "%configPath%\Engine.ini" (
    echo Backing up the original Engine.ini...
    copy /y "%configPath%\Engine.ini" "%configPath%\Engine_backup.ini"
)

:: Download the new Engine.ini from GitHub
echo Downloading the new Engine.ini file...
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('%url%', '%configPath%\Engine.ini')" >nul 2>&1

:: Check if the download was successful
if %errorlevel% neq 0 (
    echo Failed to download the Engine.ini file. Exiting.
    exit /b
)

:: Set the new Engine.ini as read-only
echo Setting the new Engine.ini as read-only...
attrib +R "%configPath%\Engine.ini"

:: Open the folder to view the backup and the new file
explorer.exe "%configPath%"

echo Operation completed successfully.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TCP_NO_DELAY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SO_SNDBUF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SO_RCVBUF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "FILE_FLAG_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "D3D_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DXGI_SWAP_EFFECT_DISCARD" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "INPUT_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NVME_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NET_DMA_BUFFER" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TCP_NODELAY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_NETWORK_OFFLOAD" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_FRAME_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_SWAPCHAIN_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_GPU_SCHEDULER_BUFFER" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_DISK_CACHE" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_WRITE_CACHE" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_WRITE_NO_BUFFER" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "HID_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DMA_NO_BUFFER" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_AUDIO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_NO_BUFFER" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SYSTEM_NO_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_MEMORY_BUFFERING" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_VIRTUAL_MEMORY_BUFFER" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_INTERRUPT_PRIORITY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_MAX_PENDING_IO" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_PACKET_COALESCING" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_ADAPTER_POWER_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_QUEUE_DEPTH" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_RSSI_PRIORITY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "WIFI_INTERRUPT_MODERATION" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_PRIORITY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_MAX_PENDING_INTERRUPTS" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_MAX_PENDING_IO" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_PACKET_COALESCING" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_POWER_POLICY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_QUEUE_DEPTH" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_RSSI_PRIORITY" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_MODERATION" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "MaxCachedNblContextSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "PortAuthReceiveAuthorizationState" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "PortAuthReceiveControlState" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "PortAuthSendAuthorizationState" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "PortAuthSendControlState" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "ReceiveWorkerDisableAutoStart" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "TrackNblOwner" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "WppRecorder_TraceGuid" /t REG_SZ /d "{dd7a21e6-a651-46d4-b7c2-66543067b869}" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "DefaultPnPCapabilities" /t REG_DWORD /d "280" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "RssBaseCpu" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "ReceiveWorkerThreadPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "MaxNumRssCpus" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "MaxNumFilters" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "PacketStackSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "StackExpansionFaultInjectionRatio" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "StackExpansionFaultInjectionLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "VerboseOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "StuckNblReaction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "ImplicitPowerRefManagement" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "DisablePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "DisableNDISWatchDog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "DisableNaps" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "DisableWDIWatchdogForceBugcheck" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "DisableReenumerationTimeoutBugcheck" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "EnableNicAutoPowerSaverInSleepStudy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "PnPCapabilities" /t REG_DWORD /d "280" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "EnableRSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "EnableTCPA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "EnableIPSecOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v MaxBufferCount /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v MaxFrameLatency /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v FPUPreserve /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v SoftwareVertexProcessing /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v UseVSync /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v BufferCount /t REG_DWORD /d 1 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v PresentationInterval /t REG_DWORD /d 0 /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v FrameLatency /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Afd\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "512" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Afd\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d "512" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Afd\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d "512" /f

SETLOCAL ENABLEDELAYEDEXPANSION

:: Function to take ownership and grant permissions for files or folders
:TakeOwnershipAndGrantAccess
SET "target=%1"
SET "grantUsers=%2"
ECHO Taking ownership of %target%...
takeown /s %computername% /u %username% /f "%target%" /a /r /d y >nul 2>&1
if %errorlevel% neq 0 (echo Failed to take ownership of %target%) else (echo Successfully took ownership of %target%)
icacls "%target%" /grant %grantUsers%:F administrators:F /t /c >nul 2>&1
if %errorlevel% neq 0 (echo Failed to grant permissions for %target%) else (echo Successfully granted permissions for %target%)

:: Killing specific processes
ECHO Killing unwanted processes...
taskkill /f /im OneDriveSetup.exe /im CompatTelRunner.exe /im CompPkgSrv.exe /im upfc.exe /im mobsync.exe /im smartscreen.exe /im MicrosoftEdgeUpdate.exe /im ScreenClippingHost.exe /im TextInputHost.exe /im LocalBridge.exe /im Microsoft.Photos.exe /im WinStore.App.exe /im SkypeApp.exe /im SkypeBridge.exe /im NcsiUwpApp.exe /im backgroundTaskHost.exe /im taskhostw.exe /im ctfmon.exe /im HxTsr.exe /im HxOutlook.exe /im HxCalendarAppImm.exe /im HxAccounts.exe /im GameBarPresenceWriter.exe /t >nul 2>&1
if %errorlevel% neq 0 (echo Failed to kill some processes, ensure no critical processes are affected) else (echo All processes terminated successfully.)

:: Delete unnecessary files and directories
ECHO Deleting unwanted files and directories...
DEL /S /F /Q "%windir%\Program Files (x86)\Internet Explorer" >nul 2>&1
DEL /S /F /Q "%windir%\Program Files (x86)\Microsoft" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\SystemApps Microsoft.MicrosoftEdge" >nul 2>&1
DEL /S /F /Q "%windir%\Program Files\Internet Explorer" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\bcastdvr" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\GameBarPresenceWriter" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\System32\CompatTelRunner.exe" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\System32\upfc.exe" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\System32\CompPkgSrv.exe" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\System32\mobsync.exe" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\System32\smartscreen.exe" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\System32\GameBarPresenceWriter" >nul 2>&1
DEL /S /F /Q "%windir%\Users\%username%\AppData\Local\Microsoft\GameDVR" >nul 2>&1
DEL /S /F /Q "%windir%\Users\%username%\AppData\Local\Microsoft\Edge" >nul 2>&1

:: Final process killing and cleanup
ECHO Finalizing cleanup...
taskkill /f /im StartMenuExperienceHost.exe /im ScreenClippingHost.exe /im GameBarPresenceWriter.exe >nul 2>&1
DEL /S /F /Q "%windir%\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" >nul 2>&1
DEL /S /F /Q "%windir%\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe" >nul 2>&1

ECHO Cleanup completed successfully.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_MEMORY_MAPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_MEMORY_ALLOCS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GRAPHICS_PIPELINE_STAGES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_TRANSACTION_LOCKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_BUFFER_FLUSHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_LOG_FLUSHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_PIPE_IO" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_HEAP_ALLOCATIONS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_FILE_MAPPINGS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_RESOURCE_LOCKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_ASYNC_IO" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_COMPUTE_TASKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_TASK_SCHEDULER" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_SHADOW_COPIES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_EVENT_HANDLERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DIRECT_IO" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_POWER_STATE_CHANGES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_WRITEBACK_CACHE" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GDI_OBJECTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_RENDER_TARGETS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_TLB_FLUSHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_THREAD_CREATION" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CONTEXT_SWITCHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CPU_TICKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_IRQ_HANDLERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_FRAMEBUFFER_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_VIRTUAL_MEMORY_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_THREAD_AFFINITY_SWITCHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_NETWORK_IO" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DISK_FLUSHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DMA_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_KERNEL_THREADS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_PCI_LATENCY" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_INTERRUPT_HANDLERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_TASKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_CLOCK_CHANGES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CACHE_FLUSHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_SYSCALLS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DMA_TRANSFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_NETWORK_EVENTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_PAGE_FAULTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CPU_CYCLES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_VRAM_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CACHE_HITS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_THREAD_SWITCHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_FILE_IO" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CPU_INTRINSICS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_PAGING_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CPU_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_STORAGE_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_NETWORK_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_USB_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_AUDIO_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_PCI_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DMA_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DPC_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_HID_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_ETHERNET_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_WIFI_CMD_BUFFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CMD_BUFFERS_GLOBAL" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_IO_COMPLETION_PORTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_ASYNC_REQUESTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DISPATCH_QUEUE" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_KERNEL_OBJECTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_HARDWARE_TIMERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_EVENT_OBJECTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GRAPHICS_RESOURCES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_RESOURCES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_PIPELINE_OBJECTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_MEMORY_TRANSFERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CACHE_ALLOCS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DISPATCH_CONTEXTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_THREAD_DISPATCHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_PROCESS_CREATION" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_OS_HANDLERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_APP_HANDLERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_MEMORY_MAPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_IRQ_REQUESTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DPC_CALLS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_IRQ_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_REALTIME_TASKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DEFERRED_TASKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_TIMER_EVENTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DPC_TASKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_INTERRUPT_REQUESTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DPC_DISPATCH" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_APC_TASKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_TIMER_EXPIRED_TASKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_NETWORK_PACKETS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_NETWORK_ADAPTERS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DISK_IO_REQUESTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DISK_READS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_DISK_WRITES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_FILE_SYSTEM_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_VIRTUAL_DISK_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_STORAGE_READ_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_STORAGE_WRITE_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_FILE_CACHING_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_NETWORK_CONNECTIONS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_TASKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_COMMAND_DISPATCH" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_RENDER_COMMANDS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_GPU_COMPUTE_COMMANDS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CPU_TASK_DISPATCH" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CPU_PROCESS_SCHEDULES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CPU_CACHE_FLUSH" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_CPU_CYCLE_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_TIMER_DISPATCH" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_SCHEDULER_TASKS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_SCHEDULER_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_REALTIME_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_SYSTEM_CLOCK_UPDATES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_THREAD_EVENTS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_PROCESS_SCHEDULES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_THREAD_SWITCHES" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_THREAD_EVENTS_DISPATCH" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_THREAD_CREATE_OPS" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_TASK_COMPLETION" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MAX_PENDING_TASK_INTERRUPTS" /t REG_SZ /d "0" /f
Reg.exe Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "$IOPageLimit" /f > $null 2>&1
Fsutil behavior set disablelastaccess 1 > $null 2>&1

taskkill /F /IM "MicrosoftEdge.exe"
taskkill /F /IM "explorer.exe"
del /f /q "C:\Users\%USERNAME%\Desktop\Your Phone.lnk"
del /f /q "C:\Users\Public\Desktop\Microsoft Edge.lnk"

echo *** Improving Startup and Memory Usage ***

sc stop DcpSvc
sc stop DiagTrack
sc stop WMPNetworkSvc
sc stop WerSvc
sc stop diagnosticshub.standardcollector.service
sc stop mwappushservice
sc stop "DoSvc" & sc config "DoSvc" start=disabled
sc stop dmwappushservice

sc config "DcpSvc" start=disabled
sc config DiagTrack start=disabled
sc config SysMain start= disabled
sc config WMPNetworkSvc start=disabled
sc config WerSvc start= disabled
sc config XblAuthManager start= disabled
sc config XblGameSave start= disabled
sc config XboxGipSvc start= disabled
sc config XboxNetApiSvc start= disabled
sc config diagnosticshub.standardcollector.service start=disabled
sc config dmwappushservice start=disabled
sc config xbgm start= disabled

sc start SysMain
powershell "Disable-MMAgent -MemoryCompression"
powershell "Disable-MMAgent -PageCombining"
sc stop SysMain

schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks /change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable


Reg.exe add "HKCR\Local Settings\Software\Microsoft\Windows\GameUX\ServiceLocation" /v Games /t REG_SZ /d localhost /f
Reg.exe add "HKCU\Control Panel\Accessibility" /v StickyKeys /t REG_SZ /d 506 /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v AutoRepeatDelay /t REG_SZ /d 0 /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v AutoRepeatRate /t REG_SZ /d 0 /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v DelayBeforeAcceptance /t REG_SZ /d 0 /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 0 /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v Flags /t REG_SZ /d 0 /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 0 /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 0 /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f
Reg.exe add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f
Reg.exe add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f
Reg.exe add "HKCU\Control Panel\Desktop" /v JPEGImportQuality /t REG_DWORD /d 256 /f
Reg.exe add "HKCU\Control Panel\Desktop" /v LowLevelHooksTimeout /t REG_SZ /d 1000 /f
Reg.exe add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
Reg.exe add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 2000 /f
Reg.exe add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Control Panel\Mouse" /v SmoothMouseXCurve /t REG_BINARY /d "0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v SmoothMouseYCurve /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000A800000000000000E00000000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /t REG_DWORD /v HideFileExt /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /t REG_DWORD /v ShowCortanaButton /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /t REG_DWORD /v ShowTaskViewButton /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /t REG_DWORD /v TaskbarGlomLevel /d 2 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableBalloonTips /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowStatusBar /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /t REG_DWORD /v ShellFeedsTaskbarViewMode /d 2 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /t REG_DWORD /v SearchboxTaskbarMode /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v FeatureManagementEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RemediationRequired /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-310093Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-314563Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /t REG_DWORD /v LaunchTo /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisablePreviewDesktop /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisallowShaking /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarSmallIcons /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /t REG_DWORD /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /t REG_DWORD /v "{645FF040-5081-101B-9F08-00AA002F954E}" /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /t REG_DWORD /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /t REG_DWORD /v "{645FF040-5081-101B-9F08-00AA002F954E}" /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen" /v SlideshowEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v PenWorkspaceButtonDesiredVisibility /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /t REG_DWORD /v HideSCAMeetNow /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v LoggingDisabled /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultConsent /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultOverrideBehavior /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_DSEBehavior /t REG_DWORD /d 2 /f
Reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
Reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f
Reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v value /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v LazyModeTimeout /t REG_DWORD /d 10000 /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NoLazyMode /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 100 /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /t REG_DWORD /f /d 0 /v parent
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v DownloadMode /t REG_SZ /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v Disabled /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V DisableNotificationCenter /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /D 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v IRQ16Priority /t REG_DWORD /d 2 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v IRQ8Priority /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v Start /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v Start /t REG_DWORD /d 4 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 2000 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v IRQ16Priority /t REG_DWORD /d 2 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v IRQ8Priority /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v CoalescingTimerInterval /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingCombining /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v SleepStudyDisabled /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v CoalescingTimerInterval /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v CoalescingTimerInterval /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 20 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v ThreadPriority /t REG_DWORD /d 31 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 20 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v ThreadPriority /t REG_DWORD /d 31 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\DXGKrnl\Parameters" /v ThreadPriority /t REG_DWORD /d 31 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\USBHUB3\Parameters" /v ThreadPriority /t REG_DWORD /d 31 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\USBXHCI\Parameters" /v ThreadPriority /t REG_DWORD /d 31 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\WMPNetworkSvc" /v Start /t REG_DWORD /d 00000004 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\nvlddmkm\Parameters" /v ThreadPriority /t REG_DWORD /d 31 /f
Reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v MaintenanceDisabled /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v SystemRestorePointCreationFrequency /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v BranchReadinessLevel /t REG_DWORD /d 32 /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /t REG_DWORD /v EnableAutoTray /d 1 /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /t REG_DWORD /v HubMode /d 1 /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\Software\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableBootTrace /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v SfTracingState /t REG_DWORD /d 0 /f

Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Id /f
Reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Id /f
Reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
Reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f

powershell Invoke-WebRequest -Uri https://raw.githubusercontent.com/rahilpathan/Win10Boost/main/Other%20Tricks/PP/IdealPowerplan.pow -OutFile "%HOMEPATH%\Documents\Type1.pow"
powercfg.exe /import "%HOMEPATH%\Documents\Type1.pow" 8d5e7fda-e8bf-4a96-9a85-a6e23a8c614b
powercfg /setactive 8d5e7fda-e8bf-4a96-9a85-a6e23a8c614b

powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 02f815b5-a5cf-4c84-bf20-649d1f75d3d8 4c793e7d-a264-42e1-87d3-7a0d2f523ccd 1
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 1
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 1
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 2
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 30
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 1
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 100
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 75
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 1
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 03680956-93bc-4294-bba6-4e0f09bb717f 1
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 10778347-1370-4ee0-8bbd-33bdacaade49 1
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 3
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 10
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 7
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 1
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 3
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 3
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 02f815b5-a5cf-4c84-bf20-649d1f75d3d8 4c793e7d-a264-42e1-87d3-7a0d2f523ccd 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 2
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 15
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 75
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 50
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 03680956-93bc-4294-bba6-4e0f09bb717f 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 10778347-1370-4ee0-8bbd-33bdacaade49 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 3
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 10
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 7
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 1
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 3
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 3
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c614b fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 0


Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v CoreParkingDisabled /t REG_DWORD /d 0 /f
powercfg /setACvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1
powercfg -h off
wmic pagefileset delete


Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "IgnoreOSNameValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DesktopTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DesktopTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "IRPStackSize" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "InterfaceMetric" /t REG_DWORD /d "70" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f

start explorer.exe

echo Cleaning NVIDIA GLCache folder...
set "nvidiaGLCache=%LOCALAPPDATA%\NVIDIA\GLCache"
if exist "%nvidiaGLCache%" (
    del /q /s "%nvidiaGLCache%\*.*"
    echo Contents of GLCache folder have been deleted.
) else (
    echo GLCache folder not found.
)

echo Cleaning Temp folder...
set "tempFolder=%LOCALAPPDATA%\Temp"
if exist "%tempFolder%" (
    del /q /s "%tempFolder%\*.*"
    echo Contents of Temp folder have been deleted.
) else (
    echo Temp folder not found.
)

echo Cleaning C:\Windows\Temp folder...
del /q /s "C:\Windows\Temp\*.*"
echo Contents of C:\Windows\Temp folder have been deleted.

echo Cleaning C:\Windows\Prefetch folder...
del /q /s "C:\Windows\Prefetch\*.*"
echo Contents of C:\Windows\Prefetch folder have been deleted.

echo Cleaning system log files...
for /F "tokens=*" %%G in ('wevtutil el') DO wevtutil cl "%%G"
echo System log files have been cleared.

echo Cleaning Internet Explorer cache...
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
echo Internet Explorer cache has been cleared.

echo Cleaning Windows Update cache...
net stop wuauserv
rd /s /q "%windir%\SoftwareDistribution\DataStore"
net start wuauserv
echo Windows Update cache has been cleared.

echo Cleaning Windows Error Reporting files...
del /q /s "%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue\*"
echo Windows Error Reporting files have been deleted.

echo Cleaning Windows temporary files...
del /q /s "%windir%\Temp\*"
echo Windows temporary files have been deleted.

echo Cleaning Windows memory dump files...
del /q /s "%windir%\Minidump\*"
echo Windows memory dump files have been deleted.

echo Cleaning Windows logs...
for /D %%i in ("%windir%\Logs\*") do (
    rmdir /s /q "%%i"
)
echo Windows logs have been cleared.

echo Cleanup complete.

echo Applied Tweaks!
POWERSHELL.EXE -Command "Add-Type -AssemblyName System.Windows.Forms; [void] [System.Windows.Forms.MessageBox]::Show( 'Tweaks Applied Successfully', 'Success', 'OK', 'Information' )"
exit


