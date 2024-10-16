setlocal enabledelayedexpansion

:: Set up log file
set logFile=%~dp0debug.log
echo Script started on %date% %time% > "%logFile%"

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

:: Create a scheduled task to run the script at system startup
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
