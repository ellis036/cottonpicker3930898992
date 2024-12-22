@Echo Off
start /b "" cmd /c "Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DisableExceptionChainValidation\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcWatchdogProfileOffset\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"ForceForegroundBoostDecay\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"GlobalTimerResolutionRequests\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"MitigationOptions\" /t REG_BINARY /d \"222222222222222222222222222222222222222222222222\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"MitigationAuditOptions\" /t REG_BINARY /d \"222222222222222222222222222222222222222222222222\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"EAFModules\" /t REG_SZ /d \"\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DPCTimeout\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcSoftTimeout\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcCumulativeSoftTimeout\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcWatchdogPeriod\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"VerifierDpcScalingFactor\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"ThreadDpcEnable\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"MinimumDpcRate\" /t REG_DWORD /d \"4294967295\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"MaximumKernelWorkerThreads\" /t REG_DWORD /d \"8192\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcRequestRate\" /t REG_DWORD /d \"4294967295\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcTimeLimit\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcTimeCount\" /t REG_DWORD /d \"1000\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"InterruptRequest\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"IdleHalt\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"ClockOwner\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"PendingTickFlags\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"MaximumDpcQueueDepth\" /t REG_DWORD /d \"1000\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcWatchdogProfileCumulativeDpcThreshold\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcWatchdogProfileSingleDpcThreshold\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcLastCount\" /t REG_DWORD /d \"1000\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DpcRoutineActive\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"QuantumEnd\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"InterruptLastCount\" /t REG_DWORD /d \"4294967295\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"InterruptRate\" /t REG_DWORD /d \"4294967295\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"ReadyThreadCount\" /t REG_DWORD /d \"2000\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"KeSpinLockOrdering\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"PriorityState\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DistributeTimers\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DisableDynamicTick\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"TimerInterruptDelay\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"MinimumIncrement\" /t REG_DWORD /d \"4\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"MaximumIncrement\" /t REG_DWORD /d \"5000\" /f & 
Reg.exe delete \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DebugPollInterval\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"PowerOffFrozenProcessors\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DisableLightWeightSuspend\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DisableIFEOCaching\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"HyperStartDisabled\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"InterruptSteeringFlags\" /t REG_DWORD /d \"0\" /f & 
Reg.exe delete \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"HeteroFavoredCoreFallback\" /f & 
Reg.exe delete \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"SeLpacEnableWatsonReporting\" /f & 
Reg.exe delete \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"SeLpacEnableWatsonThrottling\" /f & 
Reg.exe delete \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"AdminlessEnableWatsonReporting\" /f & 
Reg.exe delete \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"AdminlessEnableWatsonThrottling\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"CacheAwareScheduling\" /t REG_DWORD /d \"47\" /f & 
Reg.exe delete \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"HeteroSchedulerOptions\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"LongDpcRuntimeThreshold\" /t REG_DWORD /d \"10\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"LongDpcQueueThreshold\" /t REG_DWORD /d \"10\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"IdealNodeRandomized\" /t REG_DWORD /d \"1\" /f & 
Reg.exe delete \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DefaultHeteroCpuPolicy\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"CyclesPerClockQuantum\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"QuantumLength\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"ForceDpcDmaCoalesce\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"QuantumSize\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"DisablePrefetcher\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"LockPagesInMemory\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"KdDisable\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"ThreadPriorityBoost\" /t REG_DWORD /d \"1\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"PerfBootPerformance\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"PerfBoostPolicy\" /t REG_DWORD /d \"3\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"CpuThrottle\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"ProcessorPerformanceEnableCoreParking\" /t REG_DWORD /d \"0\" /f & 
Reg.exe add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v \"ProcessorPerformanceCoreParkingMinCores\" /t REG_DWORD /d \"100\" /f" >nul 2>&1
pause
