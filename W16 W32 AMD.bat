@echo off
set rwePath="C:\RWEverything\RW Everything Portable\Rw.exe"
start /b "" %rwePath% /Min /NoLogo /Stdout /Command="W32 0x300488 0x00000000; W32 0x000488 0x00000000; W32 0x01C7488 0x00000000; W32 0x01B0488 0x00000000; W32 0x01B4488 0x00000000; W32 0x01C0488 0x00000000; W32 0x0140488 0x00000000; W32 0x0600488 0x00000000; W32 0x0170488 0x00000000; W32 0x01C748C 0x00000000; W32 0x01C0490 0x00000000; W32 0x300 0xFFFFFFFF; W32 0x310 0x00000000; W32 0x340 0x00000000; W32 0x350 0x00000000; W32 0x360 0x00000000; W32 0x370 0x00000000" >nul 2>&1

powershell -Command "& {Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Applied All Tweaks - Thanks for your Purchase.', 'Delay Destroyer', 'Ok', [System.Windows.Forms.MessageBoxIcon]::Information);}"
