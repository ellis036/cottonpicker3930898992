@echo off
set rwePath="C:\RW Everything Portable\RW Everything Portable\Rw.exe"
start /b "" %rwePath% /Stdout /Command="W16 0x54 0x0000; W32 0x42400024 0x00000000; W32 0x42400044 0x00000000; W32 0x42400064 0x00000000; W32 0x42400018 0x00000018; W16 0x3A0 0000; W16 0x20 0000; W16 0x3A8 0000; W16 0x30 0x0000; W16 0x3B0 0000; W16 0x3C0 0000; W16 0x40 0003; W16 0x50 0000; W16 0x58 0001; W16 0x6C 0000; W16 0x20 0001; W16 0x30 0001; W32 0x50 0x0000; W32 0x54 0x0000; W32 0x58 0x0000; W16 0x3A8 0001; W16 0x290 0000; W16 0x3F0 0000; W16 0x3E0 0000; W16 0x1F0 0000; W16 0x3C 0000; W16 0x1C 0001; W16 0x60 0005; W16 0xF8 0xFFFF; W16 0xA8 0000; W16 0xC8 0001; W16 0xD0 0000; W16 0x1B0 0000; W16 0x3D0 0000; W16 0x2A0 0000; W16 0x340 0000; W16 0x1C0 0001; W16 0x180 0001; W16 0x2F0 0000; W16 0x310 0001; W16 0x320 0000; W16 0x2D0 0000; W16 0x340 0001; W16 0x350 0001; W16 0x370 0000; W16 0x3A0 0001; W16 0x2C0 0000; W16 0x400 0001; W16 0x2D0 0001; W16 0x240 0000; W16 0x250 0001; W16 0x200 0001; W16 0x2B0 0000; W16 0x260 0001; W16 0x2F0 0001; W16 0x48 0000; W16 0x49 0000; W16 0xC0 0000; W16 0xC1 0000; W16 0x60 0000; W16 0x1D0 0000; W16 0x2C1 0000; W16 0x150 0000; W16 0x1F8 0000; W16 0x122 0000; W16 0x1B2 0000; W16 0x1B3 0000; W16 0x1C8 0000; W16 0x2E0 0000; W16 0x2B8 0000; W32 0x00000024 0x00000000; W32 0x00000044 0x00000000; W32 0x00000064 0x00000000; W32 0x00000084 0x00000000; W32 0x000000A4 0x00000000; W32 0x000000C4 0x00000000; W32 0x000000E4 0x00000000; W32 0x00000104 0x00000000; W32 0x42401024 0x00000000; W32 0x42401044 0x00000000; W32 0x42401064 0x00000000; W32 0x42401084 0x00000000; W32 0x424010A4 0x00000000; W32 0x424010C4 0x00000000; W32 0x424010E4 0x00000000; W32 0x42401104 0x00000000; W16 0x54 0x0000; W32 0x42400024 0x00000000; W32 0x42400044 0x00000000; W32 0x42400064 0x00000000; W32 0x42400018 0x00000018; W16 0x3A0 0000; W16 0x20 0000; W16 0x3A8 0000; W16 0x30 0x0000; W16 0x3B0 0000; W16 0x3C0 0000; W16 0x40 0003; W16 0x50 0000; W16 0x58 0001; W16 0x6C 0000; W16 0x3A0 0000; W16 0x20 0001; W16 0x30 0001; W32 0x50 0x0000; W32 0x54 0x0000; W32 0x58 0x0000; W16 0x3A8 0001; W16 0x3B0 0000; W16 0x3C0 0000; W16 0x40 0001; W16 0x6C 0000; W32 0x00000024 0x00000000; W32 0x44020000 0x00000000; W32 0x00000044 0x00000000; W32 0x44020000 0x00000000; W32 0x00000064 0x00000000; W32 0x44020000 0x00000000; W32 0x00000084 0x00000000; W32 0x44020000 0x00000000; W32 0x000000A4 0x00000000; W32 0x44020000 0x00000000; W32 0x000000C4 0x00000000; W32 0x44020000 0x00000000; W32 0x000000E4 0x00000000; W32 0x44020000 0x00000000; W32 0x00000104 0x00000000; W32 0x44020000 0x00000000; W32 0x42401024 0x00000000; W32 0x42401044 0x00000000; W32 0x42401064 0x00000000; W32 0x42401084 0x00000000; W32 0x424010A4 0x00000000; W32 0x424010C4 0x00000000; W32 0x424010E4 0x00000000; W32 0x42401104 0x00000000; W16 0xFEE00000 0x0000; W16 0xFED00000 0x0000; W16 0xFED08000 0x0000; W16 0x0070 0x0000; W16 0x0040 0x0000; W32 0x50000200 0x00000008; W32 0x50000204 0x00000008; W32 0x50000208 0x00000008; W32 0x5000020C 0x00000010; W32 0x50000300 0x00000001; W32 0x50000304 0x000000FF; W32 0x50000600 0x00000001; W32 0x50000604 0x00000001; W32 0x50000400 0x00000000; W32 0x50000404 0x00000000; W32 0x50000800 0x00000000; W32 0x50000804 0x00000000; W32 0x50000300 0x00000FFF; W32 0x50000200 0x0000000A; W32 0x50000204 0x00000004; W32 0x50000208 0x00000006; W32 0x5000020C 0x00000014; W32 0x50000700 0x00000001; W32 0x50000704 0x00000000; W32 0x50000520 0x00000003; W32 0x50000524 0x00000002; W32 0x50000540 0x00000001; W32 0x50000C00 0x00000001; W32 0x50000E00 0x00000000; W32 0x50000E20 0x00000010; W16 0xFED1F600 0x0000; W16 0xFED1F604 0x0000; W16 0xFED1F608 0x0000; W16 0xFED1F60C 0x0000; W16 0xFED1F610 0x0000; W16 0xFED1F614 0x0000; W16 0xFED1F618 0x0000; W16 0xFED1F61C 0x0000; W16 0xFED1F620 0x0000; W16 0xFED1F624 0x0000; W16 0xFED1F628 0x0000; W16 0xFED1F62C 0x0000; W16 0xFED1F630 0x0000; W16 0xFED1F634 0x0000; W16 0xFED1F638 0x0000; W16 0xFED1F63C 0x0000; W16 0xFED1F640 0x0000; W16 0xFED1F644 0x0000; W16 0xFED1F648 0x0000; W16 0xFED1F64C 0x0000; W16 0xFED1F650 0x0000; W16 0xFED1F654 0x0000; W16 0xFED1F658 0x0000; W16 0xFED1F65C 0x0000; W16 0xFE300000 0x0000; W16 0xFE300010 0x0000; W16 0xFE000004 0x0000; W16 0x1800 0x0000; W16 0xFE200000 0x0000; W16 0xFEA00050 0x0000; W16 0xFE300000 0x0000; W16 0xFEA00400 0x0000; W16 0xFE010010 0x0000; W16 0xFE012000 0x0000; W16 0xFE204000 0x0000; W16 0xFEA00500 0xFFFF; W16 0xFEA00504 0xFFFF; W16 0xFE000100 0x0000; W16 0x1814 0x0000; W16 0xFE004000 0x0000; W16 0xB2 0x0000; W16 0xFE302000 0x0000; W16 0xFE203000 0x0000; W16 0xFEA00010 0x0000; W16 0xFEA00100 0x0000; W16 0xFEA00200 0x0000; W16 0xFEA00204 0x0000; W16 0xFEA00300 0x0000; W16 0xFEA00304 0x0000; W16 0xFEA01000 0x0000; W32 0x60000024 0x00000000; W32 0x60000044 0x00000000; W32 0x60000064 0x00000000; W32 0x60000084 0x00000000; W32 0x60000200 0x00000000; W32 0x60000400 0x00000000; W32 0x60000600 0x00000000; W32 0x50000024 0x00000000; W32 0x50000044 0x00000000; W32 0x50000064 0x00000000; W32 0x50000084 0x00000000; W32 0x50000200 0x00000000; W32 0x50000400 0x00000000; W32 0x50000600 0x00000000; W32 0x70000024 0x00000000; W32 0x70000044 0x00000000; W32 0x70000064 0x00000000; W32 0x70000084 0x00000000; W32 0x70000200 0x00000000; W32 0x70000400 0x00000000; W32 0x70000600 0x00000000; W32 0x30000024 0x00000000; W32 0x30000044 0x00000000; W32 0x30000064 0x00000000; W32 0x30000084 0x00000000; W32 0x30000200 0x00000000; W32 0x30000400 0x00000000; W32 0x30000600 0x00000000; W32 0x50000024 0x00000000; W32 0x50000044 0x00000000; W32 0x50000064 0x00000000; W32 0x50000200 0x00000000; W32 0x50000220 0x00000000; W32 0x50000400 0x00000000; W32 0x50000420 0x00000000; W32 0x60000400 0x00000000; W32 0x60000404 0x00000000; W32 0x60000600 0x00000000; W16 0xFEE00000 0x0000; W16 0xFED00000 0x0000; W16 0xFE000000 0x0000; W16 0xF0000000 0x0000; W16 0xFE100000 0x0000; W16 0xFE200000 0x0000; W16 0xFEA00000 0x0000; W16 0xFE300000 0x0000; W16 0xFEC00000 0x0000; W16 0xB2 0x0000; W16 0x1800 0x0000; W16 0xFED08000 0x0000; W16 0xFED90000 0x0000; W16 0xFED1F404 0x0000; W16 0xFED1F408 0x0000; W16 0xFED1F410 0x0000; W16 0xFED1F414 0x0000; W16 0xFED1F418 0x0000; W16 0xFED1F420 0x0000; W16 0xFED1F424 0x0000; W16 0xFED1F428 0x0000; W16 0xFED1F42C 0x0000; W16 0xFED1F430 0x0000; W16 0xFED1F434 0x0000; W16 0xFED1F438 0x0000; W16 0xFED1F43C 0x0000; W16 0xFED1F440 0x0000; W16 0xFED1F444 0x0000; W16 0xFED1F448 0x0000; W16 0xFED1F44C 0x0000; W16 0xFED1F450 0x0000; W16 0xFED1F454 0x0000; W16 0xFED1F458 0x0000; W16 0xFED1F460 0x0000; W16 0xFED1F464 0x0000; W16 0xFED1F468 0x0000; W16 0xFED1F46C 0x0000; W16 0xFED1F470 0x0000; W16 0xFED1F474 0x0000; W16 0xFED1F478 0x0000; W16 0xFED1F47C 0x0000; W16 0xFED1F480 0x0000; W16 0xFED1F484 0x0000" >nul 2>&1


powershell -Command "& {Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Applied All Tweaks - Thanks for your Purchase.', 'Delay Destroyer', 'Ok', [System.Windows.Forms.MessageBoxIcon]::Information);}"

