# pe-checks
PE file informations (VirusTotal like) for malware development and AV evasion research 

```
python pe-checks.py doggo.exe -v
---- PE Infos
-- Basic properties
Magic           23117
Magic2          523
Imphash         fbd022f8d0fe0a8fe115a444c1ffac8a
Sha256          0b89227e50495cd4650594451b46f457ff749a447cf6e2406d78a28bd2a51a6b
Entropy         6.122527913691151 (Min=0.0, Max=8.0)
File Size       143.36 KB (143360 bytes)
Headers Size    1024

-- Headers
Compilation Timestamp:    2021-08-18 22:40:48 (utc)
Machine:                  0x8664
Entry Point:              6100

-- Sections
Name     Virtual Address   Virtual Size   Raw Size   MD5                                 Entropy (Min=0.0, Max=8.0)
.text    4096              72112          72192      0b761f351d04bca38ea1be4e2b348ed2    6.512785410676443
.rdata   77824             40908          40960      427e14f73674749d2e785b8603a5d653    4.940326548943568
.data    118784            7440           3072       fab295cf3cffc26cf45bb40d0b0aebf4    2.1738396268664064
.pdata   126976            4200           4608       8cb1f79869f812d5907cef1eae94dcd8    4.617989722440477
_RDATA   135168            252            512        a45071728e916aef98d682694d452eff    1.9598700301244667
.reloc   139264            1628           2048       fd184cf520d29d02d83a2ae79cd45344    4.880900270454826

-- Imports
KERNEL32.dll.WaitForSingleObject                               [0x140013000]
KERNEL32.dll.Sleep                                             [0x140013008]
KERNEL32.dll.GetCurrentProcess                                 [0x140013010]
KERNEL32.dll.VirtualAllocExNuma                                [0x140013018]
KERNEL32.dll.GetModuleHandleA                                  [0x140013020]
KERNEL32.dll.GetProcAddress                                    [0x140013028]
KERNEL32.dll.QueryPerformanceCounter                           [0x140013030]
KERNEL32.dll.GetCurrentProcessId                               [0x140013038]
KERNEL32.dll.GetCurrentThreadId                                [0x140013040]
KERNEL32.dll.GetSystemTimeAsFileTime                           [0x140013048]
KERNEL32.dll.InitializeSListHead                               [0x140013050]
KERNEL32.dll.RtlCaptureContext                                 [0x140013058]
KERNEL32.dll.RtlLookupFunctionEntry                            [0x140013060]
KERNEL32.dll.RtlVirtualUnwind                                  [0x140013068]
KERNEL32.dll.IsDebuggerPresent                                 [0x140013070]
KERNEL32.dll.UnhandledExceptionFilter                          [0x140013078]
KERNEL32.dll.SetUnhandledExceptionFilter                       [0x140013080]
KERNEL32.dll.GetStartupInfoW                                   [0x140013088]
KERNEL32.dll.IsProcessorFeaturePresent                         [0x140013090]
KERNEL32.dll.GetModuleHandleW                                  [0x140013098]
KERNEL32.dll.WriteConsoleW                                     [0x1400130a0]
KERNEL32.dll.RtlUnwindEx                                       [0x1400130a8]
KERNEL32.dll.GetLastError                                      [0x1400130b0]
KERNEL32.dll.SetLastError                                      [0x1400130b8]
KERNEL32.dll.EnterCriticalSection                              [0x1400130c0]
KERNEL32.dll.LeaveCriticalSection                              [0x1400130c8]
KERNEL32.dll.DeleteCriticalSection                             [0x1400130d0]
KERNEL32.dll.InitializeCriticalSectionAndSpinCount             [0x1400130d8]
KERNEL32.dll.TlsAlloc                                          [0x1400130e0]
KERNEL32.dll.TlsGetValue                                       [0x1400130e8]
KERNEL32.dll.TlsSetValue                                       [0x1400130f0]
KERNEL32.dll.TlsFree                                           [0x1400130f8]
KERNEL32.dll.FreeLibrary                                       [0x140013100]
KERNEL32.dll.LoadLibraryExW                                    [0x140013108]
KERNEL32.dll.RaiseException                                    [0x140013110]
KERNEL32.dll.GetStdHandle                                      [0x140013118]
KERNEL32.dll.WriteFile                                         [0x140013120]
KERNEL32.dll.GetModuleFileNameW                                [0x140013128]
KERNEL32.dll.ExitProcess                                       [0x140013130]
KERNEL32.dll.TerminateProcess                                  [0x140013138]
KERNEL32.dll.GetModuleHandleExW                                [0x140013140]
KERNEL32.dll.GetCommandLineA                                   [0x140013148]
KERNEL32.dll.GetCommandLineW                                   [0x140013150]
KERNEL32.dll.HeapFree                                          [0x140013158]
KERNEL32.dll.HeapAlloc                                         [0x140013160]
KERNEL32.dll.CompareStringW                                    [0x140013168]
KERNEL32.dll.LCMapStringW                                      [0x140013170]
KERNEL32.dll.GetFileType                                       [0x140013178]
KERNEL32.dll.FindClose                                         [0x140013180]
KERNEL32.dll.FindFirstFileExW                                  [0x140013188]
KERNEL32.dll.FindNextFileW                                     [0x140013190]
KERNEL32.dll.IsValidCodePage                                   [0x140013198]
KERNEL32.dll.GetACP                                            [0x1400131a0]
KERNEL32.dll.GetOEMCP                                          [0x1400131a8]
KERNEL32.dll.GetCPInfo                                         [0x1400131b0]
KERNEL32.dll.MultiByteToWideChar                               [0x1400131b8]
KERNEL32.dll.WideCharToMultiByte                               [0x1400131c0]
KERNEL32.dll.GetEnvironmentStringsW                            [0x1400131c8]
KERNEL32.dll.FreeEnvironmentStringsW                           [0x1400131d0]
KERNEL32.dll.SetEnvironmentVariableW                           [0x1400131d8]
KERNEL32.dll.SetStdHandle                                      [0x1400131e0]
KERNEL32.dll.GetStringTypeW                                    [0x1400131e8]
KERNEL32.dll.GetProcessHeap                                    [0x1400131f0]
KERNEL32.dll.FlushFileBuffers                                  [0x1400131f8]
KERNEL32.dll.GetConsoleOutputCP                                [0x140013200]
KERNEL32.dll.GetConsoleMode                                    [0x140013208]
KERNEL32.dll.GetFileSizeEx                                     [0x140013210]
KERNEL32.dll.SetFilePointerEx                                  [0x140013218]
KERNEL32.dll.HeapSize                                          [0x140013220]
KERNEL32.dll.HeapReAlloc                                       [0x140013228]
KERNEL32.dll.CloseHandle                                       [0x140013230]
KERNEL32.dll.CreateFileW                                       [0x140013238]
```
