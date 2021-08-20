# pe-checks
PE file informations (VirusTotal like) for malware development and AV evasion research 

## Installation
```
pip install -r requirements.txt
``` 

## Usage exemple
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

Capa analysis...
loading : 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 603/603 [00:00<00:00, 1856.77 rules/s]
matching: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 378/378 [00:14<00:00, 25.94 functions/s, skipped 0 library functions]
+------------------------+------------------------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                                   |
|------------------------+------------------------------------------------------------------------------------|
| DEFENSE EVASION        | Obfuscated Files or Information:: T1027                                            |
|                        | Obfuscated Files or Information::Indicator Removal from Tools T1027.005            |
| DISCOVERY              | File and Directory Discovery:: T1083                                               |
|                        | System Information Discovery:: T1082                                               |
| EXECUTION              | Command and Scripting Interpreter:: T1059                                          |
|                        | Shared Modules:: T1129                                                             |
+------------------------+------------------------------------------------------------------------------------+

+-----------------------------+-------------------------------------------------------------------------------+
| MBC Objective               | MBC Behavior                                                                  |
|-----------------------------+-------------------------------------------------------------------------------|
| ANTI-STATIC ANALYSIS        | Disassembler Evasion::Argument Obfuscation [B0012.001]                        |
| DATA                        | Encode Data::XOR [C0026.002]                                                  |
| DEFENSE EVASION             | Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]      |
| FILE SYSTEM                 | Writes File:: [C0052]                                                         |
| MEMORY                      | Allocate Memory:: [C0007]                                                     |
| OPERATING SYSTEM            | Environment Variable::Set Variable [C0034.001]                                |
| PROCESS                     | Allocate Thread Local Storage:: [C0040]                                       |
|                             | Set Thread Local Storage Value:: [C0041]                                      |
|                             | Terminate Process:: [C0018]                                                   |
+-----------------------------+-------------------------------------------------------------------------------+

+------------------------------------------------------+------------------------------------------------------+
| CAPABILITY                                           | NAMESPACE                                            |
|------------------------------------------------------+------------------------------------------------------|
| contain obfuscated stackstrings                      | anti-analysis/obfuscation/string/stackstring         |
| encode data using XOR (2 matches)                    | data-manipulation/encoding/xor                       |
| accept command line arguments                        | host-interaction/cli                                 |
| query environment variable                           | host-interaction/environment-variable                |
| set environment variable                             | host-interaction/environment-variable                |
| enumerate files via kernel32 functions               | host-interaction/file-system/files/list              |
| get file size                                        | host-interaction/file-system/meta                    |
| write file (5 matches)                               | host-interaction/file-system/write                   |
| allocate thread local storage (2 matches)            | host-interaction/process                             |
| get thread local storage value (2 matches)           | host-interaction/process                             |
| set thread local storage value (2 matches)           | host-interaction/process                             |
| allocate RWX memory (2 matches)                      | host-interaction/process/inject                      |
| terminate process (3 matches)                        | host-interaction/process/terminate                   |
| terminate process via fastfail (5 matches)           | host-interaction/process/terminate                   |
| link function at runtime (2 matches)                 | linking/runtime-linking                              |
| parse PE header (10 matches)                         | load-code/pe                                         |
+------------------------------------------------------+------------------------------------------------------+

```

## TODO
- Add signature support
- Add ThreatChecks support
- Add manifest/fileversion support
