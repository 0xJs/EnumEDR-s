# EnumEDR
Tool written in `C` which enumerates EDR's running on the system by enumerating current processes and loaded drivers. It loops through both of them and print if any defined EDR's are present.

## List of supported EDR's
The listed EDR's and their processes atm are;
- Microsoft Defender Antivirus
- Microsoft Defender for Endpoint
- Elastic EDR
- Sysmon

Will add more when I get to test them.

They are listed in `EDRs.c` and its easy to add new EDR's by adding the following struct:

```c
{
	L"<EDR NAME>",
	{
		L"<EDR PROCESS>.exe",
		L"<EDR PROCESS>.exe",
		NULL // End with NULL for the loop termination
	},
	{
		L"<EDR DRIVER>.sys",
		NULL // End with NULL for the loop termination
	}
}
```

## How to run it
- Compile it using Visual Studio

```
PS C:\ > .\EnumEDR.exe -h
Usage: EnumEDR.exe --edr
Options:
  --processes            List all the active processes on the system
  --drivers              List all the active drivers on the system
  --edr                  List all the active processes and drivers of EDR's on the system
  -h                     Display this help message.
```

## Example output
```
C:\EnumEDR.exe --edr
[i] EnumerateProcesses - Enumerating running processes
        GetModuleHandleW - Received handle to ntdll.dll 0x00007FFD17220000
        GetProcAddress - Received address to NtQuerySystemInformation 0x00007FFD172C0040
        NtQuerySystemInformation - Retrieved size in bytes for the system information: 100792
        HeapAlloc - Allocated 100792 bytes of memory for SystemProcessInformation at 0x000001D90605DFF0
        NtQuerySystemInformation - Retrieved size 100792 bytes of system process information at 0x000001D90605DFF0
[+] EnumerateProcesses - Enumerated 55 processes
[i] EnumerateDrivers - Enumerating running drivers
        GetModuleHandleW - Received handle to ntdll.dll 0x00007FFD17220000
        GetProcAddress - Received address to NtQuerySystemInformation 0x00007FFD172C0040
        NtQuerySystemInformation - Retrieved size in bytes for the SystemModuleInformation: 46776
        HeapAlloc - Allocated 46776 bytes of memory for SystemModuleInformation at 0x000001D9060769B0
        NtQuerySystemInformation - Retrieved 46776 bytes of SystemModuleInformation at 0x000001D9060769B0
[+] EnumerateDrivers - Enumerated 158 drivers
[i] DetectEDRs - Checking for EDR's

        Name                                Type       Component
        ------------------------------      ---------- ----------------------------------------
        Elastic EDR                         Process    elastic-agent.exe                        (PID: 2352)
        Microsoft Defender for Endpoint     Process    MsSense.exe                              (PID: 2368)
        Elastic EDR                         Process    elastic-endpoint.exe                     (PID: 2400)
        Microsoft Defender Antivirus        Process    MsMpEng.exe                              (PID: 2452)
        Sysmon                              Process    sysmon.exe                               (PID: 2512)
        Elastic EDR                         Process    filebeat.exe                             (PID: 3996)
        Microsoft Defender Antivirus        Process    NisSrv.exe                               (PID: 4244)
        Microsoft Defender for Endpoint     Process    SenseTVM.exe                             (PID: 6028)
        Microsoft Defender for Endpoint     Process    SenseNdr.exe                             (PID: 6092)
        Microsoft Defender Antivirus        Driver     WdFilter.sys
        Microsoft Defender for Endpoint     Driver     mssecflt.sys
        Sysmon                              Driver     SysmonDrv.sys
        Elastic EDR                         Driver     elastic-endpoint-driver.sys

[+] DetectEDRs - Finished looping through all processes and drivers
```

![](Pasted%20image%2020250722092746.png)

## Credits
I got inspired to expand upon the tool provided in the Evasion Lab (CETP from [Altered Security](https://www.alteredsecurity.com/evasionlab)) which enumerated the EDR processes.
