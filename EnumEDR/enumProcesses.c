#include "common.h"

// Print process information
BOOL PrintProcesses(IN PSYSTEM_PROCESS_INFORMATION pSystemProcInfo) {

	BOOL	bSTATE = TRUE;

	infoW_t(L"%-40s %-6s", L"NAME", L"PID");
	infoW_t(L"%-40s %-6s", L"----------------------------------------", L"------");

	// Loop over all the the processes
	while (TRUE) {

		if (pSystemProcInfo->ImageName.Buffer != NULL) {
			infoW_t(L"%-40s %-6d", pSystemProcInfo->ImageName.Buffer, pSystemProcInfo->UniqueProcessId);
		}
		else {
			infoW_t(L"%-40s %-6d", L"[Unnamed Process]", pSystemProcInfo->UniqueProcessId);
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!pSystemProcInfo->NextEntryOffset) {

			//info("Reached end of SystemProcInfo array");

			break;
		}

		// From Docs: The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member. 
		pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);
	}

_cleanUp:

	return bSTATE;

}

// Count the processes
DWORD CountProcesses(IN PSYSTEM_PROCESS_INFORMATION pSystemProcInfo) {

	DWORD dwProcessCount = 0;

	while (TRUE) {

		dwProcessCount++;

		// If NextEntryOffset is 0, we reached the end of the array
		if (!pSystemProcInfo->NextEntryOffset) {
			break;
		}

		// Move to the next entry
		pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);
	}

	return dwProcessCount;
}

// Enumerate all processes on the system
BOOL EnumerateProcesses(OUT PSYSTEM_PROCESS_INFORMATION* ppSystemProcInfo) {

	BOOL							bSTATE			= TRUE;
	HMODULE							hNTDLL			= NULL; // Stores handle to ntdll.dll
	NTSTATUS						STATUS			= NULL;	// Store NTSTATUS value
	HANDLE							hGetProcessHeap = NULL;	// Handle to process heap
	ULONG							uReturnLen1		= NULL; // Stores the size of system information 1st NtQuerySystemInformation call
	ULONG							uReturnLen2		= NULL;	// Stores size of system information 2nd NtQuerySystemInformation call
	PSYSTEM_PROCESS_INFORMATION		pSystemProcInfo = NULL; // A pointer to memory which receives the requested information

	// Get handle to ntdll.dll
	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew
	hNTDLL = GetModuleHandleW(L"ntdll.dll");
	if (!hNTDLL) {
		errorWin32("GetModuleHandleW - Failed to get handle to ntdll.dll");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetModuleHandleW - Received handle to ntdll.dll 0x%p", hNTDLL);

	// Resolve address of NtQuerySystemInformation
	fnNtQuerySystemInformation pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNTDLL, "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) {
		errorWin32("GetProcAddress - Failed to address of NtQuerySystemInformation");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetProcAddress - Received address to NtQuerySystemInformation 0x%p", pNtQuerySystemInformation);

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
	// First NtQuerySystemInformation call, which fails but will save the 
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)
	pNtQuerySystemInformation(
		SystemProcessInformation,	// Returns an array of SYSTEM_PROCESS_INFORMATION structures, one for each process running in the system.
		NULL,						// Can be null the first time calling
		NULL,						// Can be null the first time calling
		&uReturnLen1				// Save the size of the system information
	);
	info_t("NtQuerySystemInformation - Retrieved size in bytes for the system information: %d", uReturnLen1);

	// Get handle to process heap
	hGetProcessHeap = GetProcessHeap();

	// Allocating enough buffer for the returned array of SYSTEM_PROCESS_INFORMATION struct
	pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(hGetProcessHeap, HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (pSystemProcInfo == NULL) {
		errorWin32("HeapAlloc - failed to allocate memory");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("HeapAlloc - Allocated %d bytes of memory for SystemProcessInformation at 0x%p", uReturnLen1, pSystemProcInfo);

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'pSystemProcInfo'
	STATUS = pNtQuerySystemInformation(
		SystemProcessInformation,	// Returns an array of SYSTEM_PROCESS_INFORMATION structures, one for each process running in the system.
		pSystemProcInfo,			// A pointer to a buffer that receives the requested information. 
		uReturnLen1,				// Size of the buffer pointed to by the SystemInformation parameter, in bytes.
		&uReturnLen2				// Size returned
	);
	if (STATUS != 0x0) {
		error("NtQuerySystemInformation - failed with error: 0x%0.8X", STATUS);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("NtQuerySystemInformation - Retrieved size %d bytes of system process information at 0x%p", uReturnLen2, pSystemProcInfo);

	// Return pointer to the process list
	*ppSystemProcInfo = pSystemProcInfo;

_cleanUp:

	return bSTATE;
}