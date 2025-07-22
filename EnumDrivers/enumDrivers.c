#include "common.h"

// Retrieve list of all the drivers
BOOL EnumerateDrivers(OUT PSYSTEM_MODULE_INFORMATION* ppDrivers) {

	BOOL							bSTATE				= TRUE;
	HMODULE							hNTDLL				= NULL;		// Stores handle to ntdll.dll
	NTSTATUS						STATUS				= NULL;		// Store NTSTATUS value
	HANDLE							hGetProcessHeap		= NULL;		// Handle to process heap
	ULONG							uReturnLen1			= NULL;		// Stores the size of system information 1st NtQuerySystemInformation call
	ULONG							uReturnLen2			= NULL;		// Stores size of system information 2nd NtQuerySystemInformation call
	PSYSTEM_MODULE_INFORMATION		pSystemModuleInfo	= NULL;		// A pointer to memory which receives the requested information

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
		SystemModuleInformation,	// Returns an array of SYSTEM_MODULE_INFORMATION structures
		NULL,						// Can be null the first time calling
		NULL,						// Can be null the first time calling
		&uReturnLen1				// Save the size of the system information
	);
	info_t("NtQuerySystemInformation - Retrieved size in bytes for the SystemModuleInformation: %d", uReturnLen1);

	// Get handle to process heap
	hGetProcessHeap = GetProcessHeap();

	// Allocating enough buffer for the returned array of SYSTEM_MODULE_INFORMATION struct
	pSystemModuleInfo = (PSYSTEM_MODULE_INFORMATION)HeapAlloc(hGetProcessHeap, HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (pSystemModuleInfo == NULL) {
		errorWin32("HeapAlloc - failed to allocate memory");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("HeapAlloc - Allocated %d bytes of memory for SystemModuleInformation at 0x%p", uReturnLen1, pSystemModuleInfo);

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'pSystemModuleInfo'
	STATUS = pNtQuerySystemInformation(
		SystemModuleInformation,	// Returns an array of SYSTEM_MODULE_INFORMATION structures
		pSystemModuleInfo,			// A pointer to a buffer that receives the requested information. 
		uReturnLen1,				// Size of the buffer pointed to by the SystemInformation parameter, in bytes.
		&uReturnLen2				// Size returned
	);
	if (STATUS != 0x0) {
		error("NtQuerySystemInformation - failed with error: 0x%0.8X", STATUS);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("NtQuerySystemInformation - Retrieved %d bytes of SystemModuleInformation at 0x%p", uReturnLen2, pSystemModuleInfo);

	// Return the values
	*ppDrivers = pSystemModuleInfo;

_cleanUp:

	return bSTATE;
}