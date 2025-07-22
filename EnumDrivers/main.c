#include "common.h"

int main() {

    PSYSTEM_MODULE_INFORMATION	pSystemModuleInfo       = NULL;     // A pointer to memory which receives the list of loaded drivers
    CHAR                        lpSystemRoot            [MAX_PATH]; // Saves the systemroot
    CHAR                        lpResolvedPath          [MAX_PATH]; // Saves the new full path with systemroot

    // Enumerate all the running drivers
    info("EnumerateDrivers - Enumerating running drivers");
    if (!EnumerateDrivers(&pSystemModuleInfo)) {
        error("EnumerateDrivers - Failed to enumerate running processes");
        return EXIT_FAILURE;
    }
    okay("EnumerateDrivers - Enumerated %lu drivers", pSystemModuleInfo->ModulesCount);
	
    // Get the actual system root directory ("C:\Windows")
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemwindowsdirectorya
    if (!GetSystemWindowsDirectoryA(lpSystemRoot, MAX_PATH)) {
        strcpy_s(lpSystemRoot, MAX_PATH, "C:\\Windows"); //Fallback to C:\Windows
    }

    // Loop over all the modules and print the information
    for (ULONG i = 0; i < pSystemModuleInfo->ModulesCount; i++) {
        PSYSTEM_MODULE pModule = &pSystemModuleInfo->Modules[i];

        // Resolve \SystemRoot to real path
        if (_strnicmp(pModule->FullPathName, "\\SystemRoot\\", 12) == 0) {
            snprintf(lpResolvedPath, sizeof(lpResolvedPath), "%s\\%s", lpSystemRoot, pModule->FullPathName + 12);
        }
        else if (_strnicmp(pModule->FullPathName, "\\??\\C:\\WINDOWS\\", 15) == 0) {
            snprintf(lpResolvedPath, sizeof(lpResolvedPath), "%s\\%s", lpSystemRoot, pModule->FullPathName + 12);
        }
        else {
            snprintf(lpResolvedPath, sizeof(lpResolvedPath), "%s", pModule->FullPathName);
        }

        info_t("%s", lpResolvedPath);
    }

    // Free the memory
    if (pSystemModuleInfo) {
        HeapFree(GetProcessHeap(), 0, pSystemModuleInfo);
    }

    return EXIT_SUCCESS;

}