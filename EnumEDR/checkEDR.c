#include "common.h"

// Detects if EDR driver or process is running, blacklisted proccesses/drivers in 'EDRs.c'
BOOL DetectEDRs(IN PSYSTEM_MODULE_INFORMATION pSystemModuleInfo, IN PSYSTEM_PROCESS_INFORMATION pSystemProcInfo) {
    
    BOOL                            bSTATE      = TRUE;
    DWORD                           i           = 0;        // Variable for iteration
    DWORD                           j           = 0;        // Variable for iteration
    PSYSTEM_PROCESS_INFORMATION     pProcCursor = NULL;     // Variable for iteration on processes while loop
    BOOL                            bEDRProc    = FALSE;    // BOOL value to check if any EDR process is identified
    BOOL                            bEDRDriver  = FALSE;    // BOOL value to check if any EDR driver is identified

    infoW_t(L"%-35s %-10s %-40s", L"Name", L"Type", L"Component");
    infoW_t(L"%-35s %-10s %-40s", L"------------------------------", L"----------", L"----------------------------------------");

    // Store the original value
    pProcCursor = pSystemProcInfo;

    // Loop over all the processes
    while (TRUE) {

        // Check if the process has a name (The first system process doesn't)
        if (pProcCursor->ImageName.Buffer != NULL) {

            // Loop over all the EDR's defined
            for (i = 0; i < g_EDRCount; i++) {

                // Loop over all the EDR's process names
                for (j = 0; g_EDRMap[i].pwszProcessNames[j] != NULL; j++) {

                    // Check if process name matches (Case insensitive)
                    if (_wcsicmp(pProcCursor->ImageName.Buffer, g_EDRMap[i].pwszProcessNames[j]) == 0) {
                        infoW_t(L"%-35s %-10s %-40s (PID: %lu)", g_EDRMap[i].pwszEDRName, L"Process", pProcCursor->ImageName.Buffer, (ULONG_PTR)pProcCursor->UniqueProcessId);
                        bEDRProc = TRUE;
                    }
                }
            }
        }
        if (!pProcCursor->NextEntryOffset) break;
        pProcCursor = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pProcCursor + pProcCursor->NextEntryOffset);
    }

    // Loop over all drivers
    for (j = 0; j < pSystemModuleInfo->ModulesCount; j++) {
        
        // Extract the base name from the full path
        CHAR* pszBaseName = strrchr((CHAR*)pSystemModuleInfo->Modules[j].FullPathName, '\\');

        // Check if its succeeded
        if (pszBaseName != NULL) {
            // Move past the backslash
            pszBaseName++;
        }
        else {
            pszBaseName = (CHAR*)pSystemModuleInfo->Modules[j].FullPathName; // No backslash found, use full path as name
        }

        // Loop over all the EDR's defined
        for (i = 0; i < g_EDRCount; i++) {

            // Loop over all the drivers defined
            for (DWORD k = 0; g_EDRMap[i].pwszDriverNames[k] != NULL; k++) {

                CHAR szDriverName[MAX_PATH] = { 0 };

                // Convert blacklisted dirver name to char
                WideCharToMultiByte(CP_ACP, 0, g_EDRMap[i].pwszDriverNames[k], -1, szDriverName, MAX_PATH, NULL, NULL);

                // Check if driver name matches (Case insensitive)
                if (_stricmp(szDriverName, pszBaseName) == 0) {
                    infoW_t(L"%-35s %-10s %-40S", g_EDRMap[i].pwszEDRName, L"Driver", pszBaseName);
                    bEDRDriver = TRUE;
                }
            }
        }
    }

    // If no EDR process or Driver identified, return false
    if (bEDRProc == FALSE || bEDRDriver == FALSE) {
        bSTATE = FALSE;
    }

    return bSTATE;
}