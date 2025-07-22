#include "common.h"

// Print help message
void printHelp(char* fileName) {
	printf("Usage: %s --edr\n", fileName);
	printf("Options:\n");
	printf("  --processes            List all the active processes on the system\n");
	printf("  --drivers              List all the active drivers on the system\n");
	printf("  --edr                  List all the active processes and drivers of EDR's on the system\n");
	printf("  -h                     Display this help message.\n");
}

int main(int argc, char** argv) {

	PSYSTEM_MODULE_INFORMATION	pSystemModuleInfo	= NULL;		// Stores pointer to the module information (drivers)
	PSYSTEM_PROCESS_INFORMATION pSystemProcInfo		= NULL;		// Stores pointer to the system process information (processes)
	PVOID						pValueToFree		= NULL;		// Save initial value of SystemProcInfo to free later
	DWORD						dwProcessCount		= 0;		// Save the process count


	// If not enough arguments are supplied print the help function
	if (argc < 2) {
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1], "--processes") == 0) {
		
		// Enumerate all the running processes
		info("EnumerateProcesses - Enumerating running processes");
		if (!EnumerateProcesses(&pSystemProcInfo)) {
			error("EnumerateProcesses - Failed to enumerate running processes");
			return EXIT_FAILURE;
		}
		dwProcessCount = CountProcesses(pSystemProcInfo);
		okay("EnumerateProcesses - Enumerated %d processes", dwProcessCount);

		// Save the original value of pSystemProcInfo to free later
		pValueToFree = pSystemProcInfo;

		// Print the driver info
		if (!PrintProcesses(pSystemProcInfo)) {
			error("PrintProcesses - Failed to print");
			return EXIT_FAILURE;
		}
	}
	else if (strcmp(argv[1], "--drivers") == 0) {
		
		// Enumerate all the running drivers
		info("EnumerateDrivers - Enumerating running drivers");
		if (!EnumerateDrivers(&pSystemModuleInfo)) {
			error("EnumerateDrivers - Failed to enumerate running processes");
			return EXIT_FAILURE;
		}
		okay("EnumerateDrivers - Enumerated %lu drivers", pSystemModuleInfo->ModulesCount);

		// Print the driver info
		if (!PrintDrivers(pSystemModuleInfo)) {
			error("PrintDrivers - Failed to print");
			return EXIT_FAILURE;
		}

	}
	else if (strcmp(argv[1], "--edr") == 0) {
		
		// Enumerate all the running processes
		info("EnumerateProcesses - Enumerating running processes");
		if (!EnumerateProcesses(&pSystemProcInfo)) {
			error("EnumerateProcesses - Failed to enumerate running processes");
			return EXIT_FAILURE;
		}
		dwProcessCount = CountProcesses(pSystemProcInfo);
		okay("EnumerateProcesses - Enumerated %d processes", dwProcessCount);

		// Enumerate all the running drivers
		info("EnumerateDrivers - Enumerating running drivers");
		if (!EnumerateDrivers(&pSystemModuleInfo)) {
			error("EnumerateDrivers - Failed to enumerate running processes");
			return EXIT_FAILURE;
		}
		okay("EnumerateDrivers - Enumerated %lu drivers", pSystemModuleInfo->ModulesCount);

		// Save the original value of pSystemProcInfo to free later
		pValueToFree = pSystemProcInfo;

		// Check for running EDR processes and drivers
		info("DetectEDRs - Checking for EDR's\n");
		if (!DetectEDRs(pSystemModuleInfo, pSystemProcInfo)) {
			error("DetectEDRs - No EDR processes or drivers identified");
			return EXIT_FAILURE;
		}
		printf("\n");
		okay("DetectEDRs - Finished looping through all processes and drivers");

	}
	else if (strcmp(argv[1], "-h") == 0) {
		printHelp(argv[0]);
		return EXIT_SUCCESS;
	}
	else {
		error("Unknown argument: %s", argv[1]);
		printHelp(argv[0]);
		return EXIT_FAILURE;
	}

_cleanUp:

	// Free the processes System Process Info
	if (pValueToFree) {
		HeapFree(GetProcessHeap(), 0, pValueToFree);
	}

	// Free the drivers System Module Info
	if (pSystemModuleInfo) {
		HeapFree(GetProcessHeap(), 0, pSystemModuleInfo);
	}

	return EXIT_SUCCESS;

}