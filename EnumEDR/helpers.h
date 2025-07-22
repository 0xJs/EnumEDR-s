// ***** INCLUDED HEADERS ***** //
#include <windows.h>
#include <stdio.h>

// ***** HELPER FUNCTIONS ***** //
// Macro's for printing
#define okay(msg, ...) printf("[+] "msg "\n", ##__VA_ARGS__);
#define info(msg, ...) printf("[i] "msg "\n", ##__VA_ARGS__);
#define error(msg, ...) printf("[-] "msg "\n", ##__VA_ARGS__);

#define okayW(msg, ...) wprintf(L"[+] " msg L"\n", ##__VA_ARGS__)
#define infoW(msg, ...) wprintf(L"[i] " msg L"\n", ##__VA_ARGS__)
#define errorW(msg, ...) wprintf(L"[-] " msg L"\n", ##__VA_ARGS__)

#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0) // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values

// Function for printing error messages WIN32 API's
int errorWin32(const char* msg) {
	error("%s (errorcode: %u)", msg, GetLastError());
}

// Function for printing error messages NT API's
int errorNT(const char* msg, NTSTATUS ntstatus) {
	error("%s (NT errorcode: 0x%0.8X)", msg, ntstatus);
}