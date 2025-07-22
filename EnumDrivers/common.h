/*
     Stores all macro's and function prototypes used across the project
*/

#pragma once

#include "windows.h"
#include "stdio.h"

#include "structs.h"
#include "typedef.h"

// ***** MAKE THESE GLOBAL ***** //
extern const wchar_t* g_EDRNames[];
extern const SIZE_T g_EDRCount;

// ***** HELPER FUNCTIONS FOR PRINTING ***** //
#define okay(msg, ...) printf("[+] "msg "\n", ##__VA_ARGS__);
#define info(msg, ...) printf("[i] "msg "\n", ##__VA_ARGS__);
#define error(msg, ...) printf("[-] "msg "\n", ##__VA_ARGS__);

#define okayW(msg, ...) wprintf(L"[+] " msg L"\n", ##__VA_ARGS__)
#define infoW(msg, ...) wprintf(L"[i] " msg L"\n", ##__VA_ARGS__)
#define errorW(msg, ...) wprintf(L"[-] " msg L"\n", ##__VA_ARGS__)

// NT Macro for succes of syscalls
#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0) // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values

// Tabbed versions for info without the [i]
#define infoW_t(msg, ...) wprintf(L"\t" msg L"\n", ##__VA_ARGS__)
#define info_t(msg, ...) printf("\t"msg "\n", ##__VA_ARGS__);

// ***** HELPER FUNCTION TO GET HANDLE TO CURRENT PROCESS OR THREAD ***** //
#define NtCurrentProcess() ((HANDLE)-1) // Return the pseudo handle for the current process
#define NtCurrentThread()  ((HANDLE)-2) // Return the pseudo handle for the current thread

// ***** FUNCTION PROTOTYPES ***** //
// Function prototypes are needed so each source file is aware of the function's signature 
// (name, return type, and parameters) before the compiler encounters the function call.

// For functions in 'helpers.c'
int errorWin32(IN const char* msg);
int errorNT(IN const char* msg, IN NTSTATUS ntstatus);
void print_bytes(IN void* ptr, IN int size);

// For functions in 'enumDrivers.c'
BOOL EnumerateDrivers(OUT PSYSTEM_MODULE_INFORMATION* ppDrivers);