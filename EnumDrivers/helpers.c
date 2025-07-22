#include "common.h"
#include "stdio.h"

// ***** HELPER FUNCTIONS FOR PRINTING ***** //

// Function for printing error messages WIN32 API's
int errorWin32(IN const char* msg) {
	error("%s (errorcode: %u)", msg, GetLastError());
}

// Function for printing error messages NT API's
int errorNT(IN const char* msg, IN NTSTATUS ntstatus) {
	error("%s (NT errorcode: 0x%0.8X)", msg, ntstatus);
}

// Function for printing memory bytes, to print the payload for example
// https://stackoverflow.com/questions/35364772/how-to-print-memory-bits-in-c
void print_bytes(IN void* ptr, IN int size)
{
	unsigned char* p = ptr;
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		printf("%02hhX ", p[i]);
	}
	printf("\n\n");
}