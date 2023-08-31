#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <tlhelp32.h>

#define perror(fname) (fprintf(stderr, "[!] %s failed (0x%x)\n", fname, GetLastError()))

enum MemType {
	code,
	data,
	heap,
	mapped,
	unknown,
	invalid
};

// See: https://stackoverflow.com/a/59635651
enum MemType get_mem_type(LPVOID ptr) {
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	// Check for invalid ptr
	if (ptr == NULL) {
		return invalid;
	}

	// Retrieves information about a range of pages in 
	// the virtual address space of the calling process.
	SIZE_T ret = VirtualQuery(ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	if (ret == 0) {
		//fprintf(stderr, "[!] VirtualQuery() failed(0x%x)\n", GetLastError());
		return invalid;
	}

	if (ret != sizeof(MEMORY_BASIC_INFORMATION)) {
		//fprintf(stderr, "[!] Incomplete buffer returned\n");
		return invalid;
	}

	// Check for bad memory regions
	if (mbi.State != MEM_COMMIT) {
		//fprintf(stderr, "[!] Invalid Memory Commit\n");
		return invalid;
	}

	// Check for PAGE_NOACCESS
	if (mbi.Protect == PAGE_NOACCESS) {
		//fprintf(stderr, "[!] Page access not granted\n");
		return invalid;
	}

	if (mbi.Protect == PAGE_READWRITE) {
		// Check for possible heap ptrs: RW/private 
		if (mbi.Type == MEM_PRIVATE) {
			return heap;
		}
		// Check for possible heap ptrs: RW/mapped into image section
		if (mbi.Type == MEM_IMAGE) {
			return data;
		}
	}

	// check for code section
	if (mbi.Type == MEM_IMAGE && mbi.Protect == PAGE_EXECUTE_READ) {
		return code;
	}

	// check for mapped section
	if (mbi.Type == MEM_MAPPED) {
		return mapped;
	}

	return unknown;
}

// Get the PROCESSENTRY32 struct corresponding to a process
DWORD FindPid(char* procname) {
	PROCESSENTRY32 _temp = { 0 };
	_temp.dwSize = sizeof(PROCESSENTRY32);

	// Take Snapshot of all processes on the system
	// See: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
	HANDLE hProcSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS, //  Take a snapshot of the processes
		0                   //  Capture a snapshot of all processes in the system
	);
	if (INVALID_HANDLE_VALUE == hProcSnap) {
		perror("CreateToolhelp32Snapshot()");
		return 0;
	}

	// Retrieves information about the first 
	// process encountered in a system snapshot.
	if (!Process32First(hProcSnap, &_temp)) {
		perror("Process32First()\n");
		CloseHandle(hProcSnap);
		return 0;
	}

	// Loop through Snapshot entries
	while (Process32Next(hProcSnap, &_temp)) {
		if (lstrcmpiA(procname, _temp.szExeFile) == 0) {
			CloseHandle(hProcSnap);
			return _temp.th32ProcessID;
		}
	}

	CloseHandle(hProcSnap);
	fprintf(stderr, "[!] No %s process found\n", procname);
	return 0;
}

// Set Debug Privlieges for current process
// Try to set debug privileges for the process
BOOL SetDebugPrivilege(void) {
    LUID luid;
    HANDLE  hToken;
    TOKEN_PRIVILEGES tp;

    // Get the access token for current process
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        perror("OpenProcessToken()");
        return FALSE;
    }

    // lookup privilege on local system
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        perror("LookupPrivilegeValueA()");
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Set privilege
    if (!AdjustTokenPrivileges(
        hToken,                             // Handle to the token
        FALSE,                              // Modifies privileges as requested
        &tp,                                // Specifies the new privileges 
        sizeof(TOKEN_PRIVILEGES),           // Size of struct
        (PTOKEN_PRIVILEGES)NULL,            // We dont need a handle to old privilege token
        (PDWORD)NULL)) {                   // Ignore return length
        perror("LookupPrivilegeValueA()");
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
}
