#pragma once
#include <Windows.h>
#include <Windows.h>
#include <stdio.h>
#include <pla.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <Evntcons.h>
#include <dbghelp.h>
#include "utils.h"

#pragma comment(lib, "dbghelp.lib")

typedef NTSTATUS(*PETWENABLECALLBACK) (
    LPCGUID                  SourceId,
    ULONG                    ControlCode,
    UCHAR                    Level,
    ULONGLONG                MatchAnyKeyword,
    ULONGLONG                MatchAllKeyword,
    PEVENT_FILTER_DESCRIPTOR FilterData,
    PVOID                    CallbackContext);

// Structs to use
typedef struct _RTL_BALANCED_NODE {
    union {
        struct _RTL_BALANCED_NODE* Children[2];
        struct {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };
    union {
        UCHAR     Red : 1;
        UCHAR     Balance : 2;
        ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE {
    struct _RTL_BALANCED_NODE* Root;
    union {
        UCHAR Encoded : 1; /* bit position: 0 */
        struct _RTL_BALANCED_NODE* Min;
    };
} RTL_RB_TREE, * PRTL_RB_TREE;

typedef struct _ETW_USER_REG_ENTRY {
    RTL_BALANCED_NODE   RegList;           // List of registration entries
    ULONG64             Padding1;
    GUID                ProviderId;        // GUID to identify Provider
    PETWENABLECALLBACK  Callback;          // Callback function executed in response to NtControlTrace
    PVOID               CallbackContext;   // Optional context
    SRWLOCK             RegLock;           // 
    SRWLOCK             NodeLock;          // 
    HANDLE              Thread;            // Handle of thread for callback
    HANDLE              ReplyHandle;       // Used to communicate with the kernel via NtTraceEvent
    USHORT              RegIndex;          // Index in EtwpRegistrationTable
    USHORT              RegType;           // 14th bit indicates a private
    ULONG64             Unknown[19];
} ETW_USER_REG_ENTRY, * PETW_USER_REG_ENTRY;

// Get the virtual address of the ntdll!EtwpRegistrationTable
LPVOID GetEtwpRegistrationTableVA(void) {
    // Remember that handle is the base address of the module in memory.
    // See: https://stackoverflow.com/questions/6126980/get-pointer-to-image-dos-header-with-getmodulehandle
    DWORD bcount = 0;
    PULONG_PTR data_segment = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (NULL == hNtdll) {
        perror("GetModuleHandleA()");
        return NULL;
    }
    printf("[i] Base Address of NTDLL:\t\t0x%p\n", hNtdll);

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    if (pDosHdr->e_magic != 0x5a4d) {
        fprintf(stderr, "[!] Invalid DOS Signature\n");
        return NULL;
    }

    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)hNtdll + pDosHdr->e_lfanew);
    if (IMAGE_NT_SIGNATURE != pNtHdr->Signature) {
        fprintf(stderr, "[!] Invalid NT Signature\n");
        return NULL;
    }

    PIMAGE_SECTION_HEADER pSecHdr = (PIMAGE_SECTION_HEADER)((LPBYTE)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader);

    // Iterate through headers
    for (DWORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
        if (*(PDWORD)pSecHdr[i].Name == *(PDWORD)".data") {
            data_segment = (PULONG_PTR)((ULONG_PTR)hNtdll + pSecHdr[i].VirtualAddress);
            bcount = pSecHdr[i].Misc.VirtualSize / sizeof(ULONG_PTR);
            break;
        }
    }

    if (NULL == data_segment) {
        fprintf(stderr, "[!] Data Segment is invalid\n");
        return NULL;
    }

    // iterate through it
    for (DWORD i = 0; i < bcount - 1; i++) {
        // Cast to a Red-Black tree
        PRTL_RB_TREE rb_tree = (PRTL_RB_TREE)&data_segment[i];

        if (get_mem_type(rb_tree->Root) == heap) {
            PETW_USER_REG_ENTRY reg_entry = (PETW_USER_REG_ENTRY)rb_tree->Root;
            if (get_mem_type(reg_entry->Callback) == code) {
                return &data_segment[i];
            }
        }
    }

    return NULL;
}

// Parse the EtwpRegistrationTable and print registration entries
BOOL ParseRegistrationTable(DWORD pid) {
    CHAR sym_search_path[MAX_PATH] = { 0 };
    LPVOID pEtwRegTable = GetEtwpRegistrationTableVA();
    if (NULL == pEtwRegTable) {
        fprintf(stderr, "[!] Failed to get VA of EtwpRegistrationTable");
        return -1;
    }
    printf("[i] VA of EtwpRegistrationTable:\t0x%p\n", pEtwRegTable);

    // Open Handle to target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (NULL == hProcess) {
        perror("OpenProcess()");
        return FALSE;
    }

    // Load symbols when a reference is made requiring the symbols be loaded.
    (void)SymSetOptions(SYMOPT_DEFERRED_LOADS);

    // Initializes the symbol handler for a process.
    if (!SymInitialize(hProcess, NULL, TRUE)) {
        perror("SymInitialize()");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Retrieve the symbol search path
    if (SymGetSearchPath(hProcess, sym_search_path, MAX_PATH)) {
        CHAR _temp[MAX_PATH] = { 0 };
        printf("[i] Symbol Search Path:\t\t\t%s\n", _fullpath(_temp, sym_search_path, MAX_PATH));
    }

        
    // CleanUp
    if (!SymCleanup(hProcess)) {
        perror("SymCleanup()");
        CloseHandle(hProcess);
        return FALSE;
    }
    CloseHandle(hProcess);
    return TRUE;
}







