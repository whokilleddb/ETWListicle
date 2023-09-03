#pragma once
#include "utils.h"

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

DWORD PROVIDER_COUNT = 0;

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

// Get ProviderName from GUID
BSTR Guid2Name(OLECHAR* id) {
    ITraceDataProvider* iTDataProv = NULL;
    BSTR name = NULL;
    
    // Create an instance of a COM class 
    HRESULT hr = CoCreateInstance(              
                    &CLSID_TraceDataProvider,               // CLSID (Class Identifier) of the TraceDataProvider Class
                    0,                                      // Indicates that the object is not being created as part of an aggregat
                    CLSCTX_INPROC_SERVER,                   // Indicates that the object should be created within the same process as the calling code.
                    &IID_ITraceDataProvider,                // Interface identifier for the ITraceDataProvider interface.
                    (LPVOID*)&iTDataProv);                        // Receive the interface pointer of the created object


    // query details for the provider GUID
    hr = iTDataProv->lpVtbl->Query(iTDataProv, id, NULL);

    if (hr != S_OK) {
        iTDataProv->lpVtbl->Release(iTDataProv);
        return L"Unknown";
        
    }
    hr = iTDataProv->lpVtbl->get_DisplayName(iTDataProv, &name);
    iTDataProv->lpVtbl->Release(iTDataProv);
    return hr == S_OK ? name : L"Unknown";
}

// Print Individual Nodes
VOID DumpNodeInfo(HANDLE hProcess, PRTL_BALANCED_NODE node, PETW_USER_REG_ENTRY uRegEntry) {
    OLECHAR guid[40];
    CHAR cbFile[MAX_PATH] = { 0 };
    CHAR ctxFile[MAX_PATH] = { 0 };
    BYTE buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)] = {0};
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;


    // Increase Provider Count
    PROVIDER_COUNT++;

    // Print Provider GUID
    StringFromGUID2(&uRegEntry->ProviderId, guid, sizeof(guid));
    wprintf(L"[%03d] Provider GUID:\t\t%s (%s)\n", PROVIDER_COUNT, guid, Guid2Name(guid));

    // Callback function executed in response to NtControlTrace
    if (GetMappedFileNameA(hProcess, (LPVOID)uRegEntry->Callback, cbFile, MAX_PATH) != 0) {
        (void)PathStripPathA(cbFile);
        printf("[%03d] Callback Function:\t0x%p :: %s", PROVIDER_COUNT, uRegEntry->Callback, cbFile);
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        if(SymFromAddr(hProcess, (ULONG_PTR)uRegEntry->Callback, NULL, pSymbol)) {
            printf("!%hs", pSymbol->Name);
        }
        printf("\n");
    }

    // Get Context
    if (GetMappedFileNameA(hProcess, (LPVOID)uRegEntry->CallbackContext, ctxFile, MAX_PATH) != 0) {
        (void)PathStripPathA(ctxFile);
        printf("[%03d] Callback Context:\t\t0x%p :: %s", PROVIDER_COUNT, uRegEntry->CallbackContext, ctxFile);
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        if (SymFromAddr(hProcess, (ULONG_PTR)uRegEntry->CallbackContext, NULL, pSymbol)) {
            printf("!%hs", pSymbol->Name);
        }
        printf("\n");
    }

    // Registration Handle to be used with EtwEventUnregister
    printf("[%03d] Registration Handle:\t0x%p\n", PROVIDER_COUNT, (PVOID)((ULONG64)node | (ULONG64)uRegEntry->RegIndex << 48));
    
    // Handle of thread for callback
    printf("[%03d] Callback Thread Handle:\t0x%p\n", PROVIDER_COUNT, (PVOID)uRegEntry->Thread);
    
    // Used to communicate with the kernel via NtTraceEvent
    printf("[%03d] ReplyHandle:\t\t0x%p\n", PROVIDER_COUNT, (PVOID)uRegEntry->ReplyHandle);
         
    printf("\n");
}

// Actual function to iterate through etw user registrations
VOID FetchUserEntries(HANDLE hProcess, PRTL_BALANCED_NODE node) {
    SIZE_T _read = 0;
    ETW_USER_REG_ENTRY etw_user_reg_entry = { 0 };

    if (node == NULL) {
        return;
    }

    if (!ReadProcessMemory(hProcess, (PBYTE)node, &etw_user_reg_entry, sizeof(ETW_USER_REG_ENTRY), &_read)) {
        perror("ReadProcessMemory()");
        return;
    }
    if (sizeof(ETW_USER_REG_ENTRY) != _read) {
        fprintf(stderr, "[!] ReadProcessMemory() returned incomplete data\n");
        return;
    }

    (void)DumpNodeInfo(hProcess, node, &etw_user_reg_entry);

    FetchUserEntries(hProcess, etw_user_reg_entry.RegList.Children[0]);
    FetchUserEntries(hProcess, etw_user_reg_entry.RegList.Children[1]);
}

// Parse the EtwpRegistrationTable and print registration entries
BOOL ParseRegistrationTable(DWORD pid) {
    SIZE_T _retlen = 0;
    RTL_RB_TREE rb_tree = { 0 };
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

    // Read EtwpRegistrationTable into memory
    if (!ReadProcessMemory(hProcess, (PBYTE)pEtwRegTable, (PBYTE)&rb_tree, sizeof(RTL_RB_TREE), &_retlen)) {
        perror("ReadProcessMemory()");
        CloseHandle(hProcess);
        return FALSE;
    }
    if (sizeof(RTL_RB_TREE) != _retlen) {
        fprintf(stderr, "[!] ReadProcessMemory() returned incomplete struct\n");
        CloseHandle(hProcess);
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

    // Initializes the COM library for use by the calling thread
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr != S_OK) {
        fprintf(stderr, "[!] CoInitializeEx() failed (0x%x)\n", hr);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Dump User Entries
    printf("[i] Dumping Registration Entries\n\n");
    (void)FetchUserEntries(hProcess, rb_tree.Root);

    printf("[i] Total Number of Entries:\t%d\n", PROVIDER_COUNT);

    // CleanUp
    if (!SymCleanup(hProcess)) {
        perror("SymCleanup()");
        CloseHandle(hProcess);
        return FALSE;
    }
    CloseHandle(hProcess);
    return TRUE;
}
