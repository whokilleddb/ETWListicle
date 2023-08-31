# ETWListicle
List the ETW provider(s) in the registration table of a process

## Usage

```
ETWListicle.exe notepad.exe
```

## Code Breakdown
> Note that this section may exclude error checks just to keep things simple

As usual, we start with the main function:

```c
```

We read in the name of the target process as a command line argument, and pass it to the `GetProcEntry()` function along with a pointer to a `PROCESSENTRY32` struct. Let's look at `GetProcEntry()` function:

```c
// Get the PROCESSENTRY32 struct corresponding to a process
BOOL GetProcEntry(char *procname, PROCESSENTRY32* pe32) {
	PROCESSENTRY32 _temp = { 0 };
	_temp.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Process32First(hProcSnap, &_temp);
	while (Process32Next(hProcSnap, &_temp)) {
		if (lstrcmpiA(procname, _temp.szExeFile) == 0) {
			RtlMoveMemory(pe32, &_temp, sizeof(PROCESSENTRY32));
			CloseHandle(hProcSnap);
			return TRUE;
		}
	}
	CloseHandle(hProcSnap);
	return FALSE;
}
```

We use `CreateToolhelp32Snapshot()` to create a snapshot of all the system process and use a `Process32First()` and `Process32Next()` to iterate through the process entries in the system snapshot. If we get a match on the process name, we copy over the `PROCESSENTRY32` struct to the location pointed by the input pointer to populate it, and then return from the function.

Back in `main()`, if the function is runs successfully, we print the PID of the target process. Next up, we try to set `DEBUG` privileges for the current process using `SetDebugPrivilege()`. This would enable us read process memory of processes which we usually might not have access to. Breaking down the code for `SetDebugPrivilege()`, we get:

```c
BOOL SetDebugPrivilege(void) {
    LUID luid;
    HANDLE  hToken;
    TOKEN_PRIVILEGES tp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(
        hToken,                             // Handle to the token
        FALSE,                              // Modifies privileges as requested
        &tp,                                // Specifies the new privileges 
        sizeof(TOKEN_PRIVILEGES),           // Size of struct
        (PTOKEN_PRIVILEGES)NULL,            // We dont need a handle to old privilege token
        (PDWORD)NULL);                       // Ignore return length

    CloseHandle(hToken);
    return (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
}
```
I ripped this off [Enabling and Disabling Privileges in C++](https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--) - check it out for the indepth explanation, but TLDR: we modify the current process token and try to elevate the current process to have `DEBUG` privileges so that we can easily read process memory of the specified target. 

Now this is the part where we pull up our Decompilers and examine `ntdll!EtwEventRegister` in Ghidra:

![](./imgs/EtwEventRegister_Ghidra.png)

As we can see, `ntdll!EtwEventRegister` calls `ntdll!EtwNotificationRegister`, looking at the pseudocode for which in IDA-Pro. we get the following:

![](./imgs/EtwNotificationRegister_IDA.png)

It inturn makes a call to `ntdll!EtwpAllocateRegistration`. This function is responsible for allocating registrations in memory:
![](./imgs/EtwpAllocateRegistration_IDA.png)

We see that it calls `RtlAllocateHeap()` with the size parameter set to `0x100` aka, 256 bytes. If we looks at the `ETW_USER_REG_ENTRY` struct, we see that it is exactly 256 bytes, just as an extra set of confirmation: 

```c
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
```

Scrolling down on `ntdll!EtwNotificationRegister`, we see that it calls `ntdll!EtwpInsertRegistration` with the value returned from `ntdll!EtwpAllocateRegistration` (which, in all suspects, is the allocated heap address)

Loading up `ntdll!EtwpInsertRegistration` in IDA, we see a reference to `EtwpRegistrationTable`. According to [windows deep internals](https://redplait.blogspot.com/2012/03/etweventregister-on-w8-consumer-preview.html):

> "Now all registered items storing in red-black tree whose root placed in EtwpRegistrationTable"

So now that we know that we have the `EtwpRegistrationTable` structure present in the `.data` segment of ntdll, we bruteforce our way and try to locate it's virtual address. 

Coming back to `main()`, we use the `GetEtwpRegistrationTableVA()` function to fetch the address of the table. To understand how the `GetEtwpRegistrationTableVA()` function, we take a look into it's source code:

```c
LPVOID GetEtwpRegistrationTableVA(void) {
    DWORD bcount = 0;
    PULONG_PTR data_segment = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)hNtdll + pDosHdr->e_lfanew);

    PIMAGE_SECTION_HEADER pSecHdr = (PIMAGE_SECTION_HEADER)((LPBYTE)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader);

    for (DWORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
        if (*(PDWORD)pSecHdr[i].Name == *(PDWORD)".data") {
            data_segment = (PULONG_PTR)((ULONG_PTR)hNtdll + pSecHdr[i].VirtualAddress);
            bcount = pSecHdr[i].Misc.VirtualSize / sizeof(ULONG_PTR);
            break;
        }
    }

    for (DWORD i = 0; i < bcount - 1; i++) {
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
```

---

Going on a tangent here, I want to discuss the `get_mem_type()` function. Its a very hacky function based off a [stackoverflow answer](https://stackoverflow.com/a/59635651). Essentially, I wanted a way to figure out the kind of memory region a pointer points to, primarily to check if it's on the heap or in the code section. Time to break the function down as such:

```c
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

	if (ptr == NULL)  return invalid;

	SIZE_T ret = VirtualQuery(ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	if (ret == 0) return invalid;
	
	if (ret != sizeof(MEMORY_BASIC_INFORMATION)) return invalid;

	if (mbi.State != MEM_COMMIT) return invalid;

	if (mbi.Protect == PAGE_NOACCESS) return invalid;

	if (mbi.Protect == PAGE_READWRITE) {
		if (mbi.Type == MEM_PRIVATE) return heap;
		if (mbi.Type == MEM_IMAGE) return data;
	}

	if (mbi.Type == MEM_IMAGE && mbi.Protect == PAGE_EXECUTE_READ) return code;

	if (mbi.Type == MEM_MAPPED) return mapped;

	return unknown;
}
```
The function uses `VirtualQuery()` function to get information about the memory pages. Now, if a page has:

- RW permissions and the memory is private, it usually indicates pointers on the heap (especially note that the heap cannot have execute permissions)
- If the memory pages within the region are mapped into the view of an image section and is RX, we can say that it belongs to the code section (remember that you cannot write to a code section)

---

Back to `GetEtwpRegistrationTableVA()`. I came across [this stackoverflow question](https://stackoverflow.com/a/6127080) which demonstrates how we can use `GetModuleHandle()` to find the base address of ntdll in memory (even I forget at times that `HMODULE` essentially represents the base address of the module in memory.) We parse the memory to locate the `.data` section. Now comes the tricky part:

```c
PRTL_RB_TREE rb_tree = (PRTL_RB_TREE)&data_segment[i];
if (get_mem_type(rb_tree->Root) == heap) {
    PETW_USER_REG_ENTRY reg_entry = (PETW_USER_REG_ENTRY)rb_tree->Root;
    if (get_mem_type(reg_entry->Callback) == code) {
        return &data_segment[i];
    }
}
```
We iterate through the data segment and cast each memory pointer into a `PRTL_RB_TREE`, thereby assuming that we have a Reb-Black tree struct in that region. Why do we do this? Because remember when [windows deep internals](https://redplait.blogspot.com/2012/03/etweventregister-on-w8-consumer-preview.html) said?

> "Now all registered items storing in red-black tree whose root placed in EtwpRegistrationTable"

And since `ntdll!EtwpAllocateRegistration` allocates registration entries on the heap using `RtlAllocateHeap()`, we check if the `Root` entry points to an address on the heap. That's check uno. Assuming we pass check one, we cast the memory pointed by the `Root` entry of the Red-Black tree into a `PETW_USER_REG_ENTRY`, essentially casting the memory region into a `ETW_USER_REG_ENTRY` and verify if the `Callback` parameter points to a region in the code segment, because it essentially points to a callback function(that is pretty self explanatory).

So, if both the checks pass, we can say that we have successfully located the `EtwpRegistrationTable`. Just to verify that we got this correct, we can put a breakpoint in our code and, at the same time, verify the same with WinDBG:

![](./imgs/etwp_reg_table_debug.png)

