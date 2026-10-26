#include <windows.h>

// Minimal custom UNICODE_STRING definition
typedef struct _UNICODE_STRING_COMPACT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_COMPACT;

// Compact LDR entry definition aligned to x64 offsets
typedef struct _LDR_DATA_TABLE_ENTRY_COMPACT {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING_COMPACT FullDllName;
    UNICODE_STRING_COMPACT BaseDllName;
} LDR_DATA_TABLE_ENTRY_COMPACT;

// Custom inline wchar comparison to eliminate dependency on _wcsicmp / CRT
__forceinline BOOL WideStrEqualsIgnoreCase(PCWSTR s1, PCWSTR s2) {
    while (*s1 && *s2) {
        WCHAR c1 = *s1++;
        WCHAR c2 = *s2++;
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
        if (c1 != c2) return FALSE;
    }
    return (*s1 == L'\0' && *s2 == L'\0');
}

// Standalone function resolving kernel32.dll base address via GS:[0x60]
__forceinline PVOID GetKernel32Base(VOID) {
    // Offset 0x60 -> PEB, Offset 0x18 -> PEB_LDR_DATA
    PBYTE pPeb = (PBYTE)__readgsqword(0x60);
    PBYTE pLdr = *(PBYTE*)(pPeb + 0x18);

    // Offset 0x10 inside PEB_LDR_DATA -> InLoadOrderModuleList head
    PLIST_ENTRY pHead = (PLIST_ENTRY)(pLdr + 0x10);
    PLIST_ENTRY pCurr = pHead->Flink;

    while (pCurr != pHead) {
        LDR_DATA_TABLE_ENTRY_COMPACT* pEntry = (LDR_DATA_TABLE_ENTRY_COMPACT*)pCurr;

        if (pEntry->BaseDllName.Buffer != NULL) {
            if (WideStrEqualsIgnoreCase(pEntry->BaseDllName.Buffer, L"kernel32.dll")) {
                return pEntry->DllBase;
            }
        }
        pCurr = pCurr->Flink;
    }

    return NULL;
}

int main(VOID) {
    PVOID pKernel32 = GetKernel32Base();
    
    if (pKernel32) {
        // Base address resolved without CRT or API calls
    }

    return 0;
}
