#include "utils.h"
#include <winternl.h>
#include <stdio.h>

void parse_teb(void* teb_Address, process_basic_info* pbi) {
    if (teb_Address == NULL) {
        fprintf(stderr, "[!] Invalid teb address: %lu\n", GetLastError());
        return;
    }

    BYTE teb_buffer[0x2000];  // a bit larger than 0x1000 to be safe
    SIZE_T bytesRead;

    if (!ReadProcessMemory(pbi->process, teb_Address, teb_buffer, sizeof(teb_buffer), &bytesRead)) {
        fprintf(stderr, "[!] Couldn’t read process memory: %lu\n", GetLastError());
        return;
    }

    printf("\n=== TEB (printing selected fields backwards) ===\n");

    PVOID* deallocationStack = (PVOID*)(teb_buffer + 0x1f18);
    printf("DeallocationStack: %p\n", *deallocationStack);

    ULONG* guaranteedStackBytes = (ULONG*)(teb_buffer + 0x1f10);
    printf("GuaranteedStackBytes: %lu\n", *guaranteedStackBytes);

    WCHAR* staticUnicodeBuffer = (WCHAR*)(teb_buffer + 0x1d78);
    printf("StaticUnicodeBuffer (first 5 chars): %.5ws\n", staticUnicodeBuffer);

    UNICODE_STRING* sus = (UNICODE_STRING*)(teb_buffer + 0x1d68);
    printf("StaticUnicodeString.Length: %d\n", sus->Length);
    printf("StaticUnicodeString.MaximumLength: %d\n", sus->MaximumLength);
    printf("StaticUnicodeString.Buffer: %p\n", sus->Buffer);

    NTSTATUS* exceptionCode = (NTSTATUS*)(teb_buffer + 0x1d64);
    printf("ExceptionCode: 0x%08X\n", *exceptionCode);

    ULONG* lastErrorValue = (ULONG*)(teb_buffer + 0x68);
    printf("LastErrorValue: %lu\n", *lastErrorValue);

    ULONG* countOfOwnedCriticalSections = (ULONG*)(teb_buffer + 0x6c);
    printf("CountOfOwnedCriticalSections: %lu\n", *countOfOwnedCriticalSections);

    CLIENT_ID* clientId = (CLIENT_ID*)(teb_buffer + 0x40);
    printf("ClientId.UniqueProcess: %p\n", clientId->UniqueProcess);
    printf("ClientId.UniqueThread: %p\n", clientId->UniqueThread);

    PVOID* peb = (PVOID*)(teb_buffer + 0x60);
    printf("ProcessEnvironmentBlock: %p\n\n", *peb);
}
