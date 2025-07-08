#include "utils.h"
#include "THREADINFOCLASS.h"

typedef NTSTATUS(__stdcall* fNtQueryInformationThread)(
    HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG
    );

void debugger_thread_info(HANDLE thread) {
    if (thread == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Invalid Thread Handle %lu\n", GetLastError());
        return;
    }

    fNtQueryInformationThread pNtQueryInformationThread =
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");

    if (!pNtQueryInformationThread) {
        fprintf(stderr, "[!] Failed to get NtQueryInformationThread address: %lu\n", GetLastError());
        return;
    }

    THREAD_BASIC_INFORMATION thread_info;
    ULONG return_length = 0;

    NTSTATUS status = pNtQueryInformationThread(
        thread,
        (THREAD_INFORMATION_CLASS)0, 
        &thread_info,
        sizeof(thread_info),
        &return_length
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtQueryInformationThread failed: NTSTATUS=0x%08X\n", status);
        return;
    }

    printf("\n=== THREAD_BASIC_INFORMATION ===\n");
    printf("\tExitStatus:        0x%08X\n", (UINT)thread_info.ExitStatus);
    printf("\tTebBaseAddress:    %p\n", thread_info.TebBaseAddress);
    printf("\tClientId.UniqueProcess: %lu\n", (ULONG)(ULONG_PTR)thread_info.ClientId.UniqueProcess);
    printf("\tClientId.UniqueThread:  %lu\n", (ULONG)(ULONG_PTR)thread_info.ClientId.UniqueThread);
    printf("\tAffinityMask:      0x%p\n", (PVOID)thread_info.AffinityMask);
    printf("\tPriority:          %ld\n", (LONG)thread_info.Priority);
    printf("\tBasePriority:      %ld\n\n", (LONG)thread_info.BasePriority);
}
