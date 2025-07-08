#include "utils.h"
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* fNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS(NTAPI* fNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

void debugger_process_info(DWORD proc) {
    DWORD size = 0;

    fNtQuerySystemInformation pNtQuerySystemInformation =
        (fNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if (!pNtQuerySystemInformation) {
        fprintf(stderr, "[-] Failed to get NtQuerySystemInformation: %lu\n", GetLastError());
        return;
    }

    NTSTATUS status = pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);
    if (size <= 0) {
        fprintf(stderr, "[-] NtQuerySystemInformation failed: %lu\n", status);
        return;
    }

    PSYSTEM_PROCESS_INFORMATION proc_info = (PSYSTEM_PROCESS_INFORMATION)malloc(size);
    if (!proc_info) {
        fprintf(stderr, "[-] malloc failed: %lu\n", GetLastError());
        return;
    }

    status = pNtQuerySystemInformation(SystemProcessInformation, proc_info, size, &size);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] NtQuerySystemInformation failed: %lu\n", status);
        free(proc_info);
        return;
    }

    PSYSTEM_PROCESS_INFORMATION current = proc_info;
    do {
        if ((ULONG)((uintptr_t)current->UniqueProcessId) == proc) {
            printf("\n[+] Process Information:\n");

            if (current->ImageName.Buffer) {
                wprintf(L"\tImageName:\t%wZ\n", &current->ImageName);
            }
            else {
                printf("\tImageName:\t(null)\n");
            }

            printf("\tPID:\t%lu\n", (ULONG)(ULONG_PTR)current->UniqueProcessId);
            printf("\tParent (Reserved2):\t%p\n", current->Reserved2);
            printf("\tHandleCount:\t%lu\n", current->HandleCount);
            printf("\tSessionId:\t%lu\n", current->SessionId);
            printf("\tReserved3:\t%p\n", current->Reserved3);
            printf("\tReserved4:\t%lu\n", current->Reserved4);
            printf("\tReserved5:\t%p\n", current->Reserved5);
            printf("\tReserved6:\t%p\n", current->Reserved6);

            printf("\tReserved1 (48 bytes):\t");
            for (int i = 0; i < 48; ++i) {
                printf("%02X ", current->Reserved1[i]);
            }
            printf("\n");

            for (int i = 0; i < 6; ++i) {
                printf("\tReserved7[%d]:\t%lld\n", i, current->Reserved7[i].QuadPart);
            }
        }

        if (current->NextEntryOffset == 0)
            break;

        current = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)current + current->NextEntryOffset);

    } while (1);

    free(proc_info);
}


void debugger_process_peb(HANDLE process) {
    fNtQueryInformationProcess pNtQueryInformationProcess =
        (fNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!pNtQueryInformationProcess) {
        fprintf(stderr, "[-] Failed to get NtQueryInformationProcess\n");
        return;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG retlen = 0;

    NTSTATUS status = pNtQueryInformationProcess(
        process, ProcessBasicInformation, &pbi, sizeof(pbi), &retlen);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] NtQueryInformationProcess failed: %lu\n", status);
        return;
    }

    PEB peb;
    SIZE_T bytesread;
    if (!ReadProcessMemory(process, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesread)) {
        fprintf(stderr, "[-] ReadProcessMemory failed to read PEB: %lu\n", GetLastError());
        return;
    }

    printf("\n[+] PEB ADDRESS: %p\n", pbi.PebBaseAddress);
    printf("\tProcess ID: %lu\n", pbi.UniqueProcessId);
    printf("\tBeing Debugged: %d\n\n", peb.BeingDebugged);

    RTL_USER_PROCESS_PARAMETERS rtl;
    if (!ReadProcessMemory(process, peb.ProcessParameters, &rtl, sizeof(rtl), &bytesread)) {
        fprintf(stderr, "[-] ReadProcessMemory failed to read RTL_USER_PROCESS_PARAMETERS: %lu\n", GetLastError());
        return;
    }

    USHORT commandlen = rtl.CommandLine.Length;
    USHORT namelen = rtl.ImagePathName.Length;

    WCHAR* command = (WCHAR*)malloc(commandlen + sizeof(WCHAR));
    WCHAR* name = (WCHAR*)malloc(namelen + sizeof(WCHAR));

    if (!command || !name) {
        fprintf(stderr, "[-] malloc failed\n");
        return;
    }

    if (!ReadProcessMemory(process, rtl.ImagePathName.Buffer, name, namelen, &bytesread)) {
        fprintf(stderr, "[-] Failed to read ImagePathName.Buffer: %lu\n", GetLastError());
        goto cleanup;
    }
    name[namelen / sizeof(WCHAR)] = L'\0';

    if (!ReadProcessMemory(process, rtl.CommandLine.Buffer, command, commandlen, &bytesread)) {
        fprintf(stderr, "[-] Failed to read CommandLine.Buffer: %lu\n", GetLastError());
        goto cleanup;
    }
    command[commandlen / sizeof(WCHAR)] = L'\0';

    wprintf(L"[+] Process Name: %s\n[+] Command Line: %s\n\n", name, command);

cleanup:
    free(command);
    free(name);
}