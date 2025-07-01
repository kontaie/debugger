#include "utils.h"

void EnumProcessActive() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failed to create snapshot Error: %lu\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    PROCESSENTRY32W proc_entry;
    proc_entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snap, &proc_entry)) {
        do {
            wprintf(L"[+] Process: %s | %lu\n",
                proc_entry.szExeFile, proc_entry.th32ProcessID);
        } while (Process32NextW(snap, &proc_entry));
    }
    else {
        fprintf(stderr, "[-] Process32FirstW failed Error: %lu\n", GetLastError());
        CloseHandle(snap);
        exit(EXIT_FAILURE);
    }

    CloseHandle(snap);
}