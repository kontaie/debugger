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

process_basic_info* init_pbi(DWORD pid) {
    if (pid <= 0) {
        fprintf(stderr, "[-] Failed invalid pid");
        exit(EXIT_FAILURE);
    };

    process_basic_info* _pbi = (process_basic_info*)malloc(sizeof(process_basic_info));
    if (!_pbi) {
        fprintf(stderr, "[-] malloc failed");
        exit(EXIT_FAILURE);
    };

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (process == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failed to get Process Handle");
        free(_pbi);
        exit(EXIT_FAILURE);
    };

    _pbi->process = process;
    _pbi->pid = pid;

    return _pbi;
}

void free_pbi(process_basic_info* pbi) {
    if (!pbi) {
        fprintf(stderr, "[-] invalid pbi");
        exit(EXIT_FAILURE);
    }

    if (pbi->process == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] invalid Process Handle");
        free(pbi);
        return;
    };

    CloseHandle(pbi->process);
    free(pbi);
}

void EnumThreads(DWORD pid) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failed to create snapshot Error: %lu\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(h, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                printf("[!]Thread: %lu\n",
                    te.th32ThreadID);
            }
        } while (Thread32Next(h, &te));
    }
    CloseHandle(h);
}