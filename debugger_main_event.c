#include "utils.h"

#define TRAP_FLAG 0x00000100

process_basic_info* debugger_init_process(DWORD pid) {
    process_basic_info* process = init_pbi(pid); // already validates pid

    if (!DebugActiveProcess(pid)) {
        fprintf(stderr, "[-] Failed to attach debugger Error: %lu\n", GetLastError());
        free_pbi(process);
        exit(EXIT_FAILURE);
    }

    printf("[+] Successfully attached to process %lu\n", pid);
    return process;
}

void DebuggerReadMemory(void* RIP, process_basic_info* pbi) {
    if (RIP == NULL) {
        fprintf(stderr, "[-] Invalid Rip Error: %lu\n", GetLastError());
        return;
    };

    char instruction[32];
    SIZE_T bytes;
    if (!ReadProcessMemory(pbi->process, RIP, instruction, 32, &bytes)) {
        fprintf(stderr, "[-] Couldnt Read Process Memory Error: %lu\n", GetLastError());
        return;
    };

    for (int i = 0; i < 10; i++) {
        printf("%02X ", (unsigned char)instruction[i]);
    }

    printf("\n\n");
}

void print_regs(DWORD thread_id) {
    HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
    if (!thread) {
        fprintf(stderr, "[-] Invalid thread handle Error: %lu\n", GetLastError());
        return;
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(thread, &ctx)) {
        fprintf(stderr, "[-] Failed to get thread context Error: %lu\n", GetLastError());
        CloseHandle(thread);
        return;
    }

#ifdef _WIN64
    printf("\n=== Thread Registers (x64) ===\n");
    printf("RIP: 0x%llx\n", ctx.Rip);
    printf("RSP: 0x%llx\n", ctx.Rsp);
    printf("RBP: 0x%llx\n", ctx.Rbp);
    printf("RAX: 0x%llx\n", ctx.Rax);
    printf("RBX: 0x%llx\n", ctx.Rbx);
    printf("RCX: 0x%llx\n", ctx.Rcx);
    printf("RDX: 0x%llx\n", ctx.Rdx);
    printf("RSI: 0x%llx\n", ctx.Rsi);
    printf("RDI: 0x%llx\n", ctx.Rdi);
    printf("R8 : 0x%llx\n", ctx.R8);
    printf("R9 : 0x%llx\n", ctx.R9);
    printf("R10: 0x%llx\n", ctx.R10);
    printf("R11: 0x%llx\n", ctx.R11);
    printf("R12: 0x%llx\n", ctx.R12);
    printf("R13: 0x%llx\n", ctx.R13);
    printf("R14: 0x%llx\n", ctx.R14);
    printf("R15: 0x%llx\n", ctx.R15);
#else
    printf("\n=== Thread Registers (x86) ===\n");
    printf("EIP: 0x%08lx\n", ctx.Eip);
    printf("ESP: 0x%08lx\n", ctx.Esp);
    printf("EBP: 0x%08lx\n", ctx.Ebp);
    printf("EAX: 0x%08lx\n", ctx.Eax);
    printf("EBX: 0x%08lx\n", ctx.Ebx);
    printf("ECX: 0x%08lx\n", ctx.Ecx);
    printf("EDX: 0x%08lx\n", ctx.Edx);
    printf("ESI: 0x%08lx\n", ctx.Esi);
    printf("EDI: 0x%08lx\n", ctx.Edi);
#endif

    printf("EFlags: 0x%08lx\n", ctx.EFlags);
    printf("=============================\n");

    CloseHandle(thread);
}

void stepin_mode(process_basic_info* pbi) {
    EnumThreads(pbi->pid);

    DWORD tid = 0;
    printf("\n[!] Please enter thread id: ");
    scanf_s("%lu", &tid, sizeof(DWORD));

    if (tid == 0) {
        fprintf(stderr, "[-] Invalid Thread Id\n");
        return;
    }

    HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!thread) {
        fprintf(stderr, "[-] Failed to open thread Error: %lu\n", GetLastError());
        return;
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;

    if (!GetThreadContext(thread, &ctx)) {
        fprintf(stderr, "[-] Failed to get thread context Error: %lu\n", GetLastError());
        CloseHandle(thread);
        return;
    }

    ctx.EFlags |= TRAP_FLAG;

    if (!SetThreadContext(thread, &ctx)) {
        fprintf(stderr, "[-] Failed to set thread context Error: %lu\n", GetLastError());
        CloseHandle(thread);
        return;
    }

    printf("[+] Trap flag set stepping mode enabled\n");
    CloseHandle(thread);
}

void debug_print_dll_info(DEBUG_EVENT* de, process_basic_info* pbi) {
    LPVOID image_name_ptr = de->u.LoadDll.lpImageName;
    SIZE_T bytes_Read;

    if (!image_name_ptr) {
        printf("       No image file name | %p\n", de->u.LoadDll.lpBaseOfDll);
        return;
    }

#ifdef _WIN64
    ULONGLONG remoteStrAddr = 0;  
    if (!ReadProcessMemory(pbi->process, image_name_ptr, &remoteStrAddr, sizeof(remoteStrAddr), &bytes_Read)) {
        fprintf(stderr, "[-] Failed to read remote string pointer Error: %lu\n", GetLastError());
        return;
    }
#else
    ULONG remoteStrAddr = 0;
    if (!ReadProcessMemory(pbi->process, image_name_ptr, &remoteStrAddr, sizeof(remoteStrAddr), &bytes_Read)) {
        fprintf(stderr, "[-] Failed to read remote string pointer Error: %lu\n", GetLastError());
        return;
    }
#endif

    if (remoteStrAddr) {
        if (de->u.LoadDll.fUnicode) {
            wchar_t image_name_buffer[100] = { 0 };
            if (ReadProcessMemory(pbi->process, (LPCVOID)remoteStrAddr, image_name_buffer, sizeof(image_name_buffer), &bytes_Read)) {
                wprintf(L"       %s | %p\n", image_name_buffer, de->u.LoadDll.lpBaseOfDll);
            }
            else {
                fprintf(stderr, "[-] Failed to read DLL name string Error: %lu\n", GetLastError());
            }
        }
        else {
            char image_name_buffer[100] = { 0 };
            if (ReadProcessMemory(pbi->process, (LPCVOID)remoteStrAddr, image_name_buffer, sizeof(image_name_buffer), &bytes_Read)) {
                printf("       %s | %p\n", image_name_buffer, de->u.LoadDll.lpBaseOfDll);
            }
            else {
                fprintf(stderr, "[-] Failed to read DLL name string Error: %lu\n", GetLastError());
            }
        }
    }
    else {
        printf("[-] remoteStrAddr was NULL\n");
    }
}

void debug_print_process_info(DEBUG_EVENT* de, process_basic_info* pbi) {
    LPVOID image_name_ptr = de->u.CreateProcessInfo.lpImageName;
    SIZE_T bytes_Read;

    if (!image_name_ptr) {
        printf("       No image file name | %p\n", de->u.CreateProcessInfo.lpImageName);
        return;
    }

#ifdef _WIN64
    ULONGLONG remoteStrAddr = 0;
    if (!ReadProcessMemory(pbi->process, image_name_ptr, &remoteStrAddr, sizeof(remoteStrAddr), &bytes_Read)) {
        fprintf(stderr, "[-] Failed to read remote string pointer Error: %lu\n", GetLastError());
        return;
    }
#else
    ULONG remoteStrAddr = 0;
    if (!ReadProcessMemory(pbi->process, image_name_ptr, &remoteStrAddr, sizeof(remoteStrAddr), &bytes_Read)) {
        fprintf(stderr, "[-] Failed to read remote string pointer Error: %lu\n", GetLastError());
        return;
    }
#endif

    if (remoteStrAddr) {
        if (de->u.CreateProcessInfo.fUnicode) {
            wchar_t image_name_buffer[100] = { 0 };
            if (ReadProcessMemory(pbi->process, (LPCVOID)remoteStrAddr, image_name_buffer, sizeof(image_name_buffer), &bytes_Read)) {
                wprintf(L"       %s | %p\n", image_name_buffer, de->u.CreateProcessInfo.lpImageName);
            }
            else {
                fprintf(stderr, "[-] Failed to read DLL name string Error: %lu\n", GetLastError());
            }
        }
        else {
            char image_name_buffer[100] = { 0 };
            if (ReadProcessMemory(pbi->process, (LPCVOID)remoteStrAddr, image_name_buffer, sizeof(image_name_buffer), &bytes_Read)) {
                printf("       %s | %p\n", image_name_buffer, de->u.CreateProcessInfo.lpImageName);
            }
            else {
                fprintf(stderr, "[-] Failed to read DLL name string Error: %lu\n", GetLastError());
            }
        }
    }
    else {
        printf("[-] remoteStrAddr was NULL\n");
    }
}

void debug_main_event(process_basic_info* pbi) {
    stepin_mode(pbi); // initial step

    DEBUG_EVENT debug_event = { 0 };

    while (1) {
        if (WaitForDebugEventEx(&debug_event, INFINITE)) {
            DWORD cont_status = DBG_CONTINUE;

            switch (debug_event.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT:
                printf("EXCEPTION_DEBUG_EVENT - Code: 0x%08X\n",
                    debug_event.u.Exception.ExceptionRecord.ExceptionCode);
                break;
            case CREATE_PROCESS_DEBUG_EVENT:
                printf("CREATE_PROCESS_DEBUG_EVENT\n");
                debug_print_process_info(&debug_event, pbi);
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                printf("EXIT_PROCESS_DEBUG_EVENT\n");
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                printf("CREATE_THREAD_DEBUG_EVENT\n");
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                printf("EXIT_THREAD_DEBUG_EVENT\n");
                break;
            case LOAD_DLL_DEBUG_EVENT:
                printf("LOAD_DLL_DEBUG_EVENT");
                debug_print_dll_info(&debug_event, pbi);
                break;
            case UNLOAD_DLL_DEBUG_EVENT:
                printf("UNLOAD_DLL_DEBUG_EVENT\n");
                break;
            case OUTPUT_DEBUG_STRING_EVENT:
                printf("OUTPUT_DEBUG_STRING_EVENT\n");
                break;
            case RIP_EVENT:
                printf("RIP_EVENT\n");
                break;
            default:
                printf("[!] Unknown debug event code: %lu\n", debug_event.dwDebugEventCode);
                break;
            }

            // Show current instruction pointer
            HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
            if (thread) {
                CONTEXT ctx = { 0 };
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(thread, &ctx)) {
#ifdef _WIN64
                    printf("[%04lX] 0x%p\n", debug_event.dwThreadId, (PVOID)ctx.Rip);
#else
                    printf("[%04lX] 0x%p\n", debug_event.dwThreadId, (PVOID)ctx.Eip);
#endif
                }
                CloseHandle(thread);
            }

            char command[100] = { 0 };
            void* RIP = NULL;

            printf("> ");
            fgets(command, (int)_countof(command), stdin);
            command[strcspn(command, "\n")] = '\0';

            if (strcmp(command, "t") == 0) {
                HANDLE thread2 = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
                if (thread2) {
                    CONTEXT ctx2 = { 0 };
                    ctx2.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(thread2, &ctx2)) {
                        ctx2.EFlags |= TRAP_FLAG;
                        SetThreadContext(thread2, &ctx2);
                    }
                    CloseHandle(thread2);
                }
            }
            else if (strcmp(command, "g") == 0) {
                // do nothing continue running
            }
            else if (strcmp(command, "reg") == 0) {
                print_regs(debug_event.dwThreadId);
            }
            else if (sscanf_s(command, "db %p", &RIP) == 1) {
                DebuggerReadMemory(RIP, pbi);
            }
            else {
                printf("Unknown command, continuing...\n");
            }
contine_dbg:
            ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, cont_status);
        }
    }

    free_pbi(pbi);
}
