#include "utils.h"

void AttachDebuggerToProcess(DWORD pid) {
    if (pid == 0) {
        fprintf(stderr, "[-] Invalid PID: %lu\n", pid);
        exit(EXIT_FAILURE);
    }

    if (!DebugActiveProcess(pid)) {
        fprintf(stderr, "[-] Failed to attach debugger to PID %lu Error: %lu\n",
            pid, GetLastError());
        exit(EXIT_FAILURE);
    }

    printf("\n\n[!] Debugger attached to process\n");
    printf("# Commands: stepin, regs, monitor, exit\n");

    debugger_main_loop(pid);
}

void debugger_main_loop(DWORD pid) {
    while (1) {
        printf("Enter Command ~> ");

        char command[20];
        scanf_s("%s", command, 20);

        if (strcmp(command, "stepin") == 0) {
            debugger_Stepin_Mode(pid);
        }
        else if (strcmp(command, "regs") == 0) {
            debugger_Examine_Regs(pid);
        }
        else if (strcmp(command, "monitor") == 0) {
            debugger_monitor();
        }
        else if (strcmp(command, "exit") == 0) {
            break;
        }
        else {
            printf("invalid command");
        }

        memset(command, 0, 20);
    }
}

void debugger_Stepin_Mode(DWORD pid) {
    HANDLE halt_thread = CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)exit_stepping,
        NULL, 0,
        NULL);

    if (halt_thread == NULL) {
        fprintf(stderr, "[-] Failed to create stop_monitoring thread Error: %lu\n", GetLastError());
        return;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (process == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failed to create process handle Error: %lu\n", GetLastError());
        CloseHandle(halt_thread);
        return;
    }

    EnumThreads(pid);

    DWORD tid = 0;
    printf("\n[~] Please enter Thread ID: ");
    scanf("%lu", &tid);

    HANDLE thread = OpenThread(THREAD_ALL_ACCESS, 0, tid);
    if (thread == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failed to create thread handle Error: %lu\n", GetLastError());
        CloseHandle(process);
        CloseHandle(halt_thread);
        return;
    }

    CONTEXT cx;
    cx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &cx);

    DEBUG_EVENT debug_ev;

    cx.EFlags |= 0x100;
    if (!SetThreadContext(thread, &cx)) {
        fprintf(stderr, "[-] Failed to set thread context Error: %lu\n", GetLastError());
        CloseHandle(thread);
        CloseHandle(process);
        CloseHandle(halt_thread);
        return;
    };

    while (1) {
        HANDLE handles[1] = { halt_thread };
        DWORD wait_result = WaitForMultipleObjects(1, handles, FALSE, 0);
        if (wait_result == WAIT_OBJECT_0) {
            DWORD exit_code;
            GetExitCodeThread(halt_thread, &exit_code);

            cx.EFlags &= ~0x100;
            SetThreadContext(thread, &cx);

            printf("\n\n[!]Stopped stepping | Code: %lu\n", exit_code);
            break;
        }

        if (WaitForDebugEvent(&debug_ev, INFINITE)) {
            if (debug_ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                if (debug_ev.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                    printf("\ninstruction has been done\n");
                }
            }
            ContinueDebugEvent(debug_ev.dwProcessId, debug_ev.dwThreadId, DBG_CONTINUE);
        }
    }

    CloseHandle(process);
    CloseHandle(thread);
    CloseHandle(halt_thread);
}

void debugger_Examine_Regs(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (process == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failed to create process handle Error: %lu\n", GetLastError());
        return;
    }
    
    EnumThreads(pid);

    DWORD tid = 0;
    printf("\n[~] Please enter Thread ID: ");
    scanf("%lu", &tid);

    HANDLE thread = OpenThread(THREAD_ALL_ACCESS, 0, tid);
    if (thread == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failed to create thread handle Error: %lu\n", GetLastError());
        CloseHandle(process);
        return;
    }

    CONTEXT cx;
    cx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &cx);
    
    PrintContext(&cx);

    CloseHandle(thread);
    CloseHandle(process);
}

unsigned char stop_monitoring(void) {
    while (1) {
        Sleep(5000);
        printf("Do you wish to stop monitoring? y,n ");
        char choice;
        scanf("%c", &choice);
        if (choice == 'y') return 1;
        else if (choice == 'n') Sleep(10000);
        Sleep(10000);
    }
}

unsigned char exit_stepping(void) {
    while (1) {
        Sleep(5000);
        printf("Do you wish to stop step-in mode? y,n ");
        char choice;
        scanf("%c", &choice);
        if (choice == 'y') return 1;
        else if (choice == 'n') Sleep(10000);
        Sleep(10000);
    }
}

void debugger_monitor(void) {
    DEBUG_EVENT debug_ev;
    HANDLE halt_thread = CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)stop_monitoring,
        NULL, 0,
        NULL);

    if (halt_thread == NULL) {
        fprintf(stderr, "[-] Failed to create stop_monitoring thread Error: %lu\n", GetLastError());
        return;
    }

    while (1) {
        HANDLE handles[1] = { halt_thread };
        DWORD wait_result = WaitForMultipleObjects(1, handles, FALSE, 0);
        if (wait_result == WAIT_OBJECT_0) {
            DWORD exit_code;
            GetExitCodeThread(halt_thread, &exit_code);
            printf("\n\n[!]Stopped monitoring | Code: %lu\n", exit_code);
            break;
        }

        if (WaitForDebugEvent(&debug_ev, 100)) {
            switch (debug_ev.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
            {
                printf("\n[+] Process created & handle obtained\n");
                CREATE_PROCESS_DEBUG_INFO process_info = debug_ev.u.CreateProcessInfo;
                printf("\t|_ Process Handle: %p\n", process_info.hProcess);
                printf("\t|_ Main Thread Handle: %p\n", process_info.hThread);
                printf("\t|_ Main Thread Start Address: 0x%p\n", process_info.lpStartAddress);
                printf("\t|_ Image Base: 0x%p\n", process_info.lpBaseOfImage);
                printf("\t|_ File Handle: %p\n", process_info.hFile);
                break;
            }

            case CREATE_THREAD_DEBUG_EVENT:
            {
                printf("\n[+] Thread created\n");
                CREATE_THREAD_DEBUG_INFO thread_info = debug_ev.u.CreateThread;
                printf("\t|_ Thread Handle: %p\n", thread_info.hThread);
                printf("\t|_ Start Address: 0x%p\n", thread_info.lpStartAddress);
                printf("\t|_ Thread Local Base: 0x%p\n", thread_info.lpThreadLocalBase);
                break;
            }

            case EXCEPTION_DEBUG_EVENT:
            {
                printf("\n[+] Exception occurred\n");
                EXCEPTION_DEBUG_INFO exception = debug_ev.u.Exception;
                printf("\t|_ Exception Code: 0x%08lx\n", exception.ExceptionRecord.ExceptionCode);
                printf("\t|_ Exception Address: 0x%p\n", exception.ExceptionRecord.ExceptionAddress);
                printf("\t|_ First chance: %s\n", exception.dwFirstChance ? "Yes" : "No");
                break;
            }

            case EXIT_PROCESS_DEBUG_EVENT:
            {
                printf("\n[+] Process exited\n");
                printf("\t|_ Exit Code: %lu\n", debug_ev.u.ExitProcess.dwExitCode);
                break;
            }

            case EXIT_THREAD_DEBUG_EVENT:
            {
                printf("\n[+] Thread exited\n");
                printf("\t|_ Exit Code: %lu\n", debug_ev.u.ExitThread.dwExitCode);
                break;
            }

            case LOAD_DLL_DEBUG_EVENT:
            {
                printf("\n[+] DLL loaded\n");
                LOAD_DLL_DEBUG_INFO dll_info = debug_ev.u.LoadDll;
                printf("\t|_ DLL Base: 0x%p\n", dll_info.lpBaseOfDll);
                printf("\t|_ DLL Handle: %p\n", dll_info.hFile);
                break;
            }

            case UNLOAD_DLL_DEBUG_EVENT:
            {
                printf("\n[+] DLL unloaded\n");
                printf("\t|_ DLL Base: 0x%p\n", debug_ev.u.UnloadDll.lpBaseOfDll);
                break;
            }

            case OUTPUT_DEBUG_STRING_EVENT:
            {
                printf("\n[+] Debug string event\n");
                OUTPUT_DEBUG_STRING_INFO out_str = debug_ev.u.DebugString;
                printf("\t|_ Length: %lu\n", out_str.nDebugStringLength);
                printf("\t|_ Unicode: %s\n", out_str.fUnicode ? "Yes" : "No");
                break;
            }

            default:
            {
                printf("\n[*] Unknown debug event: %lu\n", debug_ev.dwDebugEventCode);
                break;
            }
            }

            ContinueDebugEvent(
                debug_ev.dwProcessId,
                debug_ev.dwThreadId,
                DBG_CONTINUE);
        }
    }

    CloseHandle(halt_thread);
}
