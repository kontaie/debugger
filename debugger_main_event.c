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

    debugger_main_loop();
}

void debugger_main_loop(void) {
    while (1) {
        printf("Enter Command ~> ");

        char command[20];
        scanf_s("%s", command, 20);

        if (strcmp(command, "stepin") == 0) {

        }
        else if (strcmp(command, "regs") == 0) {
            debugger_Examine_Regs();
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

void debugger_Examine_Regs(void) {

}

void debugger_monitor(void) {
    DEBUG_EVENT debug_ev;

    while (1) {
        if (WaitForDebugEvent(&debug_ev, INFINITE)) {

            switch (debug_ev.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                printf("[+] Process created Handle obtained.\n");
                break;

            case CREATE_THREAD_DEBUG_EVENT:
                printf("[+] Thread created\n");
                break;

            case EXCEPTION_DEBUG_EVENT:
                printf("[+] Exception occurred Code: 0x%08lx\n",
                    debug_ev.u.Exception.ExceptionRecord.ExceptionCode);
                break;

            case EXIT_PROCESS_DEBUG_EVENT:
                printf("[+] Process exited with code: %lu\n",
                    debug_ev.u.ExitProcess.dwExitCode);
                break;

            case EXIT_THREAD_DEBUG_EVENT:
                printf("[+] Thread exited with code: %lu\n",
                    debug_ev.u.ExitThread.dwExitCode);
                break;

            case LOAD_DLL_DEBUG_EVENT:
                printf("[+] DLL loaded\n");
                break;

            case UNLOAD_DLL_DEBUG_EVENT:
                printf("[+] DLL unloaded\n");
                break;

            case OUTPUT_DEBUG_STRING_EVENT:
                printf("[+] Debug string event\n");
                break;

            default:
                printf("[*] Unknown debug event: %lu\n", debug_ev.dwDebugEventCode);
                break;
            }

            ContinueDebugEvent(debug_ev.dwProcessId,
                debug_ev.dwThreadId,
                DBG_CONTINUE);
        }
        else {
            fprintf(stderr, "[-] WaitForDebugEvent failed Error: %lu\n", GetLastError());
            break;
        }
    }
}
