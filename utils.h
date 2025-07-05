#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <stdlib.h>

typedef struct {
    HANDLE process;
    DWORD pid;
}process_basic_info;

void EnumProcessActive();
process_basic_info* init_pbi(DWORD pid);
void EnumThreads(DWORD pid);
void free_pbi(process_basic_info* pbi);
void debug_main_event(process_basic_info* pbi);
process_basic_info* debugger_init_process(DWORD pid);