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
void debug_main_event(process_basic_info* pbi, unsigned char stepin);
process_basic_info* debugger_init_process(DWORD pid);
DWORD pe_parse(void* BASE_ADDRESS, process_basic_info* pbi, char carry);
void debugger_process_peb(HANDLE process);
void debugger_process_info(DWORD proc);
void parse_iat(void* base_Address, void* rva);
void debugger_thread_info(HANDLE thread);
void parse_teb(void* teb_Address, process_basic_info* pbi);
void parse_eat(void* Base_Address, DWORD export_rva, process_basic_info* pbi, char carry);
void install_bp(void* addr, char dr, HANDLE Thread);