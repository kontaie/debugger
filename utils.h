#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

void EnumProcessActive();
void AttachDebuggerToProcess(DWORD pid);
void debugger_main_loop(void);
void debugger_Examine_Regs(void);
void debugger_monitor(void);