#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

void EnumProcessActive();
void AttachDebuggerToProcess(DWORD pid);
void debugger_main_loop(DWORD pid);
void debugger_Examine_Regs(DWORD pid);
void debugger_monitor(void);
void EnumThreads(DWORD pid);
void debugger_Stepin_Mode(DWORD pid); 
unsigned char exit_stepping(void);

static inline void PrintFirst9BitsOfDR7(CONTEXT* cx) {
    unsigned long long dr7 = cx->Dr7;

    unsigned int first_9_bits = (unsigned int)(dr7 & 0x1FF);

    printf("\n==First 9 bits of DR7: 0x%03X==\n", first_9_bits);

    for (int i = 0; i < 9; ++i) {
        unsigned int bit = (first_9_bits >> i) & 1;
        printf("Bit %d: %u\n", i, bit);
    }
}

/* this is from chatgpt cuz my lazy ass just cant  */
static inline void PrintContext(CONTEXT* cx) {
    printf("\n=== General Purpose Registers ===\n");
    printf("RAX: 0x%llx\n", cx->Rax);
    printf("RBX: 0x%llx\n", cx->Rbx);
    printf("RCX: 0x%llx\n", cx->Rcx);
    printf("RDX: 0x%llx\n", cx->Rdx);
    printf("RSI: 0x%llx\n", cx->Rsi);
    printf("RDI: 0x%llx\n", cx->Rdi);
    printf("RBP: 0x%llx\n", cx->Rbp);
    printf("RSP: 0x%llx\n", cx->Rsp);
    printf("R8 : 0x%llx\n", cx->R8);
    printf("R9 : 0x%llx\n", cx->R9);
    printf("R10: 0x%llx\n", cx->R10);
    printf("R11: 0x%llx\n", cx->R11);
    printf("R12: 0x%llx\n", cx->R12);
    printf("R13: 0x%llx\n", cx->R13);
    printf("R14: 0x%llx\n", cx->R14);
    printf("R15: 0x%llx\n", cx->R15);
    printf("\n");

    printf("=== Instruction Pointer & Flags ===\n");
    printf("RIP: 0x%llx\n", cx->Rip);
    printf("EFlags: 0x%08lx\n", cx->EFlags);
    printf("\n");

    printf("=== Segment Registers ===\n");
    printf("CS: 0x%04lx\n", cx->SegCs);
    printf("DS: 0x%04lx\n", cx->SegDs);
    printf("ES: 0x%04lx\n", cx->SegEs);
    printf("FS: 0x%04lx\n", cx->SegFs);
    printf("GS: 0x%04lx\n", cx->SegGs);
    printf("SS: 0x%04lx\n", cx->SegSs);
    printf("\n");

    printf("=== Debug Registers ===\n");
    printf("DR0: 0x%llx\n", cx->Dr0);
    printf("DR1: 0x%llx\n", cx->Dr1);
    printf("DR2: 0x%llx\n", cx->Dr2);
    printf("DR3: 0x%llx\n", cx->Dr3);
    printf("DR6: 0x%llx\n", cx->Dr6);
    printf("DR7: 0x%llx\n", cx->Dr7);
    PrintFirst9BitsOfDR7(cx);
    printf("\n");

    // Floating point state, vector registers (XMM*) etc. can also be printed
    // if ContextFlags includes CONTEXT_FLOATING_POINT or CONTEXT_ALL.
    // Example for first XMM register:
    printf("=== XMM Registers (first 4 as example) ===\n");
    printf("XMM0: %I64x%I64x\n", cx->Xmm0.High, cx->Xmm0.Low);
    printf("XMM1: %I64x%I64x\n", cx->Xmm1.High, cx->Xmm1.Low);
    printf("XMM2: %I64x%I64x\n", cx->Xmm2.High, cx->Xmm2.Low);
    printf("XMM3: %I64x%I64x\n", cx->Xmm3.High, cx->Xmm3.Low);
    // add others if needed
}
