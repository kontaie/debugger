#include "utils.h"

long int BreakPointHandler(struct _EXCEPTION_POINTERS* ExceptionInfo);

void print_reg(CONTEXT* context) {
	CONTEXT ctx = *context;

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

}

void install_bp(void* addr, char dr, HANDLE Thread) {
	if (Thread == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[!] Invalid Handle for thread %lu", GetLastError());
		return;
	}

	if (addr == NULL) {
		fprintf(stderr, "[!] Invalid addr %lu", GetLastError());
		return;
	};

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(Thread, &ctx)) {
		fprintf(stderr, "[!] Counldnt Get thread Context %lu", GetLastError());
		return;
	};

	int bit;

	switch (dr) {
	case 0:
		ctx.Dr0 = addr;
		ctx.Dr7 |= (1 << 1);
		bit = (ctx.Dr7 >> 1) & 1;
		printf("\n[+]Hardware BreakPoint Set Successfully on Address: %p, DR7 -> G0 flag : 0x%08d\n\n", addr, bit);
		break;
	case 1:
		ctx.Dr1 = addr;
		ctx.Dr7 |= (1 << 3);
		bit = (ctx.Dr7 >> 3) & 1;
		printf("\n[+]Hardware BreakPoint Set Successfully on Address: %p, DR7 -> G1 flag : 0x%08d\n\n", addr, bit);
		break;
	case 2:
		ctx.Dr2 = addr;
		ctx.Dr7 |= (1 << 5);
		bit = (ctx.Dr7 >> 5) & 1;
		printf("\n[+]Hardware BreakPoint Set Successfully on Address: %p, DR7 -> G2 flag : 0x%08d\n\n", addr, bit);
		break;
	case 3:
		ctx.Dr3 = addr;
		ctx.Dr7 |= (1 << 7);
		bit = (ctx.Dr7 >> 7) & 1;
		printf("\n[+]Hardware BreakPoint Set Successfully on Address: %p, DR7 -> G3 flag : 0x%08d\n\n", addr, bit);
		break;
	default:
		break;
	}
	

	if (!SetThreadContext(Thread, &ctx)) {
		fprintf(stderr, "[!] Counldnt Set thread Context %lu", GetLastError());
		return;
	};

	AddVectoredExceptionHandler(1, BreakPointHandler);
}

long int BreakPointHandler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0x1337) {
		if (ExceptionInfo->ContextRecord->Dr0 != 0) {
			printf("\n\n[!] Hardware BreakPoint at DR0 Has Been Executed\n\n");

			char carry;
			scanf_s("%c", &carry, 1);
			if (carry)
				return EXCEPTION_CONTINUE_EXECUTION;
			else {
				while (1) {
					char command[100];
					printf("Bp > ");
					scanf_s("%s", command, 100);

					if (strcmp(command, "exit") == 0) {
						ExceptionInfo->ContextRecord->Dr7 &= ~(1 << 1);
						ExceptionInfo->ContextRecord->Dr0 = 0;
						printf("[!] Cleared DR0, DR7->G0 \n");
						return EXCEPTION_CONTINUE_EXECUTION;
					}
					else if (strcmp(command, "reg") == 0) {
						print_reg(ExceptionInfo->ContextRecord);
					}
					else {
						printf("[!] Unknown Command \n");
					}
				}

			}
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}