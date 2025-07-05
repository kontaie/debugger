#include "utils.h"

int main(int argc, char** argv) {
	if (argc < 2) {
		printf("Usage:\n\t%s dbg (pid)\n\t%s show\n\t%s help",
			argv[0], argv[0], argv[0]);

		return 1;
	}

	if (strcmp(argv[1], "help") == 0) {
		printf("Usage:\n\t%s dbg (pid)\n\t%s show\n\t%s help",
			argv[0], argv[0], argv[0]);

		return 1;
	}

	else if (strcmp(argv[1], "dbg") == 0) {
		if (argc < 3) {
			printf("\nplease Enter a PID");
			return 1;
		}
		else {
			DWORD pid = strtol(argv[2], NULL, 10);
			process_basic_info* pbi = debugger_init_process(pid);
			debug_main_event(pbi);
		};
	}

	else if (strcmp(argv[1], "show") == 0) {
		EnumProcessActive();
		return 0;
	}
}