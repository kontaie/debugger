#include "utils.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage:\n\n%s help\n%s debug\n%s show\n", argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "help") == 0) {
        printf("niggers");
        return 0;
    }

    else if (strcmp(argv[1], "show") == 0) {
        EnumProcessActive();
        goto debug;
    }

    else if (strcmp(argv[1], "debug") == 0) {
        goto debug;
    }

    else {
        printf("Usage:\n\n%s help\n%s debug\n%s show\n", argv[0], argv[0], argv[0]);
        return 1;
    }

debug:
    printf("\n\n[!] Enter Process Id: ");
    DWORD pid;
    if (scanf("%lu", &pid) != 1 || pid == 0) {
        fprintf(stderr, "[-] Invalid input.\n");
        exit(EXIT_FAILURE);
    }
    AttachDebuggerToProcess(pid);

    return 0;
}
