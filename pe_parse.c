#include "utils.h"

HANDLE process = 0;

void print_optional_header64(IMAGE_OPTIONAL_HEADER64* op) {
    IMAGE_OPTIONAL_HEADER64 optional_header = *op;

    printf("\n=== IMAGE_OPTIONAL_HEADER64 ===\n");
    printf("Magic:                         0x%04X\n", optional_header.Magic);
    printf("MajorLinkerVersion:            %u\n", optional_header.MajorLinkerVersion);
    printf("MinorLinkerVersion:            %u\n", optional_header.MinorLinkerVersion);
    printf("SizeOfCode:                    0x%08X\n", optional_header.SizeOfCode);
    printf("SizeOfInitializedData:         0x%08X\n", optional_header.SizeOfInitializedData);
    printf("SizeOfUninitializedData:       0x%08X\n", optional_header.SizeOfUninitializedData);
    printf("AddressOfEntryPoint:           0x%08X\n", optional_header.AddressOfEntryPoint);
    printf("BaseOfCode:                    0x%08X\n", optional_header.BaseOfCode);
    printf("ImageBase:                     0x%016llX\n", optional_header.ImageBase);
    printf("SectionAlignment:              0x%08X\n", optional_header.SectionAlignment);
    printf("FileAlignment:                 0x%08X\n", optional_header.FileAlignment);
    printf("MajorOperatingSystemVersion:   %u\n", optional_header.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion:   %u\n", optional_header.MinorOperatingSystemVersion);
    printf("MajorImageVersion:             %u\n", optional_header.MajorImageVersion);
    printf("MinorImageVersion:             %u\n", optional_header.MinorImageVersion);
    printf("MajorSubsystemVersion:         %u\n", optional_header.MajorSubsystemVersion);
    printf("MinorSubsystemVersion:         %u\n", optional_header.MinorSubsystemVersion);
    printf("Win32VersionValue:             0x%08X\n", optional_header.Win32VersionValue);
    printf("SizeOfImage:                   0x%08X\n", optional_header.SizeOfImage);
    printf("SizeOfHeaders:                 0x%08X\n", optional_header.SizeOfHeaders);
    printf("CheckSum:                      0x%08X\n", optional_header.CheckSum);
    printf("Subsystem:                     %u\n", optional_header.Subsystem);
    printf("DllCharacteristics:            0x%04X\n", optional_header.DllCharacteristics);
    printf("SizeOfStackReserve:            0x%016llX\n", optional_header.SizeOfStackReserve);
    printf("SizeOfStackCommit:             0x%016llX\n", optional_header.SizeOfStackCommit);
    printf("SizeOfHeapReserve:             0x%016llX\n", optional_header.SizeOfHeapReserve);
    printf("SizeOfHeapCommit:              0x%016llX\n", optional_header.SizeOfHeapCommit);
    printf("LoaderFlags:                   0x%08X\n", optional_header.LoaderFlags);
    printf("NumberOfRvaAndSizes:           %u\n", optional_header.NumberOfRvaAndSizes);

    printf("=== Data Directories ===\n");

    for (int i = 0; i < optional_header.NumberOfRvaAndSizes && i < 15; i++) {
        switch (i) {
        case IMAGE_DIRECTORY_ENTRY_EXPORT:
            printf("IMAGE_DIRECTORY_ENTRY_EXPORT");
            break;
        case IMAGE_DIRECTORY_ENTRY_IMPORT:
            printf("IMAGE_DIRECTORY_ENTRY_IMPORT");
            break;
        case IMAGE_DIRECTORY_ENTRY_RESOURCE:
            printf("IMAGE_DIRECTORY_ENTRY_RESOURCE");
            break;
        case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
            printf("IMAGE_DIRECTORY_ENTRY_EXCEPTION");
            break;
        case IMAGE_DIRECTORY_ENTRY_SECURITY:
            printf("IMAGE_DIRECTORY_ENTRY_SECURITY");
            break;
        case IMAGE_DIRECTORY_ENTRY_BASERELOC:
            printf("IMAGE_DIRECTORY_ENTRY_BASERELOC");
            break;
        case IMAGE_DIRECTORY_ENTRY_DEBUG:
            printf("IMAGE_DIRECTORY_ENTRY_DEBUG");
            break;
        case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
            printf("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE");
            break;
        case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
            printf("IMAGE_DIRECTORY_ENTRY_GLOBALPTR");
            break;
        case IMAGE_DIRECTORY_ENTRY_TLS:
            printf("IMAGE_DIRECTORY_ENTRY_TLS");
            break;
        case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
            printf("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG");
            break;
        case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
            printf("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT");
            break;
        case IMAGE_DIRECTORY_ENTRY_IAT:
            printf("IMAGE_DIRECTORY_ENTRY_IAT");
            break;
        case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
            printf("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT");
            break;
        case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
            printf("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR");
            break;
        default:
            printf("UNKNOWN_DIRECTORY_ENTRY");
            break;
        }
        printf(" | [%2d] RVA: %p  Size: 0x%08X\n",
            i,
            optional_header.DataDirectory[i].VirtualAddress,
            optional_header.DataDirectory[i].Size);
    }
    printf("=============================\n\n");
}


DWORD pe_parse(void* BASE_ADDRESS, process_basic_info* pbi, char carry) {
    /*	PE PARSE	*/
    SIZE_T bytesread;

    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(pbi->process, BASE_ADDRESS, &dosHeader, sizeof(dosHeader), NULL)) {
        fprintf(stderr, "[!] Couldnt Read Process Memory: %lu\n", GetLastError());
        return;
    };

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "[!] Invalid Dos Header: %lu\n", GetLastError());
        return;
    }

#if _WIN64
    IMAGE_NT_HEADERS64 nt_header;
    if (!ReadProcessMemory(pbi->process, (LPVOID)((uintptr_t)BASE_ADDRESS + dosHeader.e_lfanew), &nt_header, sizeof(IMAGE_NT_HEADERS64), &bytesread)) {
        fprintf(stderr, "[!] Couldnt Read Process Memory: %lu\n", GetLastError());
        return;
    };

    if (nt_header.Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[!] Invalid Nt Header: %lu\n", GetLastError());
        return;
    }

    IMAGE_OPTIONAL_HEADER64 optional_header = nt_header.OptionalHeader;
#else // _WIN64
    IMAGE_NT_HEADERS32 nt_header;
    if (!ReadProcessMemory(pbi->process, (LPVOID)((uintptr_t)BASE_ADDRESS + dosHeader.e_lfanew), &nt_header, sizeof(IMAGE_NT_HEADERS32), &bytesread)) {
        fprintf(stderr, "[!] Couldnt Read Process Memory: %lu\n", GetLastError());
        return;
    };

    if (nt_header.Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[!] Invalid Nt Header: %lu\n", GetLastError());
        return;
    }

    IMAGE_OPTIONAL_HEADER32 optional_header = nt_header.OptionalHeader;
#endif

    if (carry) {
        print_optional_header64(&optional_header);
    }
    else {
        return optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }
    process = pbi->process;

    return 0;
};

void parse_iat(void* base_Address, void* rva) {
    SIZE_T bytesread;

    if (base_Address == NULL || rva == NULL) {
        fprintf(stderr, "[!] Invalid base or rva: %lu\n", GetLastError());
        return;
    }

    IMAGE_IMPORT_DESCRIPTOR iid;
    uintptr_t import_descriptor_addr = (uintptr_t)base_Address + (uintptr_t)rva;
    char name[100];

    while (1) {
        if (!ReadProcessMemory(process,
            (LPCVOID)import_descriptor_addr,
            &iid,
            sizeof(IMAGE_IMPORT_DESCRIPTOR),
            &bytesread)) {
            fprintf(stderr, "[!] Failed ReadProcessMemory: %lu\n", GetLastError());
            return;
        }

        if (iid.OriginalFirstThunk == 0 && iid.FirstThunk == 0)
            break;

        uintptr_t name_addr = (uintptr_t)base_Address + iid.Name;

        if (!ReadProcessMemory(process,
            (LPCVOID)name_addr,
            name,
            sizeof(name),
            &bytesread)) {
            fprintf(stderr, "[!] Failed to read DLL name: %lu\n", GetLastError());
            return;
        }

        name[sizeof(name) - 1] = '\0';
        printf("[+] DLL: [%s]\n", name);

        IMAGE_THUNK_DATA thunk_data;
        uintptr_t thunk_addr = (uintptr_t)base_Address + iid.OriginalFirstThunk;

        while (1) {
            if (!ReadProcessMemory(
                process,
                (LPCVOID)thunk_addr,
                &thunk_data,
                sizeof(IMAGE_THUNK_DATA),
                &bytesread
            )) {
                fprintf(stderr, "[!] Failed ReadProcessMemory for thunk: %lu\n", GetLastError());
                return;
            }

            if (thunk_data.u1.AddressOfData == 0)
                break;

            if (thunk_data.u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                break;
            }
            else {
                IMAGE_IMPORT_BY_NAME importByName;
                char function_name[100];
                uintptr_t func_name_addr = (uintptr_t)base_Address + thunk_data.u1.AddressOfData;

                if (!ReadProcessMemory(
                    process,
                    (LPCVOID)func_name_addr,
                    &importByName,
                    sizeof(importByName),
                    &bytesread
                )) {
                    fprintf(stderr, "[!] Failed to read function hint: %lu\n", GetLastError());
                    return;
                }

                if (!ReadProcessMemory(
                    process,
                    (LPCVOID)(func_name_addr + sizeof(WORD)),
                    function_name,
                    sizeof(function_name),
                    &bytesread
                )) {
                    fprintf(stderr, "[!] Failed to read function name: %lu\n", GetLastError());
                    return;
                }

                function_name[sizeof(function_name) - 1] = '\0';
                printf("\t|_ Function: %s | Address: %p\n", function_name, thunk_data.u1.Function);
            }

            thunk_addr += sizeof(IMAGE_THUNK_DATA);
        }

        import_descriptor_addr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    printf("\n");
}

void parse_eat(void* Base_Address, DWORD export_rva, process_basic_info* pbi, char carry) {
    SIZE_T bytesread;

    if (Base_Address == NULL || export_rva == 0) {
        fprintf(stderr, "[!] Invalid base or export_rva: %lu\n", GetLastError());
        return;
    }

    uintptr_t ied_address = (uintptr_t)Base_Address + export_rva;

    IMAGE_EXPORT_DIRECTORY ied;
    if (!ReadProcessMemory(
        pbi->process,
        (LPCVOID)ied_address,
        &ied,
        sizeof(ied),
        &bytesread)) {
        fprintf(stderr, "[!] ReadProcessMemory failed: %lu\n", GetLastError());
        return;
    }

    char dll_name[256] = { 0 };
    if (!ReadProcessMemory(
        pbi->process,
        (LPCVOID)((uintptr_t)Base_Address + ied.Name),
        dll_name,
        sizeof(dll_name) - 1,
        &bytesread)) {
        fprintf(stderr, "[!] failed to get Name from export: %lu\n", GetLastError());
        return;
    }

    if (!carry) {
        printf(" | file: %s ", dll_name);
        return;
    }
    else printf("[+] File: %s\n", dll_name);

    DWORD* nameRVAs = malloc(sizeof(DWORD) * ied.NumberOfNames);
    DWORD* functionAddresses = malloc(sizeof(DWORD) * ied.NumberOfFunctions);

    if (!ReadProcessMemory(
        pbi->process,
        (LPCVOID)((uintptr_t)Base_Address + ied.AddressOfNames),
        nameRVAs,
        sizeof(DWORD) * ied.NumberOfNames,
        &bytesread)) {
        fprintf(stderr, "[!] failed to read Name Pointer Table: %lu\n", GetLastError());
        free(nameRVAs);
        free(functionAddresses);
        return;
    }

    if (!ReadProcessMemory(
        pbi->process,
        (LPCVOID)((uintptr_t)Base_Address + ied.AddressOfFunctions),
        functionAddresses,
        sizeof(DWORD) * ied.NumberOfFunctions,
        &bytesread)) {
        fprintf(stderr, "[!] failed to read functions Pointer Table: %lu\n", GetLastError());
        free(nameRVAs);
        free(functionAddresses);
        return;
    }

    for (DWORD i = 0; i < ied.NumberOfNames; i++) {
        char name[100] = { 0 }; 

        uintptr_t nameAddress = (uintptr_t)Base_Address + nameRVAs[i];

        if (!ReadProcessMemory(
            pbi->process,
            (LPCVOID)nameAddress,
            name,
            sizeof(name) - 1, 
            &bytesread)) {
            fprintf(stderr, "[!] failed to get function name from export: %lu\n", GetLastError());
            free(nameRVAs);
            free(functionAddresses);
            return;
        }

        printf("\t|_Exported function: %s | Address: %p\n", name, functionAddresses[i]);
    }
    printf("\n");

    free(nameRVAs);
    free(functionAddresses);
}
