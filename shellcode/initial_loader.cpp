#include <Windows.h>
#include <winternl.h>
#include <lazy_importer.hpp>
#include <xorstr.hpp>
#include "imports.h"

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

extern "C" void initial_loader(ULONG_PTR xorKey) {
    // get module base
    ULONG_PTR base = (ULONG_PTR)LI_FN(GetModuleHandleA)(nullptr);

    // decrypt all sections
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

    // create new executable

    // allocate memory for new executable
    auto new_image_base = (ULONG_PTR)LI_FN(VirtualAlloc)(nullptr, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!new_image_base) {
        LI_FN(MessageBoxA)(nullptr, xorstr_("Failed to allocate memory for new executable"), xorstr_("Error"), MB_OK | MB_ICONERROR);
        return;
    }

    // copy headers
    inline_memcpy((PVOID)new_image_base, (PVOID)base, nt_headers->OptionalHeader.SizeOfHeaders);

    // update image base in new executable to the current base the executable is loaded at
    PIMAGE_NT_HEADERS new_nt_headers = (PIMAGE_NT_HEADERS)(new_image_base + ((PIMAGE_DOS_HEADER)new_image_base)->e_lfanew);
    new_nt_headers->OptionalHeader.ImageBase = base;

    // unmap sections
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        if (section->SizeOfRawData == 0) {
            continue;
        }
        inline_memcpy((PVOID)(new_image_base + section->PointerToRawData), (PVOID)(base + section->VirtualAddress), section->SizeOfRawData);
    }

    // generate a new random xor key
    ULONG seed = (ULONG)LI_FN(GetTickCount64)();
    ULONG_PTR new_xor_key = LI_FN(RtlRandomEx)(&seed);

    // re-encrypt all sections in new executable
    section_header = IMAGE_FIRST_SECTION(nt_headers);

    // encrypt all sections
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        // only encrypt sections that start with 'e' or 'l' (encrypted, loader)
        if (section->Name[0] == 'e' || section->Name[0] == 'l') {
            // encrypt section (8 bytes at a time)
            for (int j = 0; j < section->SizeOfRawData; j += sizeof(new_xor_key)) {
                auto data = (PULONG64)(new_image_base + section->PointerToRawData + j);
                *data ^= new_xor_key;
            }
        }
    }

    // generate a random file name
    char file_name[MAX_PATH];
    LI_FN(GetTempFileNameA)(xorstr_("."), nullptr, 0, file_name);

    // open file for the new executable
    auto file_handle = LI_FN(CreateFileA)(file_name, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle == INVALID_HANDLE_VALUE) {
        LI_FN(MessageBoxA)(nullptr, xorstr_("Failed to open file for new executable"), xorstr_("Error"), MB_OK | MB_ICONERROR);
        return;
    }

    // write new executable to disk
    DWORD bytes_written = 0;
    if (!LI_FN(WriteFile)(file_handle, (PVOID)new_image_base, nt_headers->OptionalHeader.SizeOfImage, &bytes_written, nullptr)) {
        LI_FN(MessageBoxA)(nullptr, xorstr_("Failed to write new executable to disk"), xorstr_("Error"), MB_OK | MB_ICONERROR);
        return;
    }

    // close file handle
    LI_FN(CloseHandle)(file_handle);

    // delete original executable
    LI_FN(DeleteFileA)(LI_FN(GetCommandLineA)());


    // display message box
    LI_FN(MessageBoxA)(nullptr, xorstr_("Successfully updated loader"), xorstr_("Success"), MB_OK | MB_ICONINFORMATION);
}