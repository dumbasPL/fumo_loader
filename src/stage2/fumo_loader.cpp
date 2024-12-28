#include "fumo_loader.h"
#include "stage2.h"
#include <driver_interface.h>

using fnLdrLoadDll = NTSTATUS(NTAPI*)(DWORD64, PULONG Flags, PUNICODE_STRING ModuleFileName, HMODULE* ModuleHandle);
using fnLdrGetProcedureAddress = NTSTATUS(NTAPI*)(HMODULE ModuleHandle, PANSI_STRING FunctionName, WORD Ordinal, PVOID* FunctionAddress);
using fnRtlAnsiStringToUnicodeString = decltype(&RtlAnsiStringToUnicodeString);
using fnDllMain = BOOL(WINAPI*)(HMODULE hModule, DWORD dwReason, LPVOID lpReserved);

typedef struct _MANUAL_MAPPING_DATA {
    PVOID ImageBase;
    PVOID VirtualProtectStub;
    fnLdrLoadDll LdrLoadDll;
    fnLdrGetProcedureAddress LdrGetProcedureAddress;
    fnRtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString;
} MANUAL_MAPPING_DATA, *PMANUAL_MAPPING_DATA;

MANUAL_MAPPING_DATA GetManualMappingData(PVOID pImageBase, PVOID pVirtualProtectStub) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

    MANUAL_MAPPING_DATA data = {0};
    data.ImageBase = pImageBase;
    data.VirtualProtectStub = pVirtualProtectStub;
    data.LdrLoadDll = (fnLdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");
    data.LdrGetProcedureAddress = (fnLdrGetProcedureAddress)GetProcAddress(hNtdll, "LdrGetProcedureAddress");
    data.RtlAnsiStringToUnicodeString = (fnRtlAnsiStringToUnicodeString)GetProcAddress(hNtdll, "RtlAnsiStringToUnicodeString");
    return data;
}

std::array<uint8_t, 34> virtual_protect_stub = {
    // check if lpAddress is above 0x7FFFFFFEFFFF
    0x48, 0x89, 0xC8,                                           // mov rax, rcx
    0x48, 0xC1, 0xE8, 0x10,                                     // shr rax, 0x10
    0x48, 0x3D, 0xFE, 0xFF, 0xFF, 0x7F,                         // cmp rax, 0x7ffffffe
    0x76, 0x06,                                                 // jbe .call_original
    // return STATUS_SUCCESS
    0xB8, 0x01, 0x00, 0x00, 0x00,                               // mov eax, 0x1
    0xC3,                                                       // ret
    // .call_original
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, 0x0 - original VirtualProtect
    0x48, 0xFF, 0xE0                                            // rex.W jmp rax
};
constexpr ULONG_PTR virtual_protect_stub_orig_addr_off = 23;

#define tolower(c) ((c >= 'A' && c <= 'Z') ? c + 32 : c)

DWORD Shellcode(PMANUAL_MAPPING_DATA pMmData) {
    // resolve imports
    auto nt_headers = (PIMAGE_NT_HEADERS)((ULONG_PTR)pMmData->ImageBase + ((PIMAGE_DOS_HEADER)pMmData->ImageBase)->e_lfanew);
    auto import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pMmData->ImageBase + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (import_descriptor->Name != 0) {
        auto module_name = (PCHAR)((ULONG_PTR)pMmData->ImageBase + import_descriptor->Name);

        USHORT module_name_length = 0;
        while (module_name[module_name_length] != 0)
            module_name_length++;

        BOOL is_kernel32 = FALSE;
        CHAR kernel32[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'};
        if (module_name_length == sizeof(kernel32)) {
            is_kernel32 = TRUE;
            for (int i = 0; i < sizeof(kernel32); i++) {
                if (tolower(module_name[i]) != kernel32[i]) {
                    is_kernel32 = FALSE;
                    break;
                }
            }
        }

        ANSI_STRING ansi_module_name = {0};
        ansi_module_name.Buffer = module_name;
        ansi_module_name.Length = module_name_length;
        ansi_module_name.MaximumLength = module_name_length + 1;

        UNICODE_STRING unicode_module_name = {0};
        pMmData->RtlAnsiStringToUnicodeString(&unicode_module_name, &ansi_module_name, TRUE);

        HMODULE module_handle = nullptr;
        ULONG flags = 0;
        pMmData->LdrLoadDll(1, &flags, &unicode_module_name, &module_handle);

        auto original_first_thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)pMmData->ImageBase + import_descriptor->OriginalFirstThunk);
        auto first_thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)pMmData->ImageBase + import_descriptor->FirstThunk);

        while (original_first_thunk->u1.AddressOfData != 0) {
            PVOID function_address = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                auto function_ordinal = IMAGE_ORDINAL(original_first_thunk->u1.Ordinal);
                pMmData->LdrGetProcedureAddress(module_handle, nullptr, function_ordinal, &function_address);
            } else {
                auto import_by_name = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pMmData->ImageBase + original_first_thunk->u1.AddressOfData);
                auto function_name = (PCHAR)import_by_name->Name;

                USHORT function_name_length = 0;
                while (function_name[function_name_length] != 0)
                    function_name_length++;
                
                CHAR virtual_protect[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't'};
                BOOL is_virtual_protect = FALSE;
                if (is_kernel32 && function_name_length == sizeof(virtual_protect)) {
                    is_virtual_protect = TRUE;
                    for (int i = 0; i < sizeof(virtual_protect); i++) {
                        if (function_name[i] != virtual_protect[i]) {
                            is_virtual_protect = FALSE;
                            break;
                        }
                    }
                }
                
                ANSI_STRING ansi_function_name = {0};
                ansi_function_name.Buffer = function_name;
                ansi_function_name.Length = function_name_length;
                ansi_function_name.MaximumLength = function_name_length + 1;

                pMmData->LdrGetProcedureAddress(module_handle, &ansi_function_name, 0, &function_address);

                if (is_virtual_protect) {
                    auto virtual_protect_stub = (PBYTE)pMmData->VirtualProtectStub;
                    *(PVOID*)(virtual_protect_stub + virtual_protect_stub_orig_addr_off) = function_address;
                    function_address = virtual_protect_stub;
                }
            }

            first_thunk->u1.Function = (ULONG_PTR)function_address;

            original_first_thunk++;
            first_thunk++;
        }

        import_descriptor++;
    }

    // call entry point
    auto entry_point = (fnDllMain)((ULONG_PTR)pMmData->ImageBase + nt_headers->OptionalHeader.AddressOfEntryPoint);
    entry_point((HMODULE)pMmData->ImageBase, DLL_PROCESS_ATTACH, nullptr);

    return 0;
}

VOID Shellcode_End() {}

int MapImage(fumo::DriverInterface* pDriver, ULONG pid, PVOID pImage) {
    // parse the PE header
    auto dos_header = (PIMAGE_DOS_HEADER)pImage;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        return fumo::error(ERR_STAGE2_INVALID_PE_HEADER, L"Invalid PE header");

    // parse the NT header
    auto nt_headers = (PIMAGE_NT_HEADERS)((ULONG_PTR)pImage + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        return fumo::error(ERR_STAGE2_INVALID_PE_HEADER, L"Invalid PE header");

    // make sure the image is 64-bit
    if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return fumo::error(ERR_STAGE2_INVALID_PE_HEADER, L"Invalid PE header");

    ULONG size_of_shellcode = (ULONG)((SIZE_T)Shellcode_End - (SIZE_T)Shellcode);
    ULONG size_of_virtual_protect_stub = virtual_protect_stub.size();
    ULONG size_of_shellcode_data = sizeof(MANUAL_MAPPING_DATA);
    auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
    auto size_of_mapping = size_of_image + size_of_shellcode + size_of_virtual_protect_stub + size_of_shellcode_data;

    auto kernel_image = pDriver->AllocateKernelMemory(size_of_mapping);
    if (!kernel_image)
        return fumo::error(ERR_STAGE2_FAILED_TO_ALLOCATE_MEMORY, L"Failed to allocate kernel memory");

    // copy headers
    memcpy(kernel_image, pImage, nt_headers->OptionalHeader.SizeOfHeaders);

    // map sections
    auto section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        if (section->SizeOfRawData == 0)
            continue;
        auto section_data = (PVOID)((ULONG_PTR)pImage + section->PointerToRawData);
        memcpy((PVOID)((ULONG_PTR)kernel_image + section->VirtualAddress), section_data, section->SizeOfRawData);
    }

    // relocate the image
    auto delta = (ULONG_PTR)kernel_image - nt_headers->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto base_relocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)kernel_image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (base_relocation->VirtualAddress != 0) {
            auto relocation = (PWORD)((ULONG_PTR)base_relocation + sizeof(IMAGE_BASE_RELOCATION));
            auto number_of_relocations = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (auto i = 0; i < number_of_relocations; i++) {
                if (relocation[i] >> 12 == IMAGE_REL_BASED_DIR64) {
                    auto address = (PULONG_PTR)((ULONG_PTR)kernel_image + base_relocation->VirtualAddress + (relocation[i] & 0xFFF));
                    *address += delta;
                } 
                else if (relocation[i] >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                    auto address = (PULONG)((ULONG_PTR)kernel_image + base_relocation->VirtualAddress + (relocation[i] & 0xFFF));
                    *address += (ULONG)delta;
                }
                else if (relocation[i] >> 12 != IMAGE_REL_BASED_ABSOLUTE)
                    return fumo::error(ERR_STAGE2_FAILED_TO_MAP_FILE, L"Failed to map file (unsupported relocation type)");
            }
            base_relocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)base_relocation + base_relocation->SizeOfBlock);
        }
    }

    // write the shellcode
    auto shellcode_addr = (PVOID)((ULONG_PTR)kernel_image + size_of_image);
    memcpy(shellcode_addr, Shellcode, size_of_shellcode);

    // write the virtual protect stub
    auto virtual_protect_stub_addr = (PVOID)((ULONG_PTR)shellcode_addr + size_of_shellcode);
    memcpy(virtual_protect_stub_addr, virtual_protect_stub.data(), size_of_virtual_protect_stub);

    // write the manual mapping data
    auto manual_mapping_data = GetManualMappingData(kernel_image, virtual_protect_stub_addr);
    auto manual_mapping_data_addr = (PMANUAL_MAPPING_DATA)((ULONG_PTR)virtual_protect_stub_addr + size_of_virtual_protect_stub);
    memcpy(manual_mapping_data_addr, &manual_mapping_data, size_of_shellcode_data);

    if (!pDriver->ExposeKernelMemory(pid, kernel_image, size_of_mapping))
        return fumo::error(ERR_STAGE2_FAILED_TO_EXPOSE_MEMORY, L"Failed to expose kernel memory");

    if (!pDriver->ExecuteCode(pid, shellcode_addr, manual_mapping_data_addr))
        return fumo::error(ERR_STAGE2_FAILED_TO_EXECUTE, L"Failed to execute code");

    return ERR_STAGE2_SUCCESS;
}
