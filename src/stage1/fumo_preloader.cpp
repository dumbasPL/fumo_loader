#include "fumo_preloader.h"
#include <libKDU.h>
#include <lazy_importer.hpp>
#include <fumo_drv_data.h>
#include <stage2_data.h>

int load_stage2(HANDLE process, std::vector<BYTE>& fumo_data) {
    // save process name in case it dies mid way through
    auto process_name = get_proces_name(process);

    // parse stage2 header
    LPVOID local_stage2_data = res::stage2_data.data();
    auto dos_header = (PIMAGE_DOS_HEADER)local_stage2_data;
    auto nt_headers = (PIMAGE_NT_HEADERS)((ULONG_PTR)local_stage2_data + dos_header->e_lfanew);

    // allocate memory for stage2 in the target process
    ULONG_PTR stage2_base = (ULONG_PTR)VirtualAllocEx(process, NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (stage2_base == NULL)
        return fumo::error(ERR_STAGE1_FAILED_TO_ALLOCATE_MEMORY, L"Failed to allocate memory in {}", process_name);
    
    // allocate local memory for stage2
    ULONG_PTR stage2_local_base = (ULONG_PTR)VirtualAlloc(NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (stage2_local_base == NULL) {
        VirtualFreeEx(process, (LPVOID)stage2_base, 0, MEM_RELEASE);
        return fumo::error(ERR_STAGE1_FAILED_TO_ALLOCATE_MEMORY, L"Failed to allocate memory for module in {}", process_name);
    }
    
    // copy headers
    memcpy((PVOID)stage2_local_base, local_stage2_data, nt_headers->OptionalHeader.SizeOfHeaders);
    dos_header = (PIMAGE_DOS_HEADER)stage2_local_base;
    nt_headers = (PIMAGE_NT_HEADERS)(stage2_local_base + dos_header->e_lfanew);

    // map sections
    auto section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        auto section = &section_header[i];
        if (section->SizeOfRawData == 0)
            continue;
        auto section_data = (PVOID)((ULONG_PTR)local_stage2_data + section->PointerToRawData);
        memcpy((PVOID)(stage2_local_base + section->VirtualAddress), section_data, section->SizeOfRawData);
    }

    // relocate the image
    auto delta = (ULONG_PTR)stage2_base - nt_headers->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto base_relocation = (PIMAGE_BASE_RELOCATION)(stage2_local_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (base_relocation->VirtualAddress != 0) {
            auto relocation = (PWORD)((ULONG_PTR)base_relocation + sizeof(IMAGE_BASE_RELOCATION));
            auto number_of_relocations = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (auto i = 0; i < number_of_relocations; i++) {
                auto type = relocation[i] >> 12;
                if (type == IMAGE_REL_BASED_DIR64) {
                    auto address = (PULONG_PTR)(stage2_local_base + base_relocation->VirtualAddress + (relocation[i] & 0xFFF));
                    *address += delta;
                } else if (type != IMAGE_REL_BASED_ABSOLUTE)
                    return fumo::error(ERR_STAGE1_FAILED_TO_RELOCATE_MODULE, L"Failed to relocate module");
            }
            base_relocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)base_relocation + base_relocation->SizeOfBlock);
        }
    }

    // write stage2 to target process
    if (!WriteProcessMemory(process, (LPVOID)stage2_base, (LPCVOID)stage2_local_base, nt_headers->OptionalHeader.SizeOfImage, NULL)) {
        VirtualFreeEx(process, (LPVOID)stage2_base, 0, MEM_RELEASE);   
        return fumo::error(ERR_STAGE1_FAILED_TO_WRITE_MEMORY, L"Failed to write stage2 to {}", process_name);
    }
    
    // free local memory
    VirtualFree((LPVOID)stage2_local_base, 0, MEM_RELEASE);

    // allocate memory for stage2 loader in the target process
    ULONG_PTR fumo_data_base = (ULONG_PTR)VirtualAllocEx(process, NULL, fumo_data.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (fumo_data_base == NULL) {
        VirtualFreeEx(process, (LPVOID)stage2_base, 0, MEM_RELEASE);
        return fumo::error(ERR_STAGE1_FAILED_TO_ALLOCATE_MEMORY, L"Failed to allocate memory for data in {}", process_name);
    }

    // write fumo data to target process
    if (!WriteProcessMemory(process, (LPVOID)fumo_data_base, fumo_data.data(), fumo_data.size(), NULL)) {
        VirtualFreeEx(process, (LPVOID)stage2_base, 0, MEM_RELEASE);
        VirtualFreeEx(process, (LPVOID)fumo_data_base, 0, MEM_RELEASE);
        return fumo::error(ERR_STAGE1_FAILED_TO_WRITE_MEMORY, L"Failed to write fumo data to {}", process_name);
    }

    STAGE2_LOADER_DATA loader_data = { 0 };
    loader_data.stage2_base = (ULONG_PTR)stage2_base;
    loader_data.fumo_data_base = (ULONG_PTR)fumo_data_base;
    loader_data.loader_pid = GetCurrentProcessId();

    SIZE_T shellcode_size = (SIZE_T)stage2_loader_shellcode_end - (SIZE_T)stage2_loader_shellcode;
    SIZE_T shellcode_data_size = sizeof(STAGE2_LOADER_DATA);

    // allocate memory for shellcode in the target process
    ULONG_PTR shellcode_base = (ULONG_PTR)VirtualAllocEx(process, NULL, shellcode_size + shellcode_data_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode_base == NULL) {
        VirtualFreeEx(process, (LPVOID)stage2_base, 0, MEM_RELEASE);
        VirtualFreeEx(process, (LPVOID)fumo_data_base, 0, MEM_RELEASE);
        return fumo::error(ERR_STAGE1_FAILED_TO_ALLOCATE_MEMORY, L"Failed to allocate memory for shellcode in {}", process_name);
    }

    // write shellcode to target process
    ULONG_PTR shellcode_data_base = shellcode_base + shellcode_size;
    if (
        !WriteProcessMemory(process, (LPVOID)shellcode_base, (LPCVOID)stage2_loader_shellcode, shellcode_size, NULL) ||
        !WriteProcessMemory(process, (LPVOID)shellcode_data_base, (LPCVOID)&loader_data, sizeof(STAGE2_LOADER_DATA), NULL)
    ) {
        VirtualFreeEx(process, (LPVOID)stage2_base, 0, MEM_RELEASE);
        VirtualFreeEx(process, (LPVOID)fumo_data_base, 0, MEM_RELEASE);
        VirtualFreeEx(process, (LPVOID)shellcode_base, 0, MEM_RELEASE);
        return fumo::error(ERR_STAGE1_FAILED_TO_WRITE_MEMORY, L"Failed to write shellcode to {}", process_name);
    }

    // execute shellcode
    HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)shellcode_base, (LPVOID)shellcode_data_base, 0, NULL);
    if (thread == NULL) {
        VirtualFreeEx(process, (LPVOID)stage2_base, 0, MEM_RELEASE);
        VirtualFreeEx(process, (LPVOID)fumo_data_base, 0, MEM_RELEASE);
        VirtualFreeEx(process, (LPVOID)shellcode_base, 0, MEM_RELEASE);
        return fumo::error(ERR_STAGE1_FAILED_TO_EXECUTE_SHELLCODE, L"Failed to execute shellcode in {}", process_name);
    }

    DWORD wait_result = WaitForSingleObject(thread, INFINITE);
    if (wait_result != WAIT_OBJECT_0) {
        CloseHandle(thread);
        VirtualFreeEx(process, (LPVOID)stage2_base, 0, MEM_RELEASE);
        VirtualFreeEx(process, (LPVOID)fumo_data_base, 0, MEM_RELEASE);
        VirtualFreeEx(process, (LPVOID)shellcode_base, 0, MEM_RELEASE);
        return fumo::error(ERR_STAGE1_FAILED_TO_EXECUTE_SHELLCODE, L"Failed to execute shellcode in {}", process_name);
    }

    // get shellcode exit code
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread);

    // free shellcode memory
    VirtualFreeEx(process, (LPVOID)shellcode_base, 0, MEM_RELEASE);

    // check return code
    if (exit_code != 0) {
        return fumo::error(ERR_STAGE1_FAILED_TO_EXECUTE_SHELLCODE, L"Failed to execute shellcode in {}, error code: {}", process_name, exit_code);
    }

    return ERR_STAGE1_SUCCESS;
}

DWORD stage2_loader_shellcode(PSTAGE2_LOADER_DATA loader_data) {
    auto fnLoadLibraryA = LI_FN(LoadLibraryA).get();
    auto fnGetProcAddress = LI_FN(GetProcAddress).get();

    // parse stage2 header
    auto dos_header = (PIMAGE_DOS_HEADER)loader_data->stage2_base;
    auto nt_headers = (PIMAGE_NT_HEADERS)(loader_data->stage2_base + dos_header->e_lfanew);
    auto section_header = IMAGE_FIRST_SECTION(nt_headers);

    // resolve imports
    auto import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(loader_data->stage2_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (import_descriptor->Name != 0) {
        auto module_name = (LPCSTR)(loader_data->stage2_base + import_descriptor->Name);
        auto module_base = fnLoadLibraryA(module_name);
        if (module_base == NULL)
            return 1;
        auto thunk_data = (PIMAGE_THUNK_DATA)(loader_data->stage2_base + import_descriptor->FirstThunk);
        auto import_address = (PULONG_PTR)(loader_data->stage2_base + import_descriptor->FirstThunk);
        while (thunk_data->u1.AddressOfData != 0) {
            if (thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                *import_address = (ULONG_PTR)fnGetProcAddress(module_base, (LPCSTR)(thunk_data->u1.Ordinal & 0xFFFF));
            }
            else {
                auto import_by_name = (PIMAGE_IMPORT_BY_NAME)(loader_data->stage2_base + thunk_data->u1.AddressOfData);
                *import_address = (ULONG_PTR)fnGetProcAddress(module_base, (LPCSTR)import_by_name->Name);
            }
            if (*import_address == NULL)
                return 2;
            thunk_data++;
            import_address++;
        }
        import_descriptor++;
    }


    // call entry point
    using fnDllMain = BOOL(WINAPI*)(HMODULE, DWORD, LPVOID);
    auto entry_point = (fnDllMain)(loader_data->stage2_base + nt_headers->OptionalHeader.AddressOfEntryPoint);
    BOOL success = entry_point((HMODULE)loader_data->stage2_base, DLL_PROCESS_ATTACH, loader_data);
    return success ? 0 : 1;
}

void stage2_loader_shellcode_end() {}

int init_driver(fumo::DriverInterface* pDriver, DWORD osBuildNumber, bool forceReload) {
    ULONG version;
    BOOL just_loaded = FALSE;
    if (!pDriver->GetVersion(&version)) {
        auto error = load_driver(osBuildNumber);
        if (error != ERR_STAGE1_SUCCESS)
            return error;

        just_loaded = TRUE;
        if (!pDriver->GetVersion(&version))
            return fumo::error(ERR_STAGE1_FAILED_TO_GET_DRIVER_VERSION, L"Failed to get driver version");
    }

    if (version != FUMO_DRIVER_VERSION || forceReload) {
        // if the driver we just loaded reports a wrong version something has gone terribly wrong
        if (just_loaded && !forceReload)
            return fumo::error(ERR_STAGE1_LOADED_DERIVER_VERSION_MISMATCH, L"Driver version mismatch (expected: {}, found: {})", FUMO_DRIVER_VERSION, version);

        // unload the old driver and try again
        pDriver->Unload();
        return init_driver(pDriver, osBuildNumber, false);
    }

    return ERR_STAGE1_SUCCESS;
}

int load_driver(DWORD osBuildNumber) {
    // FIXME: make the provider configurable
    if (!libKDUMapDriver(0, osBuildNumber, 34, 1, res::fumo_drv_data.data(), NULL, NULL))
        return fumo::error(ERR_STAGE1_FAILED_TO_MAP_DRIVER, L"Failed to map driver");

    return ERR_STAGE1_SUCCESS;
}

bool get_privilege(const TCHAR* Name) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid;
    if (!LookupPrivilegeValue(NULL, Name, &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES privileges;
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    return true;
}