#include "fumo_preloader.h"
#include <filesystem>
#include <fstream>

bool get_debug_privileges() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
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

int main(PFUMO_EMBEDDED_DATA embedded_data) {
    std::vector<BYTE> fumo_data;
    std::wstring fumo_file_path;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    // use embedded data if present unless a file is specified
    if (argc != 2 && embedded_data && embedded_data->Data && embedded_data->Size > 0) {
        fumo_file_path = L"embedded_data";
        fumo_data.assign((PBYTE)embedded_data->Data, (PBYTE)embedded_data->Data + embedded_data->Size);
    }
    else {
        if (argc != 2) {
            auto exe_name = std::filesystem::path(argv[0]).filename().wstring();
            return fumo::error(ERR_STAGE1_INVALID_ARGS, 
                L"Invalid arguments.\nUsage: {} <fumo_file>\nTip: you can drag the .fumo file on the loader executable",
                exe_name);
        }

        std::filesystem::path fumo_file = argv[1];
        fumo_file_path = fumo_file.wstring();
        std::ifstream fumo_stream(fumo_file, std::ios::binary);
        if (!fumo_stream.is_open())
            return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_FILE, L"Failed to open file: {}", fumo_file_path);
        
        fumo_data.assign(std::istreambuf_iterator<char>(fumo_stream), std::istreambuf_iterator<char>());
        if (fumo_data.size() < sizeof(FUMO_DATA_HEADER) + 0x1000) // header + one page
            return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_FILE, L"File to small: {}", fumo_file_path);
    }

    PFUMO_DATA_HEADER header = (PFUMO_DATA_HEADER)fumo_data.data();

    // check magic
    if (header->Magic != FUMO_MAGIC)
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_FILE,
            L"Invalid file format: {}\nTip: use fumo_encoder to generate a .fumo file", fumo_file_path);
    
    // check version
    if (header->Version != FUMO_DATA_VERSION)
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_FILE,
            L"Invalid file version (expected: {}, found: {}): {}\nTip: use fumo_encoder to generate a .fumo file",
            fumo_file_path, FUMO_DATA_VERSION, header->Version);

    OSVERSIONINFO osv;
    osv.dwOSVersionInfoSize = sizeof(osv);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);

    if (osv.dwMajorVersion < MIN_OS_MAJOR_VERSION || osv.dwBuildNumber < MIN_OS_BUILD_NUMBER)
        return fumo::error(ERR_STAGE1_UNSUPPORTED_OS, L"Unsupported OS version: {}.{}.{}", osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber);

    if (isHvciEnabled())
        return fumo::error(ERR_STAGE1_HVCI_ENABLED, L"HyperVisor Code Integrity (HVCI) is enabled, please disable it and try again");
    
    if(!get_debug_privileges())
        return fumo::error(ERR_STAGE1_FAILED_TO_GET_DEBUG_PRIVILEGES, L"Failed to get debug privileges");

    auto error = init_driver(osv.dwBuildNumber);
    if (error != ERR_STAGE1_SUCCESS)
        return error;
    
    auto pid = find_process_by_name(FUMO_SECOND_STAGE_PROCESS_NAME);
    if (pid == 0)
        return fumo::error(ERR_STAGE1_FAILED_TO_FIND_PROCESS, L"Failed to find {}", FUMO_SECOND_STAGE_PROCESS_NAME);
    
    auto process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process == NULL)
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_PROCESS, L"Failed to open {}", FUMO_SECOND_STAGE_PROCESS_NAME);
    
    error = load_stage2(process, fumo_data);
    CloseHandle(process);

    return error;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH)
        return 0;

    return main((PFUMO_EMBEDDED_DATA)lpvReserved) == ERR_STAGE1_SUCCESS;
}