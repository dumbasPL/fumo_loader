#include "fumo_preloader.h"
#include <filesystem>
#include <fstream>

int main() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc != 2) {
        auto exe_name = std::filesystem::path(argv[0]).filename().wstring();
        return fumo::error(ERR_STAGE1_INVALID_ARGS, 
            L"Invalid arguments.\nUsage: {} <fumo_file>\nTip: you can drag the .fumo file on the loader executable",
            exe_name);
    }

    std::filesystem::path fumo_file = argv[1];
    std::ifstream fumo_stream(fumo_file, std::ios::binary);
    if (!fumo_stream.is_open())
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_FILE, L"Failed to open file: {}", fumo_file.wstring());
    
    std::vector<BYTE> fumo_data;
    fumo_data.assign(std::istreambuf_iterator<char>(fumo_stream), std::istreambuf_iterator<char>());
    if (fumo_data.size() < 0x1000 + 8 + 4) // header + xor key + magic
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_FILE, L"File to small: {}", fumo_file.wstring());

    // check magic
    if ('OMUF' != *(DWORD*)&fumo_data[0]) // FUMO
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_FILE,
            L"Invalid file format: {}\nTip: use fumo_encoder to generate a .fumo file", fumo_file.wstring());
    
    // check version
    DWORD file_version = *(DWORD*)&fumo_data[4];
    if (file_version != FUMO_DRIVER_VERSION)
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_FILE,
            L"Invalid file version (expected: {}, found: {}): {}\nTip: use fumo_encoder to generate a .fumo file",
            fumo_file.wstring(), FUMO_DRIVER_VERSION, file_version);

    OSVERSIONINFO osv;
    osv.dwOSVersionInfoSize = sizeof(osv);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);

    if (osv.dwMajorVersion < MIN_OS_MAJOR_VERSION || osv.dwBuildNumber < MIN_OS_BUILD_NUMBER)
        return fumo::error(ERR_STAGE1_UNSUPPORTED_OS, L"Unsupported OS version: {}.{}.{}", osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber);

    if (isHvciEnabled())
        return fumo::error(ERR_STAGE1_HVCI_ENABLED, L"HyperVisor Code Integrity (HVCI) is enabled, please disable it and try again");
    
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

    return main() == ERR_STAGE1_SUCCESS;
}