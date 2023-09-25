#include "stage2.h"
#include "fumo_loader.h"
#include "tray_icon.h"
#include <fomo_common.h>
#include <util.h>
#include <sstream>

std::wstring loader_process_name = L"";
STAGE2_LOADER_DATA loader_data;
TrayIcon* tray_icon = NULL;

int main(HANDLE loader_process) {
    // wait for the loader process to exit
    DWORD wait_result = tray_icon->wait_for_object(loader_process, INFINITE, L"Waiting for loader process to exit");
    if (wait_result != WAIT_OBJECT_0)
        return fumo::error(ERR_STAGE2_FAILED_TO_WAIT_FOR_PROCESS, L"Failed to wait for loader process({}): {}", loader_process_name, wait_result);
    CloseHandle(loader_process);
    
    // delete the loader executable
    if (!DeleteFileW(loader_process_name.c_str()))
        return fumo::error(ERR_STAGE2_FAILED_TO_DELETE_LOADER, L"Failed to delete loader executable: {}", loader_process_name);
    
    PFUMO_DATA_HEADER header = (PFUMO_DATA_HEADER)loader_data.fumo_data_base;

    // check magic
    if (header->Magic != FUMO_MAGIC)
        return fumo::error(ERR_STAGE2_INVALID_MAGIC, L"Invalid data format", loader_process_name);
    
    // check version
    if (header->Version != FUMO_DATA_VERSION)
        return fumo::error(ERR_STAGE2_INVALID_VERSION, L"Invalid data version", loader_process_name);
    
    // decrypt the settings
    PBYTE settings_data = (PBYTE)header + sizeof(FUMO_DATA_HEADER);
    uint64_t xor_key = header->XorKey;
    for (int i = 0; i < header->SettingsSize; i += sizeof(xor_key)) {
        uint64_t* ptr = (uint64_t*)&settings_data[i];
        *ptr ^= xor_key;
    }

    // parse the settings
    DWORD settings_size = *(DWORD*)settings_data;
    settings_data += sizeof(DWORD);
    std::string settings((char*)settings_data, settings_size);
    std::stringstream settings_stream(settings);
    
    std::string process_name;
    std::string wait_for_modules_string;
    std::getline(settings_stream, process_name, ';');
    std::getline(settings_stream, wait_for_modules_string, ';');
    
    std::vector<std::string> wait_for_modules = split(wait_for_modules_string, ',');

    return fumo::error(ERR_STAGE2_SUCCESS, L"lmao: {}", (void*)&loader_data);
    // return ERR_STAGE2_SUCCESS;
}

DWORD stage2(LPVOID lpThreadParameter) {
    tray_icon = new TrayIcon(L"Fumo Loader");
    main((HANDLE)lpThreadParameter);
    delete tray_icon;
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH || lpvReserved == NULL)
        return FALSE;
    
    // copy the loader data since the one we get will be freed by the stage1 loader
    memcpy(&loader_data, lpvReserved, sizeof(STAGE2_LOADER_DATA));

    // open the loader process
    HANDLE loader_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, loader_data.loader_pid);
    if (loader_process == NULL) {
        fumo::error(ERR_STAGE2_FAILED_TO_OPEN_PROCESS, L"Failed to open loader process: {}", loader_data.loader_pid);
        return FALSE;
    }
    
    // get the loader process name here since it will not be available after the loader process exits
    loader_process_name = get_proces_name(loader_process);

    // main loader thread
    HANDLE hThread = CreateThread(NULL, 0, stage2, (LPVOID)loader_process, 0, NULL);
    if (hThread == NULL)
        return FALSE;
    
    CloseHandle(hThread);
    return TRUE;
}