#include "fumo_loader.h"
#include "tray_icon.h"

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

    tray_icon->send_notification(L"Loader has been deleted");

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