#include "fumo_loader.h"

std::wstring loader_process_name = L"";
STAGE2_LOADER_DATA loader_data;

int main(HANDLE loader_process) {
    // wait for the loader process to exit
    DWORD wait_result = WaitForSingleObject(loader_process, INFINITE);
    if (wait_result != WAIT_OBJECT_0)
        return fumo::error(ERR_STAGE2_FAILED_TO_WAIT_FOR_PROCESS, L"Failed to wait for loader process({}): {}", loader_process_name, wait_result);
    CloseHandle(loader_process);
    
    // delete the loader executable
    if (!DeleteFileW(loader_process_name.c_str()))
        return fumo::error(ERR_STAGE2_FAILED_TO_DELETE_LOADER, L"Failed to delete loader executable: {}", loader_process_name);

    return fumo::error(ERR_STAGE2_SUCCESS, L"lmao: {}", (void*)&loader_data);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH || lpvReserved == NULL)
        return FALSE;
    
    // copy the loader data since the one we get will be freed by the stage1 loader
    memcpy(&loader_data, lpvReserved, sizeof(STAGE2_LOADER_DATA));

    // open the loader process
    HANDLE loader_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, loader_data.loader_pid);
    if (loader_process == NULL)
        return fumo::error(ERR_STAGE2_FAILED_TO_OPEN_PROCESS, L"Failed to open loader process: {}", loader_data.loader_pid);
    
    // get the loader process name here since it will not be available after the loader process exits
    loader_process_name = get_proces_name(loader_process);

    // main loader thread
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)main, (LPVOID)loader_process, 0, NULL);
    if (hThread == NULL)
        return FALSE;
    
    CloseHandle(hThread);
    return TRUE;
}