#include <Windows.h>
#include <fumo_drv_data.h>
#include <string>
#include <format>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH) {
        return 0;
    }

    std::string message = std::format("fumo_drv_data at: 0x{}, size: {} bytes", (void*)res::fumo_drv_data.data(), res::fumo_drv_data.size());

    MessageBoxA(NULL, message.c_str(), "FUMO", MB_OK);
    return TRUE;
}