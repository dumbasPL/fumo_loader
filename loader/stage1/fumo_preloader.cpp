#include <Windows.h>

int stage1_main(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH) {
        return 0;
    }

    MessageBoxA(NULL, "Hello from stage!", "FUMO", MB_OK);
    return TRUE;
}