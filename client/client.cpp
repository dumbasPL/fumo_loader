#include <Windows.h>
#include <iostream>
#include <vector>
#include <optional>
#include <TlHelp32.h>
#include <fumo_loader.h>

DWORD GetProcessIdByName(LPCWSTR lpProcessName);
std::optional<std::vector<BYTE>> ReadFileToBuffer(LPCWSTR lpFileName);

int main(int argc, char** argv) {
    DWORD pid = GetProcessIdByName(L"Notepad.exe");
    if (pid == 0) {
        std::cout << "Failed to get process id" << std::endl;
        return 1;
    }
    std::cout << "Found process with pid: " << pid << std::endl;

    auto buffer = ReadFileToBuffer(L"AllocConsole64.dll");
    if (!buffer.has_value()) {
        std::cout << "Failed to read file" << std::endl;
        return 1;
    }
    std::cout << "Read " << buffer.value().size() << " bytes from file" << std::endl;

    auto driver_ref = fumo_loader::DriverInterface::Open(FUMO_HOOKED_DRIVER_NAME_USER);
    if (!driver_ref) {
        std::cout << "Failed to open driver " << GetLastError() << std::endl;
        return 1;
    }
    auto& driver = driver_ref->get();

    auto version = driver.GetVersion();
    if (version == 0) {
        std::cout << "Failed to get driver version" << std::endl;
        return 1;
    }
    std::cout << "Driver version: " << version << std::endl;
    if (version != FUMO_DRIVER_VERSION) {
        std::cout << "Driver version mismatch, expected " << FUMO_DRIVER_VERSION << std::endl;
        return 1;
    }

    auto result = fumo_loader::MapImage(&driver, pid, buffer.value().data());
    if (result != ERROR_SUCCESS) {
        std::cout << "Failed to map image: " << result << std::endl;
        return 1;
    }
    std::cout << "Successfully mapped image" << std::endl;

    driver.Unload();

    return 0;
}

// helper function to get the pid of a process
DWORD GetProcessIdByName(LPCWSTR lpProcessName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create snapshot: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(hSnapshot, &entry)) {
        std::cout << "Failed to get first process: " << GetLastError() << std::endl;
        return 0;
    }

    do {
        if (wcscmp(entry.szExeFile, lpProcessName) == 0) {
            pid = entry.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &entry));

    CloseHandle(hSnapshot);

    if (pid == 0) {
        std::cout << "Failed to find process" << std::endl;
        return 0;
    }

    return pid;
}

// helper function to read a file into a buffer
std::optional<std::vector<BYTE>> ReadFileToBuffer(LPCWSTR lpFileName) {
    HANDLE hFile = CreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    LARGE_INTEGER file_size = {0};
    if (!GetFileSizeEx(hFile, &file_size)) {
        CloseHandle(hFile);
        return std::nullopt;
    }

    std::vector<BYTE> buffer(file_size.QuadPart);
    DWORD bytes_read = 0;
    if (!ReadFile(hFile, buffer.data(), (DWORD)buffer.size(), &bytes_read, nullptr)) {
        CloseHandle(hFile);
        return std::nullopt;
    }

    CloseHandle(hFile);
    return buffer;
}