#include "util.h"

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

bool isHvciEnabled() {
    SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
    sci.Length = sizeof(sci);
    if (NT_SUCCESS(NtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), NULL))) {
        return sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED && 
          sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED;
    }
    return false;
}