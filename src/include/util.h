#pragma once
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <string>
#include <format>
#include <sstream>
#include <vector>
#include <locale>
#include <codecvt>

typedef struct _STAGE2_LOADER_DATA {
    ULONG_PTR stage2_base;
    ULONG_PTR fumo_data_base;
    DWORD loader_pid;
} STAGE2_LOADER_DATA, *PSTAGE2_LOADER_DATA;

typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION {
    union {
        ULONG KvaShadowFlags;
        struct {
            ULONG KvaShadowEnabled : 1;
            ULONG KvaShadowUserGlobal : 1;
            ULONG KvaShadowPcid : 1;
            ULONG KvaShadowInvpcid : 1;
            ULONG KvaShadowRequired : 1; // REDSTONE4
            ULONG KvaShadowRequiredAvailable : 1;
            ULONG InvalidPteBit : 6;
            ULONG L1DataCacheFlushSupported : 1;
            ULONG L1TerminalFaultMitigationPresent : 1;
            ULONG Reserved : 18;
        };
    };
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, *PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

constexpr SYSTEM_INFORMATION_CLASS SystemKernelVaShadowInformation = (SYSTEM_INFORMATION_CLASS)196;

extern "C" NTSYSAPI NTSTATUS NTAPI RtlGetVersion(
    _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
);

inline std::vector<std::string> split(std::string text, char delim) {
    std::string line;
    std::vector<std::string> vec;
    std::stringstream ss(text);
    while(std::getline(ss, line, delim))
        vec.push_back(line);
    return vec;
}

inline std::wstring convert_to_wstring(const std::string &str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> conv;
    return conv.from_bytes(str);
}

inline bool isHvciEnabled() {
    SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
    sci.Length = sizeof(sci);
    if (NT_SUCCESS(NtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), NULL))) {
        return sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED && 
          sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED;
    }
    return false;
}

inline bool isKVAShadowEnabled() {
    SYSTEM_KERNEL_VA_SHADOW_INFORMATION kvs = { 0 };
    if (NT_SUCCESS(NtQuerySystemInformation(SystemKernelVaShadowInformation, &kvs, sizeof(kvs), NULL))) {
        return kvs.KvaShadowEnabled;
    }
    return false;
}

inline std::wstring get_proces_name(HANDLE process) {
    std::wstring process_name;
    process_name.resize(MAX_PATH);
    DWORD size = process_name.size();
    QueryFullProcessImageNameW(process, 0, (LPWSTR)process_name.data(), &size);
    process_name.resize(size);
    return process_name;
}

inline DWORD find_process_by_name(LPCWSTR lpProcessName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (wcscmp(pe32.szExeFile, lpProcessName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

namespace fumo {
    template<class... Args>
    int error(int code, const WCHAR* fmt, Args... args) {
        std::wstring message = std::vformat(fmt, std::make_wformat_args(std::forward<decltype(args)>(args)...));
        message.append(L"\n\nError code: " + std::to_wstring(code));
        message.append(L"\nWin32 error: " + std::to_wstring(GetLastError()));
        MessageBoxW(NULL, message.c_str(), L"FUMO LOADER ERROR", MB_OK | MB_ICONERROR);
        return code;
    }
}