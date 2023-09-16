#pragma once
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <string>
#include <format>

extern "C" NTSYSAPI NTSTATUS NTAPI RtlGetVersion(
    _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
);

inline bool isHvciEnabled() {
    SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
    sci.Length = sizeof(sci);
    if (NT_SUCCESS(NtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), NULL))) {
        return sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED && 
          sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED;
    }
    return false;
}

namespace fumo {
    template<class... Args>
    int error(int code, const char* fmt, Args... args) {
        std::string message = std::vformat(fmt, std::make_format_args(std::forward<decltype(args)>(args)...));
        message.append("\n\nError code: " + std::to_string(code));
        message.append("\nWin32 error: " + std::to_string(GetLastError()));
        MessageBoxA(NULL, message.c_str(), "FUMO LOADER ERROR", MB_OK | MB_ICONERROR);
        return code;
    }
}