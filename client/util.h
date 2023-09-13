#pragma once
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <optional>
#include <TlHelp32.h>

DWORD GetProcessIdByName(LPCWSTR lpProcessName);
std::optional<std::vector<BYTE>> ReadFileToBuffer(LPCWSTR lpFileName);
bool isHvciEnabled();

extern "C" NTSYSAPI NTSTATUS NTAPI RtlGetVersion(
    _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
);