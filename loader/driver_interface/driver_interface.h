#pragma once
#include <Windows.h>
#include <optional>
#include <fomo_common.h>
#include <iostream>

namespace fumo {

class DriverInterface {
private:
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    DriverInterface(HANDLE hDevice) : hDevice(hDevice) {}
    // delete copy constructor and assignment operator
    DriverInterface(const DriverInterface&) = delete;
    DriverInterface& operator=(const DriverInterface&) = delete;
public:
    static std::optional<std::reference_wrapper<DriverInterface>> Open(LPCWSTR lpFileName);
    std::optional<ULONG> GetVersion();
    VOID Unload();
    PVOID AllocateKernelMemory(ULONG size);
    BOOL ExposeKernelMemory(ULONG pid, PVOID address, ULONG size);
    BOOL ExecuteCode(ULONG pid, PVOID address, PVOID argument);
    ~DriverInterface();
};

} // namespace fumo