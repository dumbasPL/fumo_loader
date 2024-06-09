#include "driver_interface.h"

std::shared_ptr<fumo::DriverInterface> fumo::DriverInterface::Open(LPCWSTR lpFileName) {
    HANDLE hDevice = CreateFileW(lpFileName, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        return nullptr;
    }
    // not using make_shared because the constructor is private
    return std::shared_ptr<fumo::DriverInterface>(new fumo::DriverInterface(hDevice));
}

VOID fumo::DriverInterface::Unload() {
    DeviceIoControl(hDevice, IO_UNLOAD_REQUEST, 
        nullptr, 0, 
        nullptr, 0, 
        nullptr, nullptr);
}

BOOL fumo::DriverInterface::GetVersion(PULONG pVersion) {
    IO_VERSION_RESPONSE_DATA version_response = {0};
    if (!DeviceIoControl(hDevice, IO_VERSION_REQUEST, 
        nullptr, 0, 
        &version_response, sizeof(version_response), 
        nullptr, nullptr)) {
        return FALSE;
    }
    *pVersion = version_response.Version;
    return TRUE;
}

PVOID fumo::DriverInterface::AllocateKernelMemory(ULONG size) {
    IO_ALLOC_REQUEST_DATA alloc_request = {0};
    alloc_request.Size = size;

    IO_ALLOC_RESPONSE_DATA alloc_response = {0};
    if (!DeviceIoControl(hDevice, IO_ALLOC_REQUEST, 
        &alloc_request, sizeof(alloc_request), 
        &alloc_response, sizeof(alloc_response), 
        nullptr, nullptr)) {
        return nullptr;
    }

    return alloc_response.Address;
}

BOOL fumo::DriverInterface::ExposeKernelMemory(ULONG pid, PVOID address, ULONG size) {
    IO_MAP_MEMORY_REQUEST_DATA map_data = {0};
    map_data.Pid = pid;
    map_data.Address = address;
    map_data.Size = size;

    return DeviceIoControl(hDevice, IO_MAP_MEMORY_REQUEST, 
        &map_data, sizeof(map_data), 
        nullptr, 0, 
        nullptr, nullptr);
}

BOOL fumo::DriverInterface::ExecuteCode(ULONG pid, PVOID address, PVOID argument) {
    IO_EXECUTE_REQUEST_DATA execute_request = {0};
    execute_request.Pid = pid;
    execute_request.Address = address;
    execute_request.Argument = argument;

    return DeviceIoControl(hDevice, IO_EXECUTE_REQUEST, 
        &execute_request, sizeof(execute_request), 
        nullptr, 0, 
        nullptr, nullptr);
}

BOOL fumo::DriverInterface::FindModule(ULONG pid, LPCWSTR lpModuleName, PVOID* Address) {
    IO_FIND_MODULE_REQUEST_DATA find_module_request = {0};
    find_module_request.Pid = pid;
    wcscpy_s(find_module_request.ModuleName, lpModuleName);

    IO_FIND_MODULE_RESPONSE_DATA find_module_response = {0};
    if (!DeviceIoControl(hDevice, IO_FIND_MODULE_REQUEST, 
        &find_module_request, sizeof(find_module_request), 
        &find_module_response, sizeof(find_module_response), 
        nullptr, nullptr)) {
        return FALSE;
    }

    *Address = find_module_response.Address;
    return TRUE;
}

fumo::DriverInterface::~DriverInterface() {
    std::cout << "Closing handle" << std::endl;
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
    }
}