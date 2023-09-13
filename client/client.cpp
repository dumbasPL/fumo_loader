#include <Windows.h>
#include <fumo_loader.h>
#include <libKDU.h>
#include "util.h"

int main(int argc, char** argv) {
    OSVERSIONINFO osv;
    osv.dwOSVersionInfoSize = sizeof(osv);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);

    if (osv.dwMajorVersion < MIN_OS_MAJOR_VERSION || osv.dwBuildNumber < MIN_OS_BUILD_NUMBER) {
        std::cout << "Unsupported OS version: " << osv.dwMajorVersion << "." << osv.dwMinorVersion << "." << osv.dwBuildNumber << std::endl;
        return 1;
    }

    if (isHvciEnabled()) {
        std::cout << "HyperVisor Code Integrity (HVCI) is enabled, please disable it and try again" << std::endl;
        return 1;
    }

    auto driver_buffer = ReadFileToBuffer(L"fumo_drv.sys");
    if (!driver_buffer.has_value()) {
        std::cout << "Failed to read file" << std::endl;
        return 1;
    }
    std::cout << "Read " << driver_buffer.value().size() << " bytes from file" << std::endl;

    BOOL loaded = libKDUMapDriver(0, osv.dwBuildNumber, 34, 1, driver_buffer.value().data(), NULL, NULL);
    if (!loaded) {
        std::cout << "Failed to map driver: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "Successfully mapped driver" << std::endl;

    system("pause");

    DWORD pid = GetProcessIdByName(L"Notepad.exe");
    if (pid == 0) {
        std::cout << "Failed to get process id" << std::endl;
        return 1;
    }
    std::cout << "Found process with pid: " << pid << std::endl;

    auto dll_buffer = ReadFileToBuffer(L"AllocConsole64.dll");
    if (!dll_buffer.has_value()) {
        std::cout << "Failed to read file" << std::endl;
        return 1;
    }
    std::cout << "Read " << dll_buffer.value().size() << " bytes from file" << std::endl;

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

    auto result = fumo_loader::MapImage(&driver, pid, dll_buffer.value().data());
    if (result != ERROR_SUCCESS) {
        std::cout << "Failed to map image: " << result << std::endl;
        return 1;
    }
    std::cout << "Successfully mapped image" << std::endl;

    driver.Unload();

    return 0;
}
