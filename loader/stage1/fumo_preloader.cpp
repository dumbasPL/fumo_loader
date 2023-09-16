#include "util.h"
#include <libKDU.h>
#include <driver_interface.h>
#include <fumo_drv_data.h>
#include <fomo_common.h>

#define ERR_STAGE1_SUCCESS 0
#define ERR_STAGE1_UNSUPPORTED_OS 1
#define ERR_STAGE1_HVCI_ENABLED 2
#define ERR_STAGE1_FAILED_TO_MAP_DRIVER 3
#define ERR_STAGE1_FAILED_TO_OPEN_DRIVER 4

int init_driver(DWORD osBuildNumber);

int main() {
    OSVERSIONINFO osv;
    osv.dwOSVersionInfoSize = sizeof(osv);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);

    if (osv.dwMajorVersion < MIN_OS_MAJOR_VERSION || osv.dwBuildNumber < MIN_OS_BUILD_NUMBER)
        return fumo::error(ERR_STAGE1_UNSUPPORTED_OS, "Unsupported OS version: {}.{}.{}", osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber);

    if (isHvciEnabled())
        return fumo::error(ERR_STAGE1_HVCI_ENABLED, "HyperVisor Code Integrity (HVCI) is enabled, please disable it and try again");
    
    auto error = init_driver(osv.dwBuildNumber);
    if (error != ERR_STAGE1_SUCCESS)
        return error;
    
    return fumo::error(ERR_STAGE1_SUCCESS, "This is a stub");
}

int load_driver(DWORD osBuildNumber) {
    // FIXME: make the provider configurable
    if (!libKDUMapDriver(0, osBuildNumber, 34, 1, res::fumo_drv_data.data(), NULL, NULL))
        return fumo::error(ERR_STAGE1_FAILED_TO_MAP_DRIVER, "Failed to map driver");

    return ERR_STAGE1_SUCCESS;
}

int init_driver(DWORD osBuildNumber) {
    auto driver = fumo::DriverInterface::Open(FUMO_HOOKED_DRIVER_NAME_USER);
    if (!driver.has_value())
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_DRIVER, "Failed to open driver");

    auto& driver_ref = driver.value().get();

    auto version = driver_ref.GetVersion();
    if (!version.has_value()) {
        auto error = load_driver(osBuildNumber);
        if (error != ERR_STAGE1_SUCCESS)
            return error;

        version = driver_ref.GetVersion();
        if (!version.has_value())
            return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_DRIVER, "Failed to get driver version");
    }

    if (version.value() != FUMO_DRIVER_VERSION) {
        // unload the old driver and try again
        driver_ref.Unload();
        return init_driver(osBuildNumber);
    }

    return ERR_STAGE1_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH)
        return 0;

    return main() == ERR_STAGE1_SUCCESS;
}
