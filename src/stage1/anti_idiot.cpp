#include "fumo_preloader.h"

std::array<std::wstring, 4> spyware_services = {
    L"FACEIT",
    L"ESEADriver2",
    L"vgk",
    L"vgc",
};

template <typename... Args> 
int s_error(int code, std::wformat_string<Args...> fmt, Args&&... args) {
    return fumo::error(
        code, 
        L"Failed to disable problematic anti-cheat services: {}",
        std::format(fmt, std::forward<decltype(args)>(args)...)
    );
};

int disable_service(SC_HANDLE sc_handle, LPWSTR service_name) {
    SC_HANDLE service_handle = OpenServiceW(sc_handle, service_name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service_handle) {
        return ERR_STAGE1_FAILED_TO_OPEN_SERVICE;
    }
    
    SERVICE_STATUS status;
    if (!ControlService(service_handle, SERVICE_CONTROL_STOP, &status)) {
        CloseServiceHandle(service_handle);
        return ERR_STAGE1_FAILED_TO_STOP_SERVICE_CONTROL;
    }

    ULONGLONG start_time = GetTickCount64();
    while (status.dwCurrentState != SERVICE_STOPPED) {
        if (GetTickCount64() - start_time > 30000) {
            CloseServiceHandle(service_handle);
            return ERR_STAGE1_FAILED_TO_STOP_SERVICE_TIMEOUT;
        }

        Sleep(status.dwWaitHint);
        
        if (!QueryServiceStatus(service_handle, &status)) {
            CloseServiceHandle(service_handle);
            return ERR_STAGE1_FAILED_TO_STOP_SERVICE_QUERY;
        }
    }

    CloseServiceHandle(service_handle);
    return ERR_STAGE1_SUCCESS;
}

int disable_spyware() {
    SC_HANDLE sc_handle = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc_handle)
        return s_error(ERR_STAGE1_FAILED_TO_OPEN_DRIVER, L"Failed to open SC manager");
    
    DWORD bytes_needed = 0;
    DWORD services_count = 0;
    EnumServicesStatusW(sc_handle, SERVICE_TYPE_ALL, SERVICE_ACTIVE, NULL, 0, &bytes_needed, &services_count, NULL);
    // the ERROR_INSUFFICIENT_BUFFER is a lie, thanks microsoft docs for lying
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER && GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(sc_handle);
        return s_error(ERR_STAGE1_FAILED_TO_ENUMERATE_SERVICE, L"Failed to enumerate services (1)");
    }
    
    std::vector<BYTE> buffer(bytes_needed);
    ENUM_SERVICE_STATUSW* services = (ENUM_SERVICE_STATUSW*)buffer.data();
    
    DWORD resume_handle = 0;
    while (true) {
        if (!EnumServicesStatusW(sc_handle, SERVICE_TYPE_ALL, SERVICE_ACTIVE, services, buffer.size(), &bytes_needed, &services_count, &resume_handle)) {
            if (GetLastError() != ERROR_MORE_DATA) {
                CloseServiceHandle(sc_handle);
                return s_error(ERR_STAGE1_FAILED_TO_ENUMERATE_SERVICE, L"Failed to enumerate services (2)");
            }
        }
        
        for (DWORD i = 0; i < services_count; i++) {
            auto& service = services[i];
            if (std::find(spyware_services.begin(), spyware_services.end(), service.lpServiceName) == spyware_services.end())
                continue;
            
            auto message = std::format(
                L"Fund potentially problematic Anti-Cheat service:\n{} ({})\nDisable automatically?",
                service.lpDisplayName, service.lpServiceName
            );
            int response = MessageBoxW(NULL, message.c_str(), L"Invasive Anti-Cheat is running", MB_YESNOCANCEL | MB_ICONWARNING | MB_SYSTEMMODAL);
            if (response == IDNO)
                continue;
            if (response != IDYES) {
                CloseServiceHandle(sc_handle);
                return ERR_STAGE1_USER_CANCELLED;
            }

            // IDYES
            while (true) {
                int status = disable_service(sc_handle, service.lpServiceName);
                if (status == ERR_STAGE1_SUCCESS)
                    break;

                std::wstring message;
                switch (status) {
                    case ERR_STAGE1_FAILED_TO_OPEN_SERVICE:
                        message = fumo::error_string(status, L"Failed to open service: {}", service.lpServiceName);
                        break;
                    case ERR_STAGE1_FAILED_TO_STOP_SERVICE_CONTROL:
                        message = fumo::error_string(status, L"Failed to stop service: {}", service.lpServiceName);
                        break;
                    case ERR_STAGE1_FAILED_TO_STOP_SERVICE_TIMEOUT:
                        message = fumo::error_string(status, L"Timeout while stopping service: {}", service.lpServiceName);
                        break;
                    case ERR_STAGE1_FAILED_TO_STOP_SERVICE_QUERY:
                        message = fumo::error_string(status, L"Failed to query service status: {}", service.lpServiceName);
                        break;
                    default:
                        message = fumo::error_string(status, L"Unknown error: {}", status);
                        break;
                }
                int response = MessageBoxW(NULL, message.c_str(), L"Failed to disable service", MB_ABORTRETRYIGNORE | MB_ICONERROR | MB_SYSTEMMODAL);
                if (response == IDRETRY)
                    continue;
                if (response == IDIGNORE)
                    break;
                
                // IDABORT
                CloseServiceHandle(sc_handle);
                return status;
            }
        }

        if (resume_handle == 0)
            break;
    }

    CloseServiceHandle(sc_handle);
    return ERR_STAGE1_SUCCESS;
}

bool is_hvci_enabled() {
    SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
    sci.Length = sizeof(sci);
    if (NT_SUCCESS(NtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), NULL))) {
        return sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED && 
          sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED;
    }
    return false;
}

bool is_kva_shadow_enabled() {
    SYSTEM_KERNEL_VA_SHADOW_INFORMATION kvs = { 0 };
    if (NT_SUCCESS(NtQuerySystemInformation(SystemKernelVaShadowInformation, &kvs, sizeof(kvs), NULL))) {
        return kvs.KvaShadowEnabled && (!kvs.KvaShadowRequiredAvailable || kvs.KvaShadowRequired);
    }
    return false;
}

int disable_hvci() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_REGISTRY, L"Failed to open DeviceGuard registry key");
    
    DWORD value = 0;
    if (RegSetValueExW(hKey, L"EnableVirtualizationBasedSecurity", 0, REG_DWORD, (BYTE*)&value, sizeof(value)) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return fumo::error(ERR_STAGE1_FAILED_TO_SET_REGISTRY_VALUE, L"Failed to set EnableVirtualizationBasedSecurity to 0");
    }

    RegCloseKey(hKey);
    return ERR_STAGE1_SUCCESS;
}

int disable_kva_shadow() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return fumo::error(ERR_STAGE1_FAILED_TO_OPEN_REGISTRY, L"Failed to open Memory Management registry key");
    
    DWORD value = 3;
    if (RegSetValueExW(hKey, L"FeatureSettingsOverride", 0, REG_DWORD, (BYTE*)&value, sizeof(value)) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return fumo::error(ERR_STAGE1_FAILED_TO_SET_REGISTRY_VALUE, L"Failed to set FeatureSettingsOverride to 3");
    }

    if (RegSetValueExW(hKey, L"FeatureSettingsOverrideMask", 0, REG_DWORD, (BYTE*)&value, sizeof(value)) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return fumo::error(ERR_STAGE1_FAILED_TO_SET_REGISTRY_VALUE, L"Failed to set FeatureSettingsOverrideMask to 3");
    }

    RegCloseKey(hKey);
    return ERR_STAGE1_SUCCESS;
}

int disable_mitigations() {
    bool reboot_required = false;

    if (is_hvci_enabled()) {
        int response = MessageBoxW(NULL, 
            L"Hypervisor Code Integrity (HVCI) is enabled!\n"
            L"Fumo loader is not compatible with HVCI.\n"
            L"Disable HVCI now?",
            L"Incompatible system settings", MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL
        );
        if (response != IDYES)
            return fumo::error(ERR_STAGE1_HVCI_ENABLED, L"Hypervisor Code Integrity (HVCI) is enabled, please disable it and try again");

        int status = disable_hvci();
        if (status != ERR_STAGE1_SUCCESS)
            return status;
        reboot_required = true;
    }
    
    if (is_kva_shadow_enabled()) {
        int response = MessageBoxW(NULL, 
            L"Kernel Virtual Address Shadow (KVAS) is enabled!\n"
            L"Fumo loader is not compatible with KVAS.\n"
            L"Disable KVAS now?",
            L"Incompatible system settings", MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL
        );
        if (response != IDYES)
            return fumo::error(ERR_STAGE1_KVA_SHADOW_ENABLED, L"Kernel Virtual Address Shadow (KVAS) is enabled, please disable it and try again");

        int status = disable_kva_shadow();
        if (status != ERR_STAGE1_SUCCESS)
            return status;
        reboot_required = true;
    }

    if (reboot_required) {
        int response = MessageBoxW(NULL, 
            L"System settings have been changed.\n"
            L"A reboot is required to apply the changes.\n"
            L"Reboot now?",
            L"Reboot required", MB_YESNO | MB_ICONQUESTION | MB_SYSTEMMODAL
        );
        if (response == IDYES) {
            if (!get_privilege(SE_SHUTDOWN_NAME))
                return fumo::error(ERR_STAGE1_FAILED_TO_GET_SHUTDOWN_PRIVILEGES, L"Failed to get shutdown privileges");

            ExitWindowsEx(EWX_REBOOT, 0);
        }
        return ERR_STAGE1_REBOOT_REQUIRED;
    }

    return ERR_STAGE1_SUCCESS;
}