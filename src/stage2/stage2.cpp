#include "stage2.h"
#include "fumo_loader.h"
#include "tray_icon.h"
#include <fomo_common.h>
#include <driver_interface.h>
#include <util.h>
#include <sstream>
#include <lz4.h>

std::wstring loader_process_name = L"";
STAGE2_LOADER_DATA loader_data;
TrayIcon* tray_icon = NULL;

int main(HANDLE loader_process) {
    // wait for the loader process to exit
    DWORD wait_result = tray_icon->wait_for_object(loader_process, INFINITE, L"Waiting for loader process to exit");
    if (wait_result != WAIT_OBJECT_0)
        return fumo::error(ERR_STAGE2_FAILED_TO_WAIT_FOR_PROCESS, L"Failed to wait for loader process({}): {}", loader_process_name, wait_result);
    CloseHandle(loader_process);
    
#ifndef FUMO_DEBUG
    // delete the loader executable
    if (!DeleteFileW(loader_process_name.c_str()))
        return fumo::error(ERR_STAGE2_FAILED_TO_DELETE_LOADER, L"Failed to delete loader executable: {}", loader_process_name);
#endif
    
    auto driver = fumo::DriverInterface::Open(FUMO_HOOKED_DRIVER_NAME_USER);
    if (!driver)
        return fumo::error(ERR_STAGE2_FAILED_TO_OPEN_DRIVER, L"Failed to open driver");

    ULONG driver_version;
    if (!driver->GetVersion(&driver_version))
        return fumo::error(ERR_STAGE2_FAILED_TO_OPEN_DRIVER, L"Failed to get driver version");

    if (driver_version != FUMO_DRIVER_VERSION)
        return fumo::error(ERR_STAGE2_INVALID_DRIVER_VERSION, L"Invalid driver version (expected: {}, found: {})", FUMO_DRIVER_VERSION, driver_version);
    
    PFUMO_DATA_HEADER header = (PFUMO_DATA_HEADER)loader_data.fumo_data_base;

    // check magic
    if (header->Magic != FUMO_MAGIC)
        return fumo::error(ERR_STAGE2_INVALID_MAGIC, L"Invalid data format", loader_process_name);
    
    // check version
    if (header->Version != FUMO_DATA_VERSION)
        return fumo::error(ERR_STAGE2_INVALID_VERSION, L"Invalid data version", loader_process_name);
    
    // decrypt the settings
    PBYTE settings_data = (PBYTE)header + sizeof(FUMO_DATA_HEADER);
    uint64_t xor_key = header->XorKey;
    for (int i = 0; i < header->SettingsSize; i += sizeof(xor_key)) {
        uint64_t* ptr = (uint64_t*)&settings_data[i];
        *ptr ^= xor_key;
    }

    // parse the settings
    DWORD settings_size = *(DWORD*)settings_data;
    settings_data += sizeof(DWORD);
    std::string settings((char*)settings_data, settings_size);
    std::stringstream settings_stream(settings);
    
    std::string process_name;
    std::string wait_for_modules_string;
    std::getline(settings_stream, process_name, ';');
    std::getline(settings_stream, wait_for_modules_string, ';');
    
    std::vector<std::string> wait_for_modules = split(wait_for_modules_string, ',');

    tray_icon->send_notification(L"Ready");

    std::wstring process_name_w = convert_to_wstring(process_name);
    WAIT_FOR_PROCESS_DATA wait_for_process_data;
    wait_for_process_data.process_id = 0;
    wait_for_process_data.process_name = process_name_w.c_str();
    wait_for_process_data.cancel_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    HANDLE hThread = CreateThread(NULL, 0, [](LPVOID lpParam) -> DWORD {
        WAIT_FOR_PROCESS_DATA* data = (WAIT_FOR_PROCESS_DATA*)lpParam;
        while (true) {
            data->process_id = find_process_by_name(data->process_name);
            if (data->process_id > 0)
                return 0;
            if (WaitForSingleObject(data->cancel_event, 100) == WAIT_TIMEOUT)
                continue;
            return 1;
        };
    }, &wait_for_process_data, 0, NULL);
    if (hThread == NULL)
        return fumo::error(ERR_STAGE2_FAILED_TO_CREATE_THREAD, L"Failed to create thread");

    // wait for the process to start
    std::wstring message = std::wstring(L"Waiting for ") + process_name_w;
    wait_result = tray_icon->wait_for_object(hThread, INFINITE, message.c_str());
    if (wait_result != WAIT_OBJECT_0) {
        SetEvent(wait_for_process_data.cancel_event); // cancel the wait
        WaitForSingleObject(hThread, INFINITE); // wait for the thread to exit
        CloseHandle(hThread);
        CloseHandle(wait_for_process_data.cancel_event);
        return fumo::error(ERR_STAGE2_FAILED_TO_WAIT_FOR_PROCESS, L"Failed to wait for process({}): {}", process_name_w, wait_result);
    }
    CloseHandle(hThread);
    CloseHandle(wait_for_process_data.cancel_event);

    auto process_id = wait_for_process_data.process_id;

    // wait for all modules to be loaded
    for (auto& module : wait_for_modules) {
        std::wstring module_name = convert_to_wstring(module);
        WAIT_FOR_MODULE_DATA wait_for_module_data;
        wait_for_module_data.driver_interface = driver;
        wait_for_module_data.process_id = process_id;
        wait_for_module_data.module_base = 0;
        wait_for_module_data.module_name = module_name.c_str();
        wait_for_module_data.cancel_event = CreateEventW(NULL, TRUE, FALSE, NULL);

        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID lpParam) -> DWORD {
            WAIT_FOR_MODULE_DATA* data = (WAIT_FOR_MODULE_DATA*)lpParam;
            while (true) {
                if (!data->driver_interface->FindModule(data->process_id, data->module_name, &data->module_base))
                    return 2;
                if (data->module_base)
                    return 0;
                if (WaitForSingleObject(data->cancel_event, 100) == WAIT_TIMEOUT)
                    continue;
                return 1;
            };
        }, &wait_for_module_data, 0, NULL);

        if (hThread == NULL)
            return fumo::error(ERR_STAGE2_FAILED_TO_CREATE_THREAD, L"Failed to create thread");
        
        // wait for the module to be loaded
        std::wstring message = std::wstring(L"Waiting for ") + module_name;
        wait_result = tray_icon->wait_for_object(hThread, INFINITE, message.c_str());
        if (wait_result != WAIT_OBJECT_0) {
            SetEvent(wait_for_module_data.cancel_event); // cancel the wait
            WaitForSingleObject(hThread, INFINITE); // wait for the thread to exit
            CloseHandle(hThread);
            CloseHandle(wait_for_module_data.cancel_event);
            return fumo::error(ERR_STAGE2_FAILED_TO_WAIT_FOR_MODULE, L"Failed to wait for module({}): {}", module_name, wait_result);
        }
        DWORD exit_code = 3;
        GetExitCodeThread(hThread, &exit_code);
        CloseHandle(hThread);
        CloseHandle(wait_for_module_data.cancel_event);

        if (exit_code != 0)
            return fumo::error(ERR_STAGE2_FAILED_TO_WAIT_FOR_MODULE, L"Failed to wait for module error ({}): {}", module_name, exit_code);
    }

    // decrypt the data
    PBYTE data = (PBYTE)header + sizeof(FUMO_DATA_HEADER) + header->SettingsSize;
    for (int i = 0; i < header->DataSize; i += sizeof(xor_key)) {
        uint64_t* ptr = (uint64_t*)&data[i];
        *ptr ^= xor_key;
    }

    // decompress the data
    auto decompressed_data = std::make_unique<char[]>(header->DecompressedDataSize);
    auto decompressed_size = LZ4_decompress_safe((char*)data, decompressed_data.get(), header->CompressedDataSize, header->DecompressedDataSize);
    if (decompressed_size <= 0)
        return fumo::error(ERR_STAGE2_FAILED_TO_DECOMPRESS_DATA, L"Failed to decompress data");

    // let the magic happen
    auto error = MapImage(driver.get(), process_id, decompressed_data.get());
    if (error != ERROR_SUCCESS)
        return error;
    
    tray_icon->clear_notification();
    tray_icon->send_notification(L"Injected");

    return ERR_STAGE2_SUCCESS;
}

DWORD stage2(LPVOID lpThreadParameter) {
    tray_icon = new TrayIcon(L"Fumo Loader");
    auto res = main((HANDLE)lpThreadParameter);
    VirtualFree((LPVOID)loader_data.fumo_data_base, 0, MEM_RELEASE);
    delete tray_icon;
    return res;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH || lpvReserved == NULL)
        return FALSE;
    
    // copy the loader data since the one we get will be freed by the stage1 loader
    memcpy(&loader_data, lpvReserved, sizeof(STAGE2_LOADER_DATA));

    // open the loader process
    HANDLE loader_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, loader_data.loader_pid);
    if (loader_process == NULL) {
        fumo::error(ERR_STAGE2_FAILED_TO_OPEN_PROCESS, L"Failed to open loader process: {}", loader_data.loader_pid);
        return FALSE;
    }
    
    // get the loader process name here since it will not be available after the loader process exits
    loader_process_name = get_proces_name(loader_process);

    // main loader thread
    HANDLE hThread = CreateThread(NULL, 0, stage2, (LPVOID)loader_process, 0, NULL);
    if (hThread == NULL)
        return FALSE;
    
    CloseHandle(hThread);
    return TRUE;
}