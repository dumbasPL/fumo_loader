#pragma once
#include <Windows.h>
#include <stdint.h>
#include <driver_interface.h>

typedef struct _WAIT_FOR_PROCESS_DATA {
    LPCWSTR process_name;
    DWORD process_id;
    HANDLE cancel_event;
} WAIT_FOR_PROCESS_DATA, *PWAIT_FOR_PROCESS_DATA;

typedef struct _WAIT_FOR_MODULE_DATA {
    fumo::DriverInterface* driver_interface;
    LPCWSTR module_name;
    DWORD process_id;
    PVOID module_base;
    HANDLE cancel_event;
} WAIT_FOR_MODULE_DATA, *PWAIT_FOR_MODULE_DATA;