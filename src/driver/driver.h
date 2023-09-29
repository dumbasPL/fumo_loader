#pragma once
#include "imports.h"

#ifndef NO_FUMO_DRIVER_DEBUG
#define FUMO_DRIVER_DEBUG
#endif

#ifdef FUMO_DRIVER_DEBUG

// FUMO
#define POOL_TAG 'OMUF'
#define Log(format, ...) DbgPrint("[FUMO] " format "\n", ##__VA_ARGS__)

#else

// None
#define POOL_TAG 'enoN'
#define Log(format, ...) 

#endif

DRIVER_INITIALIZE DriverEntry;
NTSTATUS SetHook(BOOL setHook);
NTSTATUS Hk_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);