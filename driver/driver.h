#pragma once
#include "imports.h"

#define DEBUG

#ifdef DEBUG

// FUMO
#define POOL_TAG 'OMUF'
#define Log(format, ...) DbgPrint("[FUMO] " format "\n", ##__VA_ARGS__)

#else

// None
#define POOL_TAG 'enoN'
#define Log(format, ...) 

#endif

NTSTATUS SetHook(BOOL setHook);
NTSTATUS Hk_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS Hk_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);