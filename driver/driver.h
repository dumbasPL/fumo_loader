#pragma once
#include <ntifs.h>
#include <windef.h>
#include <wdm.h>
#define DEBUG

#ifdef DEBUG
#define POOL_TAG 'OMUF' // FUMO
#else
#define POOL_TAG 'enoN' // None
#endif

#ifdef DEBUG
#define Log(format, ...) DbgPrint("[FUMO] " format "\n", ##__VA_ARGS__)
#else
#define Log(format, ...) 
#endif

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
  __in PUNICODE_STRING ObjectName,
  __in ULONG Attributes,
  __in_opt PACCESS_STATE AccessState,
  __in_opt ACCESS_MASK DesiredAccess,
  __in POBJECT_TYPE ObjectType,
  __in KPROCESSOR_MODE AccessMode,
  __inout_opt PVOID ParseContext,
  __out PVOID* Object
);

NTKERNELAPI PUCHAR NTAPI PsGetProcessImageFileName(
  _In_ PEPROCESS Process
);

NTKERNELAPI PVOID MmGetVirtualForPhysical(
  __in PHYSICAL_ADDRESS PhysicalAddress
);

typedef NTSTATUS(*DevCtrlPtr)(PDEVICE_OBJECT, PIRP Irp);

__declspec(dllimport) POBJECT_TYPE *IoDriverObjectType;

NTSTATUS SetHook(BOOL setHook);
NTSTATUS Hk_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS Hk_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);