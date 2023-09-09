#include "driver.h"
#include <fomo_common.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

void* gOriginalDispatchFunctionArray[IRP_MJ_MAXIMUM_FUNCTION];

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    SetHook(TRUE);

    Log("loaded DriverObject=%p", DriverObject);

    return STATUS_SUCCESS;
}

NTSTATUS SetHook(BOOL setHook) {
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, L"\\Driver\\Null");

    PDRIVER_OBJECT DriverObject = NULL;
    NTSTATUS status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL, (PVOID*)&DriverObject);

    if (!NT_SUCCESS(status)) {
        Log("Failed to obtain DriverObject (0x%08X)", status);
        return status;
    }

    if (setHook) {
        Log("Hooking Null driver major funcs...");
        
        RtlCopyMemory(gOriginalDispatchFunctionArray, DriverObject->MajorFunction, sizeof(gOriginalDispatchFunctionArray));
        
        DriverObject->MajorFunction[IRP_MJ_CREATE] = Hk_Create;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Hk_DeviceControl;

        Log("Hooked Null driver major functions...");
    } else {
        RtlCopyMemory(DriverObject->MajorFunction, gOriginalDispatchFunctionArray, sizeof(gOriginalDispatchFunctionArray));
        Log("Unhooked Null driver major functions...");
    }

    ObDereferenceObject(DriverObject);
    return STATUS_SUCCESS;
}

NTSTATUS Hk_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    Log("IRP_MJ_DEVICE_CONTROL hook executed!");

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IO_ECHO_REQUEST:
        Log("IO_ECHO_REQUEST received");
        break;
    default:
        Log("Unknown IOCTL received: 0x%08X", stack->Parameters.DeviceIoControl.IoControlCode);
        return ((DevCtrlPtr)(gOriginalDispatchFunctionArray[IRP_MJ_DEVICE_CONTROL]))(DeviceObject, Irp);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS Hk_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    Log("IRP_MJ_CREATE hook executed!");
    return ((DevCtrlPtr)(gOriginalDispatchFunctionArray[IRP_MJ_CREATE]))(DeviceObject, Irp);
}
