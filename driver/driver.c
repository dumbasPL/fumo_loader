#include "driver.h"
#include "memory.h"
#include <fomo_common.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

void* gOriginalDispatchFunctionArray[IRP_MJ_MAXIMUM_FUNCTION];

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    RTL_OSVERSIONINFOW version = { 0 };
    RtlGetVersion(&version);
    if (version.dwMajorVersion != 10 || version.dwBuildNumber < 19041) {
        Log("Unsupported OS version: %d.%d.%d", version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);
        return STATUS_NOT_SUPPORTED;
    }

    SetHook(TRUE);

    Log("loaded");

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
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IO_ALLOC_REQUEST: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(IO_ALLOC_REQUEST_DATA)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (stack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(IO_ALLOC_RESPONSE_DATA)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PIO_ALLOC_REQUEST_DATA input = (PIO_ALLOC_REQUEST_DATA)Irp->AssociatedIrp.SystemBuffer;
        PIO_ALLOC_RESPONSE_DATA output = (PIO_ALLOC_RESPONSE_DATA)Irp->AssociatedIrp.SystemBuffer;

        Log("IO_ALLOC_REQUEST received with size %d", input->Size);

        PVOID address = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, input->Size, POOL_TAG);
        if (address == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Log("Allocated %d bytes at 0x%p", input->Size, address);

        if (!ExposeKernelMemoryToProcess(PsGetCurrentProcess(), address, input->Size)) {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        output->Address = address;
        bytes = sizeof(IO_ALLOC_RESPONSE_DATA);
        status = STATUS_SUCCESS;
        break;
    }
    case IO_MAP_MEMORY_REQUEST: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(IO_MAP_MEMORY_REQUEST_DATA)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PIO_MAP_MEMORY_REQUEST_DATA input = (PIO_MAP_MEMORY_REQUEST_DATA)Irp->AssociatedIrp.SystemBuffer;

        Log("IO_MAP_MEMORY_REQUEST received with pid %d, address 0x%p, size %d", input->Pid, input->Address, input->Size);

        PEPROCESS pProcess = NULL;
        status = PsLookupProcessByProcessId((HANDLE)input->Pid, &pProcess);
        if (!NT_SUCCESS(status)) {
            Log("Failed to lookup process by pid (0x%08X)", status);
            break;
        }

        if (!ExposeKernelMemoryToProcess(pProcess, input->Address, input->Size)) {
            ObDereferenceObject(pProcess);
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        ObDereferenceObject(pProcess);

        bytes = 0;
        status = STATUS_SUCCESS;
        break;
    }
    default:
        Log("Unknown IOCTL received: 0x%08X", stack->Parameters.DeviceIoControl.IoControlCode);
        return ((DevCtrlPtr)(gOriginalDispatchFunctionArray[IRP_MJ_DEVICE_CONTROL]))(DeviceObject, Irp);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

