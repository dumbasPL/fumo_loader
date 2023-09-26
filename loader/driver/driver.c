#include "driver.h"
#include "memory.h"
#include "thread.h"
#include <fomo_common.h>

PVOID gOriginalDispatchFunctionArray[IRP_MJ_MAXIMUM_FUNCTION];

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    RTL_OSVERSIONINFOW version = { 0 };
    RtlGetVersion(&version);
    if (version.dwMajorVersion < MIN_OS_MAJOR_VERSION || version.dwBuildNumber < MIN_OS_BUILD_NUMBER) {
        Log("Unsupported OS version: %d.%d.%d", version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);
        return STATUS_NOT_SUPPORTED;
    }

    SetHook(TRUE);

    Log("loaded version %d running on %d.%d %d", FUMO_DRIVER_VERSION, version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);
    return STATUS_SUCCESS;
}

NTSTATUS SetHook(BOOL setHook) {
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, FUMO_HOOKED_DRIVER_NAME);

    PDRIVER_OBJECT DriverObject = NULL;
    NTSTATUS status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL, (PVOID*)&DriverObject);

    if (!NT_SUCCESS(status)) {
        Log("Failed to obtain DriverObject (0x%08X)", status);
        return status;
    }

    if (setHook) {
        Log("Hooking %ws major funcs", FUMO_HOOKED_DRIVER_NAME);
        RtlCopyMemory(gOriginalDispatchFunctionArray, DriverObject->MajorFunction, sizeof(gOriginalDispatchFunctionArray));
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Hk_DeviceControl;
        Log("Hooked %ws major funcs", FUMO_HOOKED_DRIVER_NAME);
    } else {
        Log("Unhooking %ws major funcs", FUMO_HOOKED_DRIVER_NAME);
        RtlCopyMemory(DriverObject->MajorFunction, gOriginalDispatchFunctionArray, sizeof(gOriginalDispatchFunctionArray));
        Log("Unhooked %ws major funcs", FUMO_HOOKED_DRIVER_NAME);
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
    case IO_VERSION_REQUEST: {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(IO_VERSION_RESPONSE_DATA)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PIO_VERSION_RESPONSE_DATA output = (PIO_VERSION_RESPONSE_DATA)Irp->AssociatedIrp.SystemBuffer;

        Log("IO_VERSION_REQUEST received");

        output->Version = FUMO_DRIVER_VERSION;
        bytes = sizeof(IO_VERSION_RESPONSE_DATA);
        status = STATUS_SUCCESS;
        break;
    }
    case IO_UNLOAD_REQUEST: {
        Log("IO_UNLOAD_REQUEST received");
        SetHook(FALSE);
        status = STATUS_SUCCESS;
        break;
    }
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

        KAPC_STATE apcState;
        KeStackAttachProcess(pProcess, &apcState);

        if (!ExposeKernelMemoryToProcess(pProcess, input->Address, input->Size)) {
            Log("Failed to expose kernel memory to process");
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(pProcess);
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pProcess);

        bytes = 0;
        status = STATUS_SUCCESS;
        break;
    }
    case IO_EXECUTE_REQUEST: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(IO_EXECUTE_REQUEST_DATA)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PIO_EXECUTE_REQUEST_DATA input = (PIO_EXECUTE_REQUEST_DATA)Irp->AssociatedIrp.SystemBuffer;

        Log("IO_EXECUTE_REQUEST received with pid %d, address 0x%p, Argument 0x%p", input->Pid, input->Address, input->Argument);

        PEPROCESS pProcess = NULL;
        status = PsLookupProcessByProcessId((HANDLE)input->Pid, &pProcess);
        if (!NT_SUCCESS(status)) {
            Log("Failed to lookup process by pid (0x%08X)", status);
            break;
        }

        KAPC_STATE apcState;
        KeStackAttachProcess(pProcess, &apcState);

        PETHREAD pThread = NULL;
        status = FindProcessThread(pProcess, &pThread);
        if (!NT_SUCCESS(status)) {
            Log("Failed to find process thread (0x%08X)", status);
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(pProcess);
            break;
        }

        status = QueueUserApc(pThread, input->Address, input->Argument);
        if (!NT_SUCCESS(status)) {
            Log("Failed to queue user apc (0x%08X)", status);
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(pThread);
            ObDereferenceObject(pProcess);
            break;
        }

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pThread);
        ObDereferenceObject(pProcess);

        bytes = 0;
        status = STATUS_SUCCESS;
        break;
    }
    case IO_FIND_MODULE_REQUEST: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(IO_FIND_MODULE_REQUEST_DATA)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (stack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(IO_FIND_MODULE_RESPONSE_DATA)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PIO_FIND_MODULE_REQUEST_DATA input = (PIO_FIND_MODULE_REQUEST_DATA)Irp->AssociatedIrp.SystemBuffer;
        PIO_FIND_MODULE_RESPONSE_DATA output = (PIO_FIND_MODULE_RESPONSE_DATA)Irp->AssociatedIrp.SystemBuffer;

        Log("IO_FIND_MODULE_REQUEST received with pid %d, module name %ws", input->Pid, input->ModuleName);

        PEPROCESS pProcess = NULL;
        status = PsLookupProcessByProcessId((HANDLE)input->Pid, &pProcess);
        if (!NT_SUCCESS(status)) {
            Log("Failed to lookup process by pid (0x%08X)", status);
            break;
        }

        KAPC_STATE apcState;
        KeStackAttachProcess(pProcess, &apcState);

        UNICODE_STRING moduleName;
        RtlInitUnicodeString(&moduleName, input->ModuleName);

        output->Address = FindModule(pProcess, &moduleName);

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pProcess);

        bytes = sizeof(IO_FIND_MODULE_RESPONSE_DATA);
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

