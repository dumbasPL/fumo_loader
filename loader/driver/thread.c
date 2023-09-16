#include "thread.h"

NTSTATUS EnumProcesses(PVOID *ppProcesses, SYSTEM_INFORMATION_CLASS SystemInformationClass) {
    ULONG bufferSize = 0x1000 * 0x1000;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, POOL_TAG);
    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status;
    while (TRUE) {
        status = ZwQuerySystemInformation(SystemInformationClass, buffer, bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
            Log("Buffer too small, reallocating to 0x%X", bufferSize);
            ExFreePoolWithTag(buffer, POOL_TAG);
            buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, POOL_TAG);
            if (!buffer)
                return STATUS_INSUFFICIENT_RESOURCES;
        } else {
            break;
        }
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, POOL_TAG);
        return status;
    }

    *ppProcesses = buffer;
    return STATUS_SUCCESS;
}

PSYSTEM_PROCESS_INFORMATION FindProcessInformation(PVOID Processes, HANDLE ProcessId) {
    PSYSTEM_PROCESS_INFORMATION process = (PSYSTEM_PROCESS_INFORMATION)Processes;
    for (;;) {
        if (process->UniqueProcessId == ProcessId) {
            return process;
        } else if (process->NextEntryOffset) {
            process = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)process + process->NextEntryOffset);
        } else {
            break;
        }
    }
    return NULL;
}

NTSTATUS FindProcessThread(PEPROCESS pProcess, PETHREAD* ppThread) {
    PVOID Processes = NULL;
    NTSTATUS status = EnumProcesses(&Processes, SystemProcessInformation);
    if (!NT_SUCCESS(status)) {
        Log("Failed to enumerate processes (0x%08X)", status);
        ExFreePoolWithTag(Processes, POOL_TAG);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION process = FindProcessInformation(Processes, PsGetProcessId(pProcess));
    if (!process) {
        Log("Failed to find process information");
        ExFreePoolWithTag(Processes, POOL_TAG);
        return STATUS_NOT_FOUND;
    }

    for (ULONG i = 0; i < process->NumberOfThreads; i++) {
        HANDLE threadId = process->Threads[i].ClientId.UniqueThread;

        // Skip current thread.
        if (threadId == PsGetCurrentThreadId()) {
            continue;
        }

        PETHREAD pThread = NULL;
        status = PsLookupThreadByThreadId(threadId, &pThread);
        if (!NT_SUCCESS(status) || !pThread) {
            Log("Failed to lookup thread by thread id (0x%08X)", status);
            ExFreePoolWithTag(Processes, POOL_TAG);
            return status;
        }

        if (!SkipThread(pThread)) {
            Log("Found thread 0x%p", pThread);
            *ppThread = pThread;
            ExFreePoolWithTag(Processes, POOL_TAG);
            return STATUS_SUCCESS;
        }

        ObDereferenceObject(pThread);
    }

    ExFreePoolWithTag(Processes, POOL_TAG);
    return STATUS_NOT_FOUND;
}

BOOL SkipThread(PETHREAD pThread) {
    PUCHAR pTeb64 = PsGetThreadTeb(pThread);

    // Skip GUI treads.
    if (*(PULONG64)(pTeb64 + 0x78) != 0) { // Win32ThreadInfo
        Log("Skipping GUI thread");
        return TRUE;
    }

    // Skip threads with no ActivationContext
    if (*(PULONG64)(pTeb64 + 0x2C8) == 0) { // ActivationContextStackPointer
        Log("Skipping thread with no ActivationContext");
        return TRUE;
    }

    // Skip threads with no TLS pointer
    if (*(PULONG64)(pTeb64 + 0x58) == 0) { // ThreadLocalStoragePointer
        Log("Skipping thread with no TLS pointer");
        return TRUE;
    }

    return FALSE;
}

VOID KernelApcCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, 
    PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    Log("KernelApcCallback called with NormalRoutine 0x%p", *NormalRoutine);

    // Skip execution
    if (PsIsThreadTerminating(PsGetCurrentThread()))
        *NormalRoutine = NULL;

    ExFreePoolWithTag(Apc, POOL_TAG);
}

VOID KernelApcPrepareCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    Log("KernelApcPrepareCallback called");

    // Alert current thread
    KeTestAlertThread(UserMode);

    ExFreePoolWithTag(Apc, POOL_TAG);
}

NTSTATUS QueueUserApc(PETHREAD pThread, PVOID pUserFunc, PVOID Argument) {
    PKAPC apc = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), POOL_TAG);
    if (!apc)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    KeInitializeApc(apc, pThread, OriginalApcEnvironment, &KernelApcCallback, 
        NULL, (PKNORMAL_ROUTINE)(ULONG_PTR)pUserFunc, UserMode, Argument);

    PKAPC apcPrepare = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), POOL_TAG);
    if (!apcPrepare) {
        ExFreePoolWithTag(apc, POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(apcPrepare, pThread, OriginalApcEnvironment, 
        &KernelApcPrepareCallback, NULL, NULL, KernelMode, NULL);

    if (!KeInsertQueueApc(apc, NULL, NULL, 0)) {
        Log("Failed to insert APC");
        ExFreePoolWithTag(apc, POOL_TAG);
        ExFreePoolWithTag(apcPrepare, POOL_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    if (!KeInsertQueueApc(apcPrepare, NULL, NULL, 0)) {
        Log("Failed to insert prepare APC");
        ExFreePoolWithTag(apc, POOL_TAG);
        ExFreePoolWithTag(apcPrepare, POOL_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}