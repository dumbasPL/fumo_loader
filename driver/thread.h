#pragma once
#include "driver.h"

NTSTATUS EnumProcesses(PVOID *ppProcesses, SYSTEM_INFORMATION_CLASS SystemInformationClass);
PSYSTEM_PROCESS_INFORMATION FindProcessInformation(PVOID Processes, HANDLE ProcessId);
NTSTATUS FindProcessThread(PEPROCESS pProcess, PETHREAD* ppThread);
BOOL SkipThread(PETHREAD pThread);
NTSTATUS QueueUserApc(PETHREAD pThread, PVOID pUserFunc, PVOID Argument);