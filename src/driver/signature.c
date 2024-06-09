#include "signature.h"

NTSTATUS EnumModules(PRTL_PROCESS_MODULES *ppModules) {
    ULONG bufferSize = 0x1000 * 0x1000;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, POOL_TAG);
    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status;
    while (TRUE) {
        status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
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

    *ppModules = buffer;
    return STATUS_SUCCESS;
}

PRTL_PROCESS_MODULE_INFORMATION FindModuleByName(PRTL_PROCESS_MODULES Modules, LPCSTR ModuleName) {
    for (ULONG i = 0; i < Modules->NumberOfModules; i++) {
        LPCSTR NtPath = (LPCSTR)Modules->Modules[i].FullPathName;
        if (!_stricmp(&NtPath[Modules->Modules[i].OffsetToFileName], ModuleName)) {
            return &Modules->Modules[i];
        }
    }
    return NULL;
}

PVOID FindKernelModule(LPCSTR ModuleName, PULONG pSize) {
    PRTL_PROCESS_MODULES Modules;
    NTSTATUS status = EnumModules(&Modules);
    if (!NT_SUCCESS(status)) {
        Log("Failed to enumerate modules (0x%08X)", status);
        return NULL;
    }

    PRTL_PROCESS_MODULE_INFORMATION module = FindModuleByName(Modules, ModuleName);
    if (!module) {
        Log("Failed to find module information for %s", ModuleName);
        ExFreePoolWithTag(Modules, POOL_TAG);
        return NULL;
    }

    PVOID base = module->ImageBase;
    *pSize = module->ImageSize;
    ExFreePoolWithTag(Modules, POOL_TAG);
    return base;
}

#define in_range(x,a,b) (x >= a && x <= b) 
#define get_bits( x )   (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define get_byte( x )   (get_bits(x[0]) << 4 | get_bits(x[1]))

PVOID FindPattern(PVOID ModuleBase, ULONG ModuleSize, LPCSTR Pattern) {
    PUCHAR pattern = (PUCHAR)Pattern;
    PVOID first_match = NULL;

    for (PUCHAR current = (PUCHAR)ModuleBase; current < (PUCHAR)ModuleBase + ModuleSize; current++) {
        if (!*pattern) {
            return first_match;
        }

        if (*pattern == '\?' || *current == get_byte(pattern)) {
            if (!first_match)
                first_match = current;

            if (!pattern[2])
                return first_match;

            if (*(PUSHORT)pattern == '\?\?' || *pattern != '\?')
                pattern += 3;
            else
                pattern += 2;
        } else if (first_match) {
            current = first_match;
            first_match = NULL;
            pattern = (PUCHAR)Pattern;
        }
    }
    return NULL;
}