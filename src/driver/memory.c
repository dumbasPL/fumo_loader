#include "memory.h"
#include "signature.h"

uint64_t GetProcessDirectoryTableBase(PEPROCESS pProcess) {
    PUCHAR process = (PUCHAR)pProcess;
    return *(uint64_t*)(process + 0x28); // DirectoryTableBase;
}

VOID SetAddressPolicy(PEPROCESS pProcess, UCHAR AddressPolicy) {
    PUCHAR process = (PUCHAR)pProcess;
    *(UCHAR*)(process + 0x390) = AddressPolicy;
}

PVOID GetVirtualForPhysical(uint64_t PhysicalAddress) {
    PHYSICAL_ADDRESS AddrToRead = {0};
    AddrToRead.QuadPart = PhysicalAddress;
    return MmGetVirtualForPhysical(AddrToRead);
}

BOOL ReadPhysicalUnsafe(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size) {
    PVOID VirtualAddress = GetVirtualForPhysical(TargetAddress);
    if (!VirtualAddress)
        return FALSE;
    RtlCopyMemory(lpBuffer, VirtualAddress, Size);
    return TRUE;
}

BOOL WritePhysicalUnsafe(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size) {
    PVOID VirtualAddress = GetVirtualForPhysical(TargetAddress);
    if (!VirtualAddress)
        return FALSE;
    RtlCopyMemory(VirtualAddress, lpBuffer, Size);
    return TRUE;
}

PAGE_TABLE_INFO QueryPageTableInfo(uint64_t DirectoryTableBase, PVOID Va) {
    PAGE_TABLE_INFO Pi = {0,0,0,0};

    VIRT_ADDR Addr = {(uint64_t)Va};
    PTE_CR3 Cr3 = {DirectoryTableBase};
    SIZE_T read_size = 0;

    {
        uint64_t Plm4eAddr = PFN_TO_PAGE(Cr3.pml4_p) + sizeof(PML4E) * Addr.pml4_index;
        PML4E* Plm4e = (PML4E*)GetVirtualForPhysical(Plm4eAddr);
        if (!Plm4e->present)
            return Pi;
        Pi.Pml4e = Plm4e;
    }

    {
        uint64_t PdpteAddr = PFN_TO_PAGE(Pi.Pml4e->pdpt_p) + sizeof(PDPTE) * Addr.pdpt_index;
        PDPTE* Pdpte = (PDPTE*)GetVirtualForPhysical(PdpteAddr);
        if (!Pdpte->present)
            return Pi;
        Pi.Pdpte = Pdpte;
    }

    {
        uint64_t PdeAddr = PFN_TO_PAGE(Pi.Pdpte->pd_p) + sizeof(PDE) * Addr.pd_index;
        PDE* Pde = (PDE*)GetVirtualForPhysical(PdeAddr);
        if (!Pde->present)
            return Pi;
        Pi.Pde = Pde;
        if (Pi.Pde->page_size)
            return Pi;
    }

    {
        uint64_t PteAddr = PFN_TO_PAGE(Pi.Pde->pt_p) + sizeof(PTE) * Addr.pt_index;
        PTE* Pte = (PTE*)GetVirtualForPhysical(PteAddr);
        if (!Pte->present)
            return Pi;
        Pi.Pte = Pte;
    }

    return Pi;
}

uint64_t VirtToPhys(uint64_t DirectoryTableBase, PVOID Va) {
    PAGE_TABLE_INFO Info = QueryPageTableInfo(DirectoryTableBase, Va);
    SIZE_T read_size = 0;
    uint64_t Pa = 0;

    if (!Info.Pde)
        return 0;

    if (Info.Pde->page_size) {
        Pa = PFN_TO_PAGE(Info.Pde->pt_p);
        Pa += (uint64_t)Va & (0x200000 - 1);
            return Pa;
    }

    if (!Info.Pte)
        return 0;

    Pa = PFN_TO_PAGE(Info.Pte->page_frame);
    Pa += (uint64_t)Va & (0x1000 - 1);
    
    return Pa;
}

PVOID ResolveRelativeAddress(PVOID Instruction, ULONG Offset) {
    if (!Instruction)
        return NULL;

    PVOID jmp = (PUCHAR)Instruction + Offset;
    LONG rel = *(PLONG)jmp;
    return (PUCHAR)jmp + sizeof(LONG) + rel;
}

PVOID _KeKvaShadowingActive = NULL;
ULONG KeKvaShadowingActive() {
    // failed to find KeKvaShadowingActive
    if (_KeKvaShadowingActive == (PVOID)0x1)
        return FALSE;

    if (!_KeKvaShadowingActive) {
        ULONG ntoskrnlSize = 0;
        PVOID pNtoskrnl = FindKernelModule("ntoskrnl.exe", &ntoskrnlSize);
        if (!pNtoskrnl) {
            Log("Failed to find ntoskrnl.exe");
            _KeKvaShadowingActive = (PVOID)0x1;
            return FALSE;
        }

        Log("ntoskrnl.exe found at 0x%p with size 0x%X", pNtoskrnl, ntoskrnlSize);
        PVOID found = FindPattern(pNtoskrnl, ntoskrnlSize, "41 89 1E E8 ? ? ? ? 44 8D ? ? 41");
        found = ResolveRelativeAddress(found, 4);
        if (!found) {
            Log("Failed to find KeKvaShadowingActive");
            _KeKvaShadowingActive = (PVOID)0x1;
            return FALSE;
        }

        _KeKvaShadowingActive = found;
    }

    return ((ULONG(*)())_KeKvaShadowingActive)();
}

PVOID _MiDeleteProcessShadow = NULL;
BOOL MiDeleteProcessShadow(PEPROCESS pProcess, BOOL b) {
    // failed to find MiDeleteProcessShadow
    if (_MiDeleteProcessShadow == (PVOID)0x1)
        return FALSE;

    if (!_MiDeleteProcessShadow) {
        ULONG ntoskrnlSize = 0;
        PVOID pNtoskrnl = FindKernelModule("ntoskrnl.exe", &ntoskrnlSize);
        if (!pNtoskrnl) {
            Log("Failed to find ntoskrnl.exe");
            _MiDeleteProcessShadow = (PVOID)0x1;
            return FALSE;
        }

        PVOID found = FindPattern(pNtoskrnl, ntoskrnlSize, "E8 ? ? ? ? F0 0F BA AE ? ? ? ? ? 0F 82");
        found = ResolveRelativeAddress(found, 1);
        if (!found) {
            Log("Failed to find MiDeleteProcessShadow");
            _MiDeleteProcessShadow = (PVOID)0x1;
            return FALSE;
        }

        _MiDeleteProcessShadow = found;
    }

    ((BOOL(*)(PEPROCESS, BOOL))_MiDeleteProcessShadow)(pProcess, b);
    return TRUE;
}

PVOID _KeSynchronizeAddressPolicy = NULL;
BOOL KeSynchronizeAddressPolicy(PEPROCESS pProcess) {
    // failed to find KeSynchronizeAddressPolicy
    if (_KeSynchronizeAddressPolicy == (PVOID)0x1)
        return FALSE;

    if (!_KeSynchronizeAddressPolicy) {
        ULONG ntoskrnlSize = 0;
        PVOID pNtoskrnl = FindKernelModule("ntoskrnl.exe", &ntoskrnlSize);
        if (!pNtoskrnl) {
            Log("Failed to find ntoskrnl.exe");
            _KeSynchronizeAddressPolicy = (PVOID)0x1;
            return FALSE;
        }

        PVOID found = FindPattern(pNtoskrnl, ntoskrnlSize, "E8 ? ? ? ? F0 0F BA AE ? ? ? ? ? 72");
        found = ResolveRelativeAddress(found, 1);
        if (!found) {
            Log("Failed to find KeSynchronizeAddressPolicy");
            _KeSynchronizeAddressPolicy = (PVOID)0x1;
            return FALSE;
        }

        _KeSynchronizeAddressPolicy = found;
    }

    ((VOID(*)(PEPROCESS))_KeSynchronizeAddressPolicy)(pProcess);
    return TRUE;
}

PVOID _MiWritePteShadow = NULL;
BOOL MiWritePteShadow(PTE* pte, uint64_t value) {
    // failed to find MiWritePteShadow
    if (_MiWritePteShadow == (PVOID)0x1)
        return FALSE;

    if (!_MiWritePteShadow) {
        ULONG ntoskrnlSize = 0;
        PVOID pNtoskrnl = FindKernelModule("ntoskrnl.exe", &ntoskrnlSize);
        if (!pNtoskrnl) {
            Log("Failed to find ntoskrnl.exe");
            _MiWritePteShadow = (PVOID)0x1;
            return FALSE;
        }

        PVOID found = FindPattern(pNtoskrnl, ntoskrnlSize, "48 83 EC ? 4C 8B C9 E8 ? ? ? ? 85 C0 74 ? 65 48 8B 04 25");
        if (!found) {
            Log("Failed to find MiWritePteShadow");
            _MiWritePteShadow = (PVOID)0x1;
            return FALSE;
        }

        _MiWritePteShadow = found;
    }

    ((VOID(*)(PTE*, uint64_t))_MiWritePteShadow)(pte, value);
}

BOOL DeleteProcessShadow(PEPROCESS pProcess) {
    return TRUE;
    if (!KeKvaShadowingActive())
        return TRUE;
    
    Log("Deleting process shadow");
    
    SetAddressPolicy(pProcess, 1);

    KAPC_STATE ApcState;
    KeStackAttachProcess(pProcess, &ApcState);

    BOOL res = KeSynchronizeAddressPolicy(pProcess);
    if (res)
        res = MiDeleteProcessShadow(pProcess, TRUE);

    KeUnstackDetachProcess(&ApcState);

    return res;
}

BOOL ExposeKernelMemoryToProcess(PEPROCESS pProcess, PVOID Address, SIZE_T Size) {
    if (!pProcess || !Address || !Size)
        return FALSE;

    PUCHAR pProcessName = PsGetProcessImageFileName(pProcess);
    if (!pProcessName)
        return FALSE;
  
    Log("Exposing kernel memory to %s (%d) at 0x%p with size 0x%X", pProcessName, PsGetProcessId(pProcess), Address, Size);

    uint64_t DirectoryTableBase = GetProcessDirectoryTableBase(pProcess);

    PUCHAR It = (PUCHAR)Address;
    PUCHAR End = It + Size;
    BOOL success = TRUE;

    while (It < End) {
        SIZE_T Size = (PUCHAR)(((uint64_t)It + 0x1000) & (~0xFFF)) - It;

        if ((It + Size) > End)
            Size = End - It;

        PAGE_TABLE_INFO Pti = QueryPageTableInfo(DirectoryTableBase, It);
        It += Size;

        if (!Pti.Pde || (Pti.Pte && !Pti.Pte->present)) {
            success = FALSE;
            continue;
        }

        Pti.Pml4e->user = TRUE;
        Pti.Pdpte->user = TRUE;
        Pti.Pde->user = TRUE;
        if (Pti.Pte)
            Pti.Pte->user = TRUE;
    }

    KeFlushEntireTb();
    KeInvalidateAllCaches();

    return success;
}

PVOID FindModule(PEPROCESS pProcess, PUNICODE_STRING ModuleName) {
    if (!pProcess || !ModuleName)
        return NULL;
    
    PPEB pPeb = PsGetProcessPeb(pProcess);
    if (!pPeb)
        return NULL;
    
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    if (!pLdr)
        return NULL;
    
    for (PLIST_ENTRY pListEntry = pLdr->InLoadOrderModuleList.Flink; pListEntry != &pLdr->InLoadOrderModuleList; pListEntry = pListEntry->Flink) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
            return pEntry->DllBase;
    }

    return NULL;
}