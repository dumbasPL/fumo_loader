#include "memory.h"

uint64_t GetProcessDirectoryTableBase(PEPROCESS pProcess) {
    PUCHAR process = (PUCHAR)pProcess;
    uint64_t process_dirbase = *(uint64_t*)(process + 0x28); // DirectoryTableBase
    if (process_dirbase == 0)
        process_dirbase = *(uint64_t*)(process + 0x388); // UserDirectoryTableBase
    return process_dirbase;
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