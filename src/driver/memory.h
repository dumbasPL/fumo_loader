#pragma once
#include "driver.h"

typedef unsigned long long uint64_t;

#define PFN_TO_PAGE(pfn) ( pfn << 12 )

#pragma pack(push, 1)
typedef union CR3_
{
    uint64_t value;
    struct
    {
        uint64_t ignored_1 : 3;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t ignored_2 : 7;
        uint64_t pml4_p : 40;
        uint64_t reserved : 12;
    };
} PTE_CR3;

typedef union VIRT_ADDR_
{
    uint64_t value;
    void *pointer;
    struct
    {
        uint64_t offset : 12;
        uint64_t pt_index : 9;
        uint64_t pd_index : 9;
        uint64_t pdpt_index : 9;
        uint64_t pml4_index : 9;
        uint64_t reserved : 16;
    };
} VIRT_ADDR;

typedef union PML4E_
{
    uint64_t value;
    struct
    {
        uint64_t present : 1;
        uint64_t rw : 1;
        uint64_t user : 1;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t ignored_1 : 1;
        uint64_t reserved_1 : 1;
        uint64_t ignored_2 : 4;
        uint64_t pdpt_p : 40;
        uint64_t ignored_3 : 11;
        uint64_t xd : 1;
    };
} PML4E;

typedef union PDPTE_
{
    uint64_t value;
    struct
    {
        uint64_t present : 1;
        uint64_t rw : 1;
        uint64_t user : 1;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t page_size : 1;
        uint64_t ignored_2 : 4;
        uint64_t pd_p : 40;
        uint64_t ignored_3 : 11;
        uint64_t xd : 1;
    };
} PDPTE;

typedef union PDE_
{
    uint64_t value;
    struct
    {
        uint64_t present : 1;
        uint64_t rw : 1;
        uint64_t user : 1;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t page_size : 1;
        uint64_t ignored_2 : 4;
        uint64_t pt_p : 40;
        uint64_t ignored_3 : 11;
        uint64_t xd : 1;
    };
} PDE;

typedef union PTE_
{
    uint64_t value;
    VIRT_ADDR vaddr;
    struct
    {
        uint64_t present : 1;
        uint64_t rw : 1;
        uint64_t user : 1;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t pat : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 3;
        uint64_t page_frame : 40;
        uint64_t ignored_3 : 11;
        uint64_t xd : 1;
    };
} PTE;
#pragma pack(pop)

typedef struct PAGE_TABLE_INFO_ {
    PML4E* Pml4e;
    PDPTE* Pdpte;
    PDE* Pde;
    PTE* Pte;
} PAGE_TABLE_INFO, *PPAGE_TABLE_INFO;

uint64_t GetProcessDirectoryTableBase(PEPROCESS pProcess);
PVOID GetVirtualForPhysical(uint64_t PhysicalAddress);
BOOL ReadPhysicalUnsafe(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size);
BOOL WritePhysicalUnsafe(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size);
PAGE_TABLE_INFO QueryPageTableInfo(uint64_t directoryTableBase, PVOID Va);
uint64_t VirtToPhys(uint64_t DirectoryTableBase, PVOID Va);
BOOL ExposeKernelMemoryToProcess(PEPROCESS pProcess, PVOID Address, SIZE_T Size);
PVOID FindModule(PEPROCESS pProcess, PUNICODE_STRING ModuleName);