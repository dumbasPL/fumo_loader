#pragma once
#include "driver.h"

PVOID FindKernelModule(LPCSTR ModuleName, PULONG pSize);
PVOID FindPattern(PVOID ModuleBase, ULONG ModuleSize, LPCSTR Pattern);