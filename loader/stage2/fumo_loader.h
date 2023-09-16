#pragma once
#include <Windows.h>
#include "driver_interface.h"

namespace fumo {

DWORD MapImage(DriverInterface* pDriver, ULONG pid, PVOID image);

} // namespace fumo