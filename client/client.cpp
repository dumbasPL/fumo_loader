#include <Windows.h>
#include <iostream>
#include <fomo_common.h>

int main(int argc, char** argv) {
  HANDLE hDevice = CreateFileW(L"\\\\.\\NUL", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

  IO_ALLOC_REQUEST_DATA alloc_request = {0};
  alloc_request.Size = 0x6000;

  IO_ALLOC_RESPONSE_DATA alloc_response = {0};
  DeviceIoControl(hDevice, IO_ALLOC_REQUEST, &alloc_request, sizeof(alloc_request), &alloc_response, sizeof(alloc_response), nullptr, nullptr);

  std::cout << "Last error: " << GetLastError() << std::endl;
  std::cout << "Allocated buffer at: " << std::hex << alloc_response.Address << std::endl;

  std::cout << "Data: " << (const char*)alloc_response.Address << "!" << std::endl;

  IO_MAP_MEMORY_REQUEST_DATA map_data = {0};
  map_data.Pid = GetCurrentProcessId();
  map_data.Address = alloc_response.Address;
  map_data.Size = alloc_request.Size;

  DeviceIoControl(hDevice, IO_MAP_MEMORY_REQUEST, &map_data, sizeof(map_data), nullptr, 0, nullptr, nullptr);
  std::cout << "Last error: " << GetLastError() << std::endl;

  std::cout << "Data2: " << (const char*)alloc_response.Address << "!" << std::endl;
}