#include <Windows.h>
#include <fomo_common.h>

int main(int argc, char** argv) {
  HANDLE hDevice = CreateFileW(L"\\\\.\\NUL", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
  DeviceIoControl(hDevice, IO_ECHO_REQUEST, nullptr, 0, nullptr, 0, nullptr, nullptr);
}