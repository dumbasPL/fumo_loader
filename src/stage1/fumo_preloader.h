#pragma once
#include <util.h>
#include <fomo_common.h>
#include <vector>

#define ERR_STAGE1_SUCCESS 0
#define ERR_STAGE1_INVALID_ARGS 1
#define ERR_STAGE1_FAILED_TO_OPEN_FILE 2
#define ERR_STAGE1_FAILED_TO_GET_DEBUG_PRIVILEGES 3
#define ERR_STAGE1_UNSUPPORTED_OS 50
#define ERR_STAGE1_HVCI_ENABLED 51
#define ERR_STAGE1_FAILED_TO_MAP_DRIVER 100
#define ERR_STAGE1_FAILED_TO_OPEN_DRIVER 101
#define ERR_STAGE1_FAILED_TO_GET_DRIVER_VERSION 102
#define ERR_STAGE1_FAILED_TO_FIND_PROCESS 150
#define ERR_STAGE1_FAILED_TO_OPEN_PROCESS 151
#define ERR_STAGE1_FAILED_TO_ALLOCATE_MEMORY 200
#define ERR_STAGE1_FAILED_TO_RELOCATE_MODULE 201
#define ERR_STAGE1_FAILED_TO_WRITE_MEMORY 202
#define ERR_STAGE1_FAILED_TO_EXECUTE_SHELLCODE 203

int init_driver(DWORD osBuildNumber);
int load_driver(DWORD osBuildNumber);
std::wstring get_proces_name(HANDLE process);
DWORD find_process_by_name(LPCWSTR lpProcessName);
int load_stage2(HANDLE process, std::vector<BYTE>& fumo_data);
DWORD stage2_loader_shellcode(PSTAGE2_LOADER_DATA loader_data);
void stage2_loader_shellcode_end();