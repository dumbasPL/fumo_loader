#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <optional>
#include "bootstrap.h"

NTSYSAPI ULONG RtlRandomEx(PULONG Seed);
auto fnRtlRandomEx = []() {
    return (decltype(&RtlRandomEx))GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlRandomEx");
}();

std::optional<std::vector<BYTE>> read_file(std::string path);
void randomize_section_name(PIMAGE_SECTION_HEADER section_header, PULONG seed);
DWORD GetAlignedSize(DWORD size, DWORD alignment);
void encrypt_buffer(PBYTE buffer, DWORD size, ULONG_PTR xor_key);

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <output_file> <initial_loader> [module...]" << std::endl;
        return 1;
    }

    std::string output_file_path = argv[1];
    std::string initial_loader_path = argv[2];
    std::vector<std::string> module_paths;
    for (int i = 3; i < argc; i++)
        module_paths.push_back(argv[i]);

    auto initial_loader_buffer = read_file(initial_loader_path);
    if (!initial_loader_buffer.has_value()) {
        std::cerr << "Failed to read initial_loader file" << std::endl;
        return 1;
    }

    std::vector<std::vector<BYTE>> module_buffers;
    for (auto& module_path : module_paths) {
        auto module_buffer = read_file(module_path);
        if (!module_buffer.has_value()) {
            std::cerr << "Failed to read module file: " << module_path << std::endl;
            return 1;
        }
        module_buffers.push_back(module_buffer.value());
    }

    ULONG seed = (ULONG)GetTickCount64();
    ULONG_PTR xor_key = (ULONG_PTR)fnRtlRandomEx(&seed) | ((ULONG_PTR)fnRtlRandomEx(&seed) << 32);

    DWORD NumberOfSections = 2 + module_buffers.size();

    // DOS header
    IMAGE_DOS_HEADER dos_header;
    memset(&dos_header, 0, sizeof(dos_header));
    dos_header.e_magic = IMAGE_DOS_SIGNATURE;
    dos_header.e_cblp = 0x90;
    dos_header.e_cp = 0x3;
    dos_header.e_cparhdr = 0x4;
    dos_header.e_maxalloc = 0xFFFF;
    dos_header.e_sp = 0xB8;
    dos_header.e_lfarlc = 0x40;
    dos_header.e_lfanew = 0x40;

    // NT headers
    IMAGE_NT_HEADERS64 nt_headers;
    memset(&nt_headers, 0, sizeof(nt_headers));
    nt_headers.Signature = IMAGE_NT_SIGNATURE;
    nt_headers.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt_headers.FileHeader.NumberOfSections = NumberOfSections;
    nt_headers.FileHeader.TimeDateStamp = 0x0; // FIXME: randomize
    nt_headers.FileHeader.SizeOfOptionalHeader = sizeof(nt_headers.OptionalHeader);
    nt_headers.FileHeader.Characteristics = IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | 
        IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt_headers.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt_headers.OptionalHeader.MajorLinkerVersion = 0x1;
    nt_headers.OptionalHeader.MinorLinkerVersion = 0x0;
    nt_headers.OptionalHeader.SizeOfCode = 0; //* needs to be updated
    nt_headers.OptionalHeader.SizeOfInitializedData = 0; //* needs to be updated
    nt_headers.OptionalHeader.SizeOfUninitializedData = 0x0;
    nt_headers.OptionalHeader.AddressOfEntryPoint = 0; //* needs to be updated
    nt_headers.OptionalHeader.BaseOfCode = 0x1000;
    nt_headers.OptionalHeader.ImageBase = 0x0000000140000000;
    nt_headers.OptionalHeader.SectionAlignment = 0x1000;
    nt_headers.OptionalHeader.FileAlignment = 0x200;
    nt_headers.OptionalHeader.MajorOperatingSystemVersion = 0x6;
    nt_headers.OptionalHeader.MinorOperatingSystemVersion = 0x0;
    nt_headers.OptionalHeader.MajorImageVersion = 0x0;
    nt_headers.OptionalHeader.MinorImageVersion = 0x0;
    nt_headers.OptionalHeader.MajorSubsystemVersion = 0x6;
    nt_headers.OptionalHeader.MinorSubsystemVersion = 0x0;
    nt_headers.OptionalHeader.Win32VersionValue = 0x0;
    nt_headers.OptionalHeader.SizeOfImage = 0; //* needs to be updated
    nt_headers.OptionalHeader.SizeOfHeaders = 0x400; //* needs to be updated
    nt_headers.OptionalHeader.CheckSum = 0x0;
    nt_headers.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    nt_headers.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | 
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    nt_headers.OptionalHeader.SizeOfStackReserve = 0x100000;
    nt_headers.OptionalHeader.SizeOfStackCommit = 0x1000;
    nt_headers.OptionalHeader.SizeOfHeapReserve = 0x100000;
    nt_headers.OptionalHeader.SizeOfHeapCommit = 0x1000;
    nt_headers.OptionalHeader.LoaderFlags = 0x0;
    nt_headers.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    // section headers
    DWORD SizeOfHeaders = sizeof(dos_header) + sizeof(nt_headers) + NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    // round up to nearest FileAlignment
    SizeOfHeaders = GetAlignedSize(SizeOfHeaders, nt_headers.OptionalHeader.FileAlignment);
    nt_headers.OptionalHeader.SizeOfHeaders = SizeOfHeaders;

    // round up to nearest SectionAlignment after headers
    DWORD NextVirtualAddress = GetAlignedSize(SizeOfHeaders, nt_headers.OptionalHeader.SectionAlignment);
    DWORD NextPointerToRawData = GetAlignedSize(SizeOfHeaders, nt_headers.OptionalHeader.FileAlignment);

    // loader section
    IMAGE_SECTION_HEADER initial_loader_section_header;
    memset(&initial_loader_section_header, 0, sizeof(initial_loader_section_header));
    initial_loader_section_header.Name[0] = 'l'; // loader
    randomize_section_name(&initial_loader_section_header, &seed);
    initial_loader_section_header.Misc.VirtualSize = initial_loader_buffer->size();
    initial_loader_section_header.VirtualAddress = NextVirtualAddress;
    initial_loader_section_header.SizeOfRawData = initial_loader_buffer->size();
    initial_loader_section_header.PointerToRawData = NextPointerToRawData;
    initial_loader_section_header.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // get next free virtual address and pointer to raw data (round up to nearest SectionAlignment)
    NextVirtualAddress += GetAlignedSize(initial_loader_section_header.Misc.VirtualSize, nt_headers.OptionalHeader.SectionAlignment);
    NextPointerToRawData += GetAlignedSize(initial_loader_section_header.SizeOfRawData, nt_headers.OptionalHeader.FileAlignment);

    // bootstrap section
    auto bootstrap_shellcode = get_bootstrap_shellcode(xor_key, initial_loader_section_header.VirtualAddress, initial_loader_section_header.SizeOfRawData);
    IMAGE_SECTION_HEADER bootstrap_section_header;
    memset(&bootstrap_section_header, 0, sizeof(bootstrap_section_header));
    bootstrap_section_header.Name[0] = 'b'; // bootstrap
    randomize_section_name(&bootstrap_section_header, &seed);
    bootstrap_section_header.Misc.VirtualSize = bootstrap_shellcode.size();
    bootstrap_section_header.VirtualAddress = NextVirtualAddress;
    bootstrap_section_header.SizeOfRawData = bootstrap_shellcode.size();
    bootstrap_section_header.PointerToRawData = NextPointerToRawData;
    bootstrap_section_header.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // get next free virtual address and pointer to raw data (round up to nearest SectionAlignment)
    NextVirtualAddress += GetAlignedSize(bootstrap_section_header.Misc.VirtualSize, nt_headers.OptionalHeader.SectionAlignment);
    NextPointerToRawData += GetAlignedSize(bootstrap_section_header.SizeOfRawData, nt_headers.OptionalHeader.FileAlignment);

    // module sections
    std::vector<IMAGE_SECTION_HEADER> module_section_headers;
    for (auto& module_buffer : module_buffers) {
        // section header
        IMAGE_SECTION_HEADER section_header;
        memset(&section_header, 0, sizeof(section_header));
        section_header.Name[0] = 'e'; // encrypted
        randomize_section_name(&section_header, &seed);
        section_header.Misc.VirtualSize = module_buffer.size();
        section_header.VirtualAddress = NextVirtualAddress;
        section_header.SizeOfRawData = module_buffer.size();
        section_header.PointerToRawData = NextPointerToRawData;
        section_header.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

        // get next free virtual address and pointer to raw data (round up to nearest SectionAlignment)
        NextVirtualAddress += GetAlignedSize(module_buffer.size(), nt_headers.OptionalHeader.SectionAlignment);
        NextPointerToRawData += GetAlignedSize(module_buffer.size(), nt_headers.OptionalHeader.FileAlignment);

        module_section_headers.push_back(section_header);
    }

    // update NT headers
    nt_headers.OptionalHeader.SizeOfImage = NextVirtualAddress;
    nt_headers.OptionalHeader.SizeOfCode = initial_loader_section_header.SizeOfRawData + bootstrap_section_header.SizeOfRawData;
    nt_headers.OptionalHeader.SizeOfInitializedData = initial_loader_section_header.SizeOfRawData + bootstrap_section_header.SizeOfRawData;\
    nt_headers.OptionalHeader.AddressOfEntryPoint = bootstrap_section_header.VirtualAddress;

    // write the PE file
    std::ofstream pe_file(output_file_path, std::ios::binary);
    if (!pe_file.is_open()) {
        std::cerr << "Failed to open output file" << std::endl;
        return 1;
    }

    // write DOS header
    pe_file.write((char*)&dos_header, sizeof(dos_header));

    // write NT headers
    pe_file.write((char*)&nt_headers, sizeof(nt_headers));

    // write section headers
    pe_file.write((char*)&initial_loader_section_header, sizeof(initial_loader_section_header));
    pe_file.write((char*)&bootstrap_section_header, sizeof(bootstrap_section_header));
    for (auto& module_section_header : module_section_headers)
        pe_file.write((char*)&module_section_header, sizeof(module_section_header));

    // write loader section data
    encrypt_buffer(initial_loader_buffer->data(), initial_loader_buffer->size(), xor_key);
    pe_file.seekp(initial_loader_section_header.PointerToRawData);
    pe_file.write((char*)initial_loader_buffer->data(), initial_loader_buffer->size());

    // write bootstrap section data
    pe_file.seekp(bootstrap_section_header.PointerToRawData);
    pe_file.write((char*)bootstrap_shellcode.data(), bootstrap_shellcode.size());

    // write module section data
    for (int i = 0; i < module_buffers.size(); i++) {
        encrypt_buffer(module_buffers[i].data(), module_buffers[i].size(), xor_key);
        pe_file.seekp(module_section_headers[i].PointerToRawData);
        pe_file.write((char*)module_buffers[i].data(), module_buffers[i].size());
    }

    pe_file.close();
    return 0;
}

std::optional<std::vector<BYTE>> read_file(std::string path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        return std::nullopt;

    std::vector<BYTE> data;
    data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return data;
}

void randomize_section_name(PIMAGE_SECTION_HEADER section_header, PULONG seed) {
    // start at 1 to skip our "magic" section type indicator
    for (int j = 1; j < 8; j++)
        section_header->Name[j] = (char)(fnRtlRandomEx(seed) % 26 + 'a');
}

DWORD GetAlignedSize(DWORD size, DWORD alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

void encrypt_buffer(PBYTE buffer, DWORD size, ULONG_PTR xor_key) {
    for (int i = 0; i < size; i += sizeof(xor_key)) {
        auto data = (PULONG64)(buffer + i);
        *data ^= xor_key;
    }
}