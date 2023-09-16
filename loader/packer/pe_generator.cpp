#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <optional>
#include "imports.h"
#include "bootstrap.h"
#include <lazy_importer.hpp>

std::optional<std::vector<BYTE>> read_file(std::string path);
void randomize_section_name(PIMAGE_SECTION_HEADER section_header, PULONG seed);
DWORD GetAlignedSize(DWORD size, DWORD alignment);
void encrypt_buffer(PBYTE buffer, DWORD size, ULONG_PTR xor_key);

auto fnRtlRandomEx = LI_FN(RtlRandomEx);

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <initial_loader> <output_file>" << std::endl;
        return 1;
    }

    std::string initial_loader_path = argv[1];
    std::string output_file_path = argv[2];

    auto initial_loader_buffer = read_file(initial_loader_path);
    if (!initial_loader_buffer.has_value()) {
        std::cerr << "Failed to read initial_loader file" << std::endl;
        return 1;
    }

    ULONG seed = (ULONG)GetTickCount64();
    ULONG_PTR xor_key = (ULONG_PTR)fnRtlRandomEx(&seed) | ((ULONG_PTR)fnRtlRandomEx(&seed) << 32);

    DWORD NumberOfSections = 2;

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
    nt_headers.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
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
    initial_loader_section_header.Name[0] = 'l';
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
    bootstrap_section_header.Name[0] = 'b';
    randomize_section_name(&bootstrap_section_header, &seed);
    bootstrap_section_header.Misc.VirtualSize = bootstrap_shellcode.size();
    bootstrap_section_header.VirtualAddress = NextVirtualAddress;
    bootstrap_section_header.SizeOfRawData = bootstrap_shellcode.size();
    bootstrap_section_header.PointerToRawData = NextPointerToRawData;
    bootstrap_section_header.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // get next free virtual address and pointer to raw data (round up to nearest SectionAlignment)
    NextVirtualAddress += GetAlignedSize(bootstrap_section_header.Misc.VirtualSize, nt_headers.OptionalHeader.SectionAlignment);
    NextPointerToRawData += GetAlignedSize(bootstrap_section_header.SizeOfRawData, nt_headers.OptionalHeader.FileAlignment);

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

    // write section data
    encrypt_buffer(initial_loader_buffer->data(), initial_loader_buffer->size(), xor_key);
    pe_file.seekp(initial_loader_section_header.PointerToRawData);
    pe_file.write((char*)initial_loader_buffer->data(), initial_loader_buffer->size());

    pe_file.seekp(bootstrap_section_header.PointerToRawData);
    pe_file.write((char*)bootstrap_shellcode.data(), bootstrap_shellcode.size());

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