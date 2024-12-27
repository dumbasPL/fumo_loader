#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <optional>
#include <random>
#define VAR_LEN 0
#include <linuxpe>
#include <string.h>
#include "bootstrap.h"

std::optional<std::vector<uint8_t>> read_file(std::string path);
template <typename E>
void randomize_section_name(win::section_header_t* section_header, E& engine);
uint32_t get_aligned_size(uint32_t size, uint32_t alignment);
void encrypt_buffer(uint8_t* buffer, uint32_t size, uint64_t xor_key);
std::vector<uint8_t> generate_resource_section(uint32_t virtual_address);

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

    std::vector<std::vector<uint8_t>> module_buffers;
    for (auto& module_path : module_paths) {
        auto module_buffer = read_file(module_path);
        if (!module_buffer.has_value()) {
            std::cerr << "Failed to read module file: " << module_path << std::endl;
            return 1;
        }
        module_buffers.push_back(module_buffer.value());
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned long long> dis(
        std::numeric_limits<std::uint64_t>::min(),
        std::numeric_limits<std::uint64_t>::max()
    );
    uint64_t xor_key = dis(gen);

    uint32_t NumberOfSections = 3 + module_buffers.size();

    // DOS header
    win::dos_header_t dos_header;
    memset(&dos_header, 0, sizeof(dos_header));
    dos_header.e_magic = win::DOS_HDR_MAGIC;
    dos_header.e_cblp = 0x90;
    dos_header.e_cp = 0x3;
    dos_header.e_cparhdr = 0x4;
    dos_header.e_maxalloc = 0xFFFF;
    dos_header.e_sp = 0xB8;
    dos_header.e_lfarlc = 0x40;
    dos_header.e_lfanew = 0x40;

    // NT headers
    win::nt_headers_x64_t nt_headers;
    memset(&nt_headers, 0, sizeof(nt_headers));
    nt_headers.signature = win::NT_HDR_MAGIC;
    nt_headers.file_header.machine = win::machine_id::amd64;
    nt_headers.file_header.num_sections = NumberOfSections;
    nt_headers.file_header.timedate_stamp = 0x0; // FIXME: randomize
    nt_headers.file_header.size_optional_header = sizeof(nt_headers.optional_header);
    nt_headers.file_header.characteristics.relocs_stripped = true;
    nt_headers.file_header.characteristics.executable = true;
    nt_headers.file_header.characteristics.lines_stripped = true;
    nt_headers.file_header.characteristics.local_symbols_stripped = true;
    nt_headers.file_header.characteristics.large_address_aware = true;
    nt_headers.optional_header.magic = win::OPT_HDR64_MAGIC;
    nt_headers.optional_header.linker_version.major = 0x1;
    nt_headers.optional_header.linker_version.minor = 0x0;
    nt_headers.optional_header.size_code = 0; //* needs to be updated
    nt_headers.optional_header.size_init_data = 0; //* needs to be updated
    nt_headers.optional_header.size_uninit_data = 0x0;
    nt_headers.optional_header.entry_point = 0; //* needs to be updated
    nt_headers.optional_header.base_of_code = 0x1000;
    nt_headers.optional_header.image_base = 0x0000000140000000;
    nt_headers.optional_header.section_alignment = 0x1000;
    nt_headers.optional_header.file_alignment = 0x200;
    nt_headers.optional_header.os_version.major = 0x6;
    nt_headers.optional_header.os_version.minor = 0x6;
    nt_headers.optional_header.img_version.major = 0x0;
    nt_headers.optional_header.img_version.minor = 0x0;
    nt_headers.optional_header.subsystem_version.major = 0x6;
    nt_headers.optional_header.subsystem_version.minor = 0x0;
    nt_headers.optional_header.win32_version_value = 0x0;
    nt_headers.optional_header.size_image = 0; //* needs to be updated
    nt_headers.optional_header.size_headers = 0x400; //* needs to be updated
    nt_headers.optional_header.checksum = 0x0;
    nt_headers.optional_header.subsystem = win::subsystem_id::windows_gui;
    nt_headers.optional_header.characteristics.dynamic_base = true;
    nt_headers.optional_header.characteristics.nx_compat = true;
    nt_headers.optional_header.characteristics.terminal_server_aware = true;
    nt_headers.optional_header.size_stack_reserve = 0x100000;
    nt_headers.optional_header.size_stack_commit = 0x1000;
    nt_headers.optional_header.size_heap_reserve = 0x100000;
    nt_headers.optional_header.size_heap_commit = 0x1000;
    nt_headers.optional_header.ldr_flags = 0x0;
    nt_headers.optional_header.num_data_directories = win::NUM_DATA_DIRECTORIES;

    // section headers
    uint32_t size_of_headers = sizeof(dos_header) + sizeof(nt_headers) + NumberOfSections * sizeof(win::section_header_t);
    // round up to nearest FileAlignment
    size_of_headers = get_aligned_size(size_of_headers, nt_headers.optional_header.file_alignment);
    nt_headers.optional_header.size_headers = size_of_headers;

    // round up to nearest SectionAlignment after headers
    uint32_t next_virtual_address = get_aligned_size(size_of_headers, nt_headers.optional_header.section_alignment);
    uint32_t next_pointer_to_raw_data = get_aligned_size(size_of_headers, nt_headers.optional_header.file_alignment);

    // loader section
    win::section_header_t initial_loader_section_header;
    memset(&initial_loader_section_header, 0, sizeof(initial_loader_section_header));
    initial_loader_section_header.name.short_name[0] = 'l'; // loader
    randomize_section_name(&initial_loader_section_header, gen);
    initial_loader_section_header.virtual_size = initial_loader_buffer->size();
    initial_loader_section_header.virtual_address = next_virtual_address;
    initial_loader_section_header.size_raw_data = initial_loader_buffer->size();
    initial_loader_section_header.ptr_raw_data = next_pointer_to_raw_data;
    initial_loader_section_header.characteristics.mem_execute = true;
    initial_loader_section_header.characteristics.mem_read = true;
    initial_loader_section_header.characteristics.mem_write = true;

    // get next free virtual address and pointer to raw data (round up to nearest section_alignment)
    next_virtual_address += get_aligned_size(initial_loader_section_header.virtual_size, nt_headers.optional_header.section_alignment);
    next_pointer_to_raw_data += get_aligned_size(initial_loader_section_header.size_raw_data, nt_headers.optional_header.file_alignment);

    // bootstrap section
    auto bootstrap_shellcode = get_bootstrap_shellcode(xor_key, initial_loader_section_header.virtual_address, initial_loader_section_header.size_raw_data);
    win::section_header_t bootstrap_section_header;
    memset(&bootstrap_section_header, 0, sizeof(bootstrap_section_header));
    bootstrap_section_header.name.short_name[0] = 'b'; // bootstrap
    randomize_section_name(&bootstrap_section_header, gen);
    bootstrap_section_header.virtual_size = bootstrap_shellcode.size();
    bootstrap_section_header.virtual_address = next_virtual_address;
    bootstrap_section_header.size_raw_data = bootstrap_shellcode.size();
    bootstrap_section_header.ptr_raw_data = next_pointer_to_raw_data;
    bootstrap_section_header.characteristics.mem_execute = true;
    bootstrap_section_header.characteristics.mem_read = true;
    bootstrap_section_header.characteristics.mem_write = true;

    // get next free virtual address and pointer to raw data (round up to nearest section_alignment)
    next_virtual_address += get_aligned_size(bootstrap_section_header.virtual_size, nt_headers.optional_header.section_alignment);
    next_pointer_to_raw_data += get_aligned_size(bootstrap_section_header.size_raw_data, nt_headers.optional_header.file_alignment);

    // module sections
    std::vector<win::section_header_t> module_section_headers;
    for (auto& module_buffer : module_buffers) {
        // section header
        win::section_header_t section_header;
        memset(&section_header, 0, sizeof(section_header));
        section_header.name.short_name[0] = 'e'; // encrypted
        randomize_section_name(&section_header, gen);
        section_header.virtual_size = module_buffer.size();
        section_header.virtual_address = next_virtual_address;
        section_header.size_raw_data = module_buffer.size();
        section_header.ptr_raw_data = next_pointer_to_raw_data;
        section_header.characteristics.mem_read = true;
        section_header.characteristics.mem_write = true;

        // get next free virtual address and pointer to raw data (round up to nearest section_alignment)
        next_virtual_address += get_aligned_size(section_header.virtual_size, nt_headers.optional_header.section_alignment);
        next_pointer_to_raw_data += get_aligned_size(section_header.size_raw_data, nt_headers.optional_header.file_alignment);

        module_section_headers.push_back(section_header);
    }

    // resource section
    auto resource_section_data = generate_resource_section(next_virtual_address);
    win::section_header_t resource_section_header;
    memset(&resource_section_header, 0, sizeof(resource_section_header));
    strcpy(resource_section_header.name.short_name, ".rsrc");
    resource_section_header.virtual_size = resource_section_data.size();
    resource_section_header.virtual_address = next_virtual_address;
    resource_section_header.size_raw_data = resource_section_data.size();
    resource_section_header.ptr_raw_data = next_pointer_to_raw_data;
    resource_section_header.characteristics.mem_read = true;

    // get next free virtual address and pointer to raw data (round up to nearest section_alignment)
    next_virtual_address += get_aligned_size(resource_section_header.virtual_size, nt_headers.optional_header.section_alignment);
    next_pointer_to_raw_data += get_aligned_size(resource_section_header.size_raw_data, nt_headers.optional_header.file_alignment);
    
    // update NT headers
    nt_headers.optional_header.size_image = next_virtual_address;
    nt_headers.optional_header.size_code = initial_loader_section_header.size_raw_data + bootstrap_section_header.size_raw_data;
    nt_headers.optional_header.size_init_data = initial_loader_section_header.size_raw_data + bootstrap_section_header.size_raw_data;
    nt_headers.optional_header.entry_point = bootstrap_section_header.virtual_address;
    nt_headers.optional_header.data_directories.resource_directory.rva = resource_section_header.virtual_address;
    nt_headers.optional_header.data_directories.resource_directory.size = resource_section_header.size_raw_data;

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
    pe_file.write((char*)&resource_section_header, sizeof(resource_section_header));

    // write loader section data
    encrypt_buffer(initial_loader_buffer->data(), initial_loader_buffer->size(), xor_key);
    pe_file.seekp(initial_loader_section_header.ptr_raw_data);
    pe_file.write((char*)initial_loader_buffer->data(), initial_loader_buffer->size());

    // write bootstrap section data
    pe_file.seekp(bootstrap_section_header.ptr_raw_data);
    pe_file.write((char*)bootstrap_shellcode.data(), bootstrap_shellcode.size());

    // write module section data
    for (int i = 0; i < module_buffers.size(); i++) {
        encrypt_buffer(module_buffers[i].data(), module_buffers[i].size(), xor_key);
        pe_file.seekp(module_section_headers[i].ptr_raw_data);
        pe_file.write((char*)module_buffers[i].data(), module_buffers[i].size());
    }

    // write resource section data
    pe_file.seekp(resource_section_header.ptr_raw_data);
    pe_file.write((char*)resource_section_data.data(), resource_section_data.size());

    pe_file.close();
    return 0;
}

std::optional<std::vector<uint8_t>> read_file(std::string path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        return std::nullopt;

    std::vector<uint8_t> data;
    data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return data;
}

template <typename E>
void randomize_section_name(win::section_header_t* section_header, E& engine) {
    std::uniform_int_distribution<int> dis('a', 'z');

    // start at 1 to skip our "magic" section type indicator
    for (int j = 1; j < 8; j++)
        section_header->name.short_name[j] = (char)dis(engine);
}

uint32_t get_aligned_size(uint32_t size, uint32_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

void encrypt_buffer(uint8_t* buffer, uint32_t size, uint64_t xor_key) {
    for (int i = 0; i < size; i += sizeof(xor_key)) {
        auto data = (uint64_t*)(buffer + i);
        *data ^= xor_key;
    }
}

std::vector<uint8_t> generate_resource_section(uint32_t virtual_address) {
    std::vector<uint8_t> data;

    // same thing but with a template and automatic size calculation
    auto allocate = [&]<class T>() -> T* {
        auto offset = data.size();
        data.resize(offset + sizeof(T));
        return reinterpret_cast<T*>(&data[offset]);
    };

    static_assert(sizeof(win::rsrc_directory_t) == 0x10);
    static_assert(sizeof(win::rsrc_generic_t) == 0x8);
    static_assert(sizeof(win::rsrc_data_t) == 0x10);

    auto resource_directory1 = allocate.operator()<win::rsrc_directory_t>();
    resource_directory1->characteristics = 0;
    resource_directory1->timedate_stamp = 0;
    resource_directory1->version.major = 0;
    resource_directory1->version.minor = 0;
    resource_directory1->num_named_entries = 0;
    resource_directory1->num_id_entries = 1;

    // manifest resource
    auto resource_directory_entry1 = allocate.operator()<win::rsrc_generic_t>();
    resource_directory_entry1->identifier = (uint16_t)win::resource_id::manifest;
    resource_directory_entry1->is_directory = true;
    resource_directory_entry1->offset = data.size();

    auto resource_directory2 = allocate.operator()<win::rsrc_directory_t>();
    resource_directory2->characteristics = 0;
    resource_directory2->timedate_stamp = 0;
    resource_directory2->version.major = 0;
    resource_directory2->version.minor = 0;
    resource_directory2->num_named_entries = 0;
    resource_directory2->num_id_entries = 1;

    auto resource_directory_entry2 = allocate.operator()<win::rsrc_generic_t>();
    resource_directory_entry2->identifier = 1;
    resource_directory_entry2->is_directory = true;
    resource_directory_entry2->offset = data.size();

    auto resource_directory3 = allocate.operator()<win::rsrc_directory_t>();
    resource_directory3->characteristics = 0;
    resource_directory3->timedate_stamp = 0;
    resource_directory3->version.major = 0;
    resource_directory3->version.minor = 0;
    resource_directory3->num_named_entries = 0;
    resource_directory3->num_id_entries = 1;

    auto resource_directory_entry3 = allocate.operator()<win::rsrc_generic_t>();
    resource_directory_entry3->identifier = 0x409; // english
    resource_directory_entry3->is_directory = false;
    resource_directory_entry3->offset = data.size();

    std::string manifest = R"(<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
)";

    auto resource_data_entry = allocate.operator()<win::rsrc_data_t>();
    resource_data_entry->rva_data = virtual_address + data.size();
    resource_data_entry->size_data = manifest.size();
    resource_data_entry->code_page = 0;
    resource_data_entry->reserved = 0;

    data.insert(data.end(), manifest.begin(), manifest.end());

    return data;
}