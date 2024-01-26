#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>

// purpose: extract shellcode from object file given symbol name and emit C++ code
// usage: shellcode_extractor.exe <object_file> <symbol_name> [output_file]
// reason for existence: Why manually copy it every time when you shellcode_extractorcan 
//                       overengineer an automatic extractor/encoder?
// references: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

std::string getSymbolName(PIMAGE_SYMBOL symbol, PBYTE string_table);

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <object_file> <symbol_name> <output_file>" << std::endl;
        return 1;
    }

    std::string object_file_name = argv[1];
    std::string target_symbol_name = argv[2];
    std::string output_file_name = argv[3];

    std::ifstream object_file(argv[1], std::ios::binary);
    if (!object_file.is_open()) {
        std::cerr << "Failed to open file" << std::endl;
        return 1;
    }

    std::vector<unsigned char> object_data;
    object_data.assign(std::istreambuf_iterator<char>(object_file), std::istreambuf_iterator<char>());

    PBYTE object_base = (PBYTE)object_data.data();
    PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)object_base;
    if (file_header->Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "Not a 64-bit object file" << std::endl;
        return 1;
    }

    // parse symbol table
    PIMAGE_SYMBOL symbol_table = (PIMAGE_SYMBOL)(object_base + file_header->PointerToSymbolTable);
    PBYTE string_table = (PBYTE)(symbol_table + file_header->NumberOfSymbols);

    SHORT SectionNumber = IMAGE_SYM_UNDEFINED;
    DWORD SectionOffset = 0;
    for (int i = 0; i < file_header->NumberOfSymbols; i++) {
        std::string symbol_name = getSymbolName(&symbol_table[i], string_table);
        if (symbol_name != target_symbol_name) {
            i += symbol_table[i].NumberOfAuxSymbols;
            continue;
        }

        if ((symbol_table[i].Type >> 4) != IMAGE_SYM_DTYPE_FUNCTION || (symbol_table[i].Type & 0x0F) != IMAGE_SYM_TYPE_NULL) {
            std::cerr << "Specified symbol is not a function" << std::endl;
            return 1;
        }

        if (symbol_table[i].StorageClass != IMAGE_SYM_CLASS_EXTERNAL) {
            std::cerr << "Specified symbol is not external" << std::endl;
            return 1;
        }

        if (symbol_table[i].SectionNumber <= IMAGE_SYM_UNDEFINED) {
            std::cerr << "Specified symbol is not defined in any section" << std::endl;
            return 1;
        }

        SectionNumber = symbol_table[i].SectionNumber;
        SectionOffset = symbol_table[i].Value;
        break;
    }

    if (SectionNumber == IMAGE_SYM_UNDEFINED) {
        std::cerr << "Specified symbol not found" << std::endl;
        return 1;
    }

    // find section
    PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(object_base + sizeof(IMAGE_FILE_HEADER) + file_header->SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER target_section = &section_header[SectionNumber - 1]; // section numbers are 1-based

    // extract function data
    PBYTE section_data = object_base + target_section->PointerToRawData + SectionOffset;
    DWORD section_size = target_section->SizeOfRawData - SectionOffset;

    // write to file
    std::ofstream output_file(output_file_name, std::ios::binary);
    if (!output_file.is_open()) {
        std::cerr << "Failed to open output file" << std::endl;
        return 1;
    }

    output_file.write((char*)section_data, section_size);
    output_file.close();
    return 0;
}

std::string getSymbolName(PIMAGE_SYMBOL symbol, PBYTE string_table) {
    if (symbol->N.Name.Short == 0)
        return std::string((char*)(string_table + symbol->N.Name.Long));

    char short_name[9] = { 0 };
    memcpy(short_name, symbol->N.ShortName, 8);
    return std::string(short_name);
}