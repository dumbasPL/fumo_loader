#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <array>
#include <iomanip>
#include <filesystem>

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <symbol_name> <output_path> " << std::endl;
        return 1;
    }

    std::string input_file_name = argv[1];
    std::string target_symbol_name = argv[2];
    std::filesystem::path output_path = argv[3];

    std::ifstream input_file(input_file_name, std::ios::binary);
    if (!input_file.is_open()) {
        std::cerr << "Failed to open file" << std::endl;
        return 1;
    }

    std::vector<unsigned char> input_data;
    input_data.assign(std::istreambuf_iterator<char>(input_file), std::istreambuf_iterator<char>());

    std::filesystem::path output_source_path = output_path / (target_symbol_name + ".cpp");
    std::ofstream output_file(output_source_path, std::ios::binary);
    if (!output_file.is_open()) {
        std::cerr << "Failed to open source file: " << output_source_path << std::endl;
        return 1;
    }

    output_file << "#include \"" << target_symbol_name << ".h\"\n\n";
    output_file << "std::array<unsigned char, " << input_data.size() << "> res::" << target_symbol_name << " = {\n\t";
    for (int i = 0; i < input_data.size(); i++) {
        if (i % 16 == 0 && i != 0) {
            output_file << "\n\t";
        }
        output_file << "0x" << std::setfill('0') << std::setw(2) << std::hex << (int)input_data[i] << ", ";
    }
    output_file << "\n};\n";
    output_file.close();

    std::filesystem::path output_header_path = output_path / (target_symbol_name + ".h");
    std::ofstream output_header(output_header_path, std::ios::binary);
    if (!output_header.is_open()) {
        std::cerr << "Failed to open header file: " << output_header_path << std::endl;
        return 1;
    }

    output_header << "#pragma once\n\n";
    output_header << "#include <array>\n\n";
    output_header << "namespace res {\n";
    output_header << "extern std::array<unsigned char, " << input_data.size() << "> " << target_symbol_name << ";\n";
    output_header << "}\n";
    output_header.close();

    return 0;
}