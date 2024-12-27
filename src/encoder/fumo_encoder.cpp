#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <filesystem>
#include <stdint.h>
#include <ctime>
#include <random>
#include <fumo_data_header.h>
#include <lz4.h>

int main(int argc, char** argv) {
    // usage: [input_file] [process_name] [wait_for_module1,[wait_for_module2,...]] [output_file]

    std::string input_file_name = [argc, argv]() {
        if (argc > 1)
            return std::string(argv[1]);
        std::cout << "Input file (DLL): ";
        std::string input_file_name;
        std::getline(std::cin, input_file_name);
        return input_file_name;
    }();
    std::string process_name = [argc, argv]() {
        if (argc > 2)
            return std::string(argv[2]);
        std::cout << "Target process name: ";
        std::string process_name;
        std::getline(std::cin, process_name);
        return process_name;
    }();
    std::string wait_for_modules = [argc, argv]() {
        if (argc > 3)
            return std::string(argv[3]);
        std::cout << "Wait for modules (comma separated): ";
        std::string wait_for_modules;
        std::getline(std::cin, wait_for_modules);
        return wait_for_modules;
    }();
    std::string output_file_name = [argc, argv, input_file_name]() {
        if (argc > 4)
            return std::string(argv[4]);
        return std::filesystem::path(input_file_name).replace_extension(".fumo").string();
    }();

    if (process_name.length() == 0) {
        std::cerr << "No process name specified" << std::endl;
        return 1;
    }

    if (wait_for_modules.length() == 0) {
        std::cerr << "No wait modules specified, using default: kernel32.dll" << std::endl;
        wait_for_modules = "kernel32.dll";
    }
    
    // read input file
    std::ifstream input_file(input_file_name, std::ios::binary);
    if (!input_file.is_open()) {
        std::cerr << "Failed to open input file:" << input_file_name << std::endl;
        return 1;
    }
    std::vector<char> data;
    data.assign(std::istreambuf_iterator<char>(input_file), std::istreambuf_iterator<char>());

    // compress data
    std::vector<char> compressed_data;
    compressed_data.resize(LZ4_compressBound(data.size()));
    size_t compressed_size = LZ4_compress_default(data.data(), compressed_data.data(), data.size(), compressed_data.size());
    if (compressed_size <= 0) {
        std::cerr << "Failed to compress data" << std::endl;
        return 1;
    }
    compressed_data.resize(compressed_size);

    // generate xor key
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned long long> dis(
        std::numeric_limits<std::uint64_t>::min(),
        std::numeric_limits<std::uint64_t>::max()
    );
    uint64_t xor_key = dis(gen);

    // pad to 8 bytes
    int padding = 8 - (compressed_data.size() % 8);
    if (padding != 8)
        compressed_data.insert(compressed_data.end(), padding, 0);

    // encrypt compressed_data
    for (int i = 0; i < compressed_data.size(); i += sizeof(xor_key)) {
        uint64_t* ptr = (uint64_t*)&compressed_data[i];
        *ptr ^= xor_key;
    }

    // generate loader settings
    std::stringstream loader_settings;
    loader_settings << process_name << ';' << wait_for_modules;
    std::string loader_settings_str = loader_settings.str();
    std::vector<unsigned char> loader_settings_data;
    // write size
    uint32_t loader_settings_size = loader_settings.str().length();
    loader_settings_data.insert(loader_settings_data.end(), (unsigned char*)&loader_settings_size, (unsigned char*)&loader_settings_size + sizeof(loader_settings_size));
    // write data
    loader_settings_data.insert(loader_settings_data.end(), loader_settings_str.begin(), loader_settings_str.end());
    // pad to 8 bytes
    padding = 8 - (loader_settings_data.size() % 8);
    if (padding != 8)
        loader_settings_data.insert(loader_settings_data.end(), padding, 0);
    // encrypt loader settings
    for (int i = 0; i < loader_settings_data.size(); i += sizeof(xor_key)) {
        uint64_t* ptr = (uint64_t*)&loader_settings_data[i];
        *ptr ^= xor_key;
    }

    // write output file
    std::ofstream output_file(output_file_name, std::ios::binary);
    if (!output_file.is_open()) {
        std::cerr << "Failed to open output file:" << output_file_name << std::endl;
        return 1;
    }

    FUMO_DATA_HEADER header;
    header.Magic = FUMO_MAGIC;
    header.Version = FUMO_DATA_VERSION;
    header.XorKey = xor_key;
    header.SettingsSize = loader_settings_data.size();
    header.DataSize = compressed_data.size();
    header.CompressedDataSize = compressed_size;
    header.DecompressedDataSize = data.size();
    output_file.write((char*)&header, sizeof(header));
    output_file.write((char*)loader_settings_data.data(), loader_settings_data.size());
    output_file.write((char*)compressed_data.data(), compressed_data.size());

    output_file.close();

    std::cerr << "Successfully encoded " << input_file_name << " to " << output_file_name << std::endl;
    return 0;
}
