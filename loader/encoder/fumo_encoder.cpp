#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <filesystem>
#include <stdint.h>
#include <ctime>
#include <fomo_common.h>

std::vector<std::string> split(std::string text, char delim) {
    std::string line;
    std::vector<std::string> vec;
    std::stringstream ss(text);
    while(std::getline(ss, line, delim))
        vec.push_back(line);
    return vec;
}

int main(int argc, char** argv) {
    // usage: [input_file] [process_name] [wait_for_module1,[wait_for_module2,...]]

    std::string input_file_name = [argc, argv]() {
        std::cout << "Input file (DLL): ";
        if (argc > 1) {
            std::cout << argv[1] << std::endl;
            return std::string(argv[1]);
        }
        std::string input_file_name;
        std::getline(std::cin, input_file_name);
        return input_file_name;
    }();
    std::string process_name = [argc, argv]() {
        std::cout << "Target process name: ";
        if (argc > 2) {
            std::cout << argv[2] << std::endl;
            return std::string(argv[2]);
        }
        std::string process_name;
        std::getline(std::cin, process_name);
        return process_name;
    }();
    std::string wait_for_modules = [argc, argv]() {
        std::cout << "Wait for modules (comma separated): ";
        if (argc > 3) {
            std::cout << argv[3] << std::endl;
            return std::string(argv[3]);
        }
        std::string wait_for_modules;
        std::getline(std::cin, wait_for_modules);
        return wait_for_modules;
    }();

    if (process_name.length() == 0) {
        std::cerr << "No process name specified" << std::endl;
        return 1;
    }

    if (wait_for_modules.length() == 0) {
        std::cerr << "No wait modules specified, using default: kernel32.dll" << std::endl;
        wait_for_modules = "kernel32.dll";
    }
    
    // get output file name
    std::string output_file_name = std::filesystem::path(input_file_name).replace_extension(".fumo").string();
    
    // read input file
    std::ifstream input_file(input_file_name, std::ios::binary);
    if (!input_file.is_open()) {
        std::cerr << "Failed to open input file:" << input_file_name << std::endl;
        return 1;
    }
    std::vector<unsigned char> data;
    data.assign(std::istreambuf_iterator<char>(input_file), std::istreambuf_iterator<char>());

    // generate xor key
    std::srand(std::time(nullptr));
    uint64_t xor_key = 0;
    for (int i = 0; i < 8; i++)
        xor_key |= (std::rand() % 256) << (i * 8);

    // pad to 8 bytes
    int padding = 8 - (data.size() % 8);
    if (padding != 8)
        data.insert(data.end(), padding, 0);

    // encrypt data
    for (int i = 0; i < data.size(); i += sizeof(xor_key)) {
        uint64_t* ptr = (uint64_t*)&data[i];
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

    // write encrypted data
    std::ofstream output_file(output_file_name, std::ios::binary);
    if (!output_file.is_open()) {
        std::cerr << "Failed to open output file:" << output_file_name << std::endl;
        return 1;
    }
    output_file.write("FUMO", 4); // magic
    uint32_t version = FUMO_DRIVER_VERSION;
    output_file.write((char*)&version, sizeof(version));
    output_file.write((char*)&xor_key, sizeof(xor_key));
    output_file.write((char*)loader_settings_data.data(), loader_settings_data.size());
    output_file.write((char*)data.data(), data.size());
    output_file.close();

    std::cerr << "Successfully encoded " << input_file_name << " to " << output_file_name << std::endl;

    return 0;
}
