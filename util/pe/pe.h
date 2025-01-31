#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>

namespace peutil {
    DWORD calculate_checksum(std::string file_path);

    bool fix_pe(std::string input_path, std::string output_path);
}
