// maiara was here!

#include "util/pe/pe.h"
#include <windows.h>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "[!] drag and drop a file twin" << std::endl;
        return 1;
    }

    std::string input_path = argv[1]; 
    std::string output_path = input_path.substr(0, input_path.find_last_of('.')) + "_fix.exe"; 

    if (peutil::fix_pe(input_path, output_path)) {
        std::cout << "[+] fixed " << output_path << std::endl;
    }
    else {
        std::cerr << "[!] couldnt fix" << input_path << std::endl;
        return 1;
    }

    std::cin.get();

    return 0;
}
