#include "pe.h"

DWORD peutil::calculate_checksum(std::string file_path) // not my checksum function, credit to reddit and stackoverflow ig..
{ 
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "[-] !isopen" << std::endl;
        return 0;
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(file_size);
    file.read(buffer.data(), file_size);
    file.close();

    DWORD sum = 0;
    WORD* data = reinterpret_cast<WORD*>(buffer.data());
    size_t num_words = file_size / sizeof(WORD);

    for (size_t i = 0; i < num_words; ++i) {
        sum += data[i];
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    if (file_size % sizeof(WORD)) {
        sum += (static_cast<WORD>(buffer[file_size - 1]) << 8);
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return ~sum;
}

bool peutil::fix_pe(std::string input_path, std::string output_path)
{
    std::ifstream file(input_path, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "[-] !isopen" << std::endl;
        return false;
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(file_size);
    file.read(buffer.data(), file_size);
    file.close();

    IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
    IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dos_header->e_lfanew);

    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[-] bad pe" << std::endl;
        return false;
    }

    std::cout << "[+] nt headers signature -> " << nt_headers->Signature << std::endl;

    nt_headers->OptionalHeader.CheckSum = 0;

    uint32_t section_alignment = nt_headers->OptionalHeader.SectionAlignment;
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt_headers);

    for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        sections[i].VirtualAddress = (sections[i].VirtualAddress / section_alignment) * section_alignment;
        sections[i].SizeOfRawData = (sections[i].SizeOfRawData / 512) * 512;
    }

    std::cout << "[+] virtual address -> " << sections->VirtualAddress << std::endl;

    DWORD checksum = calculate_checksum(input_path);
    nt_headers->OptionalHeader.CheckSum = checksum;

    std::cout << "[+] checksum -> " << nt_headers->OptionalHeader.CheckSum << std::endl;

    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file.is_open()) {
        std::cerr << "[!] could not open output file" << std::endl;
        return false;
    }

    output_file.write(buffer.data(), buffer.size());
    output_file.close();

    std::cout << "[+] saved as " << output_path << std::endl;
    return true;
}