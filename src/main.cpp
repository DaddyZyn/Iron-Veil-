#include "../include/Common.hpp"
#include "../include/PeParser.hpp"
#include "../include/PeBuilder.hpp"
#include <iostream>

void PrintBanner() {
    std::cout << "\x1b[95m[ IronVeil ]\x1b[0m\n\n";
}

void PrintUsage() {
    std::cout << "Usage: IronVeil.exe <input.exe> [output.exe] [options]\n\n"
              << "Options:\n"
              << "  --no-encrypt-rdata    Do not encrypt .rdata constants section (encrypted by default)\n"
              << "  --no-pdata            Do not sanitize and dynamicize runtime unwind (.pdata) tables\n"
              << "  --no-antidebug        Disable all runtime anti-debugging checks\n"
              << "  --no-relocs           Do not preserve and process base relocations\n"
              << "  --no-tls              Do not process TLS callbacks\n"
              << "  --section-name <str>  Custom name for the injected stub section (default: .guard)\n"
              << "  --help                Display this help menu\n\n";
}

int main(int argc, char* argv[]) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            SetConsoleMode(hOut, dwMode | 0x0004);
        }
    }

    PrintBanner();

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string inputPath = argv[1];
    if (inputPath == "--help" || inputPath == "-h") {
        PrintUsage();
        return 0;
    }

    std::string outputPath;
    IronVeil::ProtectorOptions options;

    int argIdx = 2;
    if (argc >= 3 && argv[2][0] != '-') {
        outputPath = argv[2];
        argIdx = 3;
    } else {
        size_t dotPos = inputPath.find_last_of('.');
        if (dotPos != std::string::npos) {
            outputPath = inputPath.substr(0, dotPos) + "_protected.exe";
        } else {
            outputPath = inputPath + "_protected.exe";
        }
    }

    for (int i = argIdx; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--encrypt-rdata") {
            options.encryptRdataSection = true;
        } else if (arg == "--no-encrypt-rdata") {
            options.encryptRdataSection = false;
        } else if (arg == "--no-pdata") {
            options.sanitizePdata = false;
        } else if (arg == "--no-antidebug") {
            options.antiDebugFlags = IronVeil::ANTIDEBUG_NONE;
        } else if (arg == "--no-relocs") {
            options.handleRelocations = false;
        } else if (arg == "--no-tls") {
            options.handleTlsCallbacks = false;
        } else if (arg == "--section-name" && i + 1 < argc) {
            options.sectionName = argv[++i];
        }
    }

    std::cout << "[*] Target Input  : " << inputPath << std::endl;
    std::cout << "[*] Output Path   : " << outputPath << std::endl;

    IronVeil::PeParser parser;
    if (!parser.Load(inputPath)) {
        std::cerr << "[-] Error: Failed to open or parse target 64-bit PE executable." << std::endl;
        return 1;
    }

    auto* nt = parser.GetNtHeaders();
    std::cout << "[+] Valid 64-bit PE detected. Original OEP: 0x" 
              << std::hex << std::uppercase << nt->OptionalHeader.AddressOfEntryPoint << std::dec << std::endl;

    IronVeil::PeBuilder builder(parser, options);
    std::vector<uint8_t> protectedPe;

    if (!builder.Build(protectedPe)) {
        std::cerr << "[-] Build process failed." << std::endl;
        return 1;
    }

    if (!parser.Save(outputPath, protectedPe)) {
        std::cerr << "[-] Error: Failed to write protected binary to " << outputPath << std::endl;
        return 1;
    }

    std::cout << "\x1b[92m[SUCCESS] Binary successfully protected!\x1b[0m File saved to: " << outputPath << std::endl;
    std::cout << "[*] Protected file size: " << protectedPe.size() / 1024 << " KB" << std::endl;

    return 0;
}
