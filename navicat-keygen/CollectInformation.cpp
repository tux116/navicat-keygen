#include "SerialNumberGenerator.hpp"
#include "ExceptionGeneric.hpp"
#include <iostream>

namespace nkg {

    [[nodiscard]]
    static int ReadInt(int MinVal, int MaxVal, const char* lpszPrompt, const char* lpszErrorMessage) {
        int val;
        std::string s;
        while (true) {
            std::cout << lpszPrompt;
            if (!std::getline(std::cin, s)) {
                throw ARL::EOFError(__FILE__, __LINE__, "Abort.");
            }

            if (s.empty())
                continue;

            try {
                val = std::stoi(s, nullptr, 0);
                if (MinVal <= val && val <= MaxVal) {
                    return val;
                } else {
                    throw std::invalid_argument("Out of range.");
                }
            } catch (std::invalid_argument&) {
                std::cout << lpszErrorMessage << std::endl;
            }
        }
    }

    [[nodiscard]]
    static int ReadInt(int MinVal, int MaxVal, int DefaultVal, const char* lpszPrompt, const char* lpszErrorMessage) {
        int val;
        std::string s;
        while (true) {
            std::cout << lpszPrompt;
            if (!std::getline(std::cin, s)) {
                throw ARL::EOFError(__FILE__, __LINE__, "Abort.");
            }

            if (s.empty()) {
                return DefaultVal;
            }

            try {
                val = std::stoi(s, nullptr, 0);
                if (MinVal <= val && val <= MaxVal) {
                    return val;
                } else {
                    throw std::invalid_argument("Out of range.");
                }
            } catch (std::invalid_argument&) {
                std::cout << lpszErrorMessage << std::endl;
            }
        }
    }

    [[nodiscard]]
    SerialNumberGenerator CollectInformationNormal() {
        SerialNumberGenerator Generator;

        Generator.SetProductSignature(NavicatProductType::Premium);
        
        std::cout << "[*] Select product language:" << std::endl;
        std::cout << " 0. English"                  << std::endl;
        std::cout << " 1. Simplified Chinese"       << std::endl;
        std::cout << " 2. Traditional Chinese"      << std::endl;
        std::cout << " 3. Japanese"                 << std::endl;
        std::cout << " 4. Polish"                   << std::endl;
        std::cout << " 5. Spanish"                  << std::endl;
        std::cout << " 6. French"                   << std::endl;
        std::cout << " 7. German"                   << std::endl;
        std::cout << " 8. Korean"                   << std::endl;
        std::cout << " 9. Russian"                  << std::endl;
        std::cout << " 10. Portuguese"              << std::endl;
        std::cout << std::endl;
        Generator.SetLanguageSignature(
            static_cast<NavicatLanguage>(ReadInt(0, 10, "(Input index)> ", "Invalid index."))
        );

        std::cout << std::endl;
        std::cout << "[*] Input major version number:" << std::endl;
        Generator.SetVersion(
            static_cast<uint8_t>(ReadInt(0, 15, 15, "(range: 0 ~ 15, default: 15)> ", "Invalid number."))
        );

        std::cout << std::endl;
        return Generator;
    }

    [[nodiscard]]
    SerialNumberGenerator CollectInformationAdvanced() {
        SerialNumberGenerator Generator;

        std::cout << "[*] Navicat Product Signature:" << std::endl;
        Generator.SetProductSignature(
            static_cast<uint8_t>(ReadInt(0x00, 0xff, "(range: 0x00 ~ 0xFF)> ", "Invalid number."))
        );

        std::cout << std::endl;
        std::cout << "[*] Navicat Language Signature 0:" << std::endl;
        auto s1 = static_cast<uint8_t>(ReadInt(0x00, 0xff, "(range: 0x00 ~ 0xFF)> ", "Invalid number."));

        std::cout << std::endl;
        std::cout << "[*] Navicat Language Signature 1:" << std::endl;
        auto s2 = static_cast<uint8_t>(ReadInt(0x00, 0xff, "(range: 0x00 ~ 0xFF)> ", "Invalid number."));
        
        Generator.SetLanguageSignature(s1, s2);

        std::cout << std::endl;
        std::cout << "[*] Input major version number:" << std::endl;
        Generator.SetVersion(
            static_cast<uint8_t>(ReadInt(0, 15, 12, "(range: 0 ~ 15, default: 12)> ", "Invalid number."))
        );

        std::cout << std::endl;
        return Generator;
    }
}
