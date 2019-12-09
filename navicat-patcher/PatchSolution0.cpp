#include "PatchSolutions.hpp"
#include "Misc.hpp"
#include <memory.h>

namespace nkg {

    const char PatchSolution0::Keyword[451] =
        "-----BEGIN PUBLIC KEY-----\x00"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\x00"
        "qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\x00"
        "a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\x00"
        "R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\x00"
        "WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\x00"
        "YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\x00"
        "awIDAQAB\x00"
        "-----END PUBLIC KEY-----";

    PatchSolution0::PatchSolution0(const X64ImageInterpreter& Image) :
        m_Image(Image) {}

    [[nodiscard]]
    bool PatchSolution0::FindPatchOffset() noexcept {
        try {
            auto lpPatch = m_Image.SearchSection("__TEXT", "__cstring", [](const void* base, size_t i, size_t size) {
                if (i + sizeof(Keyword) <= size) {
                    auto p = ARL::AddressOffset(base, i);
                    return memcmp(p, Keyword, sizeof(Keyword) - 1) == 0;
                } else {
                    return false;
                }
            });
            if (lpPatch) {
                m_PatchOffset = m_Image.ConvertPtrToOffset(lpPatch);
            } else {
                throw ARL::Exception(__FILE__, __LINE__, "not found.");
            }

            printf("[+] PatchSolution0 ...... Ready to apply.\n");
            printf("    Keyword offset = +0x%.8x\n", m_PatchOffset.value());
            return true;
        } catch (...) {
            printf("[-] PatchSolution0 ...... Omitted.\n");
            return false;
        }
    }

    [[nodiscard]]
    bool PatchSolution0::CheckKey(const RSACipher& Cipher) const noexcept {
        try {
            return Cipher.Bits() == 2048;
        } catch (...) {
            return false;
        }
    }

    void PatchSolution0::MakePatch(const RSACipher& Cipher) const {
        if (m_PatchOffset.has_value()) {
            std::string szPublicKeyPEM = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();
            for (auto& c : szPublicKeyPEM) {
                if (c == '\n') {
                    c = '\x00';
                }
            }

            while (szPublicKeyPEM.length() < sizeof(Keyword)) {
                szPublicKeyPEM.push_back('\x00');
            }

            auto lpPatch = m_Image.ImageOffset(m_PatchOffset.value());

            puts("**************************************************************");
            puts("*                      PatchSolution0                        *");
            puts("**************************************************************");
            
            printf("[*] Previous:\n");
            Misc::PrintMemory(lpPatch, sizeof(Keyword), m_Image.ImageBase());
                memcpy(lpPatch, szPublicKeyPEM.data(), sizeof(Keyword));
            printf("[*] After:\n");
            Misc::PrintMemory(lpPatch, sizeof(Keyword), m_Image.ImageBase());
            printf("\n");

        } else {
            throw ARL::Exception(__FILE__, __LINE__, "PatchSolution0: not ready yet.");
        }
    }

}

