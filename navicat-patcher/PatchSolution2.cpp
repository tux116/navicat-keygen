#include "PatchSolutions.hpp"
#include "Misc.hpp"
#include <string.h>

namespace nkg {

    const char PatchSolution2::Keyword[1114] =
        "BIjWyoeRR0NBgkqnDZWxCgKCEAw1dqF3DTvOB91ZHwecJYFrdM1KEh"
        "1yVeRoGqSdLLGZGUlngig3OD5mMzs889IqWqqfHSeHMvzyg1p6UPCY"
        "nesxa9M2dDUrXHomRHOFHSfsbSXRFwt5GivtnJG9lLJHZ7XWeIQABi"
        "dKionYD3O6c9tvUAoDosUJAdQ1RaSXTzyETbHTRtnTPeLpO3EedGMs"
        "v3jG9yPcmmdYkddSeJRwn2raPJmnvdHScHUACw0sUNuosAqPaQbTQN"
        "PATDzcrnd1Sf8RIbUp4MQJFVJugPLVZbP53Gjtyyniqe5q75kva8Qm"
        "Hr1uOuXkVppe3cwECaGamupG43L1XfcpRjCMrxRep3s2VlbL01xmfz"
        "5cIhrj34iVmgZSAmIb8ZxiHPdp1oDMFkbNetZyWegqjAHQQ9eoSOTD"
        "bERbKEwZ5FLeLsbNAxfqsapB1XBvCavFHualx6bxVxuRQceh4z8kaZ"
        "iv2pOKbZQSJ2Dx5HEq0bYZ6y6b7sN9IaeDFNQwjzQn1K7k3XlYAPWC"
        "IvDe8Ln0FUe4yMNmuUhu5RTjxE05hUqtz1HjJvYQ9Es1VA6LflKQ87"
        "TwIXBNvfrcHaZ72QM4dQtDUyEMrLgMDkJBDM9wqIDps65gSlAz6eHD"
        "8tYWUttrWose0cH0yykVnqFzPtdRiZyZRfio6lGyK48mIC9z7T6MN3"
        "a7OaLZHZSwzcpQLcGi7M9q1wXLq4Ms1UvlwntB9FLHc63tHPpG8rhn"
        "XhZIk4QrSm4GYuEKQVHwku6ulw6wfggVL8FZPhoPCGsrb2rQGurBUL"
        "3lkVJ6RO9VGHcczDYomXqAJqlt4y9pkQIj9kgwTrxTzEZgMGdYZqsV"
        "4Bd5JjtrL7u3LA0N2Hq9Xvmmis2jDVhSQoUoGukNIoqng3SBsf0E7b"
        "4W0S1aZSSOJ90nQHQkQShE9YIMDBbNwIg2ncthwADYqibYUgIvJcK9"
        "89XHnYmZsdMWtt53lICsXE1vztR5WrQjSw4WXDiB31LXTrvudCB6vw"
        "kCQa4leutETpKLJ2bYaOYBdoiBFOwvf36YaSuRoY4SP2x1pWOwGFTg"
        "d90J2uYyCqUa3Q3iX52iigT4EKL2vJKdJ";

    PatchSolution2::PatchSolution2(const X64ImageInterpreter& Image) :
        m_Image(Image),
        m_DisassemblerEngine(CS_ARCH_X86, CS_MODE_64),
        m_AssemblerEngine(KS_ARCH_X86, KS_MODE_64)
    {
        m_DisassemblerEngine.Option(CS_OPT_DETAIL, CS_OPT_ON);
    }

    [[nodiscard]]
    const char* PatchSolution2::TryResolveStubHelper(const void* lpStubHelperProc) const {
        if (auto dyld_info = m_Image.SpecialLoadCommand<LC_DYLD_INFO_ONLY>(); dyld_info) {
            auto Disassembler = m_DisassemblerEngine.CreateDisassembler();
            
            // A stub-helper proc must look like:
            //     push xxxxh;
            //     jmp loc_xxxxxxxx
            // which should be 10 bytes long.
            Disassembler.SetContext({ lpStubHelperProc, 10, 0 });

            if (Disassembler.Next()) {
                auto lpInsn = Disassembler.GetInstruction();
                if (strcasecmp(lpInsn->mnemonic, "push") == 0 && lpInsn->detail->x86.operands[0].type == X86_OP_IMM) {
                    auto pbBindOpcode = 
                        m_Image.ImageOffset<const uint8_t*>(dyld_info->lazy_bind_off) +
                        lpInsn->detail->x86.operands[0].imm;

                    while ((*pbBindOpcode & BIND_OPCODE_MASK) != BIND_OPCODE_DONE) {
                        switch (*pbBindOpcode & BIND_OPCODE_MASK) {
                            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:         // 0x10
                            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:         // 0x30
                            case BIND_OPCODE_SET_TYPE_IMM:                  // 0x50
                            case BIND_OPCODE_DO_BIND:                       // 0x90
                            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:   // 0xB0
                                ++pbBindOpcode;
                                break;
                            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:        // 0x20
                            case BIND_OPCODE_SET_ADDEND_SLEB:               // 0x60
                            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:   // 0x70
                            case BIND_OPCODE_ADD_ADDR_ULEB:                 // 0x80
                            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:         // 0xA0
                                while (*(++pbBindOpcode) & 0x80u) {}
                                ++pbBindOpcode;
                                break;
                            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: // 0x40
                                return reinterpret_cast<const char *>(pbBindOpcode + 1);
                            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:  // 0xC0
                                //
                                // This opcode is too rare to appear,
                                // It is okay to dismiss this opcode
                                //
                                return nullptr;
                            default:
                                return nullptr;
                        }
                    }

                }
            }
        }
        return nullptr;
    }

    [[nodiscard]]
    bool PatchSolution2::FindPatchOffset() noexcept {
        try {
            std::optional<X64ImageOffset> KeywordOffset;
            std::optional<X64ImageOffset> FunctionOffset;
            std::optional<X64ImageAddress> StdStringAppendStubRva;

            auto section__text = m_Image.ImageSection("__TEXT", "__text");
            auto section__stubs = m_Image.ImageSection("__TEXT", "__stubs");
            auto sectionview__text = m_Image.ImageSectionView(section__text);
            auto sectionview__stubs = m_Image.ImageSectionView(section__stubs);
            auto Disassembler = m_DisassemblerEngine.CreateDisassembler();

            auto p = m_Image.SearchSection("__TEXT", "__const", [](const void* base, size_t i, size_t size) {
                if (i + sizeof(Keyword) <= size) {
                    return memcmp(ARL::AddressOffset(base, i), Keyword, sizeof(Keyword)) == 0;
                } else {
                    return false;
                }
            });
            if (p) {
                KeywordOffset = m_Image.ConvertPtrToOffset(p);
            } else {
                throw ARL::Exception(__FILE__, __LINE__, "Keyword is not found.");
            }

            p = m_Image.SearchSection(section__text, [section__text, KeywordRva = m_Image.ConvertOffsetToRva(KeywordOffset.value())](const void* base, size_t i, size_t size) {
                if (i + sizeof(uint32_t) <= size) {
                    auto rip = i + section__text->addr + sizeof(uint32_t);
                    auto off = ARL::AddressRead<uint32_t>(ARL::AddressOffset(base, i));
                    return rip + off == KeywordRva;
                } else {
                    return false;
                }
            });
            if (p) {
                p = m_Image.SearchSection(
                    section__text, 
                    ARL::AddressDelta(p, sectionview__text) >= 0xc0 ? ARL::AddressDelta(p, sectionview__text) - 0xc0 : 0, 
                    [p](const void* base, size_t i, size_t size) {
                        static const uint8_t FunctionHeader[9] = {
                            0x55,                   //  push rbp
                            0x48, 0x89, 0xe5,       //  mov  rbp, rsp
                            0x41, 0x57,             //  push r15
                            0x41, 0x56,             //  push r14
                            0x53,                   //  push rbx
                        };
                        if (ARL::AddressOffset(base, i + sizeof(FunctionHeader)) <= p) {
                            return memcmp(ARL::AddressOffset(base, i), FunctionHeader, sizeof(FunctionHeader)) == 0;
                        } else {
                            return false;
                        }
                    }
                );
                if (p) {
                    FunctionOffset = m_Image.ConvertPtrToOffset(p);
                } else {
                    throw ARL::Exception(__FILE__, __LINE__, "Function header is not found.");
                }
            } else {
                throw ARL::Exception(__FILE__, __LINE__, "Xref of Keyword is not found.");
            }

            Disassembler.SetContext({ sectionview__stubs, section__stubs->size, section__stubs->addr });
            while (Disassembler.Next()) {
                auto lpInsn = Disassembler.GetInstruction();

                //
                // As far as I know, all stub functions have a pattern looking like:
                //     jmp qword ptr [RIP + xxxx]
                //
                if (strcasecmp(lpInsn->mnemonic, "jmp") == 0 && lpInsn->detail->x86.operands[0].type == X86_OP_MEM && lpInsn->detail->x86.operands[0].mem.base == X86_REG_RIP) {
                    try {
                        X64ImageAddress la_symbol_ptr_rva = Disassembler.GetContext().Address + lpInsn->detail->x86.operands[0].mem.disp;
                        X64ImageOffset  la_symbol_ptr_offset = m_Image.ConvertRvaToOffset(la_symbol_ptr_rva);

                        X64ImageAddress stub_helper_rva = ARL::AddressRead<uint64_t>(m_Image.ImageBase(), la_symbol_ptr_offset);
                        X64ImageOffset  stub_helper_offset = m_Image.ConvertRvaToOffset(stub_helper_rva);

                        //
                        // __ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc
                        //     is the mangled name of "std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::append(char const*)",
                        //     which is, as known as, "std::string::append(const char*)"
                        // You can demangle it by c++flit
                        // e.g.
                        //     c++filt -_ '__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc'
                        //
                        auto lpszSymbolName = TryResolveStubHelper(m_Image.ImageOffset(stub_helper_offset));
                        if (lpszSymbolName && strcmp(lpszSymbolName, "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc") == 0) {
                            StdStringAppendStubRva = Disassembler.GetInstructionContext().Address;
                            break;
                        }
                    } catch (...) {
                        continue;
                    }
                }
            }
            if (StdStringAppendStubRva.has_value()) {
                m_KeywordOffset = KeywordOffset.value();
                m_FunctionOffset = FunctionOffset.value();
                m_StdStringAppendStubRva = StdStringAppendStubRva.value();
            } else {
                throw ARL::Exception(__FILE__, __LINE__, "std::string::append(const char*) is not found.");
            }

            printf("[+] PatchSolution2 ...... Ready to apply.\n");
            printf("    Keyword offset = +0x%.8x\n", m_KeywordOffset.value());
            printf("    CSRegistrationCenter::obtainPublicKey RVA = 0x%.16llx\n", m_Image.ConvertOffsetToRva(m_FunctionOffset.value()));
            printf("    std::string::append(const char*) RVA      = 0x%.16llx\n", m_StdStringAppendStubRva.value());
            return true;
        } catch (...) {
            printf("[-] PatchSolution2 ...... Omitted.\n");
            return false;
        }
    }

    [[nodiscard]]
    bool PatchSolution2::CheckKey(const RSACipher& Cipher) const noexcept {
        return Cipher.Bits() == 2048;
    }

    void PatchSolution2::MakePatch(const RSACipher& Cipher) const {
        if (m_KeywordOffset.has_value() && m_FunctionOffset.has_value() && m_StdStringAppendStubRva.has_value()) {
            //
            //  Prepare public key string
            //
            auto szPublicKeyPEM = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

            for (auto pos = szPublicKeyPEM.find("-----BEGIN PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKeyPEM.find("-----BEGIN PUBLIC KEY-----", pos)) {
                szPublicKeyPEM.erase(pos, strlen("-----BEGIN PUBLIC KEY-----"));
            }

            for (auto pos = szPublicKeyPEM.find("-----END PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKeyPEM.find("-----END PUBLIC KEY-----", pos)) {
                szPublicKeyPEM.erase(pos, strlen("-----END PUBLIC KEY-----"));
            }

            for (auto pos = szPublicKeyPEM.find('\n'); pos != std::string::npos; pos = szPublicKeyPEM.find('\n', pos)) {
                szPublicKeyPEM.erase(pos, 1);
            }

            //
            //  Prepare new function opcodes
            //
            auto Assembler = m_AssemblerEngine.CreateAssembler();
            auto MachineCode = Assembler.GenerateMachineCode(
                [KeywordRva = m_Image.ConvertOffsetToRva(m_KeywordOffset.value()), StdStringAppendStubRva = m_StdStringAppendStubRva.value()]() -> std::string {
                    const char asm_template[] = 
                        "push rbp;"
                        "mov rbp, rsp;"

                        "xor rax, rax;"                   // initialize std::string with null
                        "mov qword ptr[rdi], rax;"
                        "mov qword ptr[rdi + 0x8], rax;"
                        "mov qword ptr[rdi + 0x10], rax;"

                        "lea rsi, qword ptr[0x%.16llx];"  // filled with address to Keyword
                        "call 0x%.16llx;"                 // filled with address to std::string::append(const char*)
                        
                        "leave;"
                        "ret;";
                    std::string asm_string;
                
                    int l = snprintf(nullptr, 0, asm_template, KeywordRva, StdStringAppendStubRva);
                    if (l < 0) {
                        std::terminate();
                    }

                    asm_string.resize(l + 1);

                    l = snprintf(asm_string.data(), asm_string.length(), asm_template, KeywordRva, StdStringAppendStubRva);
                    if (l < 0) {
                        std::terminate();
                    }

                    while (asm_string.back() == '\x00') {
                        asm_string.pop_back();
                    }

                    return asm_string;
                }().c_str(),
                m_Image.ConvertOffsetToRva(m_FunctionOffset.value())
            );

            puts("**************************************************************");
            puts("*                      PatchSolution2                        *");
            puts("**************************************************************");

            auto lpKeyword = m_Image.ImageOffset(m_KeywordOffset.value());
            auto lpFunction = m_Image.ImageOffset(m_FunctionOffset.value());

            printf("[*] Previous:\n");
            Misc::PrintMemory(lpKeyword, szPublicKeyPEM.length() + 1, m_Image.ImageBase());
                memcpy(lpKeyword, szPublicKeyPEM.c_str(), szPublicKeyPEM.length() + 1);  // with a null-terminator
            printf("[*] After:\n");
            Misc::PrintMemory(lpKeyword, szPublicKeyPEM.length() + 1, m_Image.ImageBase());
            printf("\n");

            printf("[*] Previous:\n");
            Misc::PrintMemory(lpFunction, MachineCode.size(), m_Image.ImageBase());
                memcpy(lpFunction, MachineCode.data(), MachineCode.size());
            printf("[*] After:\n");
            Misc::PrintMemory(lpFunction, MachineCode.size(), m_Image.ImageBase());
            printf("\n");
        } else {
            throw ARL::Exception(__FILE__, __LINE__, "PatchSolution2: not ready yet.");
        }
    }

}

