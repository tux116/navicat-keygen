#include "PatchSolutions.hpp"
#include "Misc.hpp"
#include <string.h>

namespace nkg {

    PatchSolution3::PatchSolution3(const X64ImageInterpreter& Image) :
        m_Image(Image),
        m_DisassemblerEngine(CS_ARCH_X86, CS_MODE_64),
        m_AssemblerEngine(KS_ARCH_X86, KS_MODE_64),
        m_lpfnGenerateKeyA(nullptr),
        m_lpfnGenerateKeyB(nullptr)
    {
        m_DisassemblerEngine.Option(CS_OPT_DETAIL, CS_OPT_ON);
    }
    
    void PatchSolution3::ScanInstructions(std::map<X64ImageAddress, X64ImageSize>& Instructions, const section_64* lpSection, const void* lpProcStart) const {
        auto Disassembler = m_DisassemblerEngine.CreateDisassembler();

        auto lpMachineCode = lpProcStart;
        auto cbMachineCode = lpSection->size - ARL::AddressDelta(lpMachineCode, m_Image.ImageSectionView(lpSection));
        auto Address = lpSection->addr + ARL::AddressDelta(lpMachineCode, m_Image.ImageSectionView(lpSection));
        
        Disassembler.SetContext({ lpMachineCode, cbMachineCode, Address });
        while (Disassembler.Next()) {
            auto lpInsn = Disassembler.GetInstruction();

            if (Instructions.find(lpInsn->address) == Instructions.end()) {
                Instructions.emplace(lpInsn->address, lpInsn->size);
                if (lpInsn->mnemonic[0] == 'J' || lpInsn->mnemonic[0] == 'j') {
                    if (lpInsn->detail->x86.operands[0].type != X86_OP_IMM) {   // "jxx reg" / "jxx qword ptr [xxx]" won't be handled.
                        return;
                    }

                    ScanInstructions(Instructions, lpSection, m_Image.ConvertRvaToPtr(lpInsn->detail->x86.operands[0].imm));

                    if (strcasecmp(lpInsn->mnemonic, "jmp") == 0) {
                        return;
                    }
                } else if (strcasecmp(lpInsn->mnemonic, "ret") == 0) {
                    return;
                }
            } else {
                return;
            }
        }
    }

    [[nodiscard]]
    const char* PatchSolution3::TryResolveStubHelper(const void* lpStubHelperProc) const {
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
    bool PatchSolution3::FindPatchOffset() noexcept {
        try {
            auto section__text = m_Image.ImageSection("__TEXT", "__text");
            auto section__cstring = m_Image.ImageSection("__TEXT", "__cstring");
            auto section__stubs = m_Image.ImageSection("__TEXT", "__stubs");
            auto sectionview__stubs = m_Image.ImageSectionView(section__stubs);
            auto Disassembler = m_DisassemblerEngine.CreateDisassembler();
            auto Assembler = m_AssemblerEngine.CreateAssembler();

            void* lpfnGenerateKeyA = nullptr;
            void* lpfnGenerateKeyB = nullptr;
            std::optional<X64ImageAddress>  StdStringAppendStubRva;
            std::vector<uint8_t> fnNewGenerateKeyA;
            std::vector<uint8_t> fnNewGenerateKeyB;

            //
            // find fnGenerateKeyA
            //

            if (auto lpKeyword = m_Image.SearchSection(section__cstring, [](const void* base, size_t i, size_t size) {
                    static const char Keyword[] = "K\xd8\x00MjZAGa6R";
                    if (i + sizeof(Keyword) <= size) {
                        return memcmp(ARL::AddressOffset(base, i), Keyword, sizeof(Keyword)) == 0;
                    } else {
                        return false;
                    }
            }); lpKeyword) {
                if (auto lpXrefKeyword = m_Image.SearchSection(section__text, [section__text, KeywordRva = m_Image.ConvertPtrToRva(lpKeyword)](const void* base, size_t i, size_t size) {
                    if (i + sizeof(uint32_t) <= size) {
                        auto rip = section__text->addr + (i + 4);
                        auto off = ARL::AddressRead<uint32_t>(base, i);
                        return rip + off == KeywordRva;
                    } else {
                        return false;
                    }
                }); lpXrefKeyword) {
                    static const uint8_t FunctionHeader[] = {
                        0x55,               // push rbp
                        0x48, 0x89, 0xe5    // mov rbp, rsp
                    };
                    for (int i = -0x90; i + static_cast<int>(sizeof(FunctionHeader)) < 0; ++i) {
                        if (memcmp(ARL::AddressOffset(lpXrefKeyword, i), FunctionHeader, sizeof(FunctionHeader)) == 0) {
                            lpfnGenerateKeyA = ARL::AddressOffset(lpXrefKeyword, i);
                            break;
                        }
                    }

                    if (lpfnGenerateKeyA == nullptr) {
                        throw ARL::Exception(__FILE__, __LINE__, "fnGenerateKeyA is not found.");
                    }
                } else {
                    throw ARL::Exception(__FILE__, __LINE__, "fnGenerateKeyA is not found.");
                }
            } else {
                throw ARL::Exception(__FILE__, __LINE__, "fnGenerateKeyA is not found.");
            }

            //
            // find fnGenerateKeyB
            //

            if (auto lpKeyword = m_Image.SearchSection(section__cstring, [](const void* base, size_t i, size_t size) {
                    static const char Keyword[] = "me30I";
                    if (i + sizeof(Keyword) <= size) {
                        return memcmp(ARL::AddressOffset(base, i), Keyword, sizeof(Keyword)) == 0;
                    } else {
                        return false;
                    }
            }); lpKeyword) {
                if (auto lpXrefKeyword = m_Image.SearchSection(section__text, [section__text, KeywordRva = m_Image.ConvertPtrToRva(lpKeyword)](const void* base, size_t i, size_t size) {
                    if (i + sizeof(uint32_t) <= size) {
                        auto rip = section__text->addr + (i + 4);
                        auto off = ARL::AddressRead<uint32_t>(base, i);
                        return rip + off == KeywordRva;
                    } else {
                        return false;
                    }
                }); lpXrefKeyword) {
                    static const uint8_t FunctionHeader[] = {
                        0x55,               // push rbp
                        0x48, 0x89, 0xe5    // mov rbp, rsp
                    };
                    for (int i = -0x90; i + static_cast<int>(sizeof(FunctionHeader)) < 0; ++i) {
                        if (memcmp(ARL::AddressOffset(lpXrefKeyword, i), FunctionHeader, sizeof(FunctionHeader)) == 0) {
                            lpfnGenerateKeyB = ARL::AddressOffset(lpXrefKeyword, i);
                        }
                    }

                    if (lpfnGenerateKeyB == nullptr) {
                        throw ARL::Exception(__FILE__, __LINE__, "fnGenerateKeyB is not found.");
                    }
                } else {
                    throw ARL::Exception(__FILE__, __LINE__, "fnGenerateKeyB is not found.");
                }
            } else {
                throw ARL::Exception(__FILE__, __LINE__, "fnGenerateKeyB is not found.");
            }

            //
            // find std::string::append(const char*)
            //

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
                        // __ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm
                        //     is the mangled name of "std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::append(char const*, size_t)",
                        //     which is, as known as, "std::string::append(const char*, size_t)"
                        // You can demangle it by c++flit
                        // e.g.
                        //     c++filt -_ '__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm'
                        //
                        auto lpszSymbolName = TryResolveStubHelper(m_Image.ImageOffset(stub_helper_offset));
                        if (lpszSymbolName && strcmp(lpszSymbolName, "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm") == 0) {
                            StdStringAppendStubRva = Disassembler.GetInstructionContext().Address;
                            break;
                        }
                    } catch (...) {
                        continue;
                    }
                }
            }
            if (StdStringAppendStubRva.has_value() == false) {
                throw ARL::Exception(__FILE__, __LINE__, "std::string::append(const char*) is not found.");
            }

            fnNewGenerateKeyA = Assembler.GenerateMachineCode(
                [&StdStringAppendStubRva]() -> std::string {
                    const char asm_template[] = 
                        "push rbp;"
                        "mov rbp, rsp;"

                        "xor rax, rax;"                   // initialize std::string with null
                        "mov qword ptr[rdi], rax;"
                        "mov qword ptr[rdi + 0x8], rax;"
                        "mov qword ptr[rdi + 0x10], rax;"

                        "mov edx, 0x188;"
                        "lea rsi, qword ptr [rip + KeyA];"
                        "call 0x%.16llx;"                 // filled with address to std::string::append(const char*, size_t)

                        "leave;"
                        "ret;"
                        "KeyA:";
                    std::string asm_string;
                
                    int l = snprintf(nullptr, 0, asm_template, StdStringAppendStubRva.value());
                    if (l < 0) {
                        std::terminate();
                    }

                    asm_string.resize(l + 1);

                    l = snprintf(asm_string.data(), asm_string.length(), asm_template, StdStringAppendStubRva.value());
                    if (l < 0) {
                        std::terminate();
                    }

                    while (asm_string.back() == '\x00') {
                        asm_string.pop_back();
                    }

                    return asm_string;
                }().c_str(),
                m_Image.ConvertPtrToRva(lpfnGenerateKeyA)
            );

            fnNewGenerateKeyB = Assembler.GenerateMachineCode(
                [&StdStringAppendStubRva]() -> std::string {
                    const char asm_template[] = 
                        "push rbp;"
                        "mov rbp, rsp;"

                        "xor rax, rax;"                   // initialize std::string with null
                        "mov qword ptr[rdi], rax;"
                        "mov qword ptr[rdi + 0x8], rax;"
                        "mov qword ptr[rdi + 0x10], rax;"

                        "mov edx, 0x188;"
                        "lea rsi, qword ptr [rip + KeyB];"
                        "call 0x%.16llx;"                 // filled with address to std::string::append(const char*, size_t)

                        "leave;"
                        "ret;"
                        "KeyB:";
                    std::string asm_string;
                
                    int l = snprintf(nullptr, 0, asm_template, StdStringAppendStubRva.value());
                    if (l < 0) {
                        std::terminate();
                    }

                    asm_string.resize(l + 1);

                    l = snprintf(asm_string.data(), asm_string.length(), asm_template, StdStringAppendStubRva.value());
                    if (l < 0) {
                        std::terminate();
                    }

                    while (asm_string.back() == '\x00') {
                        asm_string.pop_back();
                    }

                    return asm_string;
                }().c_str(),
                m_Image.ConvertPtrToRva(lpfnGenerateKeyB)
            );

            {
                std::map<X64ImageAddress, X64ImageSize> InstructionMap;
                ScanInstructions(InstructionMap, section__text, lpfnGenerateKeyA);

                // merging
                for (auto it = InstructionMap.begin(); it != InstructionMap.end(); ++it) {
                    for (auto next_it = std::next(it); it->first + it->second == next_it->first; next_it = InstructionMap.erase(next_it)) {
                        it->second += next_it->second;
                    }
                }

                if (auto it = InstructionMap.find(m_Image.ConvertPtrToRva(lpfnGenerateKeyA)); it != InstructionMap.end()) {
                    if (fnNewGenerateKeyA.size() + 0x188 > it->second) {
                        throw ARL::Exception(__FILE__, __LINE__, "No enough space.");
                    }
                } else {
                    throw ARL::AssertionError(__FILE__, __LINE__, "Something unexpected happened.");
                }
            }

            {
                std::map<X64ImageAddress, X64ImageSize> InstructionMap;
                ScanInstructions(InstructionMap, section__text, lpfnGenerateKeyB);

                // merging
                for (auto it = InstructionMap.begin(); it != InstructionMap.end(); ++it) {
                    for (auto next_it = std::next(it); it->first + it->second == next_it->first; next_it = InstructionMap.erase(next_it)) {
                        it->second += next_it->second;
                    }
                }

                if (auto it = InstructionMap.find(m_Image.ConvertPtrToRva(lpfnGenerateKeyB)); it != InstructionMap.end()) {
                    if (fnNewGenerateKeyB.size() + 0x188 > it->second) {
                        throw ARL::Exception(__FILE__, __LINE__, "No enough space.");
                    }
                } else {
                    throw ARL::AssertionError(__FILE__, __LINE__, "Something unexpected happened.");
                }
            }

            m_lpfnGenerateKeyA = lpfnGenerateKeyA;
            m_lpfnGenerateKeyB = lpfnGenerateKeyB;
            m_fnNewGenerateKeyA = std::move(fnNewGenerateKeyA);
            m_fnNewGenerateKeyB = std::move(fnNewGenerateKeyB);

            printf("[+] PatchSolution3 ...... Ready to apply.\n");
            printf("    fnGenerateKeyA RVA = 0x%.16llx\n", m_Image.ConvertPtrToRva(m_lpfnGenerateKeyA));
            printf("    fnGenerateKeyB RVA = 0x%.16llx\n", m_Image.ConvertPtrToRva(m_lpfnGenerateKeyB));
            printf("    std::string::append(const char*, size_t) RVA = 0x%.16llx\n", StdStringAppendStubRva.value());

            return true;
        } catch (...) {
            printf("[-] PatchSolution3 ...... Omitted.\n");
            return false;
        }
    }

    [[nodiscard]]
    bool PatchSolution3::CheckKey(const RSACipher& Cipher) const noexcept {
        return Cipher.Bits() == 2048;
    }

    void PatchSolution3::MakePatch(const RSACipher& Cipher) const {
        if (m_lpfnGenerateKeyA && m_lpfnGenerateKeyB && m_fnNewGenerateKeyA.size() && m_fnNewGenerateKeyB.size()) {
            //
            //  Prepare public key string
            //
            auto szKeyA = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

            for (auto pos = szKeyA.find("-----BEGIN PUBLIC KEY-----"); pos != std::string::npos; pos = szKeyA.find("-----BEGIN PUBLIC KEY-----", pos)) {
                szKeyA.erase(pos, strlen("-----BEGIN PUBLIC KEY-----"));
            }

            for (auto pos = szKeyA.find("-----END PUBLIC KEY-----"); pos != std::string::npos; pos = szKeyA.find("-----END PUBLIC KEY-----", pos)) {
                szKeyA.erase(pos, strlen("-----END PUBLIC KEY-----"));
            }

            for (auto pos = szKeyA.find('\n'); pos != std::string::npos; pos = szKeyA.find('\n', pos)) {
                szKeyA.erase(pos, 1);
            }

            if (szKeyA.size() < 0x188) {
                szKeyA.append(0x188 - szKeyA.size(), '\x00');
            }

            auto szKeyB = std::string(0x188, '\x00');

            puts("**************************************************************");
            puts("*                      PatchSolution3                        *");
            puts("**************************************************************");

            printf("[*] Previous:\n");
            Misc::PrintMemory(m_lpfnGenerateKeyA, m_fnNewGenerateKeyA.size() + 0x188, m_Image.ImageBase());
                memcpy(m_lpfnGenerateKeyA, m_fnNewGenerateKeyA.data(), m_fnNewGenerateKeyA.size());
                memcpy(ARL::AddressOffset(m_lpfnGenerateKeyA, m_fnNewGenerateKeyA.size()), szKeyA.data(), 0x188);
            printf("[*] After:\n");
            Misc::PrintMemory(m_lpfnGenerateKeyA, m_fnNewGenerateKeyA.size() + 0x188, m_Image.ImageBase());
            printf("\n");

            printf("[*] Previous:\n");
            Misc::PrintMemory(m_lpfnGenerateKeyB, m_fnNewGenerateKeyB.size() + 0x188, m_Image.ImageBase());
                memcpy(m_lpfnGenerateKeyB, m_fnNewGenerateKeyB.data(), m_fnNewGenerateKeyB.size());
                memcpy(ARL::AddressOffset(m_lpfnGenerateKeyB, m_fnNewGenerateKeyB.size()), szKeyB.data(), 0x188);
            printf("[*] After:\n");
            Misc::PrintMemory(m_lpfnGenerateKeyB, m_fnNewGenerateKeyB.size() + 0x188, m_Image.ImageBase());
            printf("\n");
        } else {
            throw ARL::Exception(__FILE__, __LINE__, "PatchSolution3: not ready yet.");
        }
    }

}

