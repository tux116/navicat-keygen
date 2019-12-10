#pragma once
#include "Exception.hpp"
#include "RSACipher.hpp"
#include "ResourceTraitsUnix.hpp"
#include "CapstoneDisassembler.hpp"
#include "KeystoneAssembler.hpp"
#include "X64ImageInterpreter.hpp"
#include <map>
#include <optional>

namespace nkg {

    class PatchSolution {
    public:

        [[nodiscard]]
        virtual bool FindPatchOffset() noexcept = 0;

        [[nodiscard]]
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept = 0;

        virtual void MakePatch(const RSACipher& Cipher) const = 0;

        virtual ~PatchSolution() = default;
    };

    class PatchSolution0 final : public PatchSolution {
    private:

        static const char Keyword[451];

        const X64ImageInterpreter&      m_Image;
        std::optional<X64ImageOffset>   m_PatchOffset;

    public:

        PatchSolution0(const X64ImageInterpreter& Image);

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual void MakePatch(const RSACipher& Cipher) const override;
    };

    class PatchSolution1 final : public PatchSolution {
    private:

        static const uint8_t Keyword[0x188];

        const X64ImageInterpreter&      m_Image;
        std::optional<X64ImageOffset>   m_PatchOffset;

    public:

        PatchSolution1(const X64ImageInterpreter& Image);

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual void MakePatch(const RSACipher& Cipher) const override;
    };

    class PatchSolution2 final : public PatchSolution {
    private:

        static const char Keyword[1114];

        const X64ImageInterpreter&      m_Image;
        CapstoneEngine                  m_DisassemblerEngine;
        KeystoneEngine                  m_AssemblerEngine;
        
        std::optional<X64ImageOffset>   m_KeywordOffset;
        std::optional<X64ImageOffset>   m_FunctionOffset;
        std::optional<X64ImageAddress>  m_StdStringAppendStubRva;

        [[nodiscard]]
        const char* TryResolveStubHelper(const void* lpStubHelperProc) const;

    public:

        PatchSolution2(const X64ImageInterpreter& Image);

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual void MakePatch(const RSACipher& Cipher) const override;
    };

    class PatchSolution3 final : public PatchSolution {
    private:

        const X64ImageInterpreter&      m_Image;
        CapstoneEngine                  m_DisassemblerEngine;
        KeystoneEngine                  m_AssemblerEngine;

        void*                           m_lpfnGenerateKeyA;
        void*                           m_lpfnGenerateKeyB;
        std::vector<uint8_t>            m_fnNewGenerateKeyA;
        std::vector<uint8_t>            m_fnNewGenerateKeyB;

        void ScanInstructions(
            std::map<X64ImageAddress, X64ImageSize>& Instructions, 
            const section_64* lpSection,
            const void* lpProcStart
        ) const;

        [[nodiscard]]
        const char* TryResolveStubHelper(const void* lpStubHelperProc) const;

    public:

        PatchSolution3(const X64ImageInterpreter& Image);

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual void MakePatch(const RSACipher& Cipher) const override;
    };

}

