#pragma once
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <vector>
#include <map>
#include "Exception.hpp"
#include "ExceptionGeneric.hpp"
#include "MemoryAccess.hpp"

namespace nkg {

    using X64ImageAddress = decltype(section_64::addr);
    using X64ImageOffset = decltype(section_64::offset);

    class X64ImageInterpreter {
    private:

        size_t                                          m_MachOSize;
        const mach_header_64*                           m_MachOHeader;
        std::vector<const segment_command_64*>          m_Segments;
        std::vector<const section_64*>                  m_Sections;
        std::map<X64ImageAddress, const section_64*>    m_SectionsAddressMap;
        std::map<X64ImageOffset, const section_64*>     m_SectionsOffsetMap;
        struct {
            const dysymtab_command* dysymtab;
            const symtab_command* symtab;
            const dyld_info_command* dyld_info;
        } m_SpecialLoadCommands;

        X64ImageInterpreter() :
            m_MachOSize(0),
            m_MachOHeader(nullptr),
            m_SpecialLoadCommands{} {}

    public:

        [[nodiscard]]
        static X64ImageInterpreter Parse(const void* lpImage, size_t cbImage);

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ImageBase() const noexcept {
            static_assert(std::is_pointer_v<__ReturnType>);
            return reinterpret_cast<__ReturnType>(
                const_cast<mach_header_64*>(m_MachOHeader)
            );
        }

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ImageOffset(size_t Offset) const {
            if (Offset < m_MachOSize) {
                return ARL::AddressOffsetWithCast<__ReturnType>(m_MachOHeader, Offset);
            } else {
                throw ARL::OverflowError(__FILE__, __LINE__, "X64ImageInterpreter: out of range.");
            }
        }

        [[nodiscard]]
        size_t ImageSize() const noexcept {
            return m_MachOSize;
        }

        [[nodiscard]]
        size_t NumberOfSegmentCommands() const noexcept;

        [[nodiscard]]
        size_t NumberOfSections() const noexcept;

        [[nodiscard]]
        const section_64* ImageSection(size_t Index) const;

        [[nodiscard]]
        const section_64* ImageSection(const char* SegmentName, const char* SectionName) const;

        [[nodiscard]]
        const section_64* ImageSectionFromOffset(X64ImageOffset Offset) const;

        [[nodiscard]]
        const section_64* ImageSectionFromRva(X64ImageAddress Rva) const;



        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ImageSectionView(const section_64* Section) const noexcept {
            return ImageOffset<__ReturnType>(Section->offset);
        }

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ImageSectionView(size_t Index) const {
            return ImageSectionView<__ReturnType>(ImageSection(Index));
        }

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ImageSectionView(const char* SegmentName, const char* SectionName) const {
            return ImageSectionView<__ReturnType>(ImageSection(SegmentName, SectionName));
        }

        template<unsigned __CommandMacro>
        [[nodiscard]]
        auto SpecialLoadCommand() const noexcept {
            if constexpr (__CommandMacro == LC_DYSYMTAB) {
                return m_SpecialLoadCommands.dysymtab;
            } else if constexpr (__CommandMacro == LC_SYMTAB) {
                return m_SpecialLoadCommands.symtab;
            } else if constexpr (__CommandMacro == LC_DYLD_INFO_ONLY) {
                return m_SpecialLoadCommands.dyld_info;
            } else {
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wtautological-compare"
                constexpr bool always_false = __CommandMacro != __CommandMacro;
#pragma clang diagnostic pop
                static_assert(always_false);

            }
        }

        template<typename __ReturnType = void*, typename __HintType>
        [[nodiscard]]
        __ReturnType SearchSection(const section_64* Section, __HintType&& Hint) const {
            static_assert(std::is_pointer_v<__ReturnType>);

            auto base = ImageSectionView<const uint8_t*>(Section);

            for (decltype(section_64::size) i = 0; i < Section->size; ++i) {
                if (Hint(base, i, Section->size) == true) {
                    return ARL::AddressOffsetWithCast<__ReturnType>(base, i);
                }
            }

            return nullptr;
        }

        template<typename __ReturnType = void*, typename __HintType>
        [[nodiscard]]
        __ReturnType SearchSection(const section_64* Section, size_t Offset, __HintType&& Hint) const {
            static_assert(std::is_pointer_v<__ReturnType>);

            auto base = ImageSectionView<const uint8_t*>(Section);

            for (decltype(section_64::size) i = Offset; i < Section->size; ++i) {
                if (Hint(base, i, Section->size) == true) {
                    return ARL::AddressOffsetWithCast<__ReturnType>(base, i);
                }
            }

            return nullptr;
        }

        template<typename __ReturnType = void*, typename __HintType>
        [[nodiscard]]
        __ReturnType SearchSection(size_t Index, __HintType&& Hint) const {
            return SearchSection<__ReturnType>(ImageSection(Index), std::forward<__HintType>(Hint));
        }

        template<typename __ReturnType = void*, typename __HintType>
        [[nodiscard]]
        __ReturnType SearchSection(size_t Index, size_t Offset, __HintType&& Hint) const {
            return SearchSection<__ReturnType>(ImageSection(Index), Offset, std::forward<__HintType>(Hint));
        }

        template<typename __ReturnType = void*, typename __HintType>
        [[nodiscard]]
        __ReturnType SearchSection(const char* SegmentName, const char* SectionName, __HintType&& Hint) const {
            return SearchSection<__ReturnType>(ImageSection(SegmentName, SectionName), std::forward<__HintType>(Hint));
        }

        template<typename __ReturnType = void*, typename __HintType>
        [[nodiscard]]
        __ReturnType SearchSection(const char* SegmentName, const char* SectionName, size_t Offset, __HintType&& Hint) const {
            return SearchSection<__ReturnType>(ImageSection(SegmentName, SectionName), Offset, std::forward<__HintType>(Hint));
        }



        [[nodiscard]]
        X64ImageAddress ConvertOffsetToRva(X64ImageOffset Offset) const;

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ConvertOffsetToPtr(X64ImageOffset Offset) const {
            return ImageOffset<__ReturnType>(Offset);
        }

        [[nodiscard]]
        X64ImageOffset ConvertRvaToOffset(X64ImageAddress Address) const;

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ConvertRvaToPtr(X64ImageAddress Rva) const {
            return ConvertOffsetToPtr<__ReturnType>(ConvertRvaToOffset(Rva));
        }

        template<typename __PtrType>
        [[nodiscard]]
        X64ImageAddress ConvertPtrToRva(__PtrType Ptr) const {
            auto offset = ARL::AddressDelta(Ptr, m_MachOHeader);
            if (offset < m_MachOSize) {
                return ConvertOffsetToRva(offset);
            } else {
                throw ARL::OverflowError(__FILE__, __LINE__, "X64ImageInterpreter: out of range.");
            }
        }

        template<typename __PtrType>
        [[nodiscard]]
        X64ImageAddress ConvertPtrToOffset(__PtrType Ptr) const {
            auto offset = ARL::AddressDelta(Ptr, m_MachOHeader);
            if (offset < m_MachOSize) {
                return offset;
            } else {
                throw ARL::OverflowError(__FILE__, __LINE__, "X64ImageInterpreter: out of range.");
            }
        }

    };

}
