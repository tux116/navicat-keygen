#include "X64ImageInterpreter.hpp"

namespace nkg {

    [[nodiscard]]
    X64ImageInterpreter X64ImageInterpreter::Parse(const void* lpImage, size_t cbImage) {
        X64ImageInterpreter Interpreter;

        Interpreter.m_MachOSize = cbImage;
        Interpreter.m_MachOHeader = reinterpret_cast<const mach_header_64*>(lpImage);
        if (Interpreter.m_MachOHeader->magic != MH_MAGIC_64) {
            throw ARL::AssertionError(__FILE__, __LINE__, "X64ImageInterpreter: bad MachO file: header magic check failure.");
        }

        auto cmd_p = ARL::AddressOffsetWithCast<const load_command*>(Interpreter.m_MachOHeader, sizeof(mach_header_64));
        for (decltype(mach_header_64::ncmds) i = 0; i < Interpreter.m_MachOHeader->ncmds; ++i) {
            switch (cmd_p->cmd) {
                case LC_SEGMENT_64: {
                    auto segcmd_p = reinterpret_cast<const segment_command_64*>(cmd_p);
                    auto section_p = ARL::AddressOffsetWithCast<const section_64*>(segcmd_p, sizeof(segment_command_64));

                    Interpreter.m_Segments.emplace_back(segcmd_p);

                    for (decltype(segment_command_64::nsects) j = 0; j < segcmd_p->nsects; ++j) {
                        Interpreter.m_Sections.emplace_back(&section_p[j]);
                        Interpreter.m_SectionsAddressMap[section_p[j].addr] = &section_p[j];
                        Interpreter.m_SectionsOffsetMap[section_p[j].offset] = &section_p[j];
                    }

                    break;
                }
                case LC_DYSYMTAB: {
                    Interpreter.m_SpecialLoadCommands.dysymtab = reinterpret_cast<const dysymtab_command*>(cmd_p);
                    break;
                }
                case LC_SYMTAB: {
                    Interpreter.m_SpecialLoadCommands.symtab = reinterpret_cast<const symtab_command*>(cmd_p);
                    break;
                }
                case LC_DYLD_INFO_ONLY: {
                    Interpreter.m_SpecialLoadCommands.dyld_info = reinterpret_cast<const dyld_info_command*>(cmd_p);
                    break;
                }
                default:
                    break;
            }

            cmd_p = ARL::AddressOffset(cmd_p, cmd_p->cmdsize);
        }

        return Interpreter;
    }

    [[nodiscard]]
    size_t X64ImageInterpreter::NumberOfSegmentCommands() const noexcept {
        return m_Segments.size();
    }

    [[nodiscard]]
    size_t X64ImageInterpreter::NumberOfSections() const noexcept {
        return m_Sections.size();
    }

    [[nodiscard]]
    const section_64* X64ImageInterpreter::ImageSection(size_t Index) const {
        if (Index < m_Sections.size()) {
            return m_Sections[Index];
        } else {
            throw ARL::IndexError(__FILE__, __LINE__, "X64ImageInterpreter: Index is out of range.");
        }
    }

    [[nodiscard]]
    const section_64* X64ImageInterpreter::ImageSection(const char* SegmentName, const char* SectionName) const {
        for (const auto& segment : m_Segments) {
            if (strncmp(SegmentName, segment->segname, sizeof(segment->segname)) == 0) {
                auto section = reinterpret_cast<const section_64*>(segment + 1);

                for (uint32_t i = 0; i < segment->nsects; ++i) {
                    if (strncmp(SectionName, section[i].sectname, sizeof(section[i].sectname)) == 0) {
                        return &section[i];
                    }
                }

                break;
            }
        }

        throw ARL::KeyError(__FILE__, __LINE__, "X64ImageInterpreter: section is not found.");
    }

    [[nodiscard]]
    const section_64* X64ImageInterpreter::ImageSectionFromOffset(X64ImageOffset Offset) const {
        auto it = m_SectionsOffsetMap.upper_bound(Offset);
        if (it != m_SectionsOffsetMap.begin() && (--it, it->first <= Offset && Offset < it->first + it->second->size)) {
            return it->second;
        } else {
            throw ARL::KeyError(__FILE__, __LINE__, "X64ImageInterpreter: section is not found.");
        }
    }

    [[nodiscard]]
    const section_64* X64ImageInterpreter::ImageSectionFromRva(X64ImageAddress Rva) const {
        auto it = m_SectionsAddressMap.upper_bound(Rva);
        if (it != m_SectionsAddressMap.begin() && (--it, it->first <= Rva && Rva < it->first + it->second->size)) {
            return it->second;
        } else {
            throw ARL::KeyError(__FILE__, __LINE__, "X64ImageInterpreter: section is not found.");
        }
    }

    [[nodiscard]]
    X64ImageAddress X64ImageInterpreter::ConvertOffsetToRva(X64ImageOffset Offset) const {
        auto section = ImageSectionFromOffset(Offset);
        return section->addr + static_cast<X64ImageAddress>(Offset - section->offset);
    }

    [[nodiscard]]
    X64ImageOffset X64ImageInterpreter::ConvertRvaToOffset(X64ImageAddress Rva) const {
        auto section = ImageSectionFromRva(Rva);
        return section->offset + static_cast<X64ImageOffset>(Rva - section->addr);
    }

}
