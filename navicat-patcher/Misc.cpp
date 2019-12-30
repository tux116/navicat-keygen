#include "Misc.hpp"
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "ExceptionSystem.hpp"

static jmp_buf g_jmbuf;

static void SIGSEGV_handler(int sig) {
    siglongjmp(g_jmbuf, 1);
}

//
//  read byte(s) at address `p` as __Type to `out`
//  succeed if return true, otherwise return false
//
template<typename __Type>
static inline bool probe_for_read(const void* p, void* out) {
    int r = sigsetjmp(g_jmbuf, 1);
    if (r == 0) {
        *reinterpret_cast<__Type*>(out) = *reinterpret_cast<const __Type*>(p);
        return true;
    } else {
        return false;
    }
}

namespace nkg::Misc {

    //
    //  Print memory data in [lpMemBegin, lpMemEnd)
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must >= `from`
    //
    void PrintMemory(const void* lpMemBegin, const void* lpMemEnd, const void* lpBase) noexcept {
        auto pbBegin = reinterpret_cast<const uint8_t*>(lpMemBegin);
        auto pbEnd = reinterpret_cast<const uint8_t*>(lpMemEnd);
        auto pbBase = reinterpret_cast<const uint8_t*>(lpBase);

        if (pbBegin >= pbEnd)
            return;

        while (reinterpret_cast<uintptr_t>(pbBegin) % 16)
            pbBegin--;

        while (reinterpret_cast<uintptr_t>(pbEnd) % 16)
            pbEnd++;

        while (pbBegin < pbEnd) {
            uint16_t Values[16] = {};

            if (pbBase) {
                uintptr_t d = pbBegin >= lpBase ? pbBegin - pbBase : pbBase - pbBegin;
                if (pbBegin >= lpBase) {
                    printf("+0x%.*zx  ", static_cast<int>(2 * sizeof(void*)), d);
                } else {
                    printf("-0x%.*zx  ", static_cast<int>(2 * sizeof(void*)), d);
                }
            } else {
                printf("0x%.*zx  ", static_cast<int>(2 * sizeof(void*)), reinterpret_cast<uintptr_t>(pbBegin));
            }

            for (int i = 0; i < 16; ++i) {
                if (pbBegin + i < lpMemBegin || pbBegin + i >= lpMemEnd) {
                    printf("   ");
                    Values[i] = 0xfffe;
                } else if (probe_for_read<uint8_t>(pbBegin + i, Values + i)) {
                    printf("%02x ", Values[i]);
                } else {
                    printf("?? ");
                    Values[i] = 0xffff;
                }
            }

            printf(" ");

            for (int i = 0; i < 16; ++i) {
                if (0x20 <= Values[i] && Values[i] < 0x7f) {
                    printf("%c", Values[i]);
                } else if (Values[i] == 0xfffe) {
                    printf(" ");
                } else {
                    printf(".");
                }
            }

            printf("\n");

            pbBegin += 0x10;
        }
    }

    //
    //  Print memory data in [lpMem, lpMem + cbMem)
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must >= `from`
    //
    void PrintMemory(const void* lpMem, size_t cbMem, const void* lpBase) noexcept {
        PrintMemory(lpMem, reinterpret_cast<const uint8_t*>(lpMem) + cbMem, lpBase);
    }

    [[nodiscard]]
    bool FsIsExist(std::string_view szPath) {
        struct stat s = {};
        if (stat(szPath.data(), &s) == 0) {
            return true;
        } else {
            if (errno == ENOENT) {
                return false;
            } else {
                throw ARL::SystemError(__FILE__, __LINE__, errno, "stat failed.");
            }
        }
    }

    [[nodiscard]]
    bool FsIsFile(std::string_view szPath) {
        struct stat s = {};
        if (stat(szPath.data(), &s) == 0) {
            return S_ISREG(s.st_mode);
        } else {
            if (errno == ENOENT) {
                return false;
            } else {
                throw ARL::SystemError(__FILE__, __LINE__, errno, "stat failed.");
            }
        }
    }
    
    [[nodiscard]]
    bool FsIsDirectory(std::string_view szPath) {
        struct stat s = {};
        if (stat(szPath.data(), &s) == 0) {
            return S_ISDIR(s.st_mode);
        } else {
            if (errno == ENOENT) {
                return false;
            } else {
                throw ARL::SystemError(__FILE__, __LINE__, errno, "stat failed.");
            }
        }
    }

    [[nodiscard]]
    std::string FsCurrentWorkingDirectory() {
        std::string path(256, '\x00');
        while (getcwd(path.data(), path.size()) == 0) {
            if (errno == ERANGE) {
                path.resize(path.size() * 2);
            } else {
                throw ARL::SystemError(__FILE__, __LINE__, errno, "getcwd failed.");
            }
        }

        path.resize(strlen(path.data()));

        return path;
    }
}

