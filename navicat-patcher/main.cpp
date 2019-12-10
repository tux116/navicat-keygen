#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <plist/plist++.h>
#include <string>

#include "ExceptionSystem.hpp"
#include "ResourceWrapper.hpp"
#include "ResourceTraitsUnix.hpp"
#include "PatchSolutions.hpp"
#include "Misc.hpp"

static void Welcome(bool bWait) {
    puts("**********************************************************");
    puts("*       Navicat Patcher (macOS) by @DoubleLabyrinth      *");
    puts("*                  Version: 5.0                          *");
    puts("**********************************************************");
    puts("");
    if (bWait) {
        puts("Press Enter to continue or Ctrl + C to abort.");
        getchar();
    }
}

static void Help() {
    puts("Usage:");
    puts("    navicat-patcher [--dry-run] <Navicat installation path> [RSA-2048 Private Key File]");
    puts("");
    puts("        [--dry-run]                   Run patcher without applying any patches.");
    puts("                                      This parameter is optional.");
    puts("");
    puts("        <Navicat installation path>   Path to `Navicat Premium.app`.");
    puts("                                      Example:");
    puts("                                          /Applications/Navicat\\ Premium.app/");
    puts("                                      This parameter must be specified.");
    puts("");
    puts("        [RSA-2048 Private Key File]   Path to a PEM-format RSA-2048 private key file.");
    puts("                                      This parameter is optional.");
    puts("");
}

static bool ParseCommandLine(int argc, char* argv[], bool& bDryrun, std::string& szInstallPath, std::string& szKeyFilePath) {
    if (argc == 2) {
        bDryrun = false;
        szInstallPath = argv[1];
        szKeyFilePath.clear();
        return true;
    } else if (argc == 3) {
        if (strcasecmp(argv[1], "--dry-run") == 0) {
            bDryrun = true;
            szInstallPath = argv[2];
            szKeyFilePath.clear();
            return true;
        } else {
            bDryrun = false;
            szInstallPath = argv[1];
            szKeyFilePath = argv[2];
            return true;
        }
    } else if (argc == 4) {
        if (strcasecmp(argv[1], "--dry-run") == 0) {
            bDryrun = true;
            szInstallPath = argv[2];
            szKeyFilePath = argv[3];
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

static std::string GetNavicatVersion(std::string_view AppPath) {
    ARL::ResourceWrapper hInfoPlist{ ARL::ResourceTraits::FileDescriptor{} };
    ARL::ResourceWrapper lpInfoPlist{ ARL::ResourceTraits::CppObject<PList::Dictionary>{} };

    hInfoPlist.TakeOver(open((std::string(AppPath) + "/Contents/Info.plist").c_str(), O_RDONLY));
    if (hInfoPlist.IsValid() == false) {
        throw ARL::SystemError(__FILE__, __LINE__, errno, "Failed to open Contents/Info.plist.");
    }

    struct stat statInfoPlist = {};
    if (fstat(hInfoPlist, &statInfoPlist) != 0) {
        throw ARL::SystemError(__FILE__, __LINE__, errno, "Failed to get file size of Contents/Info.plist.");
    }

    std::string contentInfoPlist(statInfoPlist.st_size, '\x00');
    if (read(hInfoPlist, contentInfoPlist.data(), contentInfoPlist.size()) != contentInfoPlist.size()) {
        throw ARL::SystemError(__FILE__, __LINE__, errno, "Failed to read Contents/Info.plist.");
    }

    lpInfoPlist.TakeOver(dynamic_cast<PList::Dictionary*>(PList::Structure::FromXml(contentInfoPlist)));
    if (lpInfoPlist.IsValid() == false) {
        throw ARL::Exception(__FILE__, __LINE__, "Failed to parse Contents/Info.plist.");
    }

    auto key_value = lpInfoPlist->Find("CFBundleShortVersionString");
    if (key_value == lpInfoPlist->End()) {
        throw ARL::Exception(__FILE__, __LINE__, "Cannot find CFBundleShortVersionString in Contents/Info.plist.");
    }

    if (key_value->second->GetType() == PLIST_STRING) {
        return dynamic_cast<PList::String*>(key_value->second)->GetValue();
    } else {
        throw ARL::Exception(__FILE__, __LINE__, "Type check failed for CFBundleShortVersionString.");
    }
}

static void LoadKey(nkg::RSACipher& Cipher, std::string_view szKeyFileName,
                    nkg::PatchSolution* lpSolution0,
                    nkg::PatchSolution* lpSolution1,
                    nkg::PatchSolution* lpSolution2,
                    nkg::PatchSolution* lpSolution3) {
    if (szKeyFileName.empty() == false) {
        printf("[*] Import RSA-2048 key from %s\n", szKeyFileName.data());

        Cipher.ImportKeyFromFile<nkg::RSAKeyType::PrivateKey, nkg::RSAKeyFormat::PEM>(szKeyFileName);

        if ((lpSolution0 && lpSolution0->CheckKey(Cipher) == false) ||
            (lpSolution1 && lpSolution1->CheckKey(Cipher) == false) ||
            (lpSolution2 && lpSolution2->CheckKey(Cipher) == false) ||
            (lpSolution3 && lpSolution3->CheckKey(Cipher) == false))
        {
            throw ARL::Exception(__FILE__, __LINE__, "The RSA private key you provide cannot be used.");
        }
    } else {
        puts("[*] Generating new RSA private key, it may take a long time...");

        do {
            Cipher.GenerateKey(2048);
        } while ((lpSolution0 && lpSolution0->CheckKey(Cipher) == false) ||
                 (lpSolution1 && lpSolution1->CheckKey(Cipher) == false) ||
                 (lpSolution2 && lpSolution2->CheckKey(Cipher) == false) ||
                 (lpSolution3 && lpSolution3->CheckKey(Cipher) == false));   // re-generate RSA key if CheckKey return false
    }

    printf("[*] Your RSA private key:\n");
    printf("    %s\n", 
        [&Cipher]() -> std::string {
            auto szPrivateKey = Cipher.ExportKeyString<nkg::RSAKeyType::PrivateKey, nkg::RSAKeyFormat::PEM>();
            for (size_t pos = 0; (pos = szPrivateKey.find('\n', pos)) != std::string::npos; pos += strlen("\n    ")) {
                szPrivateKey.replace(pos, 1, "\n    ");
            }
            return szPrivateKey;
        }().c_str()
    );

    printf("[*] Your RSA public key:\n");
    printf("    %s\n", 
        [&Cipher]() -> std::string {
            auto szPublicKey = Cipher.ExportKeyString<nkg::RSAKeyType::PublicKey, nkg::RSAKeyFormat::PEM>();
            for (size_t pos = 0; (pos = szPublicKey.find('\n', pos)) != std::string::npos; pos += strlen("\n    ")) {
                szPublicKey.replace(pos, 1, "\n    ");
            }
            return szPublicKey;
        }().c_str()
    );

    printf("\n");
}

int main(int argc, char* argv[]) {
    bool bDryrun;
    std::string szInstallPath;
    std::string szKeyFilePath;

    if (ParseCommandLine(argc, argv, bDryrun, szInstallPath, szKeyFilePath) == false) {
        Welcome(false);
        Help();
        return -1;
    } else {
        Welcome(true);

        try {
            if (nkg::Misc::FsIsDirectory(szInstallPath) == false) {
                 throw ARL::Exception(__FILE__, __LINE__, "Navicat installation path doesn't point to a directory.")
                    .PushHint("Are you sure the path you specified is correct?")
                    .PushFormatHint("The path you specified: %s", szInstallPath.c_str());
            }

            if (szKeyFilePath.empty() == false && nkg::Misc::FsIsFile(szKeyFilePath) == false) {
                throw ARL::Exception(__FILE__, __LINE__, "RSA key file path doesn't point to a file.")
                    .PushHint("Are you sure the path you specified is correct?")
                    .PushFormatHint("The path you specified: %s", szKeyFilePath.c_str());
            }

            while (szInstallPath.back() == '/') {
                szInstallPath.pop_back();
            }

            nkg::RSACipher Cipher;
            ARL::ResourceWrapper lpSolution0{ ARL::ResourceTraits::CppObject<nkg::PatchSolution>{} };
            ARL::ResourceWrapper lpSolution1{ ARL::ResourceTraits::CppObject<nkg::PatchSolution>{} };
            ARL::ResourceWrapper lpSolution2{ ARL::ResourceTraits::CppObject<nkg::PatchSolution>{} };
            ARL::ResourceWrapper lpSolution3{ ARL::ResourceTraits::CppObject<nkg::PatchSolution>{} };

            std::string             main_path;
            ARL::ResourceWrapper    main_fd{ ARL::ResourceTraits::FileDescriptor{} };
            ARL::ResourceWrapper    main_stat{ ARL::ResourceTraits::CppObject<struct stat>{} };
            ARL::ResourceWrapperEx  main_mmap{ ARL::ResourceTraits::MapView{}, [&main_stat](void* p) { 
                if (munmap(p, main_stat->st_size) < 0) {
                    throw ARL::SystemError(__FILE__, __LINE__, errno, "munmap failed.");
                } 
            } };
            ARL::ResourceWrapper    main_interpreter{ ARL::ResourceTraits::CppObject<nkg::X64ImageInterpreter>{} };

            std::string             libcc_path;
            ARL::ResourceWrapper    libcc_fd{ ARL::ResourceTraits::FileDescriptor{} };
            ARL::ResourceWrapper    libcc_stat{ ARL::ResourceTraits::CppObject<struct stat>{} };
            ARL::ResourceWrapperEx  libcc_mmap{ ARL::ResourceTraits::MapView{}, [&libcc_stat](void* p) { 
                if (munmap(p, libcc_stat->st_size) < 0) {
                    throw ARL::SystemError(__FILE__, __LINE__, errno, "munmap failed.");
                } 
            } };
            ARL::ResourceWrapper    libcc_interpreter{ ARL::ResourceTraits::CppObject<nkg::X64ImageInterpreter>{} };

            //
            // try open "Contents/MacOS/Navicat Premium"
            // try open "Contents/Frameworks/libcc-premium.dylib"
            //
            main_path = szInstallPath + "/Contents/MacOS/Navicat Premium";
            main_fd.TakeOver(open(main_path.c_str(), O_RDWR));
            if (main_fd.IsValid()) {
                printf("[+] Try to open \"%s\" ... Ok!\n", "Contents/MacOS/Navicat Premium");
            } else {
                if (errno == ENOENT) {
                    printf("[-] Try to open \"%s\" ... Not found!\n", "Contents/MacOS/Navicat Premium");
                } else {
                    throw ARL::SystemError(__FILE__, __LINE__, errno, "open failed.");
                }
            }

            libcc_path = szInstallPath + "/Contents/Frameworks/libcc-premium.dylib";
            libcc_fd.TakeOver(open(libcc_path.c_str(), O_RDWR));
            if (libcc_fd.IsValid()) {
                printf("[+] Try to open \"%s\" ... Ok!\n", "Contents/Frameworks/libcc-premium.dylib");
            } else {
                if (errno == ENOENT) {
                    printf("[-] Try to open \"%s\" ... Not found!\n", "Contents/Frameworks/libcc-premium.dylib");
                } else {
                    throw ARL::SystemError(__FILE__, __LINE__, errno, "open failed.");
                }
            }

            //
            // try map "Contents/MacOS/Navicat Premium"
            // try map "Contents/Frameworks/libcc-premium.dylib"
            //
            if (main_fd.IsValid()) {
                main_stat.TakeOver(new struct stat());
                if (fstat(main_fd, main_stat) != 0) {
                    throw ARL::SystemError(__FILE__, __LINE__, errno, "fstat failed.");
                }

                main_mmap.TakeOver(mmap(nullptr, main_stat->st_size, PROT_READ | PROT_WRITE, MAP_SHARED, main_fd, 0));
                if (main_mmap.IsValid() == false) {
                    throw ARL::SystemError(__FILE__, __LINE__, errno, "mmap failed.");
                }

                main_interpreter.TakeOver(
                    new nkg::X64ImageInterpreter(nkg::X64ImageInterpreter::Parse(main_mmap, main_stat->st_size))
                );

                lpSolution0.TakeOver(
                    new nkg::PatchSolution0(*main_interpreter.Get())
                );
                lpSolution1.TakeOver(
                    new nkg::PatchSolution1(*main_interpreter.Get())
                );
                lpSolution2.TakeOver(
                    new nkg::PatchSolution2(*main_interpreter.Get())
                );
            }

            if (libcc_fd.IsValid()) {
                libcc_stat.TakeOver(new struct stat());
                if (fstat(libcc_fd, libcc_stat) != 0) {
                    throw ARL::SystemError(__FILE__, __LINE__, errno, "fstat failed.");
                }

                libcc_mmap.TakeOver(mmap(nullptr, libcc_stat->st_size, PROT_READ | PROT_WRITE, MAP_SHARED, libcc_fd, 0));
                if (libcc_mmap.IsValid() == false) {
                    throw ARL::SystemError(__FILE__, __LINE__, errno, "mmap failed.");
                }

                libcc_interpreter.TakeOver(
                    new nkg::X64ImageInterpreter(nkg::X64ImageInterpreter::Parse(libcc_mmap, libcc_stat->st_size))
                );

                lpSolution3.TakeOver(
                    new nkg::PatchSolution3(*libcc_interpreter.Get())
                );
            }

            puts("");

            if (lpSolution0.IsValid() && lpSolution0->FindPatchOffset() == false) {
                lpSolution0.Release();
            }
            if (lpSolution1.IsValid() && lpSolution1->FindPatchOffset() == false) {
                lpSolution1.Release();
            }
            if (lpSolution2.IsValid() && lpSolution2->FindPatchOffset() == false) {
                lpSolution2.Release();
            }
            if (lpSolution3.IsValid() && lpSolution3->FindPatchOffset() == false) {
                lpSolution3.Release();
            }

            if (int Ver0, Ver1, Ver2; sscanf(GetNavicatVersion(szInstallPath).c_str(), "%d.%d.%d", &Ver0, &Ver1, &Ver2) == 3) {
                printf("\n");
                printf("[*] Your Navicat version: %d.%d.%d\n", Ver0, Ver1, Ver2);
                printf("\n");

                //
                // Begin strategies by different Navicat versions
                //
                if (Ver0 < 12) {    // ver < 12.0.0
                    throw ARL::SystemError(__FILE__, __LINE__, errno, "Unsupported version of Navicat.");
                } else if (Ver0 == 12 && Ver1 == 0 && Ver2 < 24) {                      // ver < 12.0.24
                    printf("[*] Your Navicat version is < 12.0.24. So there would be nothing patched.\n");
                    printf("    Just use `openssl` to generate `RegPrivateKey.pem` and `rpk` file:\n");
                    printf("        openssl genrsa -out RegPrivateKey.pem 2048\n");
                    printf("        openssl rsa -in RegPrivateKey.pem -pubout -out rpk\n");
                    printf("    and replace `%s/Contents/Resources/rpk` with the `rpk` file you just generated.\n", szInstallPath.c_str());
                    printf("\n");
                    return 0;
                } else if (Ver0 == 12 && (Ver1 == 0 || (Ver1 == 1 && Ver2 < 14))) {      // 12.0.24 <= ver && ver < 12.1.14
                    // In this case, Solution0 must be applied
                    if (lpSolution0.IsValid() == false) {
                        puts("[-] Patch abort. None of PatchSolutions will be applied.");
                        puts("    Are you sure your Navicat has not been patched/modified before?");
                        return -1;
                    }
                } else if (Ver0 == 12 && Ver1 == 1 && Ver2 == 14) {                    // ver == 12.1.14
                    // In this case, Solution0 and Solution1 must be applied
                    if ((lpSolution0.IsValid() && lpSolution1.IsValid()) == false) {
                        puts("[-] Patch abort. None of PatchSolutions will be applied.");
                        puts("    Are you sure your Navicat has not been patched/modified before?");
                        return -1;
                    }
                } else if (Ver0 == 12) {                                                // ver == 12.x.x
                    // In this case, Solution0 and Solution2 must be applied
                    if ((lpSolution0.IsValid() && lpSolution2.IsValid()) == false) {
                        puts("[-] Patch abort. None of PatchSolutions will be applied.");
                        puts("    Are you sure your Navicat has not been patched/modified before?");
                        return -1;
                    }
                } else {                                                                // ver == 15.x.x
                    // In this case, Solution3 must be applied
                    if (lpSolution3.IsValid() == false) {
                        puts("[-] Patch abort. None of PatchSolutions will be applied.");
                        puts("    Are you sure your Navicat has not been patched/modified before?");
                        return -1;
                    }
                }
                //
                // End strategies by different Navicat versions
                //
            } else {
                throw ARL::SystemError(__FILE__, __LINE__, errno, "Failed to get version of Navicat.");
            }

            //
            // Make sure that there is one patch solution at least existing.
            //
            if (lpSolution0.IsValid() == false && lpSolution1.IsValid() == false && lpSolution2.IsValid() == false && lpSolution3.IsValid() == false) {
                throw ARL::Exception(__FILE__, __LINE__, "No patch applied. Patch abort!")
                    .PushHint("Are you sure your Navicat has not been patched/modified before?");
            }

            LoadKey(Cipher, szKeyFilePath, lpSolution0, lpSolution1, lpSolution2, lpSolution3);

            if (bDryrun == false) {
                //
                // Save private key if not given
                //
                if (szKeyFilePath.empty()) {
                    Cipher.ExportKeyToFile<nkg::RSAKeyType::PrivateKey, nkg::RSAKeyFormat::PEM>("RegPrivateKey.pem");
                }

                //
                // Making patch. No way to go back here :-)
                //
                if (lpSolution0.IsValid()) {
                    lpSolution0->MakePatch(Cipher);
                }
                if (lpSolution1.IsValid()) {
                    lpSolution1->MakePatch(Cipher);
                }
                if (lpSolution2.IsValid()) {
                    lpSolution2->MakePatch(Cipher);
                }
                if (lpSolution3.IsValid()) {
                    lpSolution3->MakePatch(Cipher);
                }

                if (lpSolution0.IsValid()) {
                    puts("[+] PatchSolution0 has been applied.");
                }
                if (lpSolution1.IsValid()) {
                    puts("[+] PatchSolution1 has been applied.");
                }
                if (lpSolution2.IsValid()) {
                    puts("[+] PatchSolution2 has been applied.");
                }
                if (lpSolution3.IsValid()) {
                    puts("[+] PatchSolution3 has been applied.");
                }

                if (szKeyFilePath.empty()) {
                    printf("[*] New RSA-2048 private key has been saved to\n");
                    printf("    %s/RegPrivateKey.pem\n", nkg::Misc::FsCurrentWorkingDirectory().c_str());
                    printf("\n");
                }
                
                puts("");
                puts("**************************************************************");
                puts("*   Patch has been done successfully. Have fun and enjoy~~   *");
                puts("*    DO NOT FORGET TO SIGN NAVICAT BY YOUR CERTIFICATE!!!    *");
                puts("**************************************************************");
            } else {
                puts("**************************************************************");
                puts("*                   DRY-RUN MODE ENABLE!                     *");
                puts("*                 NO PATCH WILL BE APPLIED!                  *");
                puts("**************************************************************");
            }

            return 0;
        } catch (ARL::Exception& e) {
            printf("[-] %s:%zu ->\n", e.ExceptionFile(), e.ExceptionLine());
            printf("    %s\n", e.ExceptionMessage());

            if (e.HasErrorCode()) {
                printf("    %s (0x%zx)\n", e.ErrorString(), e.ErrorCode());
            }

            for (const auto& Hint : e.Hints()) {
                printf("    Hints: %s\n", Hint.c_str());
            }

            return -1;
        } catch (std::exception& e) {
            printf("[-] %s\n", e.what());
            return -1;
        }
    }
}

