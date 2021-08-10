#include "util.hpp"

#include "kdef.hpp"

// phnt
#include <ntimage.h>

namespace util {
    void* get_system_information(SYSTEM_INFORMATION_CLASS information_class) {
        ULONG size = 32;

        {
            char buffer[32];
            ZwQuerySystemInformation(information_class, buffer, size, &size);
        }

        auto info = ExAllocatePoolZero(NonPagedPool, size, 0);

        if (info == nullptr)
            return nullptr;

        if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size))) {
            ExFreePool(info);

            return nullptr;
        }

        return info;
    }

    uint64_t get_kernel_module(const char* name) {
        const auto to_lower = [](char* string) -> const char* {
            for (char* pointer = string; *pointer != '\0'; ++pointer) {
                *pointer = (char) (short) tolower(*pointer);
            }

            return string;
        };

        const auto info = (PRTL_PROCESS_MODULES) get_system_information(SystemModuleInformation);

        if (info == nullptr)
            return 0;

        for (size_t i = 0; i < info->NumberOfModules; ++i) {
            const auto& mod = info->Modules[i];

            if (strcmp(to_lower((char*) mod.FullPathName + mod.OffsetToFileName), name) == 0) {
                const auto address = mod.ImageBase;

                ExFreePool(info);

                return (uint64_t) address;
            }
        }

        ExFreePool(info);

        return 0;
    }

    uint64_t find_pattern(uint64_t base, size_t range, const char* pattern, const char* mask) {
        const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool {
            for (; *mask; ++base, ++pattern, ++mask) {
                if (*mask == 'x' && *base != *pattern) {
                    return false;
                }
            }

            return true;
        };

        range = range - strlen(mask);

        for (size_t i = 0; i < range; ++i) {
            if (check_mask((const char*) base + i, pattern, mask)) {
                return base + i;
            }
        }

        return 0;
    }

    uint64_t find_pattern_module(uint64_t base, const char* pattern, const char* mask) {
        const auto headers = (PIMAGE_NT_HEADERS) (base + ((PIMAGE_DOS_HEADER) base)->e_lfanew);
        const auto sections = IMAGE_FIRST_SECTION(headers);

        for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++) {
            const auto section = &sections[i];

            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                const auto match = find_pattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);

                if (match != 0) {
                    return match;
                }
            }
        }

        return 0;
    }
}