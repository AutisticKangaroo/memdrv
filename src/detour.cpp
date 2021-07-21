#include "detour.hpp"

#include "stdint.hpp"

//
// jmp QWORD PTR [rip+0x0]
//
static const UCHAR detour_bytes_template[] = {
    0xff, 0x25, 0x00, 0x00, 0x00, 0x00
};

#define FULL_DETOUR_SIZE (sizeof(detour_bytes_template) + sizeof(PVOID))
#define INTERLOCKED_EXCHANGE_SIZE (16ul)

namespace detour {
    _IRQL_requires_max_(APC_LEVEL)
    static NTSTATUS replace_code_16_bytes(void* address, uint8_t* replacement) {
        if ((uint64_t) address != ((uint64_t) address & ~0xf)) {
            return false;
        }

        auto mdl = IoAllocateMdl(address, INTERLOCKED_EXCHANGE_SIZE, FALSE, FALSE, nullptr);
        if (mdl == nullptr) {
            return false;
        }

        __try {
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(mdl);

            return false;
        }

        auto mapping = (PLONG64) MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmNonCached,
            nullptr,
            FALSE,
            NormalPagePriority
        );

        if (mapping == nullptr) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);

            return false;
        }

        NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            MmUnmapLockedPages(mapping, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);

            return status;
        }

        LONG64 previous_content[2];

        previous_content[0] = mapping[0];
        previous_content[1] = mapping[1];

        InterlockedCompareExchange128(
            mapping,
            ((PLONG64) replacement)[1],
            ((PLONG64) replacement)[0],
            previous_content
        );

        MmUnmapLockedPages(mapping, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        return STATUS_SUCCESS;
    }

    _IRQL_requires_max_(APC_LEVEL)
    static void initialize_detour(void* address, void* destination) {
        // jmp QWORD PTR [rip+0x0]
        // 00 00 00 00 00 00 00 00
        RtlCopyMemory((PUCHAR) address, detour_bytes_template, sizeof(detour_bytes_template));
        RtlCopyMemory((PUCHAR) address + sizeof(detour_bytes_template), &destination, sizeof(PVOID));
    }

    _IRQL_requires_max_(APC_LEVEL)
    bool apply(void* target, void* hook, size_t length, void** original) {
        if (length < FULL_DETOUR_SIZE) {
            return false;
        }

        auto trampoline = (PUCHAR) ExAllocatePool(
            NonPagedPool,
            INTERLOCKED_EXCHANGE_SIZE + FULL_DETOUR_SIZE + length
        );

        if (trampoline == nullptr) {
            return false;
        }

        RtlCopyMemory(trampoline, target, INTERLOCKED_EXCHANGE_SIZE);

        RtlCopyMemory(trampoline + INTERLOCKED_EXCHANGE_SIZE, target, length);
        initialize_detour(trampoline + INTERLOCKED_EXCHANGE_SIZE + length, (PVOID) ((uintptr_t) target + length));

        UCHAR detour_bytes[INTERLOCKED_EXCHANGE_SIZE];

        initialize_detour(detour_bytes, hook);
        RtlCopyMemory(
            (PUCHAR) detour_bytes + FULL_DETOUR_SIZE,
            (PUCHAR) target + FULL_DETOUR_SIZE,
            INTERLOCKED_EXCHANGE_SIZE - FULL_DETOUR_SIZE
        );

        NTSTATUS status = replace_code_16_bytes(target, detour_bytes);

        if (!NT_SUCCESS(status)) {
            ExFreePool(trampoline);
        } else {
            *original = trampoline + INTERLOCKED_EXCHANGE_SIZE;
        }

        return NT_SUCCESS(status);
    }

    _IRQL_requires_max_(APC_LEVEL)
    bool restore(void* target, void* original) {
        auto original_bytes = (PUCHAR) original - INTERLOCKED_EXCHANGE_SIZE;

        NTSTATUS status = replace_code_16_bytes(target, original_bytes);

        LARGE_INTEGER DelayInterval;
        DelayInterval.QuadPart = -100000;
        KeDelayExecutionThread(KernelMode, FALSE, &DelayInterval);

        ExFreePool(original_bytes);

        return NT_SUCCESS(status);
    }
}