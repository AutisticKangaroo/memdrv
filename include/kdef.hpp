#ifndef _KDEF_HPP_
#define _KDEF_HPP_

#include <ntifs.h>
#include <ntddk.h>

// phnt
#include <ntldr.h>
#include <ntexapi.h>

extern "C" {
    NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
        _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _Inout_   PVOID SystemInformation,
        _In_      ULONG SystemInformationLength,
        _Out_opt_ PULONG ReturnLength
    );

    NTSYSCALLAPI NTSTATUS NTAPI MmCopyVirtualMemory(
        _In_  PEPROCESS SourceProcess,
        _In_  PVOID SourceAddress,
        _In_  PEPROCESS TargetProcess,
        _In_  PVOID TargetAddress,
        _In_  SIZE_T BufferSize,
        _In_  KPROCESSOR_MODE PreviousMode,
        _Out_ PSIZE_T ReturnSize
    );
}

#endif