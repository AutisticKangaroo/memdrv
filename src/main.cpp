#include "kdef.hpp"
#include "stdint.hpp"

#include "util.hpp"

#include "detour.hpp"

#define SYSCALL_MAGIC 0xDEADBEEF

#define CURRENT_PROCESS_HANDLE ((HANDLE) -1)

#define DRIVER_ENTRY_ATTACH 0
#define DRIVER_ENTRY_DETACH 1

enum class dispatch_id : uint32_t {
    map_physical = 0,
    unmap_physical,
    copy_virtual_memory
};

struct syscall_info {
    uint32_t pad_0;
    uint32_t pad_1;
    uint32_t magic;
    uint32_t syscall;
    void* arguments;
    bool* success;
};

struct map_physical_packet_t {
    uint32_t pid;
    uint64_t address;
    uint64_t size;
    uint64_t view;
};

struct unmap_physical_packet_t {
    uint32_t pid;
    uint64_t view;
};

struct copy_virtual_memory_packet_t {
    uint32_t source_pid;
    uint64_t target_pid;

    uint64_t source_address;
    uint64_t target_address;
    uint64_t size;
};

using fn_beep_device_control = NTSTATUS(__fastcall*)(PDEVICE_OBJECT, PIRP);

static uint64_t base_address_ = 0;
static uint64_t beep_device_control_ = 0;

fn_beep_device_control beep_device_control_trampoline;

bool map_physical(uint32_t pid, uint64_t address, size_t size, uint64_t* view) {
    UNICODE_STRING PhysicalMemoryUnicodeString;
    RtlInitUnicodeString(&PhysicalMemoryUnicodeString, L"\\Device\\PhysicalMemory");

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(
        &ObjectAttributes,
        &PhysicalMemoryUnicodeString,
        OBJ_CASE_INSENSITIVE,
        (HANDLE) nullptr,
        (PSECURITY_DESCRIPTOR) nullptr);

    PEPROCESS target = nullptr;
    HANDLE physical_memory_handle = nullptr;
    void* object_handle = nullptr;

    KAPC_STATE apc_state;

    do {
        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE) (uint64_t) pid, &target)))
            return false;

        KeStackAttachProcess(target, &apc_state);

        if (!NT_SUCCESS(ZwOpenSection(&physical_memory_handle, SECTION_ALL_ACCESS, &ObjectAttributes)))
            break;

        if (!NT_SUCCESS(ObReferenceObjectByHandle(
            physical_memory_handle,
            SECTION_ALL_ACCESS,
            (POBJECT_TYPE) nullptr,
            KernelMode,
            &object_handle,
            (POBJECT_HANDLE_INFORMATION) nullptr)))
            break;

        PHYSICAL_ADDRESS start_address;
        PHYSICAL_ADDRESS end_address;

        start_address.QuadPart = address;
        end_address.QuadPart = address + size;

        ULONG address_space = 0;
        if (!HalTranslateBusAddress((INTERFACE_TYPE) 1, 0, start_address, &address_space, &start_address))
            break;

        address_space = 0;
        if (!HalTranslateBusAddress((INTERFACE_TYPE) 1, 0, end_address, &address_space, &end_address))
            break;

        size_t physical_size = end_address.QuadPart - start_address.QuadPart;

        auto view_base = start_address;

        void* view_address = nullptr;

        {
            if (ZwMapViewOfSection(
                physical_memory_handle,
                CURRENT_PROCESS_HANDLE,
                &view_address,
                0,
                physical_size,
                &view_base,
                &physical_size,
                ViewShare,
                0,
                PAGE_READWRITE | PAGE_NOCACHE) == STATUS_CONFLICTING_ADDRESSES) {
                if (!NT_SUCCESS(ZwMapViewOfSection(
                    physical_memory_handle,
                    CURRENT_PROCESS_HANDLE,
                    &view_address,
                    0,
                    physical_size,
                    &view_base,
                    &physical_size,
                    ViewShare,
                    0,
                    PAGE_READWRITE))) {
                    break;
                }
            }
        }

        *view = (uint64_t) view_address + start_address.QuadPart - view_base.QuadPart;

        ObDereferenceObject(object_handle);
        ZwClose(physical_memory_handle);

        KeUnstackDetachProcess(&apc_state);

        return true;
    } while (false);

    if (object_handle != nullptr) {
        ObDereferenceObject(object_handle);
    }

    if (physical_memory_handle != nullptr) {
        ZwClose(physical_memory_handle);
    }

    if (apc_state.Process != nullptr) {
        KeUnstackDetachProcess(&apc_state);
    }

    return false;
}

bool unmap_physical(uint32_t pid, uint64_t view) {
    return NT_SUCCESS(ZwUnmapViewOfSection(CURRENT_PROCESS_HANDLE, (void*) view));
}

bool copy_virtual_memory(uint32_t source_pid, uint32_t target_pid, uint64_t source_address, uint64_t target_address, size_t size) {
    PEPROCESS source = nullptr;
    PEPROCESS target = nullptr;

    do {
        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE) (uintptr_t) source_pid, &source)))
            break;

        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE) (uintptr_t) target_pid, &target)))
            break;

        SIZE_T bytes_written;
        if (!NT_SUCCESS(MmCopyVirtualMemory(
            source,
            (void*) source_address,
            target,
            (void*) target_address,
            size,
            KernelMode,
            &bytes_written)))
            break;

        ObDereferenceObject(source);
        ObDereferenceObject(target);

        return true;
    } while (false);

    if (source != nullptr) {
        ObDereferenceObject(source);
    }

    if (target != nullptr) {
        ObDereferenceObject(target);
    }

    return false;
}

NTSTATUS __fastcall BeepDeviceControl_Hook(PDEVICE_OBJECT device_object, PIRP irp) {
    NTSTATUS status = STATUS_SUCCESS;

    const auto* stack = IoGetCurrentIrpStackLocation(irp);

    if (stack == nullptr)
        return STATUS_ACCESS_VIOLATION;

    auto input = static_cast<syscall_info*>(irp->AssociatedIrp.SystemBuffer);

    bool dispatched = false;

    do {
        if (input != nullptr) {
            const auto safe_memcpy = [](void* destination, const void* source, size_t size) -> bool {
                const auto pid = (uint32_t) (uintptr_t) PsGetCurrentProcessId();
                return copy_virtual_memory(pid, pid, (uint64_t) source, (uint64_t) destination, size);
            };

            syscall_info info;
            if (!safe_memcpy(&info, input, sizeof(info)) || info.magic != SYSCALL_MAGIC) {
                return ((fn_beep_device_control) beep_device_control_trampoline)(device_object, irp);
            }

            const auto dispatch = [&safe_memcpy](dispatch_id id, void* args, bool* success) -> bool {
                switch (id) {
                    case dispatch_id::map_physical: {
                        map_physical_packet_t packet;
                        if (!safe_memcpy(&packet, args, sizeof(packet)))
                            return true;

                        if (!map_physical(packet.pid, packet.address, packet.size, &packet.view))
                            return true;

                        *success = true;

                        return safe_memcpy(args, &packet, sizeof(packet));
                    }

                    case dispatch_id::unmap_physical: {
                        unmap_physical_packet_t packet;
                        if (!safe_memcpy(&packet, args, sizeof(packet)))
                            return true;

                        if (!unmap_physical(packet.pid, packet.view))
                            return true;

                        *success = true;

                        return safe_memcpy(args, &packet, sizeof(packet));
                    }

                    case dispatch_id::copy_virtual_memory: {
                        copy_virtual_memory_packet_t packet;
                        if (!safe_memcpy(&packet, args, sizeof(packet)))
                            return true;

                        if (!copy_virtual_memory(packet.source_pid, packet.target_pid, packet.source_address, packet.target_address, packet.size))
                            return true;

                        *success = true;

                        return safe_memcpy(args, &packet, sizeof(packet));
                    }

                    default:
                        return false;
                }
            };

            bool success;
            if (dispatch((dispatch_id) info.syscall, info.arguments, &success)) {
                dispatched = true;
            }

            if (info.success != nullptr) {
                safe_memcpy(info.success, &success, sizeof(bool));
            }

            if (!dispatched) {
                status = STATUS_NOT_IMPLEMENTED;
            }
        }
    } while (false);

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;

    IoCompleteRequest(irp, 0);

    return STATUS_SUCCESS;
}

NTSTATUS on_attach(uint64_t base_address) {
    base_address_ = base_address;

    const uint64_t beep_module = util::get_kernel_module("beep.sys");

    if (beep_module == 0)
        return STATUS_ACCESS_VIOLATION;

    const uint64_t address = util::find_pattern_module(
        beep_module,
        "\x40\x53\x48\x83\xEC\x20\x4C\x8B\x82\x00\x00\x00\x00",
        "xxxxxxxxx????"
    );

    if (address == 0)
        return STATUS_ACCESS_VIOLATION;

    return NT_SUCCESS(detour::apply((void*) address, (void*) BeepDeviceControl_Hook, 25, (void**) &beep_device_control_trampoline))
           ? STATUS_SUCCESS
           : STATUS_ACCESS_VIOLATION;
}

NTSTATUS on_detach(uint64_t base_address) {
    UNREFERENCED_PARAMETER(base_address);

    return detour::restore((void*) beep_device_control_, (void*) beep_device_control_trampoline)
           ? STATUS_SUCCESS
           : STATUS_ACCESS_VIOLATION;
}

NTSTATUS DriverEntry(uint64_t base_address, uint64_t reason) {
    switch (reason) {
        case DRIVER_ENTRY_ATTACH:
            return on_attach(base_address);

        case DRIVER_ENTRY_DETACH:
            return on_detach(base_address);

        default:
            return STATUS_FAILED_DRIVER_ENTRY;
    }
}