/*
 * DriverEnum.c - Driver and module enumeration from kernel structures
 *
 * This module enumerates loaded drivers by walking the PsLoadedModuleList
 * and comparing against what's visible through documented APIs.
 */

#include "R77Driver.h"

//
// Loader data table entry structure (undocumented)
//
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        };
        struct {
            PVOID LoadedImports;
        };
    };
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

//
// System module information structures
//
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

//
// ZwQuerySystemInformation for modules
//
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#define SystemModuleInformation 11

//
// Global variable for PsLoadedModuleList
// This needs to be found dynamically
//
static PLIST_ENTRY g_PsLoadedModuleList = NULL;
static ERESOURCE g_PsLoadedModuleResource;
static BOOLEAN g_ResourceInitialized = FALSE;

//
// Find PsLoadedModuleList dynamically
//
static
NTSTATUS
R77FindPsLoadedModuleList(
    VOID
)
{
    NTSTATUS status;
    PRTL_PROCESS_MODULES modules = NULL;
    ULONG bufferSize = 0x10000;
    ULONG returnLength;
    ULONG i;
    PVOID ntoskrnlBase = NULL;
    ULONG ntoskrnlSize = 0;

    if (g_PsLoadedModuleList != NULL) {
        return STATUS_SUCCESS;
    }

    //
    // Get module list via documented API
    //
    while (TRUE) {
        modules = (PRTL_PROCESS_MODULES)R77AllocatePool(bufferSize);
        if (modules == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemModuleInformation,
            modules,
            bufferSize,
            &returnLength
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            R77FreePool(modules);
            bufferSize *= 2;
            if (bufferSize > 0x1000000) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }

        break;
    }

    if (!NT_SUCCESS(status)) {
        R77FreePool(modules);
        return status;
    }

    //
    // Find ntoskrnl.exe base address
    //
    for (i = 0; i < modules->NumberOfModules; i++) {
        PCHAR fileName = (PCHAR)&modules->Modules[i].FullPathName[
            modules->Modules[i].OffsetToFileName];

        if (_stricmp(fileName, "ntoskrnl.exe") == 0 ||
            _stricmp(fileName, "ntkrnlpa.exe") == 0 ||
            _stricmp(fileName, "ntkrnlmp.exe") == 0 ||
            _stricmp(fileName, "ntkrpamp.exe") == 0) {

            ntoskrnlBase = modules->Modules[i].ImageBase;
            ntoskrnlSize = modules->Modules[i].ImageSize;
            DbgPrint("[R77] Found ntoskrnl at %p, size 0x%X\n",
                     ntoskrnlBase, ntoskrnlSize);
            break;
        }
    }

    R77FreePool(modules);

    if (ntoskrnlBase == NULL) {
        DbgPrint("[R77] Failed to find ntoskrnl base\n");
        return STATUS_NOT_FOUND;
    }

    //
    // PsLoadedModuleList is exported, try to resolve it
    //
    {
        UNICODE_STRING funcName;
        RtlInitUnicodeString(&funcName, L"PsLoadedModuleList");
        g_PsLoadedModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&funcName);
    }

    if (g_PsLoadedModuleList != NULL) {
        DbgPrint("[R77] Found PsLoadedModuleList at %p\n", g_PsLoadedModuleList);
        return STATUS_SUCCESS;
    }

    //
    // If direct resolution fails, we could scan for it, but that's risky
    // For now, return not found
    //
    DbgPrint("[R77] PsLoadedModuleList not found via MmGetSystemRoutineAddress\n");
    return STATUS_NOT_FOUND;
}

//
// Get module list from ZwQuerySystemInformation for comparison
//
static
NTSTATUS
R77GetUserModeDriverList(
    _Out_ PVOID *BaseAddresses,
    _In_ ULONG MaxDrivers,
    _Out_ PULONG DriverCount
)
{
    NTSTATUS status;
    PRTL_PROCESS_MODULES modules = NULL;
    ULONG bufferSize = 0x10000;
    ULONG returnLength;
    ULONG i;

    *DriverCount = 0;

    while (TRUE) {
        modules = (PRTL_PROCESS_MODULES)R77AllocatePool(bufferSize);
        if (modules == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemModuleInformation,
            modules,
            bufferSize,
            &returnLength
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            R77FreePool(modules);
            bufferSize *= 2;
            if (bufferSize > 0x1000000) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }

        break;
    }

    if (!NT_SUCCESS(status)) {
        R77FreePool(modules);
        return status;
    }

    for (i = 0; i < modules->NumberOfModules && i < MaxDrivers; i++) {
        BaseAddresses[i] = modules->Modules[i].ImageBase;
    }

    *DriverCount = min(modules->NumberOfModules, MaxDrivers);

    R77FreePool(modules);
    return STATUS_SUCCESS;
}

//
// Check if a driver base address is in the user-mode visible list
//
static
BOOLEAN
R77IsDriverVisible(
    _In_ PVOID BaseAddress,
    _In_ PVOID *VisibleBases,
    _In_ ULONG VisibleCount
)
{
    ULONG i;

    for (i = 0; i < VisibleCount; i++) {
        if (VisibleBases[i] == BaseAddress) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Get module information by address
//
NTSTATUS
R77GetModuleByAddress(
    _In_ ULONG_PTR Address,
    _Out_ PULONG_PTR ModuleBase,
    _Out_ PULONG ModuleSize,
    _Out_writes_(ModuleNameLength) PWCHAR ModuleName,
    _In_ ULONG ModuleNameLength
)
{
    NTSTATUS status;
    PRTL_PROCESS_MODULES modules = NULL;
    ULONG bufferSize = 0x10000;
    ULONG returnLength;
    ULONG i;

    *ModuleBase = 0;
    *ModuleSize = 0;
    ModuleName[0] = L'\0';

    while (TRUE) {
        modules = (PRTL_PROCESS_MODULES)R77AllocatePool(bufferSize);
        if (modules == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemModuleInformation,
            modules,
            bufferSize,
            &returnLength
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            R77FreePool(modules);
            bufferSize *= 2;
            if (bufferSize > 0x1000000) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }

        break;
    }

    if (!NT_SUCCESS(status)) {
        R77FreePool(modules);
        return status;
    }

    for (i = 0; i < modules->NumberOfModules; i++) {
        ULONG_PTR base = (ULONG_PTR)modules->Modules[i].ImageBase;
        ULONG size = modules->Modules[i].ImageSize;

        if (Address >= base && Address < (base + size)) {
            ANSI_STRING ansiName;
            UNICODE_STRING unicodeName;

            *ModuleBase = base;
            *ModuleSize = size;

            // Convert module name from ANSI to Unicode
            RtlInitAnsiString(&ansiName,
                (PCSZ)&modules->Modules[i].FullPathName[
                    modules->Modules[i].OffsetToFileName]);

            unicodeName.Buffer = ModuleName;
            unicodeName.MaximumLength = (USHORT)(ModuleNameLength * sizeof(WCHAR));
            unicodeName.Length = 0;

            RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, FALSE);

            R77FreePool(modules);
            return STATUS_SUCCESS;
        }
    }

    R77FreePool(modules);
    return STATUS_NOT_FOUND;
}

//
// Enumerate all loaded drivers
//
NTSTATUS
R77EnumDrivers(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status;
    PR77_DRIVER_ENUM_RESULT result;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY listHead;
    PLDR_DATA_TABLE_ENTRY ldrEntry;
    ULONG driverCount = 0;
    ULONG hiddenCount = 0;
    SIZE_T requiredSize;
    PVOID *visibleBases = NULL;
    ULONG visibleCount = 0;
    KIRQL oldIrql;

    *BytesReturned = 0;

    //
    // Find PsLoadedModuleList
    //
    status = R77FindPsLoadedModuleList();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R77] R77EnumDrivers: Failed to find PsLoadedModuleList\n");

        //
        // Fall back to using ZwQuerySystemInformation only
        //
        PRTL_PROCESS_MODULES modules = NULL;
        ULONG bufferSize = 0x10000;
        ULONG returnLength;
        ULONG i;

        while (TRUE) {
            modules = (PRTL_PROCESS_MODULES)R77AllocatePool(bufferSize);
            if (modules == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = ZwQuerySystemInformation(
                SystemModuleInformation,
                modules,
                bufferSize,
                &returnLength
            );

            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                R77FreePool(modules);
                bufferSize *= 2;
                if (bufferSize > 0x1000000) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                continue;
            }

            break;
        }

        if (!NT_SUCCESS(status)) {
            R77FreePool(modules);
            return status;
        }

        requiredSize = FIELD_OFFSET(R77_DRIVER_ENUM_RESULT, Drivers) +
                       (modules->NumberOfModules * sizeof(R77_DRIVER_INFO));

        if (OutputBufferLength < requiredSize) {
            R77FreePool(modules);
            *BytesReturned = (ULONG)requiredSize;
            return STATUS_BUFFER_TOO_SMALL;
        }

        result = (PR77_DRIVER_ENUM_RESULT)OutputBuffer;
        RtlZeroMemory(result, OutputBufferLength);

        for (i = 0; i < modules->NumberOfModules && i < MAX_DRIVERS; i++) {
            PR77_DRIVER_INFO driverInfo = &result->Drivers[i];
            ANSI_STRING ansiName;
            UNICODE_STRING unicodeName;

            driverInfo->ImageBase = (ULONG_PTR)modules->Modules[i].ImageBase;
            driverInfo->ImageSize = modules->Modules[i].ImageSize;
            driverInfo->IsHidden = FALSE;

            // Convert path
            RtlInitAnsiString(&ansiName, (PCSZ)modules->Modules[i].FullPathName);
            unicodeName.Buffer = driverInfo->DriverPath;
            unicodeName.MaximumLength = sizeof(driverInfo->DriverPath);
            unicodeName.Length = 0;
            RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, FALSE);

            // Convert name
            RtlInitAnsiString(&ansiName,
                (PCSZ)&modules->Modules[i].FullPathName[
                    modules->Modules[i].OffsetToFileName]);
            unicodeName.Buffer = driverInfo->DriverName;
            unicodeName.MaximumLength = sizeof(driverInfo->DriverName);
            unicodeName.Length = 0;
            RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, FALSE);
        }

        result->Count = modules->NumberOfModules;
        result->HiddenCount = 0;

        *BytesReturned = (ULONG)(FIELD_OFFSET(R77_DRIVER_ENUM_RESULT, Drivers) +
                                (modules->NumberOfModules * sizeof(R77_DRIVER_INFO)));

        R77FreePool(modules);
        return STATUS_SUCCESS;
    }

    //
    // Get user-mode visible driver list for comparison
    //
    visibleBases = (PVOID*)R77AllocatePool(MAX_DRIVERS * sizeof(PVOID));
    if (visibleBases == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = R77GetUserModeDriverList(visibleBases, MAX_DRIVERS, &visibleCount);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R77] R77EnumDrivers: Failed to get visible driver list\n");
        visibleCount = 0;
    }

    //
    // Count drivers first
    //
    listHead = g_PsLoadedModuleList;

    //
    // Raise IRQL to prevent list modification
    //
    KeRaiseIrql(APC_LEVEL, &oldIrql);

    listEntry = listHead->Flink;
    while (listEntry != listHead && driverCount < MAX_DRIVERS) {
        driverCount++;
        listEntry = listEntry->Flink;
    }

    KeLowerIrql(oldIrql);

    requiredSize = FIELD_OFFSET(R77_DRIVER_ENUM_RESULT, Drivers) +
                   (driverCount * sizeof(R77_DRIVER_INFO));

    if (OutputBufferLength < requiredSize) {
        R77FreePool(visibleBases);
        *BytesReturned = (ULONG)requiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Fill in driver information
    //
    result = (PR77_DRIVER_ENUM_RESULT)OutputBuffer;
    RtlZeroMemory(result, OutputBufferLength);

    driverCount = 0;
    hiddenCount = 0;

    KeRaiseIrql(APC_LEVEL, &oldIrql);

    listEntry = listHead->Flink;
    while (listEntry != listHead && driverCount < MAX_DRIVERS) {
        PR77_DRIVER_INFO driverInfo;
        BOOLEAN isHidden;

        ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        isHidden = !R77IsDriverVisible(ldrEntry->DllBase, visibleBases, visibleCount);
        if (isHidden) {
            hiddenCount++;
        }

        driverInfo = &result->Drivers[driverCount];
        driverInfo->ImageBase = (ULONG_PTR)ldrEntry->DllBase;
        driverInfo->ImageSize = ldrEntry->SizeOfImage;
        driverInfo->EntryPoint = (ULONG_PTR)ldrEntry->EntryPoint;
        driverInfo->IsHidden = isHidden;

        //
        // Copy driver name
        //
        if (ldrEntry->BaseDllName.Buffer != NULL &&
            ldrEntry->BaseDllName.Length > 0) {
            RtlCopyMemory(driverInfo->DriverName,
                          ldrEntry->BaseDllName.Buffer,
                          min(ldrEntry->BaseDllName.Length,
                              sizeof(driverInfo->DriverName) - sizeof(WCHAR)));
        }

        //
        // Copy full path
        //
        if (ldrEntry->FullDllName.Buffer != NULL &&
            ldrEntry->FullDllName.Length > 0) {
            RtlCopyMemory(driverInfo->DriverPath,
                          ldrEntry->FullDllName.Buffer,
                          min(ldrEntry->FullDllName.Length,
                              sizeof(driverInfo->DriverPath) - sizeof(WCHAR)));
        }

        driverCount++;
        listEntry = listEntry->Flink;
    }

    KeLowerIrql(oldIrql);

    result->Count = driverCount;
    result->HiddenCount = hiddenCount;

    *BytesReturned = (ULONG)(FIELD_OFFSET(R77_DRIVER_ENUM_RESULT, Drivers) +
                            (driverCount * sizeof(R77_DRIVER_INFO)));

    R77FreePool(visibleBases);

    DbgPrint("[R77] R77EnumDrivers: Found %d drivers, %d hidden\n",
             driverCount, hiddenCount);

    return STATUS_SUCCESS;
}
