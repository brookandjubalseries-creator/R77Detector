/*
 * HookDetect.c - SSDT hook and callback detection
 *
 * This module detects SSDT hooks and enumerates system callbacks
 * that could be used by rootkits.
 */

#include "R77Driver.h"

//
// SSDT structures
//
typedef struct _KSERVICE_DESCRIPTOR_TABLE {
    PULONG_PTR ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG_PTR NumberOfServices;
    PUCHAR ParamTableBase;
} KSERVICE_DESCRIPTOR_TABLE, *PKSERVICE_DESCRIPTOR_TABLE;

//
// KeServiceDescriptorTable is exported
//
extern PKSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

//
// Callback registration structures (undocumented)
//
typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF RundownProtect;
    PEX_CALLBACK_FUNCTION Function;
    PVOID Context;
} EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

typedef struct _EX_CALLBACK {
    EX_FAST_REF RoutineBlock;
} EX_CALLBACK, *PEX_CALLBACK;

//
// Process notify callback array (max 64 on modern Windows)
//
#define PSP_MAX_CREATE_PROCESS_NOTIFY 64
#define PSP_MAX_CREATE_THREAD_NOTIFY  64
#define PSP_MAX_LOAD_IMAGE_NOTIFY     64

//
// Global pointers to callback arrays (need to be found dynamically)
//
static PEX_CALLBACK g_PspCreateProcessNotifyRoutine = NULL;
static PEX_CALLBACK g_PspCreateThreadNotifyRoutine = NULL;
static PEX_CALLBACK g_PspLoadImageNotifyRoutine = NULL;
static PVOID g_CmCallbackListHead = NULL;

//
// Ntoskrnl module information
//
static ULONG_PTR g_NtoskrnlBase = 0;
static ULONG g_NtoskrnlSize = 0;

//
// Initialize ntoskrnl boundaries
//
static
NTSTATUS
R77InitNtoskrnlBounds(
    VOID
)
{
    NTSTATUS status;
    ULONG_PTR base;
    ULONG size;
    WCHAR name[MAX_DRIVER_NAME];

    if (g_NtoskrnlBase != 0) {
        return STATUS_SUCCESS;
    }

    //
    // Use a known kernel function to find ntoskrnl bounds
    //
    status = R77GetModuleByAddress(
        (ULONG_PTR)KeServiceDescriptorTable,
        &base,
        &size,
        name,
        MAX_DRIVER_NAME
    );

    if (NT_SUCCESS(status)) {
        g_NtoskrnlBase = base;
        g_NtoskrnlSize = size;
        DbgPrint("[R77] Ntoskrnl: Base=%p, Size=0x%X\n",
                 (PVOID)g_NtoskrnlBase, g_NtoskrnlSize);
    }

    return status;
}

//
// Check if an address is within ntoskrnl
//
static
BOOLEAN
R77IsAddressInNtoskrnl(
    _In_ ULONG_PTR Address
)
{
    if (g_NtoskrnlBase == 0) {
        R77InitNtoskrnlBounds();
    }

    return (Address >= g_NtoskrnlBase &&
            Address < (g_NtoskrnlBase + g_NtoskrnlSize));
}

//
// Detect SSDT hooks
//
NTSTATUS
R77DetectSsdtHooks(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    PR77_SSDT_RESULT result;
    ULONG i;
    ULONG hookedCount = 0;
    ULONG totalEntries;
    SIZE_T requiredSize;
    KIRQL oldIrql;
    ULONG tempHookedIndices[MAX_SSDT_ENTRIES];
    ULONG_PTR tempCurrentAddresses[MAX_SSDT_ENTRIES];

    *BytesReturned = 0;

    //
    // Initialize ntoskrnl bounds
    //
    R77InitNtoskrnlBounds();

    //
    // Validate KeServiceDescriptorTable
    //
    if (KeServiceDescriptorTable == NULL ||
        KeServiceDescriptorTable->ServiceTableBase == NULL) {
        DbgPrint("[R77] R77DetectSsdtHooks: SSDT not found\n");
        return STATUS_NOT_FOUND;
    }

    totalEntries = (ULONG)KeServiceDescriptorTable->NumberOfServices;
    if (totalEntries > MAX_SSDT_ENTRIES) {
        totalEntries = MAX_SSDT_ENTRIES;
    }

    DbgPrint("[R77] SSDT: Base=%p, Entries=%d\n",
             KeServiceDescriptorTable->ServiceTableBase,
             totalEntries);

    //
    // First pass: count hooked entries
    //
    KeRaiseIrql(HIGH_LEVEL, &oldIrql);

    for (i = 0; i < totalEntries; i++) {
        ULONG_PTR funcAddr;

#ifdef _WIN64
        //
        // On x64, SSDT entries are offsets from ServiceTableBase
        // The actual address = ServiceTableBase + (Entry >> 4)
        //
        LONG offset = ((PLONG)KeServiceDescriptorTable->ServiceTableBase)[i] >> 4;
        funcAddr = (ULONG_PTR)KeServiceDescriptorTable->ServiceTableBase + offset;
#else
        //
        // On x86, SSDT entries are direct addresses
        //
        funcAddr = KeServiceDescriptorTable->ServiceTableBase[i];
#endif

        //
        // Check if function is outside ntoskrnl
        //
        if (!R77IsAddressInNtoskrnl(funcAddr)) {
            if (hookedCount < MAX_SSDT_ENTRIES) {
                tempHookedIndices[hookedCount] = i;
                tempCurrentAddresses[hookedCount] = funcAddr;
                hookedCount++;
            }
        }
    }

    KeLowerIrql(oldIrql);

    //
    // Calculate required buffer size
    //
    requiredSize = FIELD_OFFSET(R77_SSDT_RESULT, Hooks) +
                   (hookedCount * sizeof(R77_SSDT_HOOK_INFO));

    if (OutputBufferLength < requiredSize) {
        *BytesReturned = (ULONG)requiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Fill in result
    //
    result = (PR77_SSDT_RESULT)OutputBuffer;
    RtlZeroMemory(result, OutputBufferLength);

    result->TotalEntries = totalEntries;
    result->HookedCount = hookedCount;
    result->SsdtBase = (ULONG_PTR)KeServiceDescriptorTable->ServiceTableBase;

    for (i = 0; i < hookedCount; i++) {
        PR77_SSDT_HOOK_INFO hookInfo = &result->Hooks[i];
        ULONG_PTR moduleBase;
        ULONG moduleSize;
        WCHAR moduleName[MAX_DRIVER_NAME];

        hookInfo->SyscallIndex = tempHookedIndices[i];
        hookInfo->CurrentAddress = tempCurrentAddresses[i];
        hookInfo->OriginalAddress = 0;  // Would need symbol info
        hookInfo->IsHooked = TRUE;

        //
        // Find which module owns the hook
        //
        if (NT_SUCCESS(R77GetModuleByAddress(
                tempCurrentAddresses[i],
                &moduleBase,
                &moduleSize,
                moduleName,
                MAX_DRIVER_NAME))) {
            RtlCopyMemory(hookInfo->HookModuleName, moduleName,
                          sizeof(hookInfo->HookModuleName) - sizeof(WCHAR));
        } else {
            RtlCopyMemory(hookInfo->HookModuleName, L"<UNKNOWN>",
                          sizeof(L"<UNKNOWN>"));
        }
    }

    *BytesReturned = (ULONG)(FIELD_OFFSET(R77_SSDT_RESULT, Hooks) +
                            (hookedCount * sizeof(R77_SSDT_HOOK_INFO)));

    DbgPrint("[R77] R77DetectSsdtHooks: Found %d hooked entries out of %d\n",
             hookedCount, totalEntries);

    return STATUS_SUCCESS;
}

//
// Find callback array addresses
//
static
NTSTATUS
R77FindCallbackArrays(
    VOID
)
{
    //
    // In a production driver, we would scan ntoskrnl for these
    // callback arrays. For now, we'll use a simpler approach.
    //
    // PspCreateProcessNotifyRoutine, PspCreateThreadNotifyRoutine,
    // and PspLoadImageNotifyRoutine are not exported, so we need
    // to find them through pattern scanning or other techniques.
    //

    //
    // For demonstration purposes, we'll enumerate callbacks using
    // documented structures where possible.
    //

    return STATUS_SUCCESS;
}

//
// Enumerate callbacks registered via PsSetCreateProcessNotifyRoutine etc.
//
NTSTATUS
R77EnumCallbacks(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    PR77_CALLBACK_RESULT result;
    ULONG callbackCount = 0;
    ULONG suspiciousCount = 0;
    SIZE_T requiredSize;

    //
    // Since the callback arrays are not exported, we'll use a
    // different approach: enumerate ObRegisterCallbacks and
    // CmRegisterCallback entries where possible.
    //

    *BytesReturned = 0;

    //
    // Initialize ntoskrnl bounds for suspicious detection
    //
    R77InitNtoskrnlBounds();

    //
    // Minimum buffer size
    //
    requiredSize = FIELD_OFFSET(R77_CALLBACK_RESULT, Callbacks);

    if (OutputBufferLength < requiredSize) {
        *BytesReturned = (ULONG)requiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    result = (PR77_CALLBACK_RESULT)OutputBuffer;
    RtlZeroMemory(result, OutputBufferLength);

    //
    // For a complete implementation, we would:
    //
    // 1. Find PspCreateProcessNotifyRoutine array:
    //    - Scan ntoskrnl for pattern near PsSetCreateProcessNotifyRoutine
    //    - Walk the EX_CALLBACK array (64 entries)
    //    - Each entry points to EX_CALLBACK_ROUTINE_BLOCK
    //
    // 2. Find PspCreateThreadNotifyRoutine array:
    //    - Similar approach
    //
    // 3. Find PspLoadImageNotifyRoutine array:
    //    - Similar approach
    //
    // 4. Enumerate CmRegisterCallback list:
    //    - Find CmpCallBackVector or CmCallbackListHead
    //    - Walk the callback list
    //
    // 5. Enumerate ObRegisterCallbacks:
    //    - Walk ObTypeObjectType and enumerate registered callbacks
    //

    //
    // Placeholder: Report that callback enumeration requires
    // pattern scanning which varies by Windows build
    //
    DbgPrint("[R77] R77EnumCallbacks: Callback enumeration requires "
             "build-specific pattern scanning\n");
    DbgPrint("[R77] TODO: Implement pattern scanning for:\n");
    DbgPrint("[R77]   - PspCreateProcessNotifyRoutine\n");
    DbgPrint("[R77]   - PspCreateThreadNotifyRoutine\n");
    DbgPrint("[R77]   - PspLoadImageNotifyRoutine\n");
    DbgPrint("[R77]   - CmCallbackListHead\n");
    DbgPrint("[R77]   - ObTypeObjectType callbacks\n");

    //
    // For now, return empty result with success
    // A full implementation would scan for and enumerate these callbacks
    //

    result->TotalCount = callbackCount;
    result->SuspiciousCount = suspiciousCount;

    *BytesReturned = (ULONG)FIELD_OFFSET(R77_CALLBACK_RESULT, Callbacks);

    return STATUS_SUCCESS;
}

//
// Helper: Check if a callback address is suspicious
// (outside known legitimate modules)
//
static
BOOLEAN
R77IsCallbackSuspicious(
    _In_ ULONG_PTR CallbackAddress
)
{
    ULONG_PTR moduleBase;
    ULONG moduleSize;
    WCHAR moduleName[MAX_DRIVER_NAME];

    //
    // If we can't find the module, it's suspicious
    //
    if (!NT_SUCCESS(R77GetModuleByAddress(
            CallbackAddress,
            &moduleBase,
            &moduleSize,
            moduleName,
            MAX_DRIVER_NAME))) {
        return TRUE;
    }

    //
    // If the address is in shellcode (outside module bounds), suspicious
    //
    if (CallbackAddress < moduleBase ||
        CallbackAddress >= (moduleBase + moduleSize)) {
        return TRUE;
    }

    //
    // Could add additional checks here:
    // - Known malicious module names
    // - Modules loaded from suspicious paths
    // - Modules without valid signatures
    //

    return FALSE;
}
