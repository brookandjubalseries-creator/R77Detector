/*
 * ProcessEnum.c - Process enumeration from kernel structures
 *
 * This module walks the EPROCESS linked list to enumerate all processes
 * and detect processes hidden from user-mode APIs.
 */

#include "R77Driver.h"

//
// Undocumented EPROCESS offsets (Windows 10/11 x64)
// These need to be dynamically resolved for production use
//
// Note: These offsets vary between Windows versions and builds.
// A production driver should dynamically resolve these using symbols
// or pattern scanning.
//

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

//
// ZwQuerySystemInformation declaration
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

#define SystemProcessInformation 5

//
// PsGetProcessId and other process routines
//
NTKERNELAPI
HANDLE
PsGetProcessId(
    _In_ PEPROCESS Process
);

NTKERNELAPI
HANDLE
PsGetProcessInheritedFromUniqueProcessId(
    _In_ PEPROCESS Process
);

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

NTKERNELAPI
BOOLEAN
PsGetProcessExitProcessCalled(
    _In_ PEPROCESS Process
);

//
// PsLookupProcessByProcessId
//
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Deref_out_opt_ PEPROCESS *Process
);

//
// ActiveProcessLinks offset in EPROCESS
// This varies by Windows version - using pattern for Windows 10/11 x64
//
static ULONG g_ActiveProcessLinksOffset = 0;

//
// Initialize process enumeration offsets
//
static
NTSTATUS
R77InitProcessOffsets(
    VOID
)
{
    RTL_OSVERSIONINFOW osInfo;

    if (g_ActiveProcessLinksOffset != 0) {
        return STATUS_SUCCESS;
    }

    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    if (!NT_SUCCESS(RtlGetVersion(&osInfo))) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Determine offsets based on Windows version
    // These are approximate and may need adjustment
    //
    if (osInfo.dwMajorVersion >= 10) {
        // Windows 10/11 x64
#ifdef _WIN64
        if (osInfo.dwBuildNumber >= 22000) {
            // Windows 11
            g_ActiveProcessLinksOffset = 0x448;
        } else if (osInfo.dwBuildNumber >= 19041) {
            // Windows 10 20H1 and later
            g_ActiveProcessLinksOffset = 0x448;
        } else if (osInfo.dwBuildNumber >= 18362) {
            // Windows 10 1903/1909
            g_ActiveProcessLinksOffset = 0x2F0;
        } else {
            // Earlier Windows 10 builds
            g_ActiveProcessLinksOffset = 0x2E8;
        }
#else
        // Windows 10 x86
        g_ActiveProcessLinksOffset = 0x0B8;
#endif
    } else {
        // Older Windows versions not supported
        return STATUS_NOT_SUPPORTED;
    }

    DbgPrint("[R77] Process offsets initialized: ActiveProcessLinks=0x%X, Build=%d\n",
             g_ActiveProcessLinksOffset, osInfo.dwBuildNumber);

    return STATUS_SUCCESS;
}

//
// Get list of user-mode visible processes using ZwQuerySystemInformation
//
static
NTSTATUS
R77GetUserModeProcessList(
    _Out_ PHANDLE ProcessIds,
    _In_ ULONG MaxProcesses,
    _Out_ PULONG ProcessCount
)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000;  // Start with 64KB
    ULONG returnLength;
    PSYSTEM_PROCESS_INFORMATION processInfo;
    ULONG count = 0;

    *ProcessCount = 0;

    //
    // Allocate buffer for system information
    //
    while (TRUE) {
        buffer = R77AllocatePool(bufferSize);
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemProcessInformation,
            buffer,
            bufferSize,
            &returnLength
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            R77FreePool(buffer);
            bufferSize *= 2;
            if (bufferSize > 0x1000000) {  // Max 16MB
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }

        break;
    }

    if (!NT_SUCCESS(status)) {
        R77FreePool(buffer);
        return status;
    }

    //
    // Walk the process list
    //
    processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE) {
        if (count < MaxProcesses) {
            ProcessIds[count] = processInfo->UniqueProcessId;
            count++;
        }

        if (processInfo->NextEntryOffset == 0) {
            break;
        }

        processInfo = (PSYSTEM_PROCESS_INFORMATION)
            ((PUCHAR)processInfo + processInfo->NextEntryOffset);
    }

    R77FreePool(buffer);
    *ProcessCount = count;

    return STATUS_SUCCESS;
}

//
// Check if a process ID is in the user-mode visible list
//
static
BOOLEAN
R77IsProcessVisible(
    _In_ HANDLE ProcessId,
    _In_ PHANDLE VisibleProcessIds,
    _In_ ULONG VisibleCount
)
{
    ULONG i;

    for (i = 0; i < VisibleCount; i++) {
        if (VisibleProcessIds[i] == ProcessId) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Enumerate all processes by walking EPROCESS list
//
NTSTATUS
R77EnumProcesses(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status;
    PR77_PROCESS_ENUM_RESULT result;
    PEPROCESS currentProcess;
    PEPROCESS startProcess;
    PLIST_ENTRY processListHead;
    PLIST_ENTRY processListEntry;
    ULONG processCount = 0;
    ULONG hiddenCount = 0;
    HANDLE processId;
    PCHAR imageName;
    SIZE_T requiredSize;
    PHANDLE visibleProcessIds = NULL;
    ULONG visibleCount = 0;

    *BytesReturned = 0;

    //
    // Initialize offsets
    //
    status = R77InitProcessOffsets();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R77] R77EnumProcesses: Failed to initialize offsets\n");
        return status;
    }

    //
    // Get user-mode visible process list for comparison
    //
    visibleProcessIds = (PHANDLE)R77AllocatePool(MAX_PROCESSES * sizeof(HANDLE));
    if (visibleProcessIds == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = R77GetUserModeProcessList(visibleProcessIds, MAX_PROCESSES, &visibleCount);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R77] R77EnumProcesses: Failed to get visible process list: 0x%08X\n", status);
        // Continue anyway - we just won't be able to detect hidden processes
        visibleCount = 0;
    }

    //
    // Get current process as starting point
    //
    currentProcess = PsGetCurrentProcess();
    startProcess = currentProcess;

    //
    // Get the ActiveProcessLinks list head
    //
    processListHead = (PLIST_ENTRY)((PUCHAR)currentProcess + g_ActiveProcessLinksOffset);

    //
    // Calculate required buffer size (estimate)
    // We'll need to count processes first
    //
    processListEntry = processListHead->Flink;

    while (processListEntry != processListHead && processCount < MAX_PROCESSES) {
        processCount++;
        processListEntry = processListEntry->Flink;
    }

    requiredSize = FIELD_OFFSET(R77_PROCESS_ENUM_RESULT, Processes) +
                   (processCount * sizeof(R77_PROCESS_INFO));

    if (OutputBufferLength < requiredSize) {
        DbgPrint("[R77] R77EnumProcesses: Buffer too small. Need %llu bytes\n",
                 (ULONGLONG)requiredSize);
        R77FreePool(visibleProcessIds);
        *BytesReturned = (ULONG)requiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Fill in the result buffer
    //
    result = (PR77_PROCESS_ENUM_RESULT)OutputBuffer;
    RtlZeroMemory(result, OutputBufferLength);

    processCount = 0;
    hiddenCount = 0;
    processListEntry = processListHead->Flink;

    while (processListEntry != processListHead && processCount < MAX_PROCESSES) {
        PEPROCESS process;
        PR77_PROCESS_INFO processInfo;
        BOOLEAN isHidden;

        //
        // Get EPROCESS from list entry
        //
        process = (PEPROCESS)((PUCHAR)processListEntry - g_ActiveProcessLinksOffset);

        //
        // Get process information
        //
        processId = PsGetProcessId(process);
        imageName = PsGetProcessImageFileName(process);

        //
        // Check if process is hidden
        //
        isHidden = !R77IsProcessVisible(processId, visibleProcessIds, visibleCount);
        if (isHidden) {
            hiddenCount++;
        }

        //
        // Fill in process info structure
        //
        processInfo = &result->Processes[processCount];
        processInfo->ProcessId = HandleToULong(processId);
        processInfo->ParentProcessId = HandleToULong(
            PsGetProcessInheritedFromUniqueProcessId(process));
        processInfo->EprocessAddress = (ULONG_PTR)process;
        processInfo->IsHidden = isHidden;
        processInfo->IsTerminated = PsGetProcessExitProcessCalled(process);

        if (imageName != NULL) {
            RtlCopyMemory(processInfo->ImageFileName, imageName,
                          min(strlen(imageName), sizeof(processInfo->ImageFileName) - 1));
        }

        processCount++;
        processListEntry = processListEntry->Flink;
    }

    result->Count = processCount;
    result->HiddenCount = hiddenCount;

    *BytesReturned = (ULONG)(FIELD_OFFSET(R77_PROCESS_ENUM_RESULT, Processes) +
                            (processCount * sizeof(R77_PROCESS_INFO)));

    R77FreePool(visibleProcessIds);

    DbgPrint("[R77] R77EnumProcesses: Found %d processes, %d hidden\n",
             processCount, hiddenCount);

    return STATUS_SUCCESS;
}

//
// Get only hidden processes
//
NTSTATUS
R77GetHiddenProcesses(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status;
    PR77_PROCESS_ENUM_RESULT fullResult = NULL;
    PR77_PROCESS_ENUM_RESULT hiddenResult;
    ULONG fullBufferSize;
    ULONG i;
    ULONG hiddenIndex = 0;
    SIZE_T requiredSize;

    *BytesReturned = 0;

    //
    // First get all processes
    //
    fullBufferSize = FIELD_OFFSET(R77_PROCESS_ENUM_RESULT, Processes) +
                     (MAX_PROCESSES * sizeof(R77_PROCESS_INFO));

    fullResult = (PR77_PROCESS_ENUM_RESULT)R77AllocatePool(fullBufferSize);
    if (fullResult == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = R77EnumProcesses(fullResult, fullBufferSize, BytesReturned);
    if (!NT_SUCCESS(status)) {
        R77FreePool(fullResult);
        return status;
    }

    //
    // Calculate required size for hidden processes only
    //
    requiredSize = FIELD_OFFSET(R77_PROCESS_ENUM_RESULT, Processes) +
                   (fullResult->HiddenCount * sizeof(R77_PROCESS_INFO));

    if (OutputBufferLength < requiredSize) {
        R77FreePool(fullResult);
        *BytesReturned = (ULONG)requiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Copy only hidden processes
    //
    hiddenResult = (PR77_PROCESS_ENUM_RESULT)OutputBuffer;
    RtlZeroMemory(hiddenResult, OutputBufferLength);

    for (i = 0; i < fullResult->Count; i++) {
        if (fullResult->Processes[i].IsHidden) {
            RtlCopyMemory(&hiddenResult->Processes[hiddenIndex],
                          &fullResult->Processes[i],
                          sizeof(R77_PROCESS_INFO));
            hiddenIndex++;
        }
    }

    hiddenResult->Count = fullResult->HiddenCount;
    hiddenResult->HiddenCount = fullResult->HiddenCount;

    *BytesReturned = (ULONG)(FIELD_OFFSET(R77_PROCESS_ENUM_RESULT, Processes) +
                            (hiddenIndex * sizeof(R77_PROCESS_INFO)));

    R77FreePool(fullResult);

    DbgPrint("[R77] R77GetHiddenProcesses: Returning %d hidden processes\n", hiddenIndex);

    return STATUS_SUCCESS;
}
