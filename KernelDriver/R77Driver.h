/*
 * R77Driver.h - Shared header for R77 Kernel Driver
 *
 * This header defines IOCTL codes, structures, and common definitions
 * shared between the kernel driver and user-mode applications.
 */

#ifndef _R77_DRIVER_H_
#define _R77_DRIVER_H_

#include <ntddk.h>

//
// Device and symbolic link names
//
#define R77_DEVICE_NAME     L"\\Device\\R77Detector"
#define R77_SYMLINK_NAME    L"\\DosDevices\\R77Detector"
#define R77_WIN32_NAME      L"\\\\.\\R77Detector"

//
// Pool allocation tag
//
#define R77_POOL_TAG        'r77D'

//
// IOCTL codes
// Using METHOD_BUFFERED for simplicity and safety
//
#define R77_IOCTL_BASE      0x800

#define IOCTL_R77_ENUM_PROCESSES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_R77_ENUM_DRIVERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_R77_DETECT_SSDT_HOOKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_R77_ENUM_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_R77_GET_HIDDEN_PROCESSES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_R77_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_READ_ACCESS)

//
// Version information
//
#define R77_DRIVER_VERSION_MAJOR    1
#define R77_DRIVER_VERSION_MINOR    0
#define R77_DRIVER_VERSION_BUILD    0

//
// Maximum counts for enumeration
//
#define MAX_PROCESSES       4096
#define MAX_DRIVERS         1024
#define MAX_CALLBACKS       256
#define MAX_SSDT_ENTRIES    512
#define MAX_PROCESS_NAME    260
#define MAX_DRIVER_NAME     260

//
// Process information structure
//
typedef struct _R77_PROCESS_INFO {
    ULONG       ProcessId;
    ULONG       ParentProcessId;
    ULONG_PTR   EprocessAddress;
    BOOLEAN     IsHidden;           // Hidden from user-mode APIs
    BOOLEAN     IsTerminated;
    CHAR        ImageFileName[16];  // EPROCESS.ImageFileName is 15 chars + null
    WCHAR       FullPath[MAX_PROCESS_NAME];
} R77_PROCESS_INFO, *PR77_PROCESS_INFO;

//
// Process enumeration result
//
typedef struct _R77_PROCESS_ENUM_RESULT {
    ULONG           Count;
    ULONG           HiddenCount;
    R77_PROCESS_INFO Processes[1];  // Variable length array
} R77_PROCESS_ENUM_RESULT, *PR77_PROCESS_ENUM_RESULT;

//
// Driver/module information structure
//
typedef struct _R77_DRIVER_INFO {
    ULONG_PTR   ImageBase;
    ULONG       ImageSize;
    ULONG_PTR   DriverObject;
    ULONG_PTR   EntryPoint;
    WCHAR       DriverName[MAX_DRIVER_NAME];
    WCHAR       DriverPath[MAX_DRIVER_NAME];
    BOOLEAN     IsHidden;           // Not in PsLoadedModuleList
} R77_DRIVER_INFO, *PR77_DRIVER_INFO;

//
// Driver enumeration result
//
typedef struct _R77_DRIVER_ENUM_RESULT {
    ULONG           Count;
    ULONG           HiddenCount;
    R77_DRIVER_INFO Drivers[1];     // Variable length array
} R77_DRIVER_ENUM_RESULT, *PR77_DRIVER_ENUM_RESULT;

//
// SSDT hook information
//
typedef struct _R77_SSDT_HOOK_INFO {
    ULONG       SyscallIndex;
    ULONG_PTR   CurrentAddress;
    ULONG_PTR   OriginalAddress;
    BOOLEAN     IsHooked;
    WCHAR       HookModuleName[MAX_DRIVER_NAME];
    CHAR        FunctionName[64];
} R77_SSDT_HOOK_INFO, *PR77_SSDT_HOOK_INFO;

//
// SSDT detection result
//
typedef struct _R77_SSDT_RESULT {
    ULONG               TotalEntries;
    ULONG               HookedCount;
    ULONG_PTR           SsdtBase;
    R77_SSDT_HOOK_INFO  Hooks[1];   // Variable length - only hooked entries
} R77_SSDT_RESULT, *PR77_SSDT_RESULT;

//
// Callback types
//
typedef enum _R77_CALLBACK_TYPE {
    CallbackTypeProcessNotify = 0,
    CallbackTypeThreadNotify,
    CallbackTypeImageLoadNotify,
    CallbackTypeRegistryNotify,
    CallbackTypeObjectNotify,
    CallbackTypeCmCallback,
    CallbackTypeMax
} R77_CALLBACK_TYPE;

//
// Callback information
//
typedef struct _R77_CALLBACK_INFO {
    R77_CALLBACK_TYPE   Type;
    ULONG_PTR           CallbackAddress;
    ULONG_PTR           OwnerModuleBase;
    ULONG               OwnerModuleSize;
    WCHAR               OwnerModuleName[MAX_DRIVER_NAME];
    BOOLEAN             IsSuspicious;   // Outside known module bounds
} R77_CALLBACK_INFO, *PR77_CALLBACK_INFO;

//
// Callback enumeration result
//
typedef struct _R77_CALLBACK_RESULT {
    ULONG               TotalCount;
    ULONG               SuspiciousCount;
    R77_CALLBACK_INFO   Callbacks[1];   // Variable length array
} R77_CALLBACK_RESULT, *PR77_CALLBACK_RESULT;

//
// Version info result
//
typedef struct _R77_VERSION_INFO {
    ULONG   VersionMajor;
    ULONG   VersionMinor;
    ULONG   VersionBuild;
    ULONG   OsMajorVersion;
    ULONG   OsMinorVersion;
    ULONG   OsBuildNumber;
    BOOLEAN Is64Bit;
} R77_VERSION_INFO, *PR77_VERSION_INFO;

//
// Function prototypes - ProcessEnum.c
//
NTSTATUS
R77EnumProcesses(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS
R77GetHiddenProcesses(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

//
// Function prototypes - DriverEnum.c
//
NTSTATUS
R77EnumDrivers(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

//
// Function prototypes - HookDetect.c
//
NTSTATUS
R77DetectSsdtHooks(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS
R77EnumCallbacks(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

//
// Utility functions
//
PVOID
R77AllocatePool(
    _In_ SIZE_T NumberOfBytes
);

VOID
R77FreePool(
    _In_ PVOID Buffer
);

NTSTATUS
R77GetModuleByAddress(
    _In_ ULONG_PTR Address,
    _Out_ PULONG_PTR ModuleBase,
    _Out_ PULONG ModuleSize,
    _Out_writes_(ModuleNameLength) PWCHAR ModuleName,
    _In_ ULONG ModuleNameLength
);

#endif // _R77_DRIVER_H_
