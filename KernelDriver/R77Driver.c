/*
 * R77Driver.c - Main driver file for R77 Kernel Driver
 *
 * This is the main entry point for the R77 rootkit detection driver.
 * It provides trusted system enumeration capabilities from Ring 0.
 */

#include "R77Driver.h"

//
// Global variables
//
PDEVICE_OBJECT g_DeviceObject = NULL;

//
// Forward declarations
//
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD R77DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH R77DispatchCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH R77DispatchDeviceControl;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, R77DriverUnload)
#pragma alloc_text(PAGE, R77DispatchCreateClose)
#pragma alloc_text(PAGE, R77DispatchDeviceControl)
#endif

//
// Pool allocation wrapper with tag
//
PVOID
R77AllocatePool(
    _In_ SIZE_T NumberOfBytes
)
{
    return ExAllocatePoolWithTag(NonPagedPool, NumberOfBytes, R77_POOL_TAG);
}

//
// Pool free wrapper
//
VOID
R77FreePool(
    _In_ PVOID Buffer
)
{
    if (Buffer != NULL) {
        ExFreePoolWithTag(Buffer, R77_POOL_TAG);
    }
}

//
// DriverEntry - Driver initialization routine
//
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    BOOLEAN symbolicLinkCreated = FALSE;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[R77] DriverEntry: Initializing R77 Detector Driver v%d.%d.%d\n",
             R77_DRIVER_VERSION_MAJOR,
             R77_DRIVER_VERSION_MINOR,
             R77_DRIVER_VERSION_BUILD);

    //
    // Initialize device name
    //
    RtlInitUnicodeString(&deviceName, R77_DEVICE_NAME);

    //
    // Create device object
    //
    status = IoCreateDevice(
        DriverObject,
        0,                          // No device extension
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                      // Not exclusive
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[R77] DriverEntry: IoCreateDevice failed with status 0x%08X\n", status);
        return status;
    }

    //
    // Create symbolic link for user-mode access
    //
    RtlInitUnicodeString(&symbolicLink, R77_SYMLINK_NAME);

    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R77] DriverEntry: IoCreateSymbolicLink failed with status 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    symbolicLinkCreated = TRUE;

    //
    // Set up dispatch routines
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE] = R77DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = R77DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = R77DispatchDeviceControl;
    DriverObject->DriverUnload = R77DriverUnload;

    //
    // Set buffered I/O flag
    //
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[R77] DriverEntry: Driver initialized successfully\n");

    return STATUS_SUCCESS;
}

//
// DriverUnload - Cleanup routine
//
VOID
R77DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symbolicLink;

    PAGED_CODE();

    DbgPrint("[R77] R77DriverUnload: Unloading driver\n");

    //
    // Delete symbolic link
    //
    RtlInitUnicodeString(&symbolicLink, R77_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symbolicLink);

    //
    // Delete device object
    //
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrint("[R77] R77DriverUnload: Driver unloaded successfully\n");
}

//
// R77DispatchCreateClose - Handle create and close requests
//
NTSTATUS
R77DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// R77DispatchDeviceControl - Handle IOCTL requests
//
NTSTATUS
R77DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack;
    ULONG ioControlCode;
    PVOID inputBuffer;
    PVOID outputBuffer;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    ULONG bytesReturned = 0;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    UNREFERENCED_PARAMETER(inputBuffer);
    UNREFERENCED_PARAMETER(inputBufferLength);

    DbgPrint("[R77] R77DispatchDeviceControl: IOCTL 0x%08X\n", ioControlCode);

    switch (ioControlCode) {

    case IOCTL_R77_ENUM_PROCESSES:
        DbgPrint("[R77] Processing IOCTL_R77_ENUM_PROCESSES\n");
        status = R77EnumProcesses(outputBuffer, outputBufferLength, &bytesReturned);
        break;

    case IOCTL_R77_GET_HIDDEN_PROCESSES:
        DbgPrint("[R77] Processing IOCTL_R77_GET_HIDDEN_PROCESSES\n");
        status = R77GetHiddenProcesses(outputBuffer, outputBufferLength, &bytesReturned);
        break;

    case IOCTL_R77_ENUM_DRIVERS:
        DbgPrint("[R77] Processing IOCTL_R77_ENUM_DRIVERS\n");
        status = R77EnumDrivers(outputBuffer, outputBufferLength, &bytesReturned);
        break;

    case IOCTL_R77_DETECT_SSDT_HOOKS:
        DbgPrint("[R77] Processing IOCTL_R77_DETECT_SSDT_HOOKS\n");
        status = R77DetectSsdtHooks(outputBuffer, outputBufferLength, &bytesReturned);
        break;

    case IOCTL_R77_ENUM_CALLBACKS:
        DbgPrint("[R77] Processing IOCTL_R77_ENUM_CALLBACKS\n");
        status = R77EnumCallbacks(outputBuffer, outputBufferLength, &bytesReturned);
        break;

    case IOCTL_R77_GET_VERSION:
        DbgPrint("[R77] Processing IOCTL_R77_GET_VERSION\n");
        if (outputBufferLength >= sizeof(R77_VERSION_INFO)) {
            PR77_VERSION_INFO versionInfo = (PR77_VERSION_INFO)outputBuffer;
            RTL_OSVERSIONINFOW osInfo;

            versionInfo->VersionMajor = R77_DRIVER_VERSION_MAJOR;
            versionInfo->VersionMinor = R77_DRIVER_VERSION_MINOR;
            versionInfo->VersionBuild = R77_DRIVER_VERSION_BUILD;

            osInfo.dwOSVersionInfoSize = sizeof(osInfo);
            if (NT_SUCCESS(RtlGetVersion(&osInfo))) {
                versionInfo->OsMajorVersion = osInfo.dwMajorVersion;
                versionInfo->OsMinorVersion = osInfo.dwMinorVersion;
                versionInfo->OsBuildNumber = osInfo.dwBuildNumber;
            }

#ifdef _WIN64
            versionInfo->Is64Bit = TRUE;
#else
            versionInfo->Is64Bit = FALSE;
#endif

            bytesReturned = sizeof(R77_VERSION_INFO);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        DbgPrint("[R77] Unknown IOCTL: 0x%08X\n", ioControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    //
    // Complete the request
    //
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
