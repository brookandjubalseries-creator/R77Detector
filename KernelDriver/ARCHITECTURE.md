# R77Detector Kernel Driver Architecture

## Overview

The R77Detector Kernel Driver (R77KD) is a Windows kernel-mode driver designed to provide trusted system enumeration capabilities that cannot be subverted by user-mode rootkits. By operating at Ring 0, the driver can access kernel data structures directly, bypassing any API hooks or Direct Kernel Object Manipulation (DKOM) techniques employed by rootkits like r77.

## Design Goals

1. **Trusted Enumeration**: Provide accurate process, driver, and callback enumeration by reading kernel structures directly
2. **Hook Detection**: Identify SSDT hooks, inline hooks, and callback manipulation
3. **Minimal Footprint**: Keep the driver small and focused to reduce attack surface
4. **Secure Communication**: Implement secure IOCTL interface with proper validation
5. **Stability**: Ensure the driver cannot crash the system under any circumstances

---

## Component Diagram

```
+------------------------------------------------------------------+
|                        USER MODE (Ring 3)                         |
+------------------------------------------------------------------+
|                                                                   |
|  +---------------------------+    +---------------------------+   |
|  |    R77Detector.exe        |    |    R77DetectorGUI.exe     |   |
|  |    (Console Scanner)      |    |    (WPF Interface)        |   |
|  +-------------+-------------+    +-------------+-------------+   |
|                |                                |                 |
|                +---------------+----------------+                 |
|                                |                                  |
|                    +-----------v-----------+                      |
|                    |   R77KernelClient.dll |                      |
|                    |   (User-mode Library) |                      |
|                    +-----------+-----------+                      |
|                                |                                  |
+--------------------------------|----------------------------------+
                                 | DeviceIoControl()
                                 | \\.\R77Detector
+--------------------------------|----------------------------------+
|                        KERNEL MODE (Ring 0)                       |
+--------------------------------|----------------------------------+
|                                |                                  |
|                    +-----------v-----------+                      |
|                    |     R77KD.sys         |                      |
|                    |   (Kernel Driver)     |                      |
|                    +-----------+-----------+                      |
|                                |                                  |
|         +----------------------+----------------------+           |
|         |                      |                      |           |
|   +-----v-----+          +-----v-----+          +-----v-----+     |
|   | Process   |          | Driver    |          | Callback  |     |
|   | Enumerator|          | Enumerator|          | Enumerator|     |
|   +-----------+          +-----------+          +-----------+     |
|                                                                   |
|   +---------------------+     +-----------------------------+     |
|   | SSDT Hook Detector  |     | Memory Integrity Verifier   |     |
|   +---------------------+     +-----------------------------+     |
|                                                                   |
+------------------------------------------------------------------+
|                     KERNEL DATA STRUCTURES                        |
+------------------------------------------------------------------+
|  EPROCESS List | PsLoadedModuleList | SSDT | Callback Arrays     |
+------------------------------------------------------------------+
```

---

## IOCTL Interface Definition

### Device Information

- **Device Name**: `\Device\R77Detector`
- **Symbolic Link**: `\DosDevices\R77Detector` (accessible as `\\.\R77Detector`)
- **Device Type**: `FILE_DEVICE_UNKNOWN` (0x00000022)

### IOCTL Code Format

IOCTL codes follow the Windows standard format:
```
CTL_CODE(DeviceType, Function, Method, Access)
```

Base function code: `0x800` (start of user-defined range)

### IOCTL Codes

| IOCTL Name | Code | Function | Method | Description |
|------------|------|----------|--------|-------------|
| `IOCTL_R77_GET_VERSION` | `0x222000` | 0x800 | BUFFERED | Get driver version info |
| `IOCTL_R77_ENUM_PROCESSES` | `0x222004` | 0x801 | BUFFERED | Enumerate all processes |
| `IOCTL_R77_ENUM_DRIVERS` | `0x222008` | 0x802 | BUFFERED | Enumerate loaded drivers |
| `IOCTL_R77_ENUM_SSDT` | `0x22200C` | 0x803 | BUFFERED | Get SSDT entries |
| `IOCTL_R77_CHECK_SSDT_HOOKS` | `0x222010` | 0x804 | BUFFERED | Detect SSDT hooks |
| `IOCTL_R77_ENUM_PROCESS_CALLBACKS` | `0x222014` | 0x805 | BUFFERED | List process callbacks |
| `IOCTL_R77_ENUM_THREAD_CALLBACKS` | `0x222018` | 0x806 | BUFFERED | List thread callbacks |
| `IOCTL_R77_ENUM_IMAGE_CALLBACKS` | `0x22201C` | 0x807 | BUFFERED | List image load callbacks |
| `IOCTL_R77_ENUM_REGISTRY_CALLBACKS` | `0x222020` | 0x808 | BUFFERED | List registry callbacks |
| `IOCTL_R77_GET_PROCESS_INFO` | `0x222024` | 0x809 | BUFFERED | Get detailed process info |
| `IOCTL_R77_VERIFY_DRIVER_INTEGRITY` | `0x222028` | 0x80A | BUFFERED | Check driver code integrity |
| `IOCTL_R77_ENUM_HIDDEN_PROCESSES` | `0x22202C` | 0x80B | BUFFERED | Find DKOM-hidden processes |

---

## Data Structures

### Common Header

```c
// All responses include this header
typedef struct _R77_RESPONSE_HEADER {
    ULONG Version;          // Protocol version (1)
    NTSTATUS Status;        // Operation status
    ULONG EntryCount;       // Number of entries returned
    ULONG TotalEntries;     // Total entries available
    ULONG EntrySize;        // Size of each entry
    ULONG Reserved;         // Alignment padding
} R77_RESPONSE_HEADER, *PR77_RESPONSE_HEADER;

// Request header for paginated requests
typedef struct _R77_REQUEST_HEADER {
    ULONG Version;          // Protocol version (1)
    ULONG StartIndex;       // For pagination
    ULONG MaxEntries;       // Maximum entries to return
    ULONG Flags;            // Operation-specific flags
} R77_REQUEST_HEADER, *PR77_REQUEST_HEADER;
```

### Version Information

```c
// IOCTL_R77_GET_VERSION response
typedef struct _R77_VERSION_INFO {
    ULONG DriverVersion;    // Driver version (major.minor.patch packed)
    ULONG ProtocolVersion;  // IOCTL protocol version
    ULONG BuildNumber;      // Build number
    ULONG Features;         // Supported feature flags
    WCHAR DriverName[64];   // Driver display name
    ULONG64 LoadTime;       // Driver load timestamp
} R77_VERSION_INFO, *PR77_VERSION_INFO;

// Feature flags
#define R77_FEATURE_PROCESS_ENUM      0x00000001
#define R77_FEATURE_DRIVER_ENUM       0x00000002
#define R77_FEATURE_SSDT_CHECK        0x00000004
#define R77_FEATURE_CALLBACK_ENUM     0x00000008
#define R77_FEATURE_INTEGRITY_CHECK   0x00000010
#define R77_FEATURE_DKOM_DETECTION    0x00000020
```

### Process Enumeration

```c
// IOCTL_R77_ENUM_PROCESSES response entry
typedef struct _R77_PROCESS_ENTRY {
    ULONG64 EprocessAddress;    // Kernel EPROCESS address
    ULONG ProcessId;            // Process ID
    ULONG ParentProcessId;      // Parent PID
    ULONG SessionId;            // Session ID
    ULONG ThreadCount;          // Number of threads
    ULONG HandleCount;          // Open handles
    ULONG64 CreateTime;         // Process creation time
    ULONG64 UserTime;           // User mode CPU time
    ULONG64 KernelTime;         // Kernel mode CPU time
    ULONG64 PeakVirtualSize;    // Peak virtual memory
    ULONG64 VirtualSize;        // Current virtual memory
    ULONG64 PeakWorkingSetSize; // Peak working set
    ULONG64 WorkingSetSize;     // Current working set
    ULONG IsWow64;              // Running under WOW64
    ULONG Flags;                // Process flags (see below)
    WCHAR ImageName[260];       // Process image name
    WCHAR ImagePath[520];       // Full image path
} R77_PROCESS_ENTRY, *PR77_PROCESS_ENTRY;

// Process flags
#define R77_PROC_FLAG_HIDDEN_DKOM     0x00000001  // Hidden via DKOM
#define R77_PROC_FLAG_HIDDEN_PID      0x00000002  // Hidden from API by PID
#define R77_PROC_FLAG_SUSPICIOUS_NAME 0x00000004  // $77 prefix detected
#define R77_PROC_FLAG_NO_PEB          0x00000008  // PEB not accessible
#define R77_PROC_FLAG_PROTECTED       0x00000010  // Protected process
#define R77_PROC_FLAG_SYSTEM          0x00000020  // System process
#define R77_PROC_FLAG_EXITING         0x00000040  // Process terminating
```

### Driver/Module Enumeration

```c
// IOCTL_R77_ENUM_DRIVERS response entry
typedef struct _R77_DRIVER_ENTRY {
    ULONG64 DriverObject;       // DRIVER_OBJECT address
    ULONG64 DriverStart;        // Module base address
    ULONG64 DriverSize;         // Module size
    ULONG64 EntryPoint;         // Driver entry point
    ULONG Flags;                // Driver flags (see below)
    ULONG LoadOrder;            // Load order index
    WCHAR DriverName[256];      // Driver name
    WCHAR DriverPath[520];      // Full driver path
    WCHAR ServiceName[256];     // Service registry name
    UCHAR ImageHash[32];        // SHA-256 of module on disk
    UCHAR MemoryHash[32];       // SHA-256 of module in memory
    ULONG HashMatch;            // 1 if hashes match, 0 if different
} R77_DRIVER_ENTRY, *PR77_DRIVER_ENTRY;

// Driver flags
#define R77_DRV_FLAG_HIDDEN           0x00000001  // Hidden from API
#define R77_DRV_FLAG_UNSIGNED         0x00000002  // Not digitally signed
#define R77_DRV_FLAG_MODIFIED         0x00000004  // Memory != Disk
#define R77_DRV_FLAG_NO_FILE          0x00000008  // No file on disk
#define R77_DRV_FLAG_SUSPICIOUS_NAME  0x00000010  // $77 in name
#define R77_DRV_FLAG_HOOKED           0x00000020  // Has hooks installed
```

### SSDT Information

```c
// IOCTL_R77_ENUM_SSDT response entry
typedef struct _R77_SSDT_ENTRY {
    ULONG Index;                // Syscall number
    ULONG64 CurrentAddress;     // Current function address
    ULONG64 OriginalAddress;    // Expected address (from disk)
    ULONG64 ModuleBase;         // Containing module base
    ULONG IsHooked;             // 1 if hooked
    CHAR FunctionName[64];      // Function name (if known)
    WCHAR ModuleName[256];      // Module containing the function
} R77_SSDT_ENTRY, *PR77_SSDT_ENTRY;

// IOCTL_R77_CHECK_SSDT_HOOKS response
typedef struct _R77_SSDT_HOOK_INFO {
    ULONG TotalEntries;         // Total SSDT entries
    ULONG HookedEntries;        // Number of hooked entries
    ULONG SuspiciousEntries;    // Entries pointing outside ntoskrnl
    R77_SSDT_ENTRY Hooks[1];    // Variable-length array of hooked entries
} R77_SSDT_HOOK_INFO, *PR77_SSDT_HOOK_INFO;
```

### Callback Enumeration

```c
// Common callback entry structure
typedef struct _R77_CALLBACK_ENTRY {
    ULONG64 CallbackAddress;    // Callback function address
    ULONG64 ModuleBase;         // Module containing callback
    ULONG64 ModuleSize;         // Module size
    ULONG Type;                 // Callback type (see enum below)
    ULONG Flags;                // Callback flags
    ULONG64 RegistrationHandle; // Handle for removal
    WCHAR ModuleName[256];      // Module name
    CHAR FunctionName[128];     // Function name (if resolvable)
} R77_CALLBACK_ENTRY, *PR77_CALLBACK_ENTRY;

// Callback types
typedef enum _R77_CALLBACK_TYPE {
    R77_CALLBACK_PROCESS_CREATE = 1,    // PsSetCreateProcessNotifyRoutine
    R77_CALLBACK_PROCESS_CREATE_EX,     // PsSetCreateProcessNotifyRoutineEx
    R77_CALLBACK_THREAD_CREATE,         // PsSetCreateThreadNotifyRoutine
    R77_CALLBACK_IMAGE_LOAD,            // PsSetLoadImageNotifyRoutine
    R77_CALLBACK_REGISTRY,              // CmRegisterCallback
    R77_CALLBACK_OBJECT_PRE,            // ObRegisterCallbacks (pre-operation)
    R77_CALLBACK_OBJECT_POST,           // ObRegisterCallbacks (post-operation)
    R77_CALLBACK_MINIFILTER_PRE,        // FltRegisterFilter (pre-operation)
    R77_CALLBACK_MINIFILTER_POST,       // FltRegisterFilter (post-operation)
    R77_CALLBACK_SHUTDOWN,              // IoRegisterShutdownNotification
    R77_CALLBACK_BUGCHECK,              // KeRegisterBugCheckCallback
    R77_CALLBACK_POWER,                 // PoRegisterPowerSettingCallback
} R77_CALLBACK_TYPE;

// Callback flags
#define R77_CB_FLAG_SUSPICIOUS_MODULE 0x00000001  // Unknown/suspicious module
#define R77_CB_FLAG_UNSIGNED_MODULE   0x00000002  // Module not signed
#define R77_CB_FLAG_HIDDEN_MODULE     0x00000004  // Module hidden
#define R77_CB_FLAG_R77_DETECTED      0x00000008  // Likely r77 callback
```

### Hidden Process Detection

```c
// IOCTL_R77_ENUM_HIDDEN_PROCESSES request
typedef struct _R77_HIDDEN_PROC_REQUEST {
    R77_REQUEST_HEADER Header;
    ULONG DetectionMethod;      // Bitmask of methods to use
} R77_HIDDEN_PROC_REQUEST, *PR77_HIDDEN_PROC_REQUEST;

// Detection methods
#define R77_DETECT_DKOM_UNLINK      0x00000001  // Check EPROCESS list gaps
#define R77_DETECT_PID_SPOOFING     0x00000002  // Check PID table vs list
#define R77_DETECT_HANDLE_TABLE     0x00000004  // Scan handle tables
#define R77_DETECT_THREAD_SCAN      0x00000008  // Find processes via threads
#define R77_DETECT_VAD_SCAN         0x00000010  // Scan VAD trees
#define R77_DETECT_ALL              0xFFFFFFFF  // Use all methods

// Response entry for hidden process
typedef struct _R77_HIDDEN_PROCESS_ENTRY {
    R77_PROCESS_ENTRY Process;  // Standard process info
    ULONG DetectionMethod;      // How it was detected
    ULONG Confidence;           // Detection confidence (0-100)
    WCHAR DetectionDetails[256];// Human-readable details
} R77_HIDDEN_PROCESS_ENTRY, *PR77_HIDDEN_PROCESS_ENTRY;
```

---

## Data Flow

### Process Enumeration Flow

```
User Mode                          Kernel Mode
---------                          -----------

1. Application calls
   R77_EnumProcesses()
         |
         v
2. DeviceIoControl(
   IOCTL_R77_ENUM_PROCESSES)
         |
         +------------------------>  3. IRP_MJ_DEVICE_CONTROL handler
                                           |
                                           v
                                     4. Validate request buffer
                                           |
                                           v
                                     5. Walk EPROCESS list via
                                        PsGetNextProcess() or
                                        direct list traversal
                                           |
                                           v
                                     6. For each EPROCESS:
                                        - Read process fields
                                        - Check for DKOM signs
                                        - Check name for $77
                                        - Populate R77_PROCESS_ENTRY
                                           |
                                           v
                                     7. Copy to user buffer
                                           |
         <----------------------------+
         |
         v
8. Parse response entries
         |
         v
9. Compare with user-mode
   enumeration results
         |
         v
10. Report discrepancies
    as hidden processes
```

### SSDT Hook Detection Flow

```
1. User requests SSDT check
         |
         v
2. IOCTL_R77_CHECK_SSDT_HOOKS
         |
         +------------------------>  3. Locate KeServiceDescriptorTable
                                           |
                                           v
                                     4. Read SSDT base and count
                                           |
                                           v
                                     5. For each SSDT entry:
                                        a. Get current address
                                        b. Check if within ntoskrnl range
                                        c. If outside, mark as hooked
                                        d. Resolve module containing address
                                           |
                                           v
                                     6. Compare with clean SSDT
                                        (from ntoskrnl.exe on disk)
                                           |
                                           v
                                     7. Return hooked entries
                                           |
         <----------------------------+
         |
         v
8. Display hook information
   with module attribution
```

---

## Kernel Functions and Techniques

### Process Enumeration (Bypassing DKOM)

The driver will use multiple techniques to enumerate processes:

1. **EPROCESS List Walking**
   - Access `PsActiveProcessHead` (undocumented but stable)
   - Walk `ActiveProcessLinks` LIST_ENTRY in each EPROCESS
   - Detect gaps that indicate DKOM unlinking

2. **PID Table Scanning**
   - Access `PspCidTable` handle table
   - Enumerate all process handles
   - Compare with EPROCESS list to find hidden processes

3. **Thread-Based Discovery**
   - Enumerate all threads via `PsGetNextProcessThread()`
   - Find owning process for each thread
   - Discovers processes hidden from process list but with active threads

4. **Handle Table Scanning**
   - Walk handle tables of all processes
   - Look for handles to hidden processes

### Driver Enumeration

1. **PsLoadedModuleList Walking**
   - Access the kernel's module list
   - Compare with user-mode `EnumDeviceDrivers()` results

2. **Object Directory Enumeration**
   - Enumerate `\Driver` object directory
   - Find drivers not in module list

3. **Memory Range Scanning**
   - Scan kernel memory for PE headers
   - Find manually mapped drivers

### SSDT Hook Detection

1. **KeServiceDescriptorTable Access**
   - Read SSDT base and entry count
   - Get current function addresses

2. **Module Range Validation**
   - Get ntoskrnl base and size
   - Verify each SSDT entry points within ntoskrnl

3. **Disk Comparison**
   - Read ntoskrnl.exe from disk
   - Parse its export table
   - Compare function addresses

### Callback Enumeration

1. **Process/Thread/Image Callbacks**
   - Access `PspCreateProcessNotifyRoutine` array
   - Access `PspCreateThreadNotifyRoutine` array
   - Access `PspLoadImageNotifyRoutine` array
   - Decode EX_CALLBACK_ROUTINE_BLOCK structures

2. **Registry Callbacks**
   - Access `CmpCallbackListHead` or `CallbackListHead`
   - Walk the callback list

3. **Object Callbacks**
   - Access `ObTypeIndexTable`
   - For each object type, enumerate `CallbackList`

---

## Security Considerations

### Input Validation

All IOCTL handlers MUST:

1. **Validate buffer sizes** - Check `InputBufferLength` and `OutputBufferLength`
2. **Validate buffer alignment** - Ensure proper alignment for structures
3. **Probe user buffers** - Use `ProbeForRead`/`ProbeForWrite` in try/except
4. **Validate request parameters** - Check index ranges, flag values
5. **Limit output size** - Cap maximum entries to prevent DoS

### Access Control

1. **Administrator Only** - Device only accessible to administrators
   ```c
   // In DriverEntry or device creation
   IoCreateDeviceSecure(..., &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, ...);
   ```

2. **Process Validation** - Optionally verify calling process
   - Check if caller is signed R77Detector executable
   - Use `PsGetCurrentProcess()` and validate image signature

3. **Rate Limiting** - Prevent abuse
   - Limit requests per second
   - Track client processes

### Memory Safety

1. **No User Pointers in Kernel** - Always copy data, never dereference user pointers directly
2. **SEH Protection** - Wrap all user buffer access in `__try/__except`
3. **Pool Tagging** - Use unique pool tags for debugging
4. **Resource Cleanup** - Ensure cleanup on all error paths

### Anti-Tampering

1. **Self-Integrity Checks**
   - Verify own code sections haven't been modified
   - Check IRP dispatch table integrity

2. **Secure Communication**
   - Consider encrypting sensitive data in IOCTLs
   - Add request signing/verification

### Stability Requirements

1. **No Panics** - Driver must handle all errors gracefully
2. **IRQL Compliance** - Respect IRQL requirements for all APIs
3. **Lock Management** - Proper spinlock/mutex usage
4. **Reference Counting** - Proper object reference management

---

## Build Requirements

### Development Environment

- Windows Driver Kit (WDK) 10.0.22621.0 or later
- Visual Studio 2022 with Desktop development with C++
- Windows SDK matching WDK version

### Compilation Flags

```xml
<!-- Driver project settings -->
<DriverType>KMDF</DriverType>
<TargetVersion>Windows10</TargetVersion>
<KMDF_VERSION_MAJOR>1</KMDF_VERSION_MAJOR>
<KMDF_VERSION_MINOR>33</KMDF_VERSION_MINOR>
```

### Signing Requirements

For development:
- Enable test signing: `bcdedit /set testsigning on`
- Sign with test certificate

For production:
- EV code signing certificate required
- Microsoft attestation signing for Windows 10+
- Consider WHQL certification

---

## File Structure

```
KernelDriver/
|-- ARCHITECTURE.md          # This document
|-- R77KD/                   # Kernel driver project
|   |-- R77KD.vcxproj
|   |-- driver.c             # DriverEntry and IRP handlers
|   |-- ioctl.c              # IOCTL dispatch implementation
|   |-- ioctl.h              # IOCTL definitions and structures
|   |-- process.c            # Process enumeration
|   |-- driver_enum.c        # Driver enumeration
|   |-- ssdt.c               # SSDT access and hook detection
|   |-- callbacks.c          # Callback enumeration
|   |-- memory.c             # Memory utilities
|   |-- utils.c              # Common utilities
|-- R77KernelClient/         # User-mode client library
|   |-- R77KernelClient.vcxproj
|   |-- client.c             # DeviceIoControl wrapper
|   |-- client.h             # Public API header
|-- R77KD.sln                # Solution file
|-- build.cmd                # Build script
|-- sign.cmd                 # Signing script
```

---

## Error Codes

The driver uses NTSTATUS codes. Common codes returned:

| Code | Name | Description |
|------|------|-------------|
| `0x00000000` | STATUS_SUCCESS | Operation completed successfully |
| `0xC0000022` | STATUS_ACCESS_DENIED | Caller lacks required privileges |
| `0xC000000D` | STATUS_INVALID_PARAMETER | Invalid input parameter |
| `0xC0000023` | STATUS_BUFFER_TOO_SMALL | Output buffer too small |
| `0xC0000225` | STATUS_NOT_FOUND | Requested item not found |
| `0xC0000001` | STATUS_UNSUCCESSFUL | General failure |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-05 | Initial architecture document |

---

## References

- Windows Internals, 7th Edition - Russinovich, Solomon, Ionescu
- Windows Kernel Programming - Pavel Yosifovich
- WDK Documentation: https://docs.microsoft.com/windows-hardware/drivers/
- Rootkit Detection Methods - Academic papers on DKOM detection

---

## Appendix A: IOCTL Code Calculation

```c
// IOCTL code format:
// Bits 31-16: Device type (0x22 = FILE_DEVICE_UNKNOWN)
// Bits 15-14: Required access (0 = FILE_ANY_ACCESS)
// Bits 13-2:  Function code (0x800+)
// Bits 1-0:   Method (0 = BUFFERED)

#define R77_DEVICE_TYPE  FILE_DEVICE_UNKNOWN  // 0x22

#define IOCTL_R77_GET_VERSION \
    CTL_CODE(R77_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
    // = (0x22 << 16) | (0 << 14) | (0x800 << 2) | 0
    // = 0x00220000 | 0x00000000 | 0x00002000 | 0x00000000
    // = 0x00222000

#define IOCTL_R77_ENUM_PROCESSES \
    CTL_CODE(R77_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
    // = 0x00222004

// ... and so on
```

---

## Appendix B: User-Mode Client API

```c
// R77KernelClient.h - Public API for user-mode applications

#pragma once
#include <windows.h>

#ifdef R77KERNELCLIENT_EXPORTS
#define R77KC_API __declspec(dllexport)
#else
#define R77KC_API __declspec(dllimport)
#endif

// Initialize connection to driver
R77KC_API BOOL R77_Initialize(void);

// Close connection
R77KC_API void R77_Cleanup(void);

// Check if driver is loaded and accessible
R77KC_API BOOL R77_IsDriverLoaded(void);

// Get driver version
R77KC_API BOOL R77_GetVersion(PR77_VERSION_INFO pVersionInfo);

// Enumerate all processes
R77KC_API BOOL R77_EnumProcesses(
    PR77_PROCESS_ENTRY pEntries,
    ULONG MaxEntries,
    PULONG pActualCount
);

// Enumerate loaded drivers
R77KC_API BOOL R77_EnumDrivers(
    PR77_DRIVER_ENTRY pEntries,
    ULONG MaxEntries,
    PULONG pActualCount
);

// Check for SSDT hooks
R77KC_API BOOL R77_CheckSSDTHooks(
    PR77_SSDT_HOOK_INFO pHookInfo,
    ULONG BufferSize
);

// Enumerate callbacks
R77KC_API BOOL R77_EnumCallbacks(
    R77_CALLBACK_TYPE Type,
    PR77_CALLBACK_ENTRY pEntries,
    ULONG MaxEntries,
    PULONG pActualCount
);

// Find hidden processes
R77KC_API BOOL R77_FindHiddenProcesses(
    ULONG DetectionMethods,
    PR77_HIDDEN_PROCESS_ENTRY pEntries,
    ULONG MaxEntries,
    PULONG pActualCount
);

// Get last error message
R77KC_API PCWSTR R77_GetLastErrorMessage(void);
```

---

## Appendix C: Integration with DeepScan

The kernel driver integrates with the existing DeepScan module architecture:

```csharp
// Example: KernelModule.cs in DeepScan
public class KernelModule : IDetectionModule
{
    private readonly R77KernelClient _client;

    public string Name => "Kernel Enumerator";
    public string Description => "Ring 0 trusted system enumeration";
    public RingLevel TargetRing => RingLevel.Ring0_Kernel;

    public bool IsSupported => _client.IsDriverLoaded();

    public async Task<IEnumerable<Detection>> ScanAsync(
        IProgress<string>? progress = null)
    {
        var detections = new List<Detection>();

        // Compare kernel process list with user-mode list
        var kernelProcesses = _client.EnumProcesses();
        var userProcesses = Process.GetProcesses()
            .Select(p => p.Id).ToHashSet();

        foreach (var proc in kernelProcesses)
        {
            if (!userProcesses.Contains((int)proc.ProcessId))
            {
                detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Hidden Process",
                    Severity = Severity.Critical,
                    Description = $"Process hidden from user-mode: " +
                        $"{proc.ImageName} (PID: {proc.ProcessId})",
                    Ring = RingLevel.Ring0_Kernel
                });
            }

            if (proc.Flags.HasFlag(R77ProcessFlags.SuspiciousName))
            {
                detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Suspicious Process",
                    Severity = Severity.Critical,
                    Description = $"$77 prefix detected: {proc.ImageName}",
                    Ring = RingLevel.Ring0_Kernel
                });
            }
        }

        // Check SSDT hooks
        var hooks = _client.CheckSSDTHooks();
        foreach (var hook in hooks.HookedEntries)
        {
            detections.Add(new Detection
            {
                Module = Name,
                Category = "SSDT Hook",
                Severity = Severity.Critical,
                Description = $"SSDT entry {hook.Index} hooked: " +
                    $"{hook.FunctionName} -> {hook.ModuleName}",
                Ring = RingLevel.Ring0_Kernel
            });
        }

        return detections;
    }
}
```
