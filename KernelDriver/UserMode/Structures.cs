using System;
using System.Runtime.InteropServices;

namespace R77Detector.KernelBridge;

/// <summary>
/// IOCTL codes for communicating with the R77Detector kernel driver.
/// These must match the definitions in the kernel driver (ioctl.h).
/// </summary>
public static class IoctlCodes
{
    // Device type: FILE_DEVICE_UNKNOWN (0x22)
    private const uint FILE_DEVICE_UNKNOWN = 0x00000022;

    // Base function code (start of user-defined range)
    private const uint FUNCTION_BASE = 0x800;

    /// <summary>
    /// IOCTL to get driver version information.
    /// Code: 0x222000
    /// </summary>
    public static readonly uint IOCTL_R77_GET_VERSION = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x00,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to enumerate all processes directly from kernel structures.
    /// Code: 0x222004
    /// </summary>
    public static readonly uint IOCTL_R77_ENUM_PROCESSES = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x01,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to enumerate all loaded kernel drivers.
    /// Code: 0x222008
    /// </summary>
    public static readonly uint IOCTL_R77_ENUM_DRIVERS = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x02,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to get SSDT entries.
    /// Code: 0x22200C
    /// </summary>
    public static readonly uint IOCTL_R77_ENUM_SSDT = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x03,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to detect SSDT hooks.
    /// Code: 0x222010
    /// </summary>
    public static readonly uint IOCTL_R77_CHECK_SSDT_HOOKS = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x04,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to enumerate process creation callbacks.
    /// Code: 0x222014
    /// </summary>
    public static readonly uint IOCTL_R77_ENUM_PROCESS_CALLBACKS = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x05,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to enumerate thread creation callbacks.
    /// Code: 0x222018
    /// </summary>
    public static readonly uint IOCTL_R77_ENUM_THREAD_CALLBACKS = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x06,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to enumerate image load callbacks.
    /// Code: 0x22201C
    /// </summary>
    public static readonly uint IOCTL_R77_ENUM_IMAGE_CALLBACKS = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x07,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to enumerate registry callbacks.
    /// Code: 0x222020
    /// </summary>
    public static readonly uint IOCTL_R77_ENUM_REGISTRY_CALLBACKS = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x08,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to get detailed process information.
    /// Code: 0x222024
    /// </summary>
    public static readonly uint IOCTL_R77_GET_PROCESS_INFO = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x09,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to verify driver code integrity.
    /// Code: 0x222028
    /// </summary>
    public static readonly uint IOCTL_R77_VERIFY_DRIVER_INTEGRITY = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x0A,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    /// <summary>
    /// IOCTL to find DKOM-hidden processes.
    /// Code: 0x22202C
    /// </summary>
    public static readonly uint IOCTL_R77_ENUM_HIDDEN_PROCESSES = NativeMethods.CTL_CODE(
        FILE_DEVICE_UNKNOWN,
        FUNCTION_BASE + 0x0B,
        NativeMethods.METHOD_BUFFERED,
        NativeMethods.FILE_ANY_ACCESS);

    // Legacy aliases for backward compatibility
    public static readonly uint IOCTL_ENUM_PROCESSES = IOCTL_R77_ENUM_PROCESSES;
    public static readonly uint IOCTL_ENUM_DRIVERS = IOCTL_R77_ENUM_DRIVERS;
    public static readonly uint IOCTL_CHECK_SSDT = IOCTL_R77_CHECK_SSDT_HOOKS;
    public static readonly uint IOCTL_ENUM_CALLBACKS = IOCTL_R77_ENUM_PROCESS_CALLBACKS;
}

#region Response Header

/// <summary>
/// Common response header for all IOCTL responses.
/// Must match R77_RESPONSE_HEADER in kernel driver.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct R77ResponseHeader
{
    /// <summary>
    /// Protocol version (currently 1).
    /// </summary>
    public uint Version;

    /// <summary>
    /// NTSTATUS code for the operation.
    /// </summary>
    public int Status;

    /// <summary>
    /// Number of entries returned in this response.
    /// </summary>
    public uint EntryCount;

    /// <summary>
    /// Total entries available (for pagination).
    /// </summary>
    public uint TotalEntries;

    /// <summary>
    /// Size of each entry structure in bytes.
    /// </summary>
    public uint EntrySize;

    /// <summary>
    /// Reserved for alignment.
    /// </summary>
    public uint Reserved;
}

/// <summary>
/// Request header for paginated requests.
/// Must match R77_REQUEST_HEADER in kernel driver.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct R77RequestHeader
{
    /// <summary>
    /// Protocol version (currently 1).
    /// </summary>
    public uint Version;

    /// <summary>
    /// Start index for pagination.
    /// </summary>
    public uint StartIndex;

    /// <summary>
    /// Maximum entries to return.
    /// </summary>
    public uint MaxEntries;

    /// <summary>
    /// Operation-specific flags.
    /// </summary>
    public uint Flags;
}

#endregion

#region Version Information

/// <summary>
/// Driver version information.
/// Must match R77_VERSION_INFO in kernel driver.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct R77VersionInfo
{
    /// <summary>
    /// Driver version (packed as major.minor.patch).
    /// </summary>
    public uint DriverVersion;

    /// <summary>
    /// IOCTL protocol version.
    /// </summary>
    public uint ProtocolVersion;

    /// <summary>
    /// Build number.
    /// </summary>
    public uint BuildNumber;

    /// <summary>
    /// Supported feature flags.
    /// </summary>
    public R77Features Features;

    /// <summary>
    /// Driver display name.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string DriverName;

    /// <summary>
    /// Driver load timestamp (FILETIME).
    /// </summary>
    public ulong LoadTime;
}

/// <summary>
/// Feature flags indicating driver capabilities.
/// </summary>
[Flags]
public enum R77Features : uint
{
    None = 0,
    ProcessEnum = 0x00000001,
    DriverEnum = 0x00000002,
    SsdtCheck = 0x00000004,
    CallbackEnum = 0x00000008,
    IntegrityCheck = 0x00000010,
    DkomDetection = 0x00000020,
    All = 0xFFFFFFFF
}

#endregion

#region Process Structures

/// <summary>
/// Process flags returned by kernel enumeration.
/// </summary>
[Flags]
public enum R77ProcessFlags : uint
{
    None = 0,
    /// <summary>Hidden via Direct Kernel Object Manipulation.</summary>
    HiddenDkom = 0x00000001,
    /// <summary>Hidden from API by PID manipulation.</summary>
    HiddenPid = 0x00000002,
    /// <summary>$77 prefix detected in name.</summary>
    SuspiciousName = 0x00000004,
    /// <summary>PEB not accessible.</summary>
    NoPeb = 0x00000008,
    /// <summary>Protected process (PP/PPL).</summary>
    Protected = 0x00000010,
    /// <summary>System process.</summary>
    System = 0x00000020,
    /// <summary>Process is terminating.</summary>
    Exiting = 0x00000040
}

/// <summary>
/// Process entry from kernel enumeration.
/// Must match R77_PROCESS_ENTRY in kernel driver.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct KernelProcessInfoNative
{
    /// <summary>
    /// Kernel EPROCESS address.
    /// </summary>
    public ulong EprocessAddress;

    /// <summary>
    /// Process ID.
    /// </summary>
    public uint ProcessId;

    /// <summary>
    /// Parent process ID.
    /// </summary>
    public uint ParentProcessId;

    /// <summary>
    /// Session ID.
    /// </summary>
    public uint SessionId;

    /// <summary>
    /// Number of threads.
    /// </summary>
    public uint ThreadCount;

    /// <summary>
    /// Open handle count.
    /// </summary>
    public uint HandleCount;

    /// <summary>
    /// Process creation time (FILETIME).
    /// </summary>
    public ulong CreateTime;

    /// <summary>
    /// User mode CPU time.
    /// </summary>
    public ulong UserTime;

    /// <summary>
    /// Kernel mode CPU time.
    /// </summary>
    public ulong KernelTime;

    /// <summary>
    /// Peak virtual memory size.
    /// </summary>
    public ulong PeakVirtualSize;

    /// <summary>
    /// Current virtual memory size.
    /// </summary>
    public ulong VirtualSize;

    /// <summary>
    /// Peak working set size.
    /// </summary>
    public ulong PeakWorkingSetSize;

    /// <summary>
    /// Current working set size.
    /// </summary>
    public ulong WorkingSetSize;

    /// <summary>
    /// Running under WOW64 (32-bit on 64-bit).
    /// </summary>
    public uint IsWow64;

    /// <summary>
    /// Process flags.
    /// </summary>
    public R77ProcessFlags Flags;

    /// <summary>
    /// Process image name.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ImageName;

    /// <summary>
    /// Full image path.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string ImagePath;
}

/// <summary>
/// High-level process information class for managed code.
/// </summary>
public class KernelProcessInfo
{
    public ulong EprocessAddress { get; set; }
    public uint ProcessId { get; set; }
    public uint ParentProcessId { get; set; }
    public uint SessionId { get; set; }
    public uint ThreadCount { get; set; }
    public uint HandleCount { get; set; }
    public DateTime CreateTime { get; set; }
    public TimeSpan UserTime { get; set; }
    public TimeSpan KernelTime { get; set; }
    public ulong PeakVirtualSize { get; set; }
    public ulong VirtualSize { get; set; }
    public ulong PeakWorkingSetSize { get; set; }
    public ulong WorkingSetSize { get; set; }
    public bool IsWow64 { get; set; }
    public R77ProcessFlags Flags { get; set; }
    public string ImageName { get; set; } = string.Empty;
    public string ImagePath { get; set; } = string.Empty;

    // Convenience properties
    public bool IsHidden => Flags.HasFlag(R77ProcessFlags.HiddenDkom) ||
                            Flags.HasFlag(R77ProcessFlags.HiddenPid);
    public bool IsProtected => Flags.HasFlag(R77ProcessFlags.Protected);
    public bool IsSuspicious => Flags.HasFlag(R77ProcessFlags.SuspiciousName);
    public bool IsSystem => Flags.HasFlag(R77ProcessFlags.System);

    /// <summary>
    /// Creates a KernelProcessInfo from the native structure.
    /// </summary>
    public static KernelProcessInfo FromNative(KernelProcessInfoNative native)
    {
        return new KernelProcessInfo
        {
            EprocessAddress = native.EprocessAddress,
            ProcessId = native.ProcessId,
            ParentProcessId = native.ParentProcessId,
            SessionId = native.SessionId,
            ThreadCount = native.ThreadCount,
            HandleCount = native.HandleCount,
            CreateTime = native.CreateTime > 0 ? DateTime.FromFileTimeUtc((long)native.CreateTime) : DateTime.MinValue,
            UserTime = TimeSpan.FromTicks((long)(native.UserTime / 100)), // 100-ns intervals to ticks
            KernelTime = TimeSpan.FromTicks((long)(native.KernelTime / 100)),
            PeakVirtualSize = native.PeakVirtualSize,
            VirtualSize = native.VirtualSize,
            PeakWorkingSetSize = native.PeakWorkingSetSize,
            WorkingSetSize = native.WorkingSetSize,
            IsWow64 = native.IsWow64 != 0,
            Flags = native.Flags,
            ImageName = native.ImageName ?? string.Empty,
            ImagePath = native.ImagePath ?? string.Empty
        };
    }

    public override string ToString()
    {
        var flags = new List<string>();
        if (IsHidden) flags.Add("HIDDEN");
        if (IsProtected) flags.Add("PROTECTED");
        if (IsSuspicious) flags.Add("SUSPICIOUS");
        if (IsSystem) flags.Add("SYSTEM");

        var flagStr = flags.Count > 0 ? $" [{string.Join(", ", flags)}]" : "";
        return $"[{ProcessId}] {ImageName}{flagStr}";
    }
}

#endregion

#region Driver Structures

/// <summary>
/// Driver flags returned by kernel enumeration.
/// </summary>
[Flags]
public enum R77DriverFlags : uint
{
    None = 0,
    /// <summary>Hidden from API.</summary>
    Hidden = 0x00000001,
    /// <summary>Not digitally signed.</summary>
    Unsigned = 0x00000002,
    /// <summary>Memory differs from disk.</summary>
    Modified = 0x00000004,
    /// <summary>No file on disk.</summary>
    NoFile = 0x00000008,
    /// <summary>$77 in name.</summary>
    SuspiciousName = 0x00000010,
    /// <summary>Has hooks installed.</summary>
    Hooked = 0x00000020
}

/// <summary>
/// Driver entry from kernel enumeration.
/// Must match R77_DRIVER_ENTRY in kernel driver.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct KernelDriverInfoNative
{
    /// <summary>
    /// DRIVER_OBJECT kernel address.
    /// </summary>
    public ulong DriverObject;

    /// <summary>
    /// Module base address.
    /// </summary>
    public ulong DriverStart;

    /// <summary>
    /// Module size in bytes.
    /// </summary>
    public ulong DriverSize;

    /// <summary>
    /// Driver entry point address.
    /// </summary>
    public ulong EntryPoint;

    /// <summary>
    /// Driver flags.
    /// </summary>
    public R77DriverFlags Flags;

    /// <summary>
    /// Load order index.
    /// </summary>
    public uint LoadOrder;

    /// <summary>
    /// Driver name.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string DriverName;

    /// <summary>
    /// Full driver path.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string DriverPath;

    /// <summary>
    /// Service registry name.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ServiceName;

    /// <summary>
    /// SHA-256 hash of module on disk.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] ImageHash;

    /// <summary>
    /// SHA-256 hash of module in memory.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] MemoryHash;

    /// <summary>
    /// 1 if hashes match, 0 if different.
    /// </summary>
    public uint HashMatch;
}

/// <summary>
/// High-level driver information class for managed code.
/// </summary>
public class KernelDriverInfo
{
    public ulong DriverObject { get; set; }
    public ulong ImageBase { get; set; }
    public ulong ImageSize { get; set; }
    public ulong EntryPoint { get; set; }
    public R77DriverFlags Flags { get; set; }
    public uint LoadOrder { get; set; }
    public string DriverName { get; set; } = string.Empty;
    public string DriverPath { get; set; } = string.Empty;
    public string ServiceName { get; set; } = string.Empty;
    public byte[] ImageHash { get; set; } = Array.Empty<byte>();
    public byte[] MemoryHash { get; set; } = Array.Empty<byte>();
    public bool HashMatch { get; set; }

    // Convenience properties
    public bool IsHidden => Flags.HasFlag(R77DriverFlags.Hidden);
    public bool IsSigned => !Flags.HasFlag(R77DriverFlags.Unsigned);
    public bool IsModified => Flags.HasFlag(R77DriverFlags.Modified);
    public bool IsSuspicious => Flags.HasFlag(R77DriverFlags.SuspiciousName);

    /// <summary>
    /// Creates a KernelDriverInfo from the native structure.
    /// </summary>
    public static KernelDriverInfo FromNative(KernelDriverInfoNative native)
    {
        return new KernelDriverInfo
        {
            DriverObject = native.DriverObject,
            ImageBase = native.DriverStart,
            ImageSize = native.DriverSize,
            EntryPoint = native.EntryPoint,
            Flags = native.Flags,
            LoadOrder = native.LoadOrder,
            DriverName = native.DriverName ?? string.Empty,
            DriverPath = native.DriverPath ?? string.Empty,
            ServiceName = native.ServiceName ?? string.Empty,
            ImageHash = native.ImageHash ?? Array.Empty<byte>(),
            MemoryHash = native.MemoryHash ?? Array.Empty<byte>(),
            HashMatch = native.HashMatch != 0
        };
    }

    public override string ToString()
    {
        var flags = new List<string>();
        if (IsHidden) flags.Add("HIDDEN");
        if (!IsSigned) flags.Add("UNSIGNED");
        if (IsModified) flags.Add("MODIFIED");
        if (IsSuspicious) flags.Add("SUSPICIOUS");

        var flagStr = flags.Count > 0 ? $" [{string.Join(", ", flags)}]" : "";
        return $"{DriverName} @ 0x{ImageBase:X16}{flagStr}";
    }
}

#endregion

#region SSDT Structures

/// <summary>
/// SSDT entry from kernel enumeration.
/// Must match R77_SSDT_ENTRY in kernel driver.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct SsdtHookInfoNative
{
    /// <summary>
    /// Syscall number (index in SSDT).
    /// </summary>
    public uint Index;

    /// <summary>
    /// Current function address in SSDT.
    /// </summary>
    public ulong CurrentAddress;

    /// <summary>
    /// Expected address from disk image.
    /// </summary>
    public ulong OriginalAddress;

    /// <summary>
    /// Base address of module containing current address.
    /// </summary>
    public ulong ModuleBase;

    /// <summary>
    /// 1 if entry is hooked (address modified).
    /// </summary>
    public uint IsHooked;

    /// <summary>
    /// Function name (e.g., NtOpenProcess).
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string FunctionName;

    /// <summary>
    /// Module containing the current address.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ModuleName;
}

/// <summary>
/// High-level SSDT entry information class for managed code.
/// </summary>
public class SsdtHookInfo
{
    public uint ServiceIndex { get; set; }
    public ulong CurrentAddress { get; set; }
    public ulong OriginalAddress { get; set; }
    public ulong ModuleBase { get; set; }
    public bool IsHooked { get; set; }
    public string FunctionName { get; set; } = string.Empty;
    public string ModuleName { get; set; } = string.Empty;

    /// <summary>
    /// Creates an SsdtHookInfo from the native structure.
    /// </summary>
    public static SsdtHookInfo FromNative(SsdtHookInfoNative native)
    {
        return new SsdtHookInfo
        {
            ServiceIndex = native.Index,
            CurrentAddress = native.CurrentAddress,
            OriginalAddress = native.OriginalAddress,
            ModuleBase = native.ModuleBase,
            IsHooked = native.IsHooked != 0,
            FunctionName = native.FunctionName ?? string.Empty,
            ModuleName = native.ModuleName ?? string.Empty
        };
    }

    public override string ToString()
    {
        if (IsHooked)
            return $"[HOOKED] {FunctionName} (#{ServiceIndex}): 0x{OriginalAddress:X16} -> 0x{CurrentAddress:X16} ({ModuleName})";
        return $"{FunctionName} (#{ServiceIndex}) @ 0x{CurrentAddress:X16}";
    }
}

/// <summary>
/// Summary of SSDT hook check results.
/// </summary>
public class SsdtHookSummary
{
    public uint TotalEntries { get; set; }
    public uint HookedEntries { get; set; }
    public uint SuspiciousEntries { get; set; }
    public List<SsdtHookInfo> Hooks { get; set; } = new();
}

#endregion

#region Callback Structures

/// <summary>
/// Types of kernel callbacks.
/// Must match R77_CALLBACK_TYPE in kernel driver.
/// </summary>
public enum CallbackType : uint
{
    /// <summary>PsSetCreateProcessNotifyRoutine callback.</summary>
    ProcessCreate = 1,
    /// <summary>PsSetCreateProcessNotifyRoutineEx callback.</summary>
    ProcessCreateEx = 2,
    /// <summary>PsSetCreateThreadNotifyRoutine callback.</summary>
    ThreadCreate = 3,
    /// <summary>PsSetLoadImageNotifyRoutine callback.</summary>
    ImageLoad = 4,
    /// <summary>CmRegisterCallback callback.</summary>
    Registry = 5,
    /// <summary>ObRegisterCallbacks pre-operation callback.</summary>
    ObjectPre = 6,
    /// <summary>ObRegisterCallbacks post-operation callback.</summary>
    ObjectPost = 7,
    /// <summary>FltRegisterFilter pre-operation callback.</summary>
    MinifilterPre = 8,
    /// <summary>FltRegisterFilter post-operation callback.</summary>
    MinifilterPost = 9,
    /// <summary>IoRegisterShutdownNotification callback.</summary>
    Shutdown = 10,
    /// <summary>KeRegisterBugCheckCallback callback.</summary>
    Bugcheck = 11,
    /// <summary>PoRegisterPowerSettingCallback callback.</summary>
    Power = 12,
    /// <summary>Unknown callback type.</summary>
    Unknown = 0xFFFFFFFF
}

/// <summary>
/// Callback flags.
/// </summary>
[Flags]
public enum R77CallbackFlags : uint
{
    None = 0,
    /// <summary>Callback from unknown/suspicious module.</summary>
    SuspiciousModule = 0x00000001,
    /// <summary>Callback module not signed.</summary>
    UnsignedModule = 0x00000002,
    /// <summary>Callback module hidden.</summary>
    HiddenModule = 0x00000004,
    /// <summary>Likely r77 rootkit callback.</summary>
    R77Detected = 0x00000008
}

/// <summary>
/// Callback entry from kernel enumeration.
/// Must match R77_CALLBACK_ENTRY in kernel driver.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct CallbackInfoNative
{
    /// <summary>
    /// Callback function address.
    /// </summary>
    public ulong CallbackAddress;

    /// <summary>
    /// Module containing the callback.
    /// </summary>
    public ulong ModuleBase;

    /// <summary>
    /// Size of the containing module.
    /// </summary>
    public ulong ModuleSize;

    /// <summary>
    /// Type of callback.
    /// </summary>
    public CallbackType Type;

    /// <summary>
    /// Callback flags.
    /// </summary>
    public R77CallbackFlags Flags;

    /// <summary>
    /// Registration handle (for removal).
    /// </summary>
    public ulong RegistrationHandle;

    /// <summary>
    /// Module name containing the callback.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ModuleName;

    /// <summary>
    /// Function name (if resolvable).
    /// </summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string FunctionName;
}

/// <summary>
/// High-level callback information class for managed code.
/// </summary>
public class CallbackInfo
{
    public ulong CallbackAddress { get; set; }
    public ulong ModuleBase { get; set; }
    public ulong ModuleSize { get; set; }
    public CallbackType Type { get; set; }
    public R77CallbackFlags Flags { get; set; }
    public ulong RegistrationHandle { get; set; }
    public string ModuleName { get; set; } = string.Empty;
    public string FunctionName { get; set; } = string.Empty;

    // Convenience properties
    public bool IsSuspicious => Flags.HasFlag(R77CallbackFlags.SuspiciousModule) ||
                                Flags.HasFlag(R77CallbackFlags.R77Detected);
    public bool IsUnsigned => Flags.HasFlag(R77CallbackFlags.UnsignedModule);
    public bool IsHidden => Flags.HasFlag(R77CallbackFlags.HiddenModule);

    /// <summary>
    /// Creates a CallbackInfo from the native structure.
    /// </summary>
    public static CallbackInfo FromNative(CallbackInfoNative native)
    {
        return new CallbackInfo
        {
            CallbackAddress = native.CallbackAddress,
            ModuleBase = native.ModuleBase,
            ModuleSize = native.ModuleSize,
            Type = native.Type,
            Flags = native.Flags,
            RegistrationHandle = native.RegistrationHandle,
            ModuleName = native.ModuleName ?? string.Empty,
            FunctionName = native.FunctionName ?? string.Empty
        };
    }

    public override string ToString()
    {
        var flags = new List<string>();
        if (IsSuspicious) flags.Add("SUSPICIOUS");
        if (IsUnsigned) flags.Add("UNSIGNED");
        if (IsHidden) flags.Add("HIDDEN");

        var flagStr = flags.Count > 0 ? $" [{string.Join(", ", flags)}]" : "";
        var funcName = string.IsNullOrEmpty(FunctionName) ? "Unknown" : FunctionName;
        return $"{Type}: {funcName} ({ModuleName}) @ 0x{CallbackAddress:X16}{flagStr}";
    }
}

#endregion

#region Hidden Process Detection

/// <summary>
/// Hidden process detection methods.
/// </summary>
[Flags]
public enum HiddenProcessDetectionMethod : uint
{
    None = 0,
    /// <summary>Check for EPROCESS list gaps (DKOM unlinking).</summary>
    DkomUnlink = 0x00000001,
    /// <summary>Check PID table vs EPROCESS list.</summary>
    PidSpoofing = 0x00000002,
    /// <summary>Scan handle tables for hidden process references.</summary>
    HandleTable = 0x00000004,
    /// <summary>Find processes via thread enumeration.</summary>
    ThreadScan = 0x00000008,
    /// <summary>Scan VAD trees.</summary>
    VadScan = 0x00000010,
    /// <summary>Use all detection methods.</summary>
    All = 0xFFFFFFFF
}

/// <summary>
/// Hidden process detection request.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct HiddenProcessRequest
{
    public R77RequestHeader Header;
    public HiddenProcessDetectionMethod DetectionMethod;
}

/// <summary>
/// Hidden process entry with detection details.
/// </summary>
public class HiddenProcessInfo
{
    public KernelProcessInfo Process { get; set; } = new();
    public HiddenProcessDetectionMethod DetectionMethod { get; set; }
    public uint Confidence { get; set; }
    public string DetectionDetails { get; set; } = string.Empty;

    public override string ToString()
    {
        return $"[HIDDEN] {Process.ImageName} (PID: {Process.ProcessId}) - {DetectionMethod} ({Confidence}% confidence)";
    }
}

#endregion

#region Legacy Compatibility

/// <summary>
/// Legacy response header for backward compatibility.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct IoctlResponseHeader
{
    public uint Count;
    public uint Status;
    public uint DataSize;
    public uint Reserved;

    public static IoctlResponseHeader FromR77Header(R77ResponseHeader header)
    {
        return new IoctlResponseHeader
        {
            Count = header.EntryCount,
            Status = (uint)header.Status,
            DataSize = header.EntryCount * header.EntrySize,
            Reserved = 0
        };
    }
}

#endregion
