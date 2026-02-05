using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace R77Detector.KernelBridge;

/// <summary>
/// P/Invoke declarations for Windows API functions used to communicate with kernel drivers.
/// </summary>
internal static class NativeMethods
{
    #region Constants

    /// <summary>
    /// Read access to the device.
    /// </summary>
    public const uint GENERIC_READ = 0x80000000;

    /// <summary>
    /// Write access to the device.
    /// </summary>
    public const uint GENERIC_WRITE = 0x40000000;

    /// <summary>
    /// Open the device for overlapped (asynchronous) I/O.
    /// </summary>
    public const uint FILE_FLAG_OVERLAPPED = 0x40000000;

    /// <summary>
    /// Share mode: allow others to read.
    /// </summary>
    public const uint FILE_SHARE_READ = 0x00000001;

    /// <summary>
    /// Share mode: allow others to write.
    /// </summary>
    public const uint FILE_SHARE_WRITE = 0x00000002;

    /// <summary>
    /// Open existing file/device only.
    /// </summary>
    public const uint OPEN_EXISTING = 3;

    /// <summary>
    /// Invalid handle value returned on failure.
    /// </summary>
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    #endregion

    #region IOCTL Helpers

    /// <summary>
    /// Constructs an IOCTL control code using the Windows CTL_CODE macro formula.
    /// </summary>
    /// <param name="deviceType">The device type (0x8000 for custom devices).</param>
    /// <param name="function">The function code (0x800 and above for custom).</param>
    /// <param name="method">The buffering method (0=BUFFERED, 1=IN_DIRECT, 2=OUT_DIRECT, 3=NEITHER).</param>
    /// <param name="access">The required access (0=ANY, 1=READ, 2=WRITE, 3=READ|WRITE).</param>
    /// <returns>The computed IOCTL code.</returns>
    public static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
    {
        return ((deviceType << 16) | (access << 14) | (function << 2) | method);
    }

    // Method types for IOCTL
    public const uint METHOD_BUFFERED = 0;
    public const uint METHOD_IN_DIRECT = 1;
    public const uint METHOD_OUT_DIRECT = 2;
    public const uint METHOD_NEITHER = 3;

    // Access types for IOCTL
    public const uint FILE_ANY_ACCESS = 0;
    public const uint FILE_READ_ACCESS = 1;
    public const uint FILE_WRITE_ACCESS = 2;

    // Device type for our driver (FILE_DEVICE_UNKNOWN)
    public const uint FILE_DEVICE_UNKNOWN = 0x00000022;

    #endregion

    #region CreateFile

    /// <summary>
    /// Opens a handle to a device driver.
    /// </summary>
    /// <param name="lpFileName">The device path (e.g., \\.\R77DetectorDriver).</param>
    /// <param name="dwDesiredAccess">The access mode (GENERIC_READ | GENERIC_WRITE).</param>
    /// <param name="dwShareMode">The sharing mode.</param>
    /// <param name="lpSecurityAttributes">Security attributes (typically IntPtr.Zero).</param>
    /// <param name="dwCreationDisposition">Creation disposition (OPEN_EXISTING for devices).</param>
    /// <param name="dwFlagsAndAttributes">File flags and attributes.</param>
    /// <param name="hTemplateFile">Template file handle (typically IntPtr.Zero).</param>
    /// <returns>A handle to the device, or INVALID_HANDLE_VALUE on failure.</returns>
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    #endregion

    #region DeviceIoControl

    /// <summary>
    /// Sends a control code directly to a specified device driver.
    /// </summary>
    /// <param name="hDevice">Handle to the device.</param>
    /// <param name="dwIoControlCode">The IOCTL control code.</param>
    /// <param name="lpInBuffer">Input buffer (can be IntPtr.Zero).</param>
    /// <param name="nInBufferSize">Size of input buffer in bytes.</param>
    /// <param name="lpOutBuffer">Output buffer.</param>
    /// <param name="nOutBufferSize">Size of output buffer in bytes.</param>
    /// <param name="lpBytesReturned">Number of bytes returned.</param>
    /// <param name="lpOverlapped">Overlapped structure (typically IntPtr.Zero for sync).</param>
    /// <returns>True if successful, false otherwise.</returns>
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    /// <summary>
    /// Overload with byte array for input buffer.
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        byte[]? lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    /// <summary>
    /// Overload with byte arrays for both buffers.
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        byte[]? lpInBuffer,
        uint nInBufferSize,
        byte[] lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    #endregion

    #region Service Control Manager (for driver loading)

    /// <summary>
    /// Opens the service control manager database.
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenSCManager(
        string? lpMachineName,
        string? lpDatabaseName,
        uint dwDesiredAccess);

    /// <summary>
    /// Creates a service object.
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateService(
        IntPtr hSCManager,
        string lpServiceName,
        string lpDisplayName,
        uint dwDesiredAccess,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string? lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        string? lpPassword);

    /// <summary>
    /// Opens an existing service.
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenService(
        IntPtr hSCManager,
        string lpServiceName,
        uint dwDesiredAccess);

    /// <summary>
    /// Starts a service.
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool StartService(
        IntPtr hService,
        uint dwNumServiceArgs,
        IntPtr lpServiceArgVectors);

    /// <summary>
    /// Sends a control code to a service.
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ControlService(
        IntPtr hService,
        uint dwControl,
        ref SERVICE_STATUS lpServiceStatus);

    /// <summary>
    /// Deletes a service.
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DeleteService(IntPtr hService);

    /// <summary>
    /// Closes a service handle.
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CloseServiceHandle(IntPtr hSCObject);

    // Service Control Manager access rights
    public const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    public const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
    public const uint SC_MANAGER_CONNECT = 0x0001;

    // Service access rights
    public const uint SERVICE_ALL_ACCESS = 0xF01FF;
    public const uint SERVICE_START = 0x0010;
    public const uint SERVICE_STOP = 0x0020;
    public const uint SERVICE_QUERY_STATUS = 0x0004;
    public const uint DELETE = 0x00010000;

    // Service types
    public const uint SERVICE_KERNEL_DRIVER = 0x00000001;
    public const uint SERVICE_FILE_SYSTEM_DRIVER = 0x00000002;

    // Service start types
    public const uint SERVICE_DEMAND_START = 0x00000003;
    public const uint SERVICE_BOOT_START = 0x00000000;
    public const uint SERVICE_SYSTEM_START = 0x00000001;

    // Service error control
    public const uint SERVICE_ERROR_NORMAL = 0x00000001;
    public const uint SERVICE_ERROR_IGNORE = 0x00000000;

    // Service control codes
    public const uint SERVICE_CONTROL_STOP = 0x00000001;

    /// <summary>
    /// Service status structure.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    // Service states
    public const uint SERVICE_STOPPED = 0x00000001;
    public const uint SERVICE_START_PENDING = 0x00000002;
    public const uint SERVICE_STOP_PENDING = 0x00000003;
    public const uint SERVICE_RUNNING = 0x00000004;

    #endregion

    #region Error Codes

    /// <summary>
    /// Gets the last Win32 error code.
    /// </summary>
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    // Common error codes
    public const uint ERROR_SUCCESS = 0;
    public const uint ERROR_FILE_NOT_FOUND = 2;
    public const uint ERROR_ACCESS_DENIED = 5;
    public const uint ERROR_INVALID_HANDLE = 6;
    public const uint ERROR_INSUFFICIENT_BUFFER = 122;
    public const uint ERROR_SERVICE_EXISTS = 1073;
    public const uint ERROR_SERVICE_ALREADY_RUNNING = 1056;
    public const uint ERROR_SERVICE_NOT_ACTIVE = 1062;

    #endregion
}
