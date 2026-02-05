using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace R77Detector.KernelBridge;

/// <summary>
/// Provides communication with the R77Detector kernel driver via IOCTLs.
/// This class enables user-mode applications to request trusted system enumeration
/// data from the kernel driver, bypassing any user-mode hooks.
/// </summary>
public class KernelBridge : IDisposable
{
    #region Constants

    /// <summary>
    /// The device path used to communicate with the driver.
    /// Per ARCHITECTURE.md: Symbolic link \DosDevices\R77Detector accessible as \\.\R77Detector
    /// </summary>
    private const string DevicePath = @"\\.\R77Detector";

    /// <summary>
    /// The name of the driver service.
    /// </summary>
    private const string ServiceName = "R77KD";

    /// <summary>
    /// Default buffer size for IOCTL operations.
    /// </summary>
    private const int DefaultBufferSize = 1024 * 1024; // 1 MB

    /// <summary>
    /// Maximum buffer size for IOCTL operations.
    /// </summary>
    private const int MaxBufferSize = 16 * 1024 * 1024; // 16 MB

    #endregion

    #region Fields

    private SafeFileHandle? _deviceHandle;
    private bool _disposed;
    private readonly string? _driverPath;
    private readonly object _lock = new();

    #endregion

    #region Properties

    /// <summary>
    /// Gets a value indicating whether the driver is currently loaded and connected.
    /// </summary>
    public bool IsConnected => _deviceHandle != null && !_deviceHandle.IsInvalid && !_deviceHandle.IsClosed;

    /// <summary>
    /// Gets the last error message if an operation failed.
    /// </summary>
    public string? LastError { get; private set; }

    /// <summary>
    /// Gets the last Win32 error code.
    /// </summary>
    public int LastErrorCode { get; private set; }

    #endregion

    #region Constructor

    /// <summary>
    /// Creates a new KernelBridge instance.
    /// </summary>
    /// <param name="driverPath">Optional path to the driver file (.sys) for loading.</param>
    public KernelBridge(string? driverPath = null)
    {
        _driverPath = driverPath;
    }

    #endregion

    #region Driver Loading

    /// <summary>
    /// Attempts to load the kernel driver and establish a connection.
    /// </summary>
    /// <returns>True if the driver was loaded and connected successfully.</returns>
    public bool LoadDriver()
    {
        lock (_lock)
        {
            if (IsConnected)
            {
                return true;
            }

            // First, try to connect to an already loaded driver
            if (TryConnect())
            {
                return true;
            }

            // If we have a driver path, try to load it
            if (!string.IsNullOrEmpty(_driverPath))
            {
                if (!File.Exists(_driverPath))
                {
                    SetError($"Driver file not found: {_driverPath}", 2);
                    return false;
                }

                if (!LoadDriverService(_driverPath))
                {
                    return false;
                }

                // Try connecting again after loading
                return TryConnect();
            }

            SetError("Driver not loaded and no driver path specified", 0);
            return false;
        }
    }

    /// <summary>
    /// Attempts to connect to an already loaded driver.
    /// </summary>
    /// <returns>True if connection was successful.</returns>
    public bool TryConnect()
    {
        lock (_lock)
        {
            if (IsConnected)
            {
                return true;
            }

            _deviceHandle = NativeMethods.CreateFile(
                DevicePath,
                NativeMethods.GENERIC_READ | NativeMethods.GENERIC_WRITE,
                NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
                IntPtr.Zero,
                NativeMethods.OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (_deviceHandle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                SetError($"Failed to open driver device: {new Win32Exception(error).Message}", error);
                _deviceHandle = null;
                return false;
            }

            LastError = null;
            LastErrorCode = 0;
            return true;
        }
    }

    /// <summary>
    /// Loads the driver as a kernel service.
    /// </summary>
    private bool LoadDriverService(string driverPath)
    {
        IntPtr scManager = IntPtr.Zero;
        IntPtr service = IntPtr.Zero;

        try
        {
            // Open Service Control Manager
            scManager = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ALL_ACCESS);
            if (scManager == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                SetError($"Failed to open Service Control Manager: {new Win32Exception(error).Message}", error);
                return false;
            }

            // Try to open existing service first
            service = NativeMethods.OpenService(scManager, ServiceName, NativeMethods.SERVICE_ALL_ACCESS);

            if (service == IntPtr.Zero)
            {
                int openError = Marshal.GetLastWin32Error();

                // Service doesn't exist, create it
                string fullPath = Path.GetFullPath(driverPath);
                service = NativeMethods.CreateService(
                    scManager,
                    ServiceName,
                    "R77Detector Kernel Driver",
                    NativeMethods.SERVICE_ALL_ACCESS,
                    NativeMethods.SERVICE_KERNEL_DRIVER,
                    NativeMethods.SERVICE_DEMAND_START,
                    NativeMethods.SERVICE_ERROR_NORMAL,
                    fullPath,
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null);

                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    SetError($"Failed to create driver service: {new Win32Exception(error).Message}", error);
                    return false;
                }
            }

            // Start the service
            if (!NativeMethods.StartService(service, 0, IntPtr.Zero))
            {
                int error = Marshal.GetLastWin32Error();
                if (error != (int)NativeMethods.ERROR_SERVICE_ALREADY_RUNNING)
                {
                    SetError($"Failed to start driver service: {new Win32Exception(error).Message}", error);
                    return false;
                }
            }

            return true;
        }
        finally
        {
            if (service != IntPtr.Zero)
                NativeMethods.CloseServiceHandle(service);
            if (scManager != IntPtr.Zero)
                NativeMethods.CloseServiceHandle(scManager);
        }
    }

    /// <summary>
    /// Unloads the kernel driver.
    /// </summary>
    /// <returns>True if the driver was unloaded successfully.</returns>
    public bool UnloadDriver()
    {
        lock (_lock)
        {
            // Close device handle first
            _deviceHandle?.Close();
            _deviceHandle = null;

            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;

            try
            {
                scManager = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_CONNECT);
                if (scManager == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    SetError($"Failed to open Service Control Manager: {new Win32Exception(error).Message}", error);
                    return false;
                }

                service = NativeMethods.OpenService(scManager, ServiceName,
                    NativeMethods.SERVICE_STOP | NativeMethods.DELETE | NativeMethods.SERVICE_QUERY_STATUS);

                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == (int)NativeMethods.ERROR_FILE_NOT_FOUND)
                    {
                        // Service doesn't exist, consider it unloaded
                        return true;
                    }
                    SetError($"Failed to open driver service: {new Win32Exception(error).Message}", error);
                    return false;
                }

                // Stop the service
                var status = new NativeMethods.SERVICE_STATUS();
                if (!NativeMethods.ControlService(service, NativeMethods.SERVICE_CONTROL_STOP, ref status))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != (int)NativeMethods.ERROR_SERVICE_NOT_ACTIVE)
                    {
                        SetError($"Failed to stop driver service: {new Win32Exception(error).Message}", error);
                        return false;
                    }
                }

                // Delete the service
                if (!NativeMethods.DeleteService(service))
                {
                    int error = Marshal.GetLastWin32Error();
                    SetError($"Failed to delete driver service: {new Win32Exception(error).Message}", error);
                    return false;
                }

                return true;
            }
            finally
            {
                if (service != IntPtr.Zero)
                    NativeMethods.CloseServiceHandle(service);
                if (scManager != IntPtr.Zero)
                    NativeMethods.CloseServiceHandle(scManager);
            }
        }
    }

    #endregion

    #region IOCTL Methods

    /// <summary>
    /// Gets the list of all processes from the kernel driver.
    /// This enumeration is performed in kernel mode and cannot be hidden by user-mode rootkits.
    /// </summary>
    /// <returns>A list of process information, or an empty list on failure.</returns>
    public List<KernelProcessInfo> GetProcessList()
    {
        var processes = new List<KernelProcessInfo>();

        if (!EnsureConnected())
        {
            return processes;
        }

        var data = SendIoctl(IoctlCodes.IOCTL_R77_ENUM_PROCESSES);
        if (data == null || data.Length == 0)
        {
            return processes;
        }

        // Parse the response using R77ResponseHeader
        int headerSize = Marshal.SizeOf<R77ResponseHeader>();
        if (data.Length < headerSize)
        {
            SetError("Invalid response: too small for header", 0);
            return processes;
        }

        var header = BytesToStruct<R77ResponseHeader>(data, 0);
        if (header.Status != 0)
        {
            SetError($"Driver returned error status: 0x{header.Status:X8}", header.Status);
            return processes;
        }

        // Use EntrySize from header if provided, otherwise calculate
        int structSize = header.EntrySize > 0 ? (int)header.EntrySize : Marshal.SizeOf<KernelProcessInfoNative>();
        int offset = headerSize;

        for (uint i = 0; i < header.EntryCount && offset + structSize <= data.Length; i++)
        {
            var native = BytesToStruct<KernelProcessInfoNative>(data, offset);
            processes.Add(KernelProcessInfo.FromNative(native));
            offset += structSize;
        }

        return processes;
    }

    /// <summary>
    /// Gets the list of all loaded kernel drivers from the kernel driver.
    /// </summary>
    /// <returns>A list of driver information, or an empty list on failure.</returns>
    public List<KernelDriverInfo> GetDriverList()
    {
        var drivers = new List<KernelDriverInfo>();

        if (!EnsureConnected())
        {
            return drivers;
        }

        var data = SendIoctl(IoctlCodes.IOCTL_R77_ENUM_DRIVERS);
        if (data == null || data.Length == 0)
        {
            return drivers;
        }

        // Parse the response using R77ResponseHeader
        int headerSize = Marshal.SizeOf<R77ResponseHeader>();
        if (data.Length < headerSize)
        {
            SetError("Invalid response: too small for header", 0);
            return drivers;
        }

        var header = BytesToStruct<R77ResponseHeader>(data, 0);
        if (header.Status != 0)
        {
            SetError($"Driver returned error status: 0x{header.Status:X8}", header.Status);
            return drivers;
        }

        int structSize = header.EntrySize > 0 ? (int)header.EntrySize : Marshal.SizeOf<KernelDriverInfoNative>();
        int offset = headerSize;

        for (uint i = 0; i < header.EntryCount && offset + structSize <= data.Length; i++)
        {
            var native = BytesToStruct<KernelDriverInfoNative>(data, offset);
            drivers.Add(KernelDriverInfo.FromNative(native));
            offset += structSize;
        }

        return drivers;
    }

    /// <summary>
    /// Checks the SSDT (System Service Descriptor Table) for hooks.
    /// </summary>
    /// <returns>A list of SSDT entries with hook information, or an empty list on failure.</returns>
    public List<SsdtHookInfo> GetSsdtHooks()
    {
        var hooks = new List<SsdtHookInfo>();

        if (!EnsureConnected())
        {
            return hooks;
        }

        var data = SendIoctl(IoctlCodes.IOCTL_R77_CHECK_SSDT_HOOKS);
        if (data == null || data.Length == 0)
        {
            return hooks;
        }

        // Parse the response using R77ResponseHeader
        int headerSize = Marshal.SizeOf<R77ResponseHeader>();
        if (data.Length < headerSize)
        {
            SetError("Invalid response: too small for header", 0);
            return hooks;
        }

        var header = BytesToStruct<R77ResponseHeader>(data, 0);
        if (header.Status != 0)
        {
            SetError($"Driver returned error status: 0x{header.Status:X8}", header.Status);
            return hooks;
        }

        int structSize = header.EntrySize > 0 ? (int)header.EntrySize : Marshal.SizeOf<SsdtHookInfoNative>();
        int offset = headerSize;

        for (uint i = 0; i < header.EntryCount && offset + structSize <= data.Length; i++)
        {
            var native = BytesToStruct<SsdtHookInfoNative>(data, offset);
            hooks.Add(SsdtHookInfo.FromNative(native));
            offset += structSize;
        }

        return hooks;
    }

    /// <summary>
    /// Gets the list of registered kernel callbacks (all types).
    /// </summary>
    /// <returns>A list of callback information, or an empty list on failure.</returns>
    public List<CallbackInfo> GetCallbacks()
    {
        var allCallbacks = new List<CallbackInfo>();

        // Collect callbacks from all callback types
        allCallbacks.AddRange(GetCallbacksByType(IoctlCodes.IOCTL_R77_ENUM_PROCESS_CALLBACKS));
        allCallbacks.AddRange(GetCallbacksByType(IoctlCodes.IOCTL_R77_ENUM_THREAD_CALLBACKS));
        allCallbacks.AddRange(GetCallbacksByType(IoctlCodes.IOCTL_R77_ENUM_IMAGE_CALLBACKS));
        allCallbacks.AddRange(GetCallbacksByType(IoctlCodes.IOCTL_R77_ENUM_REGISTRY_CALLBACKS));

        return allCallbacks;
    }

    /// <summary>
    /// Gets the list of process creation callbacks.
    /// </summary>
    public List<CallbackInfo> GetProcessCallbacks()
    {
        return GetCallbacksByType(IoctlCodes.IOCTL_R77_ENUM_PROCESS_CALLBACKS);
    }

    /// <summary>
    /// Gets the list of thread creation callbacks.
    /// </summary>
    public List<CallbackInfo> GetThreadCallbacks()
    {
        return GetCallbacksByType(IoctlCodes.IOCTL_R77_ENUM_THREAD_CALLBACKS);
    }

    /// <summary>
    /// Gets the list of image load callbacks.
    /// </summary>
    public List<CallbackInfo> GetImageLoadCallbacks()
    {
        return GetCallbacksByType(IoctlCodes.IOCTL_R77_ENUM_IMAGE_CALLBACKS);
    }

    /// <summary>
    /// Gets the list of registry callbacks.
    /// </summary>
    public List<CallbackInfo> GetRegistryCallbacks()
    {
        return GetCallbacksByType(IoctlCodes.IOCTL_R77_ENUM_REGISTRY_CALLBACKS);
    }

    /// <summary>
    /// Internal method to get callbacks by IOCTL code.
    /// </summary>
    private List<CallbackInfo> GetCallbacksByType(uint ioctlCode)
    {
        var callbacks = new List<CallbackInfo>();

        if (!EnsureConnected())
        {
            return callbacks;
        }

        var data = SendIoctl(ioctlCode);
        if (data == null || data.Length == 0)
        {
            return callbacks;
        }

        // Parse the response using R77ResponseHeader
        int headerSize = Marshal.SizeOf<R77ResponseHeader>();
        if (data.Length < headerSize)
        {
            SetError("Invalid response: too small for header", 0);
            return callbacks;
        }

        var header = BytesToStruct<R77ResponseHeader>(data, 0);
        if (header.Status != 0)
        {
            SetError($"Driver returned error status: 0x{header.Status:X8}", header.Status);
            return callbacks;
        }

        int structSize = header.EntrySize > 0 ? (int)header.EntrySize : Marshal.SizeOf<CallbackInfoNative>();
        int offset = headerSize;

        for (uint i = 0; i < header.EntryCount && offset + structSize <= data.Length; i++)
        {
            var native = BytesToStruct<CallbackInfoNative>(data, offset);
            callbacks.Add(CallbackInfo.FromNative(native));
            offset += structSize;
        }

        return callbacks;
    }

    /// <summary>
    /// Gets the driver version information.
    /// </summary>
    /// <returns>Version info or null on failure.</returns>
    public R77VersionInfo? GetVersion()
    {
        if (!EnsureConnected())
        {
            return null;
        }

        var data = SendIoctl(IoctlCodes.IOCTL_R77_GET_VERSION);
        if (data == null || data.Length < Marshal.SizeOf<R77VersionInfo>())
        {
            return null;
        }

        return BytesToStruct<R77VersionInfo>(data, 0);
    }

    /// <summary>
    /// Finds processes that are hidden using DKOM or other techniques.
    /// </summary>
    /// <param name="methods">Detection methods to use.</param>
    /// <returns>List of hidden processes with detection details.</returns>
    public List<HiddenProcessInfo> GetHiddenProcesses(HiddenProcessDetectionMethod methods = HiddenProcessDetectionMethod.All)
    {
        var hiddenProcesses = new List<HiddenProcessInfo>();

        if (!EnsureConnected())
        {
            return hiddenProcesses;
        }

        // Build request
        var request = new HiddenProcessRequest
        {
            Header = new R77RequestHeader
            {
                Version = 1,
                StartIndex = 0,
                MaxEntries = 1000,
                Flags = 0
            },
            DetectionMethod = methods
        };

        var requestBytes = StructToBytes(request);
        var data = SendIoctl(IoctlCodes.IOCTL_R77_ENUM_HIDDEN_PROCESSES, requestBytes);

        if (data == null || data.Length == 0)
        {
            return hiddenProcesses;
        }

        // Parse the response using R77ResponseHeader
        int headerSize = Marshal.SizeOf<R77ResponseHeader>();
        if (data.Length < headerSize)
        {
            SetError("Invalid response: too small for header", 0);
            return hiddenProcesses;
        }

        var header = BytesToStruct<R77ResponseHeader>(data, 0);
        if (header.Status != 0)
        {
            SetError($"Driver returned error status: 0x{header.Status:X8}", header.Status);
            return hiddenProcesses;
        }

        // For hidden processes, we expect KernelProcessInfoNative plus detection info
        // This is a simplified implementation; the actual structure depends on kernel driver
        int structSize = header.EntrySize > 0 ? (int)header.EntrySize : Marshal.SizeOf<KernelProcessInfoNative>();
        int offset = headerSize;

        for (uint i = 0; i < header.EntryCount && offset + structSize <= data.Length; i++)
        {
            var native = BytesToStruct<KernelProcessInfoNative>(data, offset);
            var hiddenInfo = new HiddenProcessInfo
            {
                Process = KernelProcessInfo.FromNative(native),
                DetectionMethod = methods,
                Confidence = 100 // Set by driver in actual implementation
            };
            hiddenProcesses.Add(hiddenInfo);
            offset += structSize;
        }

        return hiddenProcesses;
    }

    /// <summary>
    /// Verifies the integrity of a driver by comparing memory to disk.
    /// </summary>
    /// <param name="driverName">Name of the driver to verify.</param>
    /// <returns>True if integrity check passed, false otherwise.</returns>
    public bool VerifyDriverIntegrity(string driverName)
    {
        if (!EnsureConnected())
        {
            return false;
        }

        // Convert driver name to bytes for IOCTL
        var nameBytes = System.Text.Encoding.Unicode.GetBytes(driverName + "\0");
        var data = SendIoctl(IoctlCodes.IOCTL_R77_VERIFY_DRIVER_INTEGRITY, nameBytes);

        if (data == null || data.Length < Marshal.SizeOf<R77ResponseHeader>())
        {
            return false;
        }

        var header = BytesToStruct<R77ResponseHeader>(data, 0);
        return header.Status == 0;
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Ensures a connection to the driver is established.
    /// </summary>
    private bool EnsureConnected()
    {
        if (IsConnected)
        {
            return true;
        }

        return TryConnect();
    }

    /// <summary>
    /// Sends an IOCTL to the driver and returns the response data.
    /// </summary>
    private byte[]? SendIoctl(uint ioctlCode, byte[]? inputData = null)
    {
        if (_deviceHandle == null || _deviceHandle.IsInvalid)
        {
            SetError("Not connected to driver", 0);
            return null;
        }

        int bufferSize = DefaultBufferSize;
        IntPtr outputBuffer = IntPtr.Zero;

        try
        {
            while (bufferSize <= MaxBufferSize)
            {
                outputBuffer = Marshal.AllocHGlobal(bufferSize);

                bool success = NativeMethods.DeviceIoControl(
                    _deviceHandle,
                    ioctlCode,
                    inputData,
                    inputData != null ? (uint)inputData.Length : 0,
                    outputBuffer,
                    (uint)bufferSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (success)
                {
                    if (bytesReturned > 0)
                    {
                        var result = new byte[bytesReturned];
                        Marshal.Copy(outputBuffer, result, 0, (int)bytesReturned);
                        return result;
                    }
                    return Array.Empty<byte>();
                }

                int error = Marshal.GetLastWin32Error();

                // If buffer too small, try larger
                if (error == (int)NativeMethods.ERROR_INSUFFICIENT_BUFFER)
                {
                    Marshal.FreeHGlobal(outputBuffer);
                    outputBuffer = IntPtr.Zero;
                    bufferSize *= 2;
                    continue;
                }

                SetError($"DeviceIoControl failed: {new Win32Exception(error).Message}", error);
                return null;
            }

            SetError("Buffer size exceeded maximum", 0);
            return null;
        }
        finally
        {
            if (outputBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(outputBuffer);
            }
        }
    }

    /// <summary>
    /// Converts a byte array to a structure at the specified offset.
    /// </summary>
    private static T BytesToStruct<T>(byte[] data, int offset) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        IntPtr ptr = Marshal.AllocHGlobal(size);

        try
        {
            Marshal.Copy(data, offset, ptr, size);
            return Marshal.PtrToStructure<T>(ptr);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Converts a structure to a byte array.
    /// </summary>
    private static byte[] StructToBytes<T>(T structure) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        byte[] bytes = new byte[size];
        IntPtr ptr = Marshal.AllocHGlobal(size);

        try
        {
            Marshal.StructureToPtr(structure, ptr, false);
            Marshal.Copy(ptr, bytes, 0, size);
            return bytes;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Sets the last error information.
    /// </summary>
    private void SetError(string message, int errorCode)
    {
        LastError = message;
        LastErrorCode = errorCode;
    }

    #endregion

    #region IDisposable

    /// <summary>
    /// Releases the driver handle.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the driver handle.
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _deviceHandle?.Dispose();
                _deviceHandle = null;
            }

            _disposed = true;
        }
    }

    /// <summary>
    /// Finalizer.
    /// </summary>
    ~KernelBridge()
    {
        Dispose(false);
    }

    #endregion
}

/// <summary>
/// Exception thrown when a kernel bridge operation fails.
/// </summary>
public class KernelBridgeException : Exception
{
    /// <summary>
    /// The Win32 error code associated with the failure.
    /// </summary>
    public int ErrorCode { get; }

    public KernelBridgeException(string message) : base(message)
    {
    }

    public KernelBridgeException(string message, int errorCode) : base(message)
    {
        ErrorCode = errorCode;
    }

    public KernelBridgeException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
