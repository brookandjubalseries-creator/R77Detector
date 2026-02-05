using System.Diagnostics;
using System.Runtime.InteropServices;
using DeepScan.Core;

namespace DeepScan.Modules;

/// <summary>
/// Kernel Trust Module - Uses the R77Detector kernel driver for trusted system enumeration.
/// Compares kernel-mode enumeration results with user-mode APIs to detect rootkit hiding.
/// Falls back gracefully to user-mode detection if the driver is not available.
/// </summary>
public class KernelTrustModule : IDetectionModule
{
    public string Name => "Kernel Trust Verification";
    public string Description => "Uses kernel driver for trusted enumeration and compares against user-mode APIs to detect hiding";
    public RingLevel TargetRing => RingLevel.Ring0_Kernel;
    public bool IsSupported => Environment.OSVersion.Platform == PlatformID.Win32NT;

    private readonly List<Detection> _detections = new();
    private bool _driverLoaded = false;
    private IntPtr _driverHandle = IntPtr.Zero;

    // Driver communication constants
    private const string DeviceName = @"\\.\R77Detector";
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    // IOCTL codes matching R77Driver.h (actual kernel driver implementation)
    // Device type: FILE_DEVICE_UNKNOWN (0x22)
    // Access: FILE_READ_ACCESS (1)
    // Method: METHOD_BUFFERED (0)
    // Base function code: 0x800
    private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
    private const uint METHOD_BUFFERED = 0;
    private const uint FILE_READ_ACCESS = 1;
    private const uint R77_IOCTL_BASE = 0x800;

    private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
        => ((deviceType << 16) | (access << 14) | (function << 2) | method);

    // IOCTL codes per R77Driver.h
    private static readonly uint IOCTL_R77_ENUM_PROCESSES = CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS);
    private static readonly uint IOCTL_R77_ENUM_DRIVERS = CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_READ_ACCESS);
    private static readonly uint IOCTL_R77_CHECK_SSDT_HOOKS = CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_READ_ACCESS);
    private static readonly uint IOCTL_R77_ENUM_CALLBACKS = CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_READ_ACCESS);
    private static readonly uint IOCTL_R77_GET_HIDDEN_PROCESSES = CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_READ_ACCESS);
    private static readonly uint IOCTL_R77_GET_VERSION = CTL_CODE(FILE_DEVICE_UNKNOWN, R77_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_READ_ACCESS);

    // Maximum sizes
    private const int MAX_PROCESSES = 4096;
    private const int MAX_DRIVERS = 1024;
    private const int MAX_CALLBACKS = 256;
    private const int MAX_PROCESS_NAME = 260;
    private const int MAX_DRIVER_NAME = 260;

    #region Native Structures (matching R77Driver.h)

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct R77_PROCESS_INFO
    {
        public uint ProcessId;
        public uint ParentProcessId;
        public UIntPtr EprocessAddress;
        [MarshalAs(UnmanagedType.U1)]
        public bool IsHidden;
        [MarshalAs(UnmanagedType.U1)]
        public bool IsTerminated;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string ImageFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PROCESS_NAME)]
        public string FullPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct R77_DRIVER_INFO
    {
        public UIntPtr ImageBase;
        public uint ImageSize;
        public UIntPtr DriverObject;
        public UIntPtr EntryPoint;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_DRIVER_NAME)]
        public string DriverName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_DRIVER_NAME)]
        public string DriverPath;
        [MarshalAs(UnmanagedType.U1)]
        public bool IsHidden;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct R77_SSDT_HOOK_INFO
    {
        public uint SyscallIndex;
        public UIntPtr CurrentAddress;
        public UIntPtr OriginalAddress;
        [MarshalAs(UnmanagedType.U1)]
        public bool IsHooked;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_DRIVER_NAME)]
        public string HookModuleName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string FunctionName;
    }

    private enum R77_CALLBACK_TYPE
    {
        ProcessNotify = 0,
        ThreadNotify,
        ImageLoadNotify,
        RegistryNotify,
        ObjectNotify,
        CmCallback,
        Max
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct R77_CALLBACK_INFO
    {
        public R77_CALLBACK_TYPE Type;
        public UIntPtr CallbackAddress;
        public UIntPtr OwnerModuleBase;
        public uint OwnerModuleSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_DRIVER_NAME)]
        public string OwnerModuleName;
        [MarshalAs(UnmanagedType.U1)]
        public bool IsSuspicious;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct R77_VERSION_INFO
    {
        public uint VersionMajor;
        public uint VersionMinor;
        public uint VersionBuild;
        public uint OsMajorVersion;
        public uint OsMinorVersion;
        public uint OsBuildNumber;
        [MarshalAs(UnmanagedType.U1)]
        public bool Is64Bit;
    }

    #endregion

    #region Native Methods

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    #endregion

    public async Task<IEnumerable<Detection>> ScanAsync(IProgress<string>? progress = null)
    {
        _detections.Clear();

        progress?.Report("Attempting to connect to R77Detector kernel driver...");
        _driverLoaded = await Task.Run(TryLoadDriver);

        if (_driverLoaded)
        {
            progress?.Report("Kernel driver connected - performing trusted enumeration...");

            progress?.Report("Comparing kernel vs user-mode process lists...");
            await Task.Run(CompareProcessLists);

            progress?.Report("Checking for SSDT hooks...");
            await Task.Run(CheckSsdtHooks);

            progress?.Report("Enumerating kernel callbacks...");
            await Task.Run(EnumerateCallbacks);

            progress?.Report("Checking for hidden drivers...");
            await Task.Run(CheckHiddenDrivers);

            // Cleanup
            if (_driverHandle != IntPtr.Zero && _driverHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(_driverHandle);
                _driverHandle = IntPtr.Zero;
            }
        }
        else
        {
            progress?.Report("Kernel driver not available - using fallback detection...");
            _detections.Add(new Detection
            {
                Module = Name,
                Category = "Driver Status",
                Severity = Severity.Info,
                Description = "R77Detector kernel driver is not loaded - using user-mode detection only",
                Ring = TargetRing,
                TechnicalDetails = "For trusted enumeration, install and load the R77Detector driver",
                Remediation = "Run R77DetectorDriver installation to enable kernel-level detection"
            });

            // Perform fallback user-mode detection
            progress?.Report("Performing user-mode process cross-referencing...");
            await Task.Run(FallbackProcessCheck);
        }

        return _detections;
    }

    private bool TryLoadDriver()
    {
        try
        {
            _driverHandle = CreateFile(
                DeviceName,
                GENERIC_READ | GENERIC_WRITE,
                0,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);

            if (_driverHandle == INVALID_HANDLE_VALUE)
            {
                _driverHandle = IntPtr.Zero;
                return false;
            }

            // Verify driver version
            var versionInfo = new R77_VERSION_INFO();
            int versionSize = Marshal.SizeOf<R77_VERSION_INFO>();
            IntPtr versionBuffer = Marshal.AllocHGlobal(versionSize);

            try
            {
                if (DeviceIoControl(_driverHandle, IOCTL_R77_GET_VERSION, IntPtr.Zero, 0,
                    versionBuffer, (uint)versionSize, out _, IntPtr.Zero))
                {
                    versionInfo = Marshal.PtrToStructure<R77_VERSION_INFO>(versionBuffer);
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Driver Status",
                        Severity = Severity.Info,
                        Description = $"R77Detector driver v{versionInfo.VersionMajor}.{versionInfo.VersionMinor}.{versionInfo.VersionBuild} connected",
                        Ring = TargetRing,
                        TechnicalDetails = $"OS: {versionInfo.OsMajorVersion}.{versionInfo.OsMinorVersion} Build {versionInfo.OsBuildNumber}, 64-bit: {versionInfo.Is64Bit}"
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(versionBuffer);
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private void CompareProcessLists()
    {
        if (_driverHandle == IntPtr.Zero) return;

        try
        {
            // Get user-mode process list first
            var userModeProcesses = Process.GetProcesses()
                .Select(p => (p.Id, p.ProcessName))
                .ToHashSet();

            // Get kernel-enumerated processes
            int bufferSize = Marshal.SizeOf<R77_PROCESS_INFO>() * MAX_PROCESSES + 8; // +8 for Count and HiddenCount
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                if (DeviceIoControl(_driverHandle, IOCTL_R77_ENUM_PROCESSES, IntPtr.Zero, 0,
                    buffer, (uint)bufferSize, out uint bytesReturned, IntPtr.Zero) && bytesReturned > 8)
                {
                    uint count = (uint)Marshal.ReadInt32(buffer);
                    uint hiddenCount = (uint)Marshal.ReadInt32(buffer, 4);

                    var kernelProcesses = new List<(uint pid, string name, bool hidden)>();

                    int structSize = Marshal.SizeOf<R77_PROCESS_INFO>();
                    IntPtr current = buffer + 8;

                    for (int i = 0; i < count && i < MAX_PROCESSES; i++)
                    {
                        var procInfo = Marshal.PtrToStructure<R77_PROCESS_INFO>(current);
                        kernelProcesses.Add((procInfo.ProcessId, procInfo.ImageFileName ?? "Unknown", procInfo.IsHidden));
                        current += structSize;
                    }

                    // Check for hidden processes (visible to kernel but not user-mode)
                    foreach (var kproc in kernelProcesses.Where(p => p.hidden || !userModeProcesses.Any(u => u.Id == p.pid)))
                    {
                        if (kproc.pid > 4) // Skip System and Idle
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Hidden Process",
                                Severity = Severity.Critical,
                                Description = $"Process hidden from user-mode APIs: {kproc.name} (PID: {kproc.pid})",
                                Ring = TargetRing,
                                TechnicalDetails = "Process visible via kernel driver but hidden from standard enumeration APIs",
                                Remediation = "This process is using rootkit techniques to hide. Investigate immediately."
                            });
                        }
                    }

                    if (hiddenCount > 0)
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "DKOM Detection",
                            Severity = Severity.Critical,
                            Description = $"Kernel detected {hiddenCount} process(es) using DKOM hiding techniques",
                            Ring = TargetRing,
                            TechnicalDetails = "Direct Kernel Object Manipulation detected - processes unlinked from active process list",
                            Remediation = "Active rootkit detected. Boot from clean media for investigation."
                        });
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            _detections.Add(new Detection
            {
                Module = Name,
                Category = "Error",
                Severity = Severity.Low,
                Description = $"Process comparison failed: {ex.Message}",
                Ring = TargetRing
            });
        }
    }

    private void CheckSsdtHooks()
    {
        if (_driverHandle == IntPtr.Zero) return;

        try
        {
            int bufferSize = Marshal.SizeOf<R77_SSDT_HOOK_INFO>() * 512 + 16; // Header + entries
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                if (DeviceIoControl(_driverHandle, IOCTL_R77_CHECK_SSDT_HOOKS, IntPtr.Zero, 0,
                    buffer, (uint)bufferSize, out uint bytesReturned, IntPtr.Zero) && bytesReturned > 16)
                {
                    uint totalEntries = (uint)Marshal.ReadInt32(buffer);
                    uint hookedCount = (uint)Marshal.ReadInt32(buffer, 4);
                    ulong ssdtBase = (ulong)Marshal.ReadInt64(buffer, 8);

                    if (hookedCount > 0)
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "SSDT Hooks",
                            Severity = Severity.Critical,
                            Description = $"Detected {hookedCount} SSDT hook(s) - kernel syscalls are being intercepted",
                            Ring = TargetRing,
                            TechnicalDetails = $"SSDT Base: 0x{ssdtBase:X16}, Total entries: {totalEntries}",
                            Remediation = "SSDT hooks indicate kernel-mode rootkit activity. Professional remediation required."
                        });

                        // Parse individual hooks
                        int structSize = Marshal.SizeOf<R77_SSDT_HOOK_INFO>();
                        IntPtr current = buffer + 16;

                        for (int i = 0; i < hookedCount && i < 50; i++) // Limit to 50 for reporting
                        {
                            var hookInfo = Marshal.PtrToStructure<R77_SSDT_HOOK_INFO>(current);
                            if (hookInfo.IsHooked)
                            {
                                _detections.Add(new Detection
                                {
                                    Module = Name,
                                    Category = "SSDT Hook Detail",
                                    Severity = Severity.High,
                                    Description = $"Syscall {hookInfo.FunctionName} (#{hookInfo.SyscallIndex}) hooked by {hookInfo.HookModuleName}",
                                    Ring = TargetRing,
                                    TechnicalDetails = $"Original: 0x{hookInfo.OriginalAddress:X}, Current: 0x{hookInfo.CurrentAddress:X}"
                                });
                            }
                            current += structSize;
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            _detections.Add(new Detection
            {
                Module = Name,
                Category = "Error",
                Severity = Severity.Low,
                Description = $"SSDT hook detection failed: {ex.Message}",
                Ring = TargetRing
            });
        }
    }

    private void EnumerateCallbacks()
    {
        if (_driverHandle == IntPtr.Zero) return;

        try
        {
            int bufferSize = Marshal.SizeOf<R77_CALLBACK_INFO>() * MAX_CALLBACKS + 8;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                if (DeviceIoControl(_driverHandle, IOCTL_R77_ENUM_CALLBACKS, IntPtr.Zero, 0,
                    buffer, (uint)bufferSize, out uint bytesReturned, IntPtr.Zero) && bytesReturned > 8)
                {
                    uint totalCount = (uint)Marshal.ReadInt32(buffer);
                    uint suspiciousCount = (uint)Marshal.ReadInt32(buffer, 4);

                    if (suspiciousCount > 0)
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Suspicious Callbacks",
                            Severity = Severity.High,
                            Description = $"Detected {suspiciousCount} suspicious kernel callback(s) out of {totalCount} total",
                            Ring = TargetRing,
                            TechnicalDetails = "Callbacks registered from outside known module memory ranges",
                            Remediation = "Suspicious callbacks may indicate rootkit notification routines."
                        });

                        // Parse individual callbacks
                        int structSize = Marshal.SizeOf<R77_CALLBACK_INFO>();
                        IntPtr current = buffer + 8;

                        for (int i = 0; i < totalCount && i < MAX_CALLBACKS; i++)
                        {
                            var cbInfo = Marshal.PtrToStructure<R77_CALLBACK_INFO>(current);
                            if (cbInfo.IsSuspicious)
                            {
                                string callbackType = cbInfo.Type switch
                                {
                                    R77_CALLBACK_TYPE.ProcessNotify => "Process Creation Notify",
                                    R77_CALLBACK_TYPE.ThreadNotify => "Thread Creation Notify",
                                    R77_CALLBACK_TYPE.ImageLoadNotify => "Image Load Notify",
                                    R77_CALLBACK_TYPE.RegistryNotify => "Registry Notify",
                                    R77_CALLBACK_TYPE.ObjectNotify => "Object Notify",
                                    R77_CALLBACK_TYPE.CmCallback => "Configuration Manager Callback",
                                    _ => "Unknown"
                                };

                                _detections.Add(new Detection
                                {
                                    Module = Name,
                                    Category = "Suspicious Callback Detail",
                                    Severity = Severity.High,
                                    Description = $"Suspicious {callbackType} callback from {cbInfo.OwnerModuleName}",
                                    Ring = TargetRing,
                                    TechnicalDetails = $"Address: 0x{cbInfo.CallbackAddress:X}, Module base: 0x{cbInfo.OwnerModuleBase:X}"
                                });
                            }
                            current += structSize;
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            _detections.Add(new Detection
            {
                Module = Name,
                Category = "Error",
                Severity = Severity.Low,
                Description = $"Callback enumeration failed: {ex.Message}",
                Ring = TargetRing
            });
        }
    }

    private void CheckHiddenDrivers()
    {
        if (_driverHandle == IntPtr.Zero) return;

        try
        {
            int bufferSize = Marshal.SizeOf<R77_DRIVER_INFO>() * MAX_DRIVERS + 8;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                if (DeviceIoControl(_driverHandle, IOCTL_R77_ENUM_DRIVERS, IntPtr.Zero, 0,
                    buffer, (uint)bufferSize, out uint bytesReturned, IntPtr.Zero) && bytesReturned > 8)
                {
                    uint count = (uint)Marshal.ReadInt32(buffer);
                    uint hiddenCount = (uint)Marshal.ReadInt32(buffer, 4);

                    if (hiddenCount > 0)
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Hidden Drivers",
                            Severity = Severity.Critical,
                            Description = $"Detected {hiddenCount} hidden kernel driver(s)",
                            Ring = TargetRing,
                            TechnicalDetails = "Drivers hidden from PsLoadedModuleList - indicates active rootkit",
                            Remediation = "Hidden drivers are a strong rootkit indicator. Professional investigation required."
                        });

                        // Parse individual drivers
                        int structSize = Marshal.SizeOf<R77_DRIVER_INFO>();
                        IntPtr current = buffer + 8;

                        for (int i = 0; i < count && i < MAX_DRIVERS; i++)
                        {
                            var drvInfo = Marshal.PtrToStructure<R77_DRIVER_INFO>(current);
                            if (drvInfo.IsHidden)
                            {
                                _detections.Add(new Detection
                                {
                                    Module = Name,
                                    Category = "Hidden Driver Detail",
                                    Severity = Severity.Critical,
                                    Description = $"Hidden driver: {drvInfo.DriverName}",
                                    Ring = TargetRing,
                                    TechnicalDetails = $"Base: 0x{drvInfo.ImageBase:X}, Size: 0x{drvInfo.ImageSize:X}, Path: {drvInfo.DriverPath}"
                                });
                            }
                            current += structSize;
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            _detections.Add(new Detection
            {
                Module = Name,
                Category = "Error",
                Severity = Severity.Low,
                Description = $"Driver enumeration failed: {ex.Message}",
                Ring = TargetRing
            });
        }
    }

    /// <summary>
    /// Fallback detection when kernel driver is not available.
    /// Uses multiple user-mode enumeration methods to cross-reference.
    /// </summary>
    private void FallbackProcessCheck()
    {
        try
        {
            // Method 1: Process.GetProcesses() - uses NtQuerySystemInformation
            var apiProcesses = Process.GetProcesses().Select(p => p.Id).ToHashSet();

            // Method 2: WMI enumeration
            var wmiProcesses = new HashSet<int>();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "wmic",
                    Arguments = "process get processid",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    foreach (var line in output.Split('\n'))
                    {
                        if (int.TryParse(line.Trim(), out int pid))
                            wmiProcesses.Add(pid);
                    }
                }
            }
            catch { }

            // Method 3: tasklist
            var tasklistProcesses = new HashSet<int>();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "tasklist",
                    Arguments = "/FO CSV /NH",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    foreach (var line in output.Split('\n'))
                    {
                        var parts = line.Split(',');
                        if (parts.Length >= 2)
                        {
                            var pidStr = parts[1].Trim('"', ' ');
                            if (int.TryParse(pidStr, out int pid))
                                tasklistProcesses.Add(pid);
                        }
                    }
                }
            }
            catch { }

            // Compare results
            var allMethods = new[] { apiProcesses, wmiProcesses, tasklistProcesses };
            var validMethods = allMethods.Where(m => m.Count > 0).ToList();

            if (validMethods.Count >= 2)
            {
                var maxCount = validMethods.Max(m => m.Count);
                var minCount = validMethods.Min(m => m.Count);

                if (maxCount - minCount > 5)
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Process Count Discrepancy",
                        Severity = Severity.High,
                        Description = "Significant discrepancy in process counts between enumeration methods",
                        Ring = TargetRing,
                        TechnicalDetails = $"API: {apiProcesses.Count}, WMI: {wmiProcesses.Count}, TaskList: {tasklistProcesses.Count}",
                        Remediation = "This may indicate process hiding. Install kernel driver for definitive detection."
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _detections.Add(new Detection
            {
                Module = Name,
                Category = "Error",
                Severity = Severity.Info,
                Description = $"Fallback detection error: {ex.Message}",
                Ring = TargetRing
            });
        }
    }
}
