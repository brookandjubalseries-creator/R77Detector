using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DeepScan.Core;
using Microsoft.Win32;

namespace DeepScan.Modules;

/// <summary>
/// Ring 0 (Kernel-mode) rootkit detection module
/// Detects: Unsigned drivers, kernel debugger, suspicious drivers, DKOM indicators
/// </summary>
public class Ring0Module : IDetectionModule
{
    public string Name => "Ring 0 - Kernel Mode";
    public string Description => "Detects kernel-mode rootkits via driver analysis, kernel integrity, and DKOM detection";
    public RingLevel TargetRing => RingLevel.Ring0_Kernel;
    public bool IsSupported => Environment.OSVersion.Platform == PlatformID.Win32NT;

    private readonly List<Detection> _detections = new();

    // Known suspicious driver names (partial list)
    private static readonly HashSet<string> SuspiciousDriverNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "win32k.sys.bak", "ntfs.sys.bak", "tdl", "siredef", "zeroaccess",
        "necurs", "alureon", "sirefef", "pihar", "maxss", "gmer",
        "amsdk", "rkreveal", "rkdetect"
    };

    // Known rootkit driver signatures (simplified)
    private static readonly HashSet<string> RootkitSignatures = new(StringComparer.OrdinalIgnoreCase)
    {
        "TDL", "ZeroAccess", "Necurs", "Alureon", "Sirefef", "MaxSS"
    };

    public async Task<IEnumerable<Detection>> ScanAsync(IProgress<string>? progress = null)
    {
        _detections.Clear();

        progress?.Report("Enumerating loaded kernel drivers...");
        await Task.Run(CheckLoadedDrivers);

        progress?.Report("Checking for kernel debugger...");
        await Task.Run(CheckKernelDebugger);

        progress?.Report("Verifying Code Integrity status...");
        await Task.Run(CheckCodeIntegrity);

        progress?.Report("Analyzing driver signatures...");
        await Task.Run(CheckDriverSignatures);

        progress?.Report("Checking for DKOM indicators...");
        await Task.Run(CheckDKOM);

        progress?.Report("Scanning driver registry entries...");
        await Task.Run(CheckDriverRegistry);

        progress?.Report("Checking for DSE bypass indicators...");
        await Task.Run(CheckDSEBypass);

        return _detections;
    }

    private void CheckLoadedDrivers()
    {
        try
        {
            // Get list of loaded drivers
            uint needed = 0;
            NativeMethods.EnumDeviceDrivers(null!, 0, out needed);

            int driverCount = (int)(needed / IntPtr.Size);
            var drivers = new IntPtr[driverCount];

            if (NativeMethods.EnumDeviceDrivers(drivers, needed, out _))
            {
                var driverInfos = new List<(IntPtr baseAddr, string name, string path)>();

                foreach (var driver in drivers)
                {
                    if (driver == IntPtr.Zero) continue;

                    var nameBuilder = new StringBuilder(1024);
                    var pathBuilder = new StringBuilder(1024);

                    NativeMethods.GetDeviceDriverBaseName(driver, nameBuilder, 1024);
                    NativeMethods.GetDeviceDriverFileName(driver, pathBuilder, 1024);

                    var name = nameBuilder.ToString();
                    var path = pathBuilder.ToString();

                    if (string.IsNullOrEmpty(name)) continue;

                    driverInfos.Add((driver, name, path));

                    // Check against known suspicious names
                    foreach (var suspicious in SuspiciousDriverNames)
                    {
                        if (name.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Suspicious Driver",
                                Severity = Severity.Critical,
                                Description = $"Known suspicious driver loaded: {name}",
                                Ring = TargetRing,
                                TechnicalDetails = $"Base address: 0x{driver:X}\nPath: {path}",
                                Remediation = "This driver is associated with known rootkits. Boot into Safe Mode and remove it."
                            });
                        }
                    }

                    // Check for drivers loaded from unusual locations
                    if (!string.IsNullOrEmpty(path))
                    {
                        var normalizedPath = path.ToLower();
                        if (!normalizedPath.Contains("\\windows\\") &&
                            !normalizedPath.Contains("\\system32\\") &&
                            !normalizedPath.Contains("\\syswow64\\") &&
                            !normalizedPath.StartsWith("\\systemroot\\"))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Suspicious Driver Location",
                                Severity = Severity.High,
                                Description = $"Driver loaded from unusual location: {name}",
                                Ring = TargetRing,
                                TechnicalDetails = $"Path: {path}\nBase: 0x{driver:X}"
                            });
                        }
                    }
                }

                // Store for later analysis
                _loadedDrivers = driverInfos;
            }
        }
        catch (Exception ex)
        {
            _detections.Add(new Detection
            {
                Module = Name,
                Category = "Error",
                Severity = Severity.Info,
                Description = $"Could not enumerate drivers: {ex.Message}",
                Ring = TargetRing
            });
        }
    }

    private List<(IntPtr baseAddr, string name, string path)> _loadedDrivers = new();

    private void CheckKernelDebugger()
    {
        try
        {
            int size = Marshal.SizeOf<NativeMethods.SYSTEM_KERNEL_DEBUGGER_INFORMATION>();
            IntPtr buffer = Marshal.AllocHGlobal(size);

            try
            {
                int status = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SystemKernelDebuggerInformation,
                    buffer, size, out _);

                if (status == 0)
                {
                    var info = Marshal.PtrToStructure<NativeMethods.SYSTEM_KERNEL_DEBUGGER_INFORMATION>(buffer);

                    if (info.KernelDebuggerEnabled != 0)
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Kernel Debugger",
                            Severity = Severity.High,
                            Description = "Kernel debugger is enabled",
                            Ring = TargetRing,
                            TechnicalDetails = $"KernelDebuggerEnabled: {info.KernelDebuggerEnabled}\nKernelDebuggerNotPresent: {info.KernelDebuggerNotPresent}",
                            Remediation = "Kernel debugging should not be enabled on production systems unless actively debugging."
                        });
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch { }

        // Also check via bcdedit
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "bcdedit",
                Arguments = "/enum {current}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (output.Contains("debug") && output.Contains("Yes"))
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Boot Configuration",
                        Severity = Severity.High,
                        Description = "Boot configuration has debugging enabled",
                        Ring = TargetRing,
                        Remediation = "Run 'bcdedit /debug off' to disable kernel debugging"
                    });
                }

                if (output.Contains("testsigning") && output.Contains("Yes"))
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Boot Configuration",
                        Severity = Severity.Critical,
                        Description = "Test signing mode is enabled - allows unsigned drivers",
                        Ring = TargetRing,
                        TechnicalDetails = "Test signing mode bypasses driver signature enforcement",
                        Remediation = "Run 'bcdedit /set testsigning off' and reboot"
                    });
                }
            }
        }
        catch { }
    }

    private void CheckCodeIntegrity()
    {
        try
        {
            int size = Marshal.SizeOf<NativeMethods.SYSTEM_CODEINTEGRITY_INFORMATION>();
            IntPtr buffer = Marshal.AllocHGlobal(size);

            try
            {
                // Set the length field
                Marshal.WriteInt32(buffer, size);

                int status = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SystemCodeIntegrityInformation,
                    buffer, size, out _);

                if (status == 0)
                {
                    var info = Marshal.PtrToStructure<NativeMethods.SYSTEM_CODEINTEGRITY_INFORMATION>(buffer);

                    // Check various CI flags
                    const uint CODEINTEGRITY_OPTION_ENABLED = 0x01;
                    const uint CODEINTEGRITY_OPTION_TESTSIGN = 0x02;
                    const uint CODEINTEGRITY_OPTION_UMCI_ENABLED = 0x04;
                    const uint CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED = 0x80;

                    if ((info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) != 0)
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Code Integrity",
                            Severity = Severity.Critical,
                            Description = "Code Integrity test signing is enabled",
                            Ring = TargetRing,
                            TechnicalDetails = $"CodeIntegrityOptions: 0x{info.CodeIntegrityOptions:X8}"
                        });
                    }

                    if ((info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED) != 0)
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Code Integrity",
                            Severity = Severity.High,
                            Description = "Code Integrity debug mode is enabled",
                            Ring = TargetRing,
                            TechnicalDetails = $"CodeIntegrityOptions: 0x{info.CodeIntegrityOptions:X8}"
                        });
                    }

                    if ((info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) == 0)
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Code Integrity",
                            Severity = Severity.Critical,
                            Description = "Code Integrity is DISABLED",
                            Ring = TargetRing,
                            Remediation = "Code Integrity should be enabled for driver signature enforcement"
                        });
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch { }
    }

    private void CheckDriverSignatures()
    {
        // Check driver files for valid signatures using WinVerifyTrust
        // This properly handles both embedded and catalog-signed drivers
        string driverPath = Path.Combine(Environment.SystemDirectory, "drivers");

        try
        {
            foreach (var file in Directory.GetFiles(driverPath, "*.sys"))
            {
                try
                {
                    var fileName = Path.GetFileName(file);

                    // Skip Windows inbox drivers - they're catalog signed and trusted
                    if (IsWindowsInboxDriver(file))
                        continue;

                    // Check if driver file is signed using WinVerifyTrust
                    var (isSigned, signerName) = VerifyFileSignature(file);

                    if (!isSigned)
                    {
                        // Skip known unsigned but legitimate drivers
                        if (!IsKnownUnsignedDriver(fileName))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Unsigned Driver",
                                Severity = Severity.High,
                                Description = $"Unsigned driver file: {fileName}",
                                Ring = TargetRing,
                                TechnicalDetails = $"Path: {file}",
                                Remediation = "Investigate the origin of this driver file"
                            });
                        }
                    }
                    else
                    {
                        // Check for suspicious signers
                        if (signerName != null && IsSuspiciousSigner(signerName))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Suspicious Certificate",
                                Severity = Severity.Medium,
                                Description = $"Driver signed by suspicious certificate: {fileName}",
                                Ring = TargetRing,
                                TechnicalDetails = $"Signer: {signerName}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Verifies file signature using WinVerifyTrust API
    /// This handles both embedded and catalog-signed files
    /// </summary>
    private static (bool isSigned, string? signerName) VerifyFileSignature(string filePath)
    {
        IntPtr fileInfoPtr = IntPtr.Zero;
        IntPtr trustDataPtr = IntPtr.Zero;

        try
        {
            // Set up WINTRUST_FILE_INFO structure
            var fileInfo = new NativeMethods.WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>(),
                pcwszFilePath = Marshal.StringToCoTaskMemUni(filePath),
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            // Set up WINTRUST_DATA structure
            var trustData = new NativeMethods.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = NativeMethods.WTD_UI_NONE,
                fdwRevocationChecks = NativeMethods.WTD_REVOKE_NONE,
                dwUnionChoice = NativeMethods.WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = NativeMethods.WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = NativeMethods.WTD_CACHE_ONLY_URL_RETRIEVAL, // Don't go online
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            trustDataPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<NativeMethods.WINTRUST_DATA>());
            Marshal.StructureToPtr(trustData, trustDataPtr, false);

            // Call WinVerifyTrust
            int result = NativeMethods.WinVerifyTrust(
                IntPtr.Zero,
                NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2,
                trustDataPtr);

            // Clean up state
            trustData.dwStateAction = NativeMethods.WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(trustData, trustDataPtr, false);
            NativeMethods.WinVerifyTrust(IntPtr.Zero, NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, trustDataPtr);

            // Check result
            bool isSigned = (result == 0);

            // Try to get signer name if signed
            string? signerName = null;
            if (isSigned)
            {
                try
                {
                    var cert = X509Certificate.CreateFromSignedFile(filePath);
                    signerName = cert.Subject;
                }
                catch { }
            }

            // Free the file path string
            Marshal.FreeCoTaskMem(fileInfo.pcwszFilePath);

            return (isSigned, signerName);
        }
        catch
        {
            return (false, null);
        }
        finally
        {
            if (fileInfoPtr != IntPtr.Zero)
                Marshal.FreeCoTaskMem(fileInfoPtr);
            if (trustDataPtr != IntPtr.Zero)
                Marshal.FreeCoTaskMem(trustDataPtr);
        }
    }

    /// <summary>
    /// Checks if a driver is a Windows inbox driver (ships with Windows)
    /// These are catalog-signed and inherently trusted
    /// </summary>
    private static bool IsWindowsInboxDriver(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var driversPath = Path.Combine(systemRoot, "System32", "drivers");

            // Check if it's in the standard drivers directory
            if (!filePath.StartsWith(driversPath, StringComparison.OrdinalIgnoreCase))
                return false;

            // Check if file is owned by TrustedInstaller (indicates Windows component)
            // For simplicity, we'll check if the file was present since Windows installation
            // by comparing file version info
            var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);

            // Microsoft-signed drivers typically have these company names
            if (versionInfo.CompanyName != null)
            {
                var company = versionInfo.CompanyName.ToLower();
                if (company.Contains("microsoft") ||
                    company.Contains("windows") ||
                    company.Contains("intel") ||
                    company.Contains("nvidia") ||
                    company.Contains("amd") ||
                    company.Contains("realtek") ||
                    company.Contains("qualcomm") ||
                    company.Contains("broadcom"))
                {
                    return true;
                }
            }

            // Check file description for Windows components
            if (versionInfo.FileDescription != null)
            {
                var desc = versionInfo.FileDescription.ToLower();
                if (desc.Contains("windows") || desc.Contains("microsoft"))
                {
                    return true;
                }
            }

            // Check product name
            if (versionInfo.ProductName != null)
            {
                var product = versionInfo.ProductName.ToLower();
                if (product.Contains("windows") || product.Contains("microsoft"))
                {
                    return true;
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private void CheckDKOM()
    {
        // Direct Kernel Object Manipulation detection
        // Compare process counts from different sources

        try
        {
            // Count from Process.GetProcesses
            int apiCount = Process.GetProcesses().Length;

            // Count from WMI
            int wmiCount = 0;
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
                    wmiCount = output.Split('\n').Count(l => int.TryParse(l.Trim(), out _));
                }
            }
            catch { }

            // Count from tasklist
            int tasklistCount = 0;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "tasklist",
                    Arguments = "/NH",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    tasklistCount = output.Split('\n').Count(l => !string.IsNullOrWhiteSpace(l));
                }
            }
            catch { }

            // Significant discrepancy might indicate DKOM
            // Note: Only compare values that are non-zero (zero indicates enumeration failure, not hidden processes)
            var validCounts = new List<int>();
            if (apiCount > 0) validCounts.Add(apiCount);
            if (wmiCount > 0) validCounts.Add(wmiCount);
            if (tasklistCount > 0) validCounts.Add(tasklistCount);

            if (validCounts.Count >= 2)
            {
                int maxCount = validCounts.Max();
                int minCount = validCounts.Min();

                if (maxCount - minCount > 10) // Threshold of 10 to avoid noise
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "DKOM Indicator",
                        Severity = Severity.High,
                        Description = "Significant discrepancy in process counts between different enumeration methods",
                        Ring = TargetRing,
                        TechnicalDetails = $"API: {apiCount}, WMI: {wmiCount}, TaskList: {tasklistCount}\nDifference: {maxCount - minCount}",
                        Remediation = "This may indicate Direct Kernel Object Manipulation (DKOM) used to hide processes"
                    });
                }
            }
        }
        catch { }
    }

    private void CheckDriverRegistry()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var services = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");

            if (services != null)
            {
                foreach (var serviceName in services.GetSubKeyNames())
                {
                    try
                    {
                        using var serviceKey = services.OpenSubKey(serviceName);
                        if (serviceKey == null) continue;

                        var type = serviceKey.GetValue("Type") as int?;
                        var imagePath = serviceKey.GetValue("ImagePath") as string;
                        var start = serviceKey.GetValue("Start") as int?;

                        // Type 1 = Kernel driver, Type 2 = File system driver
                        if (type == 1 || type == 2)
                        {
                            // Check for suspicious image paths
                            if (!string.IsNullOrEmpty(imagePath))
                            {
                                var normalizedPath = imagePath.ToLower();

                                if (normalizedPath.Contains("temp") ||
                                    normalizedPath.Contains("appdata") ||
                                    normalizedPath.Contains("users"))
                                {
                                    _detections.Add(new Detection
                                    {
                                        Module = Name,
                                        Category = "Suspicious Driver Registry",
                                        Severity = Severity.Critical,
                                        Description = $"Driver registered from suspicious location: {serviceName}",
                                        Ring = TargetRing,
                                        TechnicalDetails = $"ImagePath: {imagePath}\nStart: {start}"
                                    });
                                }
                            }

                            // Check for boot-start drivers (Start = 0) with suspicious names
                            if (start == 0 && IsSuspiciousServiceName(serviceName))
                            {
                                _detections.Add(new Detection
                                {
                                    Module = Name,
                                    Category = "Suspicious Boot Driver",
                                    Severity = Severity.High,
                                    Description = $"Suspicious boot-start driver: {serviceName}",
                                    Ring = TargetRing,
                                    TechnicalDetails = $"ImagePath: {imagePath}"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private void CheckDSEBypass()
    {
        // Check for known DSE (Driver Signature Enforcement) bypass techniques

        // Check for vulnerable drivers commonly used for DSE bypass
        string[] vulnerableDrivers = {
            "cpuz", "aswvmm", "aswarPot", "gdrv", "dbutil",
            "rtcore", "gmer", "aswsp", "aswsnx"
        };

        foreach (var driver in _loadedDrivers)
        {
            foreach (var vuln in vulnerableDrivers)
            {
                if (driver.name.Contains(vuln, StringComparison.OrdinalIgnoreCase))
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Vulnerable Driver",
                        Severity = Severity.High,
                        Description = $"Known vulnerable driver loaded: {driver.name}",
                        Ring = TargetRing,
                        TechnicalDetails = "This driver has known vulnerabilities that can be exploited for DSE bypass or privilege escalation",
                        Remediation = "Update or remove this driver if not needed"
                    });
                }
            }
        }

        // Check for CI.dll patches (would need kernel read access)
        // Check for g_CiOptions modification indicators
    }

    #region Helper Methods

    private static bool IsKnownUnsignedDriver(string fileName)
    {
        // Some drivers may legitimately be unsigned in development environments
        string[] knownUnsigned = { };
        return knownUnsigned.Contains(fileName, StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsSuspiciousSigner(string signer)
    {
        string[] suspiciousSigners = {
            "test", "debug", "unsigned", "self-signed",
            "Hacking Team", "FinFisher", "Gamma"
        };

        return suspiciousSigners.Any(s => signer.Contains(s, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSuspiciousServiceName(string name)
    {
        // Known legitimate Windows services with long names
        string[] legitimateLongNames = {
            "WindowsTrustedRT", "WindowsDefender", "WindowsUpdate",
            "MicrosoftEdge", "SystemGuard", "DeviceGuard"
        };

        // Check if it's a known legitimate service
        if (legitimateLongNames.Any(l => name.Contains(l, StringComparison.OrdinalIgnoreCase)))
            return false;

        // Random-looking names (long alphanumeric strings without recognizable words)
        if (name.Length > 25 && name.All(c => char.IsLetterOrDigit(c)))
        {
            // Additional check: legitimate services usually have CamelCase or underscores
            bool hasMixedCase = name.Any(char.IsUpper) && name.Any(char.IsLower);
            if (!hasMixedCase)
                return true; // Looks like random string (all same case, very long)
        }

        string[] suspicious = { "tdl", "zero", "necurs", "siref", "alur" };
        return suspicious.Any(s => name.Contains(s, StringComparison.OrdinalIgnoreCase));
    }

    #endregion
}
