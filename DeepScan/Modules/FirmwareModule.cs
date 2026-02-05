using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using DeepScan.Core;
using Microsoft.Win32;

namespace DeepScan.Modules;

/// <summary>
/// Ring -2 (Firmware/UEFI/SMM) rootkit detection module
/// Detects: UEFI bootkits, Secure Boot violations, firmware tampering
/// </summary>
public class FirmwareModule : IDetectionModule
{
    public string Name => "Ring -2 - Firmware/UEFI";
    public string Description => "Detects firmware-level threats including UEFI bootkits and Secure Boot violations";
    public RingLevel TargetRing => RingLevel.RingMinus2_Firmware;
    public bool IsSupported => Environment.OSVersion.Platform == PlatformID.Win32NT;

    private readonly List<Detection> _detections = new();

    public async Task<IEnumerable<Detection>> ScanAsync(IProgress<string>? progress = null)
    {
        _detections.Clear();

        progress?.Report("Checking firmware type...");
        await Task.Run(CheckFirmwareType);

        progress?.Report("Verifying Secure Boot status...");
        await Task.Run(CheckSecureBoot);

        progress?.Report("Analyzing UEFI variables...");
        await Task.Run(CheckUEFIVariables);

        progress?.Report("Checking boot configuration...");
        await Task.Run(CheckBootConfiguration);

        progress?.Report("Scanning for known UEFI threats...");
        await Task.Run(CheckKnownUEFIThreats);

        progress?.Report("Verifying bootloader integrity...");
        await Task.Run(CheckBootloaderIntegrity);

        progress?.Report("Checking firmware update status...");
        await Task.Run(CheckFirmwareUpdateStatus);

        return _detections;
    }

    private void CheckFirmwareType()
    {
        try
        {
            if (NativeMethods.GetFirmwareType(out var firmwareType))
            {
                string typeStr = firmwareType switch
                {
                    NativeMethods.FirmwareType.Bios => "Legacy BIOS",
                    NativeMethods.FirmwareType.Uefi => "UEFI",
                    _ => "Unknown"
                };

                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Firmware Type",
                    Severity = Severity.Info,
                    Description = $"System firmware type: {typeStr}",
                    Ring = TargetRing
                });

                if (firmwareType == NativeMethods.FirmwareType.Bios)
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Legacy BIOS",
                        Severity = Severity.Medium,
                        Description = "System uses Legacy BIOS - no Secure Boot protection available",
                        Ring = TargetRing,
                        Remediation = "Consider upgrading to UEFI if hardware supports it for better security"
                    });
                }
            }
        }
        catch { }
    }

    private void CheckSecureBoot()
    {
        try
        {
            // Check via registry
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var secureBootKey = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");

            if (secureBootKey != null)
            {
                var enabled = secureBootKey.GetValue("UEFISecureBootEnabled") as int?;

                if (enabled == 1)
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Secure Boot",
                        Severity = Severity.Info,
                        Description = "Secure Boot is ENABLED",
                        Ring = TargetRing
                    });
                }
                else
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Secure Boot",
                        Severity = Severity.High,
                        Description = "Secure Boot is DISABLED",
                        Ring = TargetRing,
                        TechnicalDetails = "Without Secure Boot, unsigned bootloaders can run",
                        Remediation = "Enable Secure Boot in UEFI settings for bootkit protection"
                    });
                }
            }
            else
            {
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Secure Boot",
                    Severity = Severity.Medium,
                    Description = "Could not determine Secure Boot status",
                    Ring = TargetRing
                });
            }

            // Also check via NtQuerySystemInformation
            try
            {
                int size = Marshal.SizeOf<NativeMethods.SYSTEM_SECUREBOOT_INFORMATION>();
                IntPtr buffer = Marshal.AllocHGlobal(size);

                try
                {
                    int status = NativeMethods.NtQuerySystemInformation(
                        NativeMethods.SystemSecureBootInformation,
                        buffer, size, out _);

                    if (status == 0)
                    {
                        var info = Marshal.PtrToStructure<NativeMethods.SYSTEM_SECUREBOOT_INFORMATION>(buffer);

                        if (info.SecureBootCapable != 0 && info.SecureBootEnabled == 0)
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Secure Boot",
                                Severity = Severity.High,
                                Description = "System is Secure Boot capable but it's not enabled",
                                Ring = TargetRing,
                                Remediation = "Enable Secure Boot in UEFI/BIOS settings"
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
        catch { }
    }

    private void CheckUEFIVariables()
    {
        try
        {
            // Try to read UEFI variables
            // This requires SeSystemEnvironmentPrivilege

            NativeUtils.EnablePrivilege("SeSystemEnvironmentPrivilege");

            // Check for suspicious UEFI variables
            string[] suspiciousVariables = {
                "HackingTeam",
                "FinFisher",
                "LoJax",
                "MosaicRegressor",
                "CosmicStrand",
                "BlackLotus"
            };

            // Standard UEFI variable GUIDs
            string efiGlobalGuid = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

            IntPtr buffer = Marshal.AllocHGlobal(4096);
            try
            {
                // Try to read SecureBoot variable
                uint size = NativeMethods.GetFirmwareEnvironmentVariable(
                    "SecureBoot", efiGlobalGuid, buffer, 4096);

                if (size > 0)
                {
                    byte value = Marshal.ReadByte(buffer);
                    if (value == 0)
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "UEFI Variable",
                            Severity = Severity.High,
                            Description = "SecureBoot UEFI variable indicates Secure Boot is off",
                            Ring = TargetRing
                        });
                    }
                }

                // Try to detect suspicious UEFI variables
                // (This is limited from user mode - full analysis needs firmware tools)
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch { }
    }

    private void CheckBootConfiguration()
    {
        try
        {
            // Use bcdedit to check boot configuration
            var psi = new ProcessStartInfo
            {
                FileName = "bcdedit",
                Arguments = "/enum all",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Check for suspicious boot entries
                if (output.Contains("bootmgfw.efi.bak") || output.Contains("bootx64.efi.bak"))
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Boot Configuration",
                        Severity = Severity.High,
                        Description = "Backup bootloader files detected - possible bootkit indicator",
                        Ring = TargetRing
                    });
                }

                // Check for non-standard boot paths
                var lines = output.Split('\n');
                foreach (var line in lines)
                {
                    if (line.Contains("path") && line.Contains(".efi"))
                    {
                        var path = line.ToLower();
                        if (!path.Contains("\\efi\\microsoft\\boot\\") &&
                            !path.Contains("\\efi\\boot\\"))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Boot Configuration",
                                Severity = Severity.Medium,
                                Description = "Non-standard EFI boot path detected",
                                Ring = TargetRing,
                                TechnicalDetails = line.Trim()
                            });
                        }
                    }
                }

                // Check for integrity policy being disabled
                if (output.Contains("nointegritychecks") && output.Contains("Yes"))
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Boot Configuration",
                        Severity = Severity.Critical,
                        Description = "Boot integrity checks are DISABLED",
                        Ring = TargetRing,
                        Remediation = "Run 'bcdedit /set nointegritychecks off' to re-enable"
                    });
                }
            }
        }
        catch { }
    }

    private void CheckKnownUEFIThreats()
    {
        // Check for indicators of known UEFI rootkits/bootkits

        // Known UEFI threat file indicators
        var threatIndicators = new Dictionary<string, string>
        {
            { "rpcnetp.exe", "LoJax (Sednit/APT28)" },
            { "autoche.exe", "LoJax" },
            { "ReAgent.xml.bak", "Possible bootkit backup" },
            { "MosaicRegressor", "MosaicRegressor bootkit" },
            { "IntelUpdate.exe", "Possible firmware threat" }
        };

        string[] searchPaths = {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\Recovery")
        };

        foreach (var basePath in searchPaths)
        {
            try
            {
                if (!Directory.Exists(basePath)) continue;

                foreach (var file in Directory.GetFiles(basePath))
                {
                    var fileName = Path.GetFileName(file);
                    foreach (var (indicator, threat) in threatIndicators)
                    {
                        if (fileName.Equals(indicator, StringComparison.OrdinalIgnoreCase))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Known UEFI Threat",
                                Severity = Severity.Critical,
                                Description = $"Indicator of {threat} detected: {fileName}",
                                Ring = TargetRing,
                                TechnicalDetails = $"Path: {file}",
                                Remediation = "This requires firmware-level remediation. Consider reflashing UEFI."
                            });
                        }
                    }
                }
            }
            catch { }
        }

        // Check EFI System Partition if accessible
        CheckESPForThreats();
    }

    private void CheckESPForThreats()
    {
        try
        {
            // Try to find and check the EFI System Partition
            var psi = new ProcessStartInfo
            {
                FileName = "mountvol",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Look for EFI partition indicators
                // Note: Direct ESP access typically requires admin + mounting
            }

            // Check Windows bootloader hashes
            string bootPath = @"C:\Windows\Boot\EFI";
            if (Directory.Exists(bootPath))
            {
                foreach (var file in Directory.GetFiles(bootPath, "*.efi"))
                {
                    try
                    {
                        var hash = ComputeFileHash(file);
                        // In a real implementation, compare against known-good hashes
                        // For now, just note that we checked it
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private void CheckBootloaderIntegrity()
    {
        try
        {
            // Check Windows bootloader files
            string[] bootloaderFiles = {
                @"C:\Windows\Boot\EFI\bootmgfw.efi",
                @"C:\Windows\Boot\EFI\bootmgr.efi",
                @"C:\Windows\System32\winload.efi"
            };

            foreach (var file in bootloaderFiles)
            {
                if (File.Exists(file))
                {
                    try
                    {
                        var fileInfo = new FileInfo(file);

                        // Check for suspicious modifications (size, date)
                        // Normal bootmgfw.efi is typically 1-2 MB
                        if (fileInfo.Length < 100000 || fileInfo.Length > 10000000)
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Bootloader Integrity",
                                Severity = Severity.High,
                                Description = $"Bootloader file has unusual size: {Path.GetFileName(file)}",
                                Ring = TargetRing,
                                TechnicalDetails = $"Size: {fileInfo.Length} bytes"
                            });
                        }

                        // Check signature
                        bool isSigned = false;
                        try
                        {
                            var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(file);
                            isSigned = true;

                            // Check if signed by Microsoft
                            if (!cert.Subject.Contains("Microsoft"))
                            {
                                _detections.Add(new Detection
                                {
                                    Module = Name,
                                    Category = "Bootloader Integrity",
                                    Severity = Severity.Critical,
                                    Description = $"Bootloader not signed by Microsoft: {Path.GetFileName(file)}",
                                    Ring = TargetRing,
                                    TechnicalDetails = $"Signer: {cert.Subject}"
                                });
                            }
                        }
                        catch
                        {
                            isSigned = false;
                        }

                        if (!isSigned)
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Bootloader Integrity",
                                Severity = Severity.Critical,
                                Description = $"Unsigned bootloader detected: {Path.GetFileName(file)}",
                                Ring = TargetRing,
                                Remediation = "Restore bootloader from Windows installation media"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private void CheckFirmwareUpdateStatus()
    {
        try
        {
            // Check BIOS/UEFI version via WMI
            var psi = new ProcessStartInfo
            {
                FileName = "wmic",
                Arguments = "bios get smbiosbiosversion,releasedate,manufacturer",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Firmware Info",
                    Severity = Severity.Info,
                    Description = "BIOS/UEFI version information",
                    Ring = TargetRing,
                    TechnicalDetails = output.Trim()
                });

                // Check for very old firmware (potential security issue)
                if (output.Contains("2018") || output.Contains("2017") ||
                    output.Contains("2016") || output.Contains("2015"))
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Outdated Firmware",
                        Severity = Severity.Medium,
                        Description = "Firmware appears to be outdated",
                        Ring = TargetRing,
                        Remediation = "Check manufacturer website for firmware updates"
                    });
                }
            }
        }
        catch { }
    }

    #region Helper Methods

    private static string ComputeFileHash(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha256.ComputeHash(stream);
        return BitConverter.ToString(hash).Replace("-", "").ToLower();
    }

    #endregion
}
