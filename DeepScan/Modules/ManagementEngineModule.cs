using System.Diagnostics;
using System.Runtime.InteropServices;
using DeepScan.Core;
using Microsoft.Win32;

namespace DeepScan.Modules;

/// <summary>
/// Ring -3 (Intel ME / AMD PSP) detection module
/// Detects: ME status, vulnerabilities, suspicious ME behavior
/// </summary>
public class ManagementEngineModule : IDetectionModule
{
    public string Name => "Ring -3 - Management Engine";
    public string Description => "Analyzes Intel ME / AMD PSP status and checks for known vulnerabilities";
    public RingLevel TargetRing => RingLevel.RingMinus3_ManagementEngine;
    public bool IsSupported => Environment.OSVersion.Platform == PlatformID.Win32NT;

    private readonly List<Detection> _detections = new();

    public async Task<IEnumerable<Detection>> ScanAsync(IProgress<string>? progress = null)
    {
        _detections.Clear();

        progress?.Report("Detecting processor vendor...");
        await Task.Run(DetectProcessorVendor);

        progress?.Report("Checking Intel ME status...");
        await Task.Run(CheckIntelME);

        progress?.Report("Checking AMD PSP status...");
        await Task.Run(CheckAMDPSP);

        progress?.Report("Scanning for ME vulnerabilities...");
        await Task.Run(CheckMEVulnerabilities);

        progress?.Report("Checking for suspicious ME activity...");
        await Task.Run(CheckMEActivity);

        return _detections;
    }

    private void DetectProcessorVendor()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wmic",
                Arguments = "cpu get manufacturer,name",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                bool isIntel = output.Contains("Intel", StringComparison.OrdinalIgnoreCase);
                bool isAMD = output.Contains("AMD", StringComparison.OrdinalIgnoreCase);

                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Processor Info",
                    Severity = Severity.Info,
                    Description = isIntel ? "Intel processor detected (has Intel ME)" :
                                  isAMD ? "AMD processor detected (has AMD PSP)" :
                                  "Unknown processor vendor",
                    Ring = TargetRing,
                    TechnicalDetails = output.Trim()
                });
            }
        }
        catch { }
    }

    private void CheckIntelME()
    {
        try
        {
            // Check for Intel ME driver and service
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

            // Check for MEI driver
            using var meiKey = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\MEIx64");
            if (meiKey != null)
            {
                var imagePath = meiKey.GetValue("ImagePath") as string;
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Intel ME",
                    Severity = Severity.Info,
                    Description = "Intel Management Engine Interface driver found",
                    Ring = TargetRing,
                    TechnicalDetails = $"Driver: {imagePath}"
                });
            }

            // Check for Intel ME service
            using var lmsKey = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LMS");
            if (lmsKey != null)
            {
                var start = lmsKey.GetValue("Start") as int?;
                var status = start switch
                {
                    0 => "Boot",
                    1 => "System",
                    2 => "Automatic",
                    3 => "Manual",
                    4 => "Disabled",
                    _ => "Unknown"
                };

                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Intel ME",
                    Severity = Severity.Info,
                    Description = $"Intel ME Local Management Service: {status}",
                    Ring = TargetRing
                });
            }

            // Check ME version using Intel tools if available
            CheckMEVersionViaTool();

            // Check for ME in Device Manager
            using var deviceKey = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\PCI");
            if (deviceKey != null)
            {
                foreach (var subKeyName in deviceKey.GetSubKeyNames())
                {
                    // Intel ME devices have specific VEN_8086 and DEV codes
                    if (subKeyName.Contains("VEN_8086") &&
                        (subKeyName.Contains("DEV_A13A") || // 100 Series ME
                         subKeyName.Contains("DEV_A2BA") || // 200 Series ME
                         subKeyName.Contains("DEV_A360") || // 300 Series ME
                         subKeyName.Contains("DEV_02E0") || // 400 Series ME
                         subKeyName.Contains("DEV_43E0")))   // 500 Series ME
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Intel ME Hardware",
                            Severity = Severity.Info,
                            Description = "Intel ME hardware component detected",
                            Ring = TargetRing,
                            TechnicalDetails = subKeyName
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }

    private void CheckAMDPSP()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

            // Check for AMD PSP driver
            using var pspKey = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\amdpsp");
            if (pspKey != null)
            {
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "AMD PSP",
                    Severity = Severity.Info,
                    Description = "AMD Platform Security Processor driver found",
                    Ring = TargetRing
                });
            }

            // Check for AMD fTPM
            using var ftpmKey = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\amd_ftpm");
            if (ftpmKey != null)
            {
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "AMD PSP",
                    Severity = Severity.Info,
                    Description = "AMD fTPM (firmware TPM) detected",
                    Ring = TargetRing
                });
            }
        }
        catch { }
    }

    private void CheckMEVulnerabilities()
    {
        // Check for known Intel ME vulnerabilities based on version/configuration

        try
        {
            // Get ME version if possible
            string? meVersion = GetMEVersion();

            if (!string.IsNullOrEmpty(meVersion))
            {
                // Known vulnerable versions (simplified check)
                // CVE-2017-5689 (AMT vulnerability) affects ME 6.x-11.x
                // CVE-2018-3616 (TXE vulnerability)
                // CVE-2020-8758 (ME vulnerability)

                if (meVersion.StartsWith("11.") || meVersion.StartsWith("10.") ||
                    meVersion.StartsWith("9.") || meVersion.StartsWith("8."))
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "ME Vulnerability",
                        Severity = Severity.High,
                        Description = $"Intel ME version {meVersion} may be vulnerable to known exploits",
                        Ring = TargetRing,
                        TechnicalDetails = "Older ME versions are affected by CVE-2017-5689 and others",
                        Remediation = "Update Intel ME firmware from your system manufacturer"
                    });
                }
            }

            // Check if AMT is enabled (potential attack surface)
            CheckAMTStatus();
        }
        catch { }
    }

    private void CheckAMTStatus()
    {
        try
        {
            // Check for Intel AMT (Active Management Technology) which is part of ME
            // AMT listens on ports 16992-16995

            var psi = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-an",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                int[] amtPorts = { 16992, 16993, 16994, 16995 };
                foreach (var port in amtPorts)
                {
                    if (output.Contains($":{port}"))
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Intel AMT",
                            Severity = Severity.High,
                            Description = $"Intel AMT port {port} is listening",
                            Ring = TargetRing,
                            TechnicalDetails = "AMT provides out-of-band management - can be exploited if misconfigured",
                            Remediation = "Disable AMT in BIOS if not needed, or ensure it's properly secured"
                        });
                    }
                }
            }

            // Check for LMS service (Local Management Service)
            var lmsProcess = Process.GetProcessesByName("LMS");
            if (lmsProcess.Length > 0)
            {
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Intel AMT",
                    Severity = Severity.Medium,
                    Description = "Intel AMT Local Management Service is running",
                    Ring = TargetRing,
                    TechnicalDetails = $"PID: {lmsProcess[0].Id}"
                });
            }
        }
        catch { }
    }

    private void CheckMEActivity()
    {
        try
        {
            // Check for suspicious ME-related activity

            // Look for ME-related processes
            string[] meProcesses = { "LMS", "jhi_service", "IntelCpHeciSvc", "DAL" };

            foreach (var procName in meProcesses)
            {
                var processes = Process.GetProcessesByName(procName);
                if (processes.Length > 0)
                {
                    foreach (var proc in processes)
                    {
                        try
                        {
                            // Check CPU usage - high CPU on ME services could indicate abuse
                            // This is a simplified check
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "ME Process",
                                Severity = Severity.Info,
                                Description = $"Intel ME process running: {proc.ProcessName}",
                                Ring = TargetRing,
                                TechnicalDetails = $"PID: {proc.Id}"
                            });
                        }
                        catch { }
                    }
                }
            }

            // Check for unusual network activity from ME (would need packet capture)
            // ME can have its own network stack independent of OS

            // Check event logs for ME-related events
            CheckMEEventLogs();
        }
        catch { }
    }

    private void CheckMEEventLogs()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wevtutil",
                Arguments = "qe System /q:\"*[System[Provider[@Name='Intel(R) Management Engine']]]\" /c:10 /f:text",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (!string.IsNullOrWhiteSpace(output) && !output.Contains("No events"))
                {
                    // Check for error events
                    if (output.Contains("Error") || output.Contains("Warning"))
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "ME Events",
                            Severity = Severity.Medium,
                            Description = "Intel ME has logged errors/warnings",
                            Ring = TargetRing,
                            TechnicalDetails = output.Length > 500 ? output[..500] + "..." : output
                        });
                    }
                }
            }
        }
        catch { }
    }

    private void CheckMEVersionViaTool()
    {
        // Try to get ME version using Intel's MEInfo tool if available
        string[] possiblePaths = {
            @"C:\Program Files\Intel\Intel(R) Management Engine Components\MEInfo",
            @"C:\Program Files (x86)\Intel\Intel(R) Management Engine Components\MEInfo"
        };

        foreach (var basePath in possiblePaths)
        {
            var meinfoPath = Path.Combine(basePath, "MEInfoWin64.exe");
            if (!File.Exists(meinfoPath))
                meinfoPath = Path.Combine(basePath, "MEInfo.exe");

            if (File.Exists(meinfoPath))
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = meinfoPath,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(psi);
                    if (process != null)
                    {
                        var output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        if (output.Contains("FW Version"))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Intel ME Version",
                                Severity = Severity.Info,
                                Description = "Intel ME firmware version detected",
                                Ring = TargetRing,
                                TechnicalDetails = output
                            });
                        }
                    }
                }
                catch { }
                break;
            }
        }
    }

    private string? GetMEVersion()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var meKey = hklm.OpenSubKey(@"SOFTWARE\Intel\ME");
            if (meKey != null)
            {
                return meKey.GetValue("Version") as string;
            }
        }
        catch { }
        return null;
    }
}
