using System.Diagnostics;
using System.Runtime.InteropServices;
using DeepScan.Core;
using Microsoft.Win32;

namespace DeepScan.Modules;

/// <summary>
/// Ring -1 (Hypervisor) rootkit detection module
/// Detects: Rogue hypervisors, "Blue Pill" style attacks, VM escape indicators
/// Uses timing attacks and CPUID analysis
/// </summary>
public class HypervisorModule : IDetectionModule
{
    public string Name => "Ring -1 - Hypervisor";
    public string Description => "Detects rogue hypervisors via timing analysis, CPUID inspection, and VM detection";
    public RingLevel TargetRing => RingLevel.RingMinus1_Hypervisor;
    public bool IsSupported => Environment.OSVersion.Platform == PlatformID.Win32NT;

    private readonly List<Detection> _detections = new();

    public async Task<IEnumerable<Detection>> ScanAsync(IProgress<string>? progress = null)
    {
        _detections.Clear();

        progress?.Report("Checking CPUID for hypervisor presence...");
        await Task.Run(CheckCPUIDHypervisor);

        progress?.Report("Analyzing timing anomalies...");
        await Task.Run(CheckTimingAnomalies);

        progress?.Report("Checking for known hypervisor signatures...");
        await Task.Run(CheckHypervisorSignatures);

        progress?.Report("Verifying VT-x/AMD-V status...");
        await Task.Run(CheckVirtualizationStatus);

        progress?.Report("Checking for hypervisor artifacts...");
        await Task.Run(CheckHypervisorArtifacts);

        progress?.Report("Running Red Pill detection...");
        await Task.Run(CheckRedPill);

        return _detections;
    }

    private void CheckCPUIDHypervisor()
    {
        try
        {
            // CPUID with EAX=1 returns hypervisor present bit in ECX bit 31
            // We can't execute CPUID directly from C#, so we use indirect methods

            // Check Windows' knowledge of hypervisor
            bool hypervisorPresent = IsHypervisorPresent();

            if (hypervisorPresent)
            {
                // Try to identify the hypervisor
                string hypervisorVendor = GetHypervisorVendor();

                // Known legitimate hypervisors
                string[] legitimate = {
                    "Microsoft Hv", "VMwareVMware", "KVMKVMKVM", "XenVMMXenVMM",
                    "VBoxVBoxVBox", "prl hyperv", "bhyve bhyve"
                };

                bool isKnown = legitimate.Any(l =>
                    hypervisorVendor.Contains(l, StringComparison.OrdinalIgnoreCase) ||
                    l.Contains(hypervisorVendor, StringComparison.OrdinalIgnoreCase));

                if (string.IsNullOrEmpty(hypervisorVendor) || !isKnown)
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Unknown Hypervisor",
                        Severity = Severity.Critical,
                        Description = "Unknown or hidden hypervisor detected",
                        Ring = TargetRing,
                        TechnicalDetails = $"Hypervisor vendor string: '{hypervisorVendor}' (empty or unrecognized)",
                        Remediation = "An unknown hypervisor is running beneath your OS. This could be a 'Blue Pill' style rootkit."
                    });
                }
                else
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Hypervisor Present",
                        Severity = Severity.Info,
                        Description = $"Known hypervisor detected: {hypervisorVendor}",
                        Ring = TargetRing,
                        TechnicalDetails = "This appears to be a legitimate virtualization platform"
                    });
                }
            }
        }
        catch { }
    }

    private void CheckTimingAnomalies()
    {
        try
        {
            // VM exits cause timing anomalies
            // Measure time for operations that would cause VM exits

            var samples = new List<long>();
            int iterations = 100;

            for (int i = 0; i < iterations; i++)
            {
                NativeMethods.QueryPerformanceCounter(out long start);

                // Operations that may cause VM exits
                _ = Environment.TickCount;
                Thread.SpinWait(100);

                NativeMethods.QueryPerformanceCounter(out long end);
                samples.Add(end - start);
            }

            // Analyze timing
            double mean = samples.Average();
            double variance = samples.Select(s => Math.Pow(s - mean, 2)).Average();
            double stdDev = Math.Sqrt(variance);

            // High variance might indicate VM exits
            double coefficientOfVariation = stdDev / mean;

            if (coefficientOfVariation > 0.5)
            {
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Timing Anomaly",
                    Severity = Severity.Medium,
                    Description = "High timing variance detected - possible hypervisor activity",
                    Ring = TargetRing,
                    TechnicalDetails = $"Mean: {mean:F2}, StdDev: {stdDev:F2}, CV: {coefficientOfVariation:F3}",
                    Remediation = "High timing variance may indicate VM exits from a hypervisor"
                });
            }

            // Check for suspiciously consistent timing (some rootkits try to hide)
            if (coefficientOfVariation < 0.01 && mean > 100)
            {
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Timing Anomaly",
                    Severity = Severity.High,
                    Description = "Suspiciously consistent timing - possible timing attack countermeasure",
                    Ring = TargetRing,
                    TechnicalDetails = $"CV: {coefficientOfVariation:F4} (too consistent)"
                });
            }
        }
        catch { }
    }

    private void CheckHypervisorSignatures()
    {
        try
        {
            // Check registry for hypervisor indicators
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

            // Check for Hyper-V
            using var hyperV = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters");
            if (hyperV != null)
            {
                var hostName = hyperV.GetValue("HostName") as string;
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Hyper-V Guest",
                    Severity = Severity.Info,
                    Description = $"Running as Hyper-V guest (Host: {hostName ?? "Unknown"})",
                    Ring = TargetRing
                });
            }

            // Check for VMware
            using var vmware = hklm.OpenSubKey(@"SOFTWARE\VMware, Inc.\VMware Tools");
            if (vmware != null)
            {
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "VMware Guest",
                    Severity = Severity.Info,
                    Description = "Running as VMware guest",
                    Ring = TargetRing
                });
            }

            // Check for VirtualBox
            using var vbox = hklm.OpenSubKey(@"SOFTWARE\Oracle\VirtualBox Guest Additions");
            if (vbox != null)
            {
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "VirtualBox Guest",
                    Severity = Severity.Info,
                    Description = "Running as VirtualBox guest",
                    Ring = TargetRing
                });
            }

            // Check for suspicious hypervisor-related registry entries
            string[] suspiciousKeys = {
                @"SOFTWARE\BluePill",
                @"SOFTWARE\SubVirt",
                @"SOFTWARE\Vitriol",
                @"SYSTEM\CurrentControlSet\Services\psychsvc"
            };

            foreach (var keyPath in suspiciousKeys)
            {
                using var key = hklm.OpenSubKey(keyPath);
                if (key != null)
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "Suspicious Hypervisor",
                        Severity = Severity.Critical,
                        Description = $"Suspicious hypervisor registry key found: {keyPath}",
                        Ring = TargetRing
                    });
                }
            }
        }
        catch { }
    }

    private void CheckVirtualizationStatus()
    {
        try
        {
            // Check if VT-x/AMD-V is available and in use
            bool vtEnabled = NativeMethods.IsProcessorFeaturePresent(NativeMethods.PF_VIRT_FIRMWARE_ENABLED);
            bool slatEnabled = NativeMethods.IsProcessorFeaturePresent(NativeMethods.PF_SECOND_LEVEL_ADDRESS_TRANSLATION);

            if (!vtEnabled && IsHypervisorPresent())
            {
                // Hypervisor present but VT not reported as enabled
                // Could indicate nested virtualization or hidden hypervisor
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Virtualization Mismatch",
                    Severity = Severity.High,
                    Description = "Hypervisor detected but VT-x/AMD-V not reported as enabled",
                    Ring = TargetRing,
                    TechnicalDetails = "This inconsistency may indicate a hidden hypervisor"
                });
            }

            // Check systeminfo for hypervisor details
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "systeminfo",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (output.Contains("Hyper-V Requirements"))
                    {
                        bool vmDetected = output.Contains("A hypervisor has been detected");
                        bool vmMonitorExtensions = output.Contains("VM Monitor Mode Extensions: Yes");

                        if (vmDetected)
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Hypervisor Confirmed",
                                Severity = Severity.Info,
                                Description = "Windows confirms hypervisor presence",
                                Ring = TargetRing
                            });
                        }
                    }
                }
            }
            catch { }
        }
        catch { }
    }

    private void CheckHypervisorArtifacts()
    {
        try
        {
            // Check for hypervisor-related processes
            string[] hypervisorProcesses = {
                "vmtoolsd", "vmwaretray", "vmwareuser",
                "vboxservice", "vboxtray",
                "vmcompute", "vmms",
                "qemu-ga"
            };

            string[] suspiciousProcesses = {
                "psychsvc", "bluepill", "subvirt"
            };

            var processes = Process.GetProcesses();

            foreach (var proc in processes)
            {
                try
                {
                    var name = proc.ProcessName.ToLower();

                    if (suspiciousProcesses.Any(s => name.Contains(s)))
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Suspicious Process",
                            Severity = Severity.Critical,
                            Description = $"Suspicious hypervisor-related process: {proc.ProcessName}",
                            Ring = TargetRing,
                            TechnicalDetails = $"PID: {proc.Id}"
                        });
                    }
                }
                catch { }
            }

            // Check for hypervisor-related drivers
            string[] hypervisorDrivers = {
                "vmci.sys", "vsock.sys", "vmhgfs.sys",
                "vboxguest.sys", "vboxsf.sys", "vboxmouse.sys"
            };

            string driversPath = Path.Combine(Environment.SystemDirectory, "drivers");
            if (Directory.Exists(driversPath))
            {
                foreach (var driver in hypervisorDrivers)
                {
                    if (File.Exists(Path.Combine(driversPath, driver)))
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Hypervisor Driver",
                            Severity = Severity.Info,
                            Description = $"Hypervisor driver present: {driver}",
                            Ring = TargetRing
                        });
                    }
                }
            }
        }
        catch { }
    }

    private void CheckRedPill()
    {
        // "Red Pill" technique - detect VM by checking IDT base address
        // On native hardware, IDT is at predictable addresses
        // In a VM, it may be at unusual addresses

        try
        {
            // We can't directly read IDT from user mode, but we can use timing
            // of privileged instructions as a proxy

            // Check RDTSC behavior
            var rdtscTimes = new List<long>();

            for (int i = 0; i < 50; i++)
            {
                NativeMethods.QueryPerformanceCounter(out long start);

                // Tight loop that would behave differently in VM
                for (int j = 0; j < 10000; j++)
                {
                    _ = Environment.TickCount64;
                }

                NativeMethods.QueryPerformanceCounter(out long end);
                rdtscTimes.Add(end - start);

                Thread.Sleep(1); // Small delay between measurements
            }

            // Look for bimodal distribution (indicates VM exits)
            var sorted = rdtscTimes.OrderBy(t => t).ToList();
            long median = sorted[sorted.Count / 2];
            int outliers = rdtscTimes.Count(t => t > median * 2);

            if (outliers > rdtscTimes.Count * 0.2)
            {
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Red Pill Detection",
                    Severity = Severity.Medium,
                    Description = "Timing analysis suggests possible hypervisor presence",
                    Ring = TargetRing,
                    TechnicalDetails = $"Outlier rate: {outliers}/{rdtscTimes.Count} ({100.0 * outliers / rdtscTimes.Count:F1}%)"
                });
            }
        }
        catch { }
    }

    #region Helper Methods

    private static bool IsHypervisorPresent()
    {
        try
        {
            // Check WMI for hypervisor
            var psi = new ProcessStartInfo
            {
                FileName = "wmic",
                Arguments = "computersystem get hypervisorpresent",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return output.Contains("TRUE", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch { }

        return false;
    }

    private static string GetHypervisorVendor()
    {
        try
        {
            // Try to get hypervisor vendor from WMI
            var psi = new ProcessStartInfo
            {
                FileName = "wmic",
                Arguments = "computersystem get manufacturer,model",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (output.Contains("VMware")) return "VMware";
                if (output.Contains("VirtualBox")) return "VirtualBox";
                if (output.Contains("Microsoft") && output.Contains("Virtual")) return "Microsoft Hv";
                if (output.Contains("QEMU")) return "QEMU/KVM";
                if (output.Contains("Xen")) return "Xen";
            }
        }
        catch { }

        return string.Empty;
    }

    #endregion
}
