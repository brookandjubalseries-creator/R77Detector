using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Win32;

namespace R77Detector;

/// <summary>
/// Advanced detection using direct syscalls to find hidden items
/// </summary>
public static class AdvancedDetector
{
    private const string R77Prefix = "$77";

    public static List<Detection> RunAdvancedDetection()
    {
        var detections = new List<Detection>();

        Console.WriteLine("\n[*] Running advanced detection with direct syscalls...\n");

        // Detect hidden processes
        detections.AddRange(DetectHiddenProcesses());

        // Detect hidden registry keys
        detections.AddRange(DetectHiddenRegistryKeys());

        // Cross-reference detection
        detections.AddRange(CrossReferenceDetection());

        return detections;
    }

    private static List<Detection> DetectHiddenProcesses()
    {
        var detections = new List<Detection>();

        Console.WriteLine("[*] Comparing process lists (API vs Direct Syscall)...");

        try
        {
            // Get processes via normal .NET API (may be filtered by rootkit)
            var apiProcesses = new HashSet<int>();
            foreach (var p in Process.GetProcesses())
            {
                apiProcesses.Add(p.Id);
            }

            // Get processes via direct NtQuerySystemInformation (harder to hook)
            var directProcesses = DirectSyscalls.GetProcessListDirect();
            var directPids = directProcesses.Select(p => p.Pid).ToHashSet();

            // Find processes visible to syscall but not API (potentially hidden)
            var hiddenFromApi = directPids.Except(apiProcesses).Where(p => p > 4).ToList();

            foreach (var pid in hiddenFromApi)
            {
                var processInfo = directProcesses.FirstOrDefault(p => p.Pid == pid);
                detections.Add(new Detection("HiddenProcess", "CRITICAL",
                    $"Process hidden from API but visible via syscall: PID {pid} ({processInfo.Name})"));
            }

            // Check if any direct process has $77 in name
            foreach (var (pid, name) in directProcesses)
            {
                if (name.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                {
                    detections.Add(new Detection("Process", "CRITICAL",
                        $"$77 prefixed process found via syscall: {name} (PID: {pid})"));
                }
            }

            Console.WriteLine($"    API found {apiProcesses.Count} processes, syscall found {directPids.Count}");

            if (hiddenFromApi.Count > 0)
            {
                Console.WriteLine($"    [!] {hiddenFromApi.Count} process(es) hidden from normal API!");
            }
            else
            {
                Console.WriteLine("    No hidden processes detected via this method.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Error in hidden process detection: {ex.Message}");
        }

        return detections;
    }

    private static List<Detection> DetectHiddenRegistryKeys()
    {
        var detections = new List<Detection>();

        Console.WriteLine("[*] Checking for hidden registry keys...");

        try
        {
            // Check for $77config key directly via NT API
            bool configKeyExists = DirectSyscalls.RegistryKeyExistsDirect(@"HKLM\SOFTWARE\$77config");

            if (configKeyExists)
            {
                detections.Add(new Detection("Registry", "CRITICAL",
                    "r77 config key found via direct NT API: HKLM\\SOFTWARE\\$77config"));
            }

            // Compare SOFTWARE subkeys between API and direct call
            Console.WriteLine("[*] Comparing registry enumeration methods...");

            // Get via normal API
            var apiSubkeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var software = hklm.OpenSubKey("SOFTWARE");
                if (software != null)
                {
                    foreach (var name in software.GetSubKeyNames())
                    {
                        apiSubkeys.Add(name);
                    }
                }
            }
            catch { }

            // Get via direct syscall
            var directSubkeys = DirectSyscalls.EnumerateSubKeysDirect(@"HKLM\SOFTWARE");
            var directSet = new HashSet<string>(directSubkeys, StringComparer.OrdinalIgnoreCase);

            // Find keys visible to syscall but not API (hidden by rootkit)
            var hiddenKeys = directSet.Except(apiSubkeys, StringComparer.OrdinalIgnoreCase).ToList();

            foreach (var key in hiddenKeys)
            {
                detections.Add(new Detection("Registry", "CRITICAL",
                    $"Hidden registry key found: HKLM\\SOFTWARE\\{key}"));

                if (key.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                {
                    detections.Add(new Detection("Registry", "CRITICAL",
                        $"$77 prefixed hidden key: HKLM\\SOFTWARE\\{key}"));
                }
            }

            // Also check for $77 keys in the direct list
            foreach (var key in directSubkeys)
            {
                if (key.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                {
                    detections.Add(new Detection("Registry", "CRITICAL",
                        $"$77 prefixed key found via syscall: HKLM\\SOFTWARE\\{key}"));
                }
            }

            Console.WriteLine($"    API found {apiSubkeys.Count} subkeys, syscall found {directSet.Count}");

            if (hiddenKeys.Count > 0)
            {
                Console.WriteLine($"    [!] {hiddenKeys.Count} hidden registry key(s) detected!");
            }
            else
            {
                Console.WriteLine("    No hidden registry keys detected via this method.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Error in hidden registry detection: {ex.Message}");
        }

        return detections;
    }

    private static List<Detection> CrossReferenceDetection()
    {
        var detections = new List<Detection>();

        Console.WriteLine("[*] Cross-referencing detection data...");

        try
        {
            // Get all process names that have open handles to suspicious registry keys
            var directProcesses = DirectSyscalls.GetProcessListDirect();

            // Look for r77 service patterns
            string[] suspiciousServicePatterns = {
                "$77",
                "r77",
                "Stager",
                "TestService"  // r77 test service name
            };

            // Check services via SC query (bypasses some hooks)
            var psi = new ProcessStartInfo
            {
                FileName = "sc",
                Arguments = "query state= all",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                foreach (var pattern in suspiciousServicePatterns)
                {
                    if (output.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        detections.Add(new Detection("Service", "HIGH",
                            $"Suspicious service pattern '{pattern}' found in service list"));
                    }
                }
            }

            // Check for PowerShell with suspicious command lines
            foreach (var (pid, name) in directProcesses)
            {
                if (name.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("pwsh", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        // Try to get command line via WMI
                        var wmiPsi = new ProcessStartInfo
                        {
                            FileName = "wmic",
                            Arguments = $"process where processid={pid} get commandline /format:list",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using var wmiProcess = Process.Start(wmiPsi);
                        if (wmiProcess != null)
                        {
                            var cmdLine = wmiProcess.StandardOutput.ReadToEnd();
                            wmiProcess.WaitForExit();

                            // Check for suspicious patterns
                            if (cmdLine.Contains("$77", StringComparison.OrdinalIgnoreCase) ||
                                cmdLine.Contains("AmsiScanBuffer", StringComparison.OrdinalIgnoreCase) ||
                                cmdLine.Contains("Invoke-Expression", StringComparison.OrdinalIgnoreCase) &&
                                cmdLine.Contains("Download", StringComparison.OrdinalIgnoreCase))
                            {
                                detections.Add(new Detection("Process", "HIGH",
                                    $"Suspicious PowerShell command detected (PID: {pid})"));
                            }
                        }
                    }
                    catch { }
                }
            }

            Console.WriteLine("    Cross-reference analysis complete.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Error in cross-reference detection: {ex.Message}");
        }

        return detections;
    }
}
