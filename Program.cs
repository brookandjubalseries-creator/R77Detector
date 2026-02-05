using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace R77Detector;

class Program
{
    static readonly List<Detection> Detections = new();
    static readonly string R77Prefix = "$77";
    static readonly string R77ConfigKey = @"SOFTWARE\$77config";

    static void Main(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
  ____  _____ _____   ____       _            _
 |  _ \|___  |___  | |  _ \  ___| |_ ___  ___| |_ ___  _ __
 | |_) |  / /   / /  | | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 |  _ <  / /   / /   | |_| |  __/ ||  __/ (__| || (_) | |
 |_| \_\/_/   /_/    |____/ \___|\__\___|\___|\__\___/|_|

        r77-rootkit Detection Tool v1.0
");
        Console.ResetColor();

        Console.WriteLine("[*] Starting r77 rootkit detection scan...\n");

        // Run all detection modules
        CheckR77Registry();
        CheckR77Processes();
        CheckR77Services();
        CheckR77Files();
        CheckR77ScheduledTasks();
        CheckNtdllIntegrity();
        CheckAmsiIntegrity();
        CheckInjectedModules();
        CheckHiddenProcesses();
        CheckR77NetworkConnections();
        CheckR77Signatures();

        // Run advanced detection with direct syscalls
        var advancedDetections = AdvancedDetector.RunAdvancedDetection();
        Detections.AddRange(advancedDetections);

        // Print results
        PrintResults();
    }

    static void CheckR77Registry()
    {
        Console.WriteLine("[*] Checking registry for r77 indicators...");

        // Check for $77config key using direct registry access
        try
        {
            // Try HKLM
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var configKey = hklm.OpenSubKey(R77ConfigKey);
            if (configKey != null)
            {
                AddDetection("Registry", "CRITICAL", $"r77 config key found: HKLM\\{R77ConfigKey}");

                // Enumerate values
                foreach (var valueName in configKey.GetValueNames())
                {
                    var value = configKey.GetValue(valueName);
                    AddDetection("Registry", "HIGH", $"  Config value: {valueName} = {value}");
                }
            }
        }
        catch (Exception ex)
        {
            // Key not accessible or doesn't exist
            Console.WriteLine($"    Registry check (normal API): {ex.Message}");
        }

        // Check for any $77 prefixed keys in common locations
        string[] registryPaths = {
            @"SOFTWARE",
            @"SYSTEM\CurrentControlSet\Services",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        };

        foreach (var path in registryPaths)
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = hklm.OpenSubKey(path);
                if (key != null)
                {
                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        if (subKeyName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            AddDetection("Registry", "HIGH", $"$77 prefixed key: HKLM\\{path}\\{subKeyName}");
                        }
                    }
                    foreach (var valueName in key.GetValueNames())
                    {
                        if (valueName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            AddDetection("Registry", "HIGH", $"$77 prefixed value: HKLM\\{path}\\{valueName}");
                        }
                    }
                }
            }
            catch { }
        }

        // Also check HKCU
        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
            using var configKey = hkcu.OpenSubKey(R77ConfigKey);
            if (configKey != null)
            {
                AddDetection("Registry", "CRITICAL", $"r77 config key found: HKCU\\{R77ConfigKey}");
            }
        }
        catch { }

        Console.WriteLine("    Registry scan complete.");
    }

    static void CheckR77Processes()
    {
        Console.WriteLine("[*] Checking processes for r77 indicators...");

        try
        {
            var processes = Process.GetProcesses();
            foreach (var process in processes)
            {
                try
                {
                    if (process.ProcessName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        AddDetection("Process", "CRITICAL",
                            $"$77 prefixed process: {process.ProcessName} (PID: {process.Id})");
                    }

                    // Check command line for $77 if possible
                    try
                    {
                        var path = process.MainModule?.FileName;
                        if (path != null && path.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            AddDetection("Process", "CRITICAL",
                                $"Process with $77 in path: {path} (PID: {process.Id})");
                        }
                    }
                    catch { }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Process enumeration error: {ex.Message}");
        }

        Console.WriteLine("    Process scan complete.");
    }

    static void CheckR77Services()
    {
        Console.WriteLine("[*] Checking services for r77 indicators...");

        try
        {
            // Use sc query to enumerate services (avoids dependency on ServiceController)
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

                // Parse sc query output
                string currentServiceName = "";
                string currentDisplayName = "";

                foreach (var line in output.Split('\n'))
                {
                    var trimmedLine = line.Trim();
                    if (trimmedLine.StartsWith("SERVICE_NAME:", StringComparison.OrdinalIgnoreCase))
                    {
                        currentServiceName = trimmedLine.Substring("SERVICE_NAME:".Length).Trim();
                    }
                    else if (trimmedLine.StartsWith("DISPLAY_NAME:", StringComparison.OrdinalIgnoreCase))
                    {
                        currentDisplayName = trimmedLine.Substring("DISPLAY_NAME:".Length).Trim();

                        // Check if either name contains $77
                        if (currentServiceName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase) ||
                            currentDisplayName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            AddDetection("Service", "CRITICAL",
                                $"$77 prefixed service: {currentServiceName} ({currentDisplayName})");
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Service enumeration error: {ex.Message}");
        }

        Console.WriteLine("    Service scan complete.");
    }

    static void CheckR77Files()
    {
        Console.WriteLine("[*] Checking filesystem for r77 indicators...");

        // Common locations to check
        string[] searchPaths = {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath()
        };

        foreach (var searchPath in searchPaths)
        {
            try
            {
                SearchDirectory(searchPath, 2); // Limit depth to avoid taking too long
            }
            catch { }
        }

        Console.WriteLine("    Filesystem scan complete.");
    }

    static void SearchDirectory(string path, int maxDepth, int currentDepth = 0)
    {
        if (currentDepth > maxDepth) return;

        try
        {
            foreach (var file in Directory.GetFiles(path))
            {
                var fileName = Path.GetFileName(file);
                if (fileName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                {
                    AddDetection("File", "HIGH", $"$77 prefixed file: {file}");
                }
            }

            foreach (var dir in Directory.GetDirectories(path))
            {
                var dirName = Path.GetFileName(dir);
                if (dirName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                {
                    AddDetection("Directory", "HIGH", $"$77 prefixed directory: {dir}");
                }
                SearchDirectory(dir, maxDepth, currentDepth + 1);
            }
        }
        catch { }
    }

    static void CheckR77ScheduledTasks()
    {
        Console.WriteLine("[*] Checking scheduled tasks for r77 indicators...");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = "/Query /FO CSV",
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
                    if (line.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        AddDetection("ScheduledTask", "HIGH", $"$77 prefixed task: {line.Trim()}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Scheduled task check error: {ex.Message}");
        }

        Console.WriteLine("    Scheduled task scan complete.");
    }

    static void CheckNtdllIntegrity()
    {
        Console.WriteLine("[*] Checking ntdll.dll integrity (hook detection)...");

        try
        {
            // Get the loaded ntdll from our process
            var ntdllModule = GetLoadedModule("ntdll.dll");
            if (ntdllModule == IntPtr.Zero)
            {
                Console.WriteLine("    Could not find loaded ntdll.dll");
                return;
            }

            // Read the disk copy
            var ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            if (!File.Exists(ntdllPath))
            {
                Console.WriteLine("    Could not find ntdll.dll on disk");
                return;
            }

            var diskBytes = File.ReadAllBytes(ntdllPath);

            // Parse PE headers to find .text section
            var textSectionInfo = GetTextSectionInfo(diskBytes);
            if (textSectionInfo.Size == 0)
            {
                Console.WriteLine("    Could not parse ntdll.dll PE headers");
                return;
            }

            // Compare .text section
            var memoryTextBytes = new byte[textSectionInfo.Size];
            var bytesRead = IntPtr.Zero;

            var textVirtualAddress = ntdllModule + (int)textSectionInfo.VirtualAddress;

            if (NativeMethods.ReadProcessMemory(
                NativeMethods.GetCurrentProcess(),
                textVirtualAddress,
                memoryTextBytes,
                (uint)textSectionInfo.Size,
                out bytesRead))
            {
                int differences = 0;
                var hookedFunctions = new List<string>();

                for (int i = 0; i < Math.Min(textSectionInfo.Size, diskBytes.Length - textSectionInfo.RawAddress); i++)
                {
                    if (i + textSectionInfo.RawAddress < diskBytes.Length &&
                        memoryTextBytes[i] != diskBytes[i + textSectionInfo.RawAddress])
                    {
                        differences++;
                    }
                }

                if (differences > 100) // Some differences are normal due to relocations
                {
                    AddDetection("Integrity", "CRITICAL",
                        $"ntdll.dll appears to be hooked/modified ({differences} byte differences in .text section)");
                    AddDetection("Integrity", "INFO",
                        "This may indicate r77's ntdll unhooking or other rootkit activity");
                }
                else
                {
                    Console.WriteLine($"    ntdll.dll integrity check passed ({differences} minor differences)");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    ntdll.dll integrity check error: {ex.Message}");
        }

        Console.WriteLine("    ntdll.dll integrity check complete.");
    }

    static void CheckAmsiIntegrity()
    {
        Console.WriteLine("[*] Checking AMSI integrity...");

        try
        {
            // Try to load amsi.dll
            var amsiHandle = NativeMethods.LoadLibrary("amsi.dll");
            if (amsiHandle == IntPtr.Zero)
            {
                Console.WriteLine("    AMSI not loaded (may be normal on some systems)");
                return;
            }

            // Get AmsiScanBuffer address
            var amsiScanBuffer = NativeMethods.GetProcAddress(amsiHandle, "AmsiScanBuffer");
            if (amsiScanBuffer == IntPtr.Zero)
            {
                Console.WriteLine("    Could not find AmsiScanBuffer");
                return;
            }

            // Read first bytes of AmsiScanBuffer
            var bytes = new byte[16];
            if (NativeMethods.ReadProcessMemory(
                NativeMethods.GetCurrentProcess(),
                amsiScanBuffer,
                bytes,
                16,
                out _))
            {
                // Check for common AMSI bypass patterns
                // ret instruction at start
                if (bytes[0] == 0xC3)
                {
                    AddDetection("AMSI", "CRITICAL", "AmsiScanBuffer starts with RET - AMSI is bypassed!");
                }
                // xor eax, eax; ret (return 0)
                else if (bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
                {
                    AddDetection("AMSI", "CRITICAL", "AmsiScanBuffer patched to return 0 - AMSI is bypassed!");
                }
                // mov eax, 0; ret
                else if (bytes[0] == 0xB8 && bytes[1] == 0x00 && bytes[2] == 0x00 &&
                         bytes[3] == 0x00 && bytes[4] == 0x00 && bytes[5] == 0xC3)
                {
                    AddDetection("AMSI", "CRITICAL", "AmsiScanBuffer patched to return 0 - AMSI is bypassed!");
                }
                // mov eax, 80070057h (E_INVALIDARG) - common bypass
                else if (bytes[0] == 0xB8 && bytes[1] == 0x57 && bytes[2] == 0x00 &&
                         bytes[3] == 0x07 && bytes[4] == 0x80)
                {
                    AddDetection("AMSI", "CRITICAL", "AmsiScanBuffer patched to return E_INVALIDARG - AMSI is bypassed!");
                }
                else
                {
                    Console.WriteLine("    AMSI integrity appears intact");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    AMSI check error: {ex.Message}");
        }

        Console.WriteLine("    AMSI integrity check complete.");
    }

    static void CheckInjectedModules()
    {
        Console.WriteLine("[*] Checking for suspicious injected modules...");

        try
        {
            var currentProcess = Process.GetCurrentProcess();
            foreach (ProcessModule module in currentProcess.Modules)
            {
                try
                {
                    // Check for $77 in module name or path
                    if (module.ModuleName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase) ||
                        module.FileName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        AddDetection("Module", "CRITICAL",
                            $"$77 prefixed module loaded: {module.FileName}");
                    }

                    // Check for unsigned modules in unusual locations
                    if (!module.FileName.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase) &&
                        !module.FileName.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase) &&
                        !module.FileName.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase))
                    {
                        // Could be suspicious, but don't flag everything
                        if (module.FileName.Contains("Temp", StringComparison.OrdinalIgnoreCase) ||
                            module.FileName.Contains("AppData", StringComparison.OrdinalIgnoreCase))
                        {
                            AddDetection("Module", "MEDIUM",
                                $"Module loaded from unusual location: {module.FileName}");
                        }
                    }
                }
                catch { }
            }

            // Check other processes for $77 modules
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        if (module.ModuleName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase) ||
                            module.FileName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            AddDetection("Module", "CRITICAL",
                                $"$77 prefixed module in {process.ProcessName} (PID {process.Id}): {module.FileName}");
                        }
                    }
                }
                catch { } // Access denied for many processes
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Module check error: {ex.Message}");
        }

        Console.WriteLine("    Module scan complete.");
    }

    static void CheckHiddenProcesses()
    {
        Console.WriteLine("[*] Checking for hidden processes (comparing APIs)...");

        try
        {
            // Get process list via .NET
            var dotnetProcesses = new HashSet<int>();
            foreach (var p in Process.GetProcesses())
            {
                dotnetProcesses.Add(p.Id);
            }

            // Get process list via WMI
            var wmiProcesses = new HashSet<int>();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "wmic",
                    Arguments = "process get processid /format:csv",
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
                        if (parts.Length >= 2 && int.TryParse(parts[^1].Trim(), out int pid))
                        {
                            wmiProcesses.Add(pid);
                        }
                    }
                }
            }
            catch { }

            // Compare - processes in WMI but not .NET might be hidden
            foreach (var pid in wmiProcesses.Except(dotnetProcesses))
            {
                if (pid > 4) // Skip System and Idle
                {
                    AddDetection("HiddenProcess", "HIGH",
                        $"Process visible in WMI but not .NET API: PID {pid}");
                }
            }

            // Also check via tasklist
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
                            {
                                tasklistProcesses.Add(pid);
                            }
                        }
                    }
                }
            }
            catch { }

            // Discrepancies between different enumeration methods
            var discrepancies = tasklistProcesses.Except(dotnetProcesses).Where(p => p > 4).ToList();
            discrepancies.AddRange(dotnetProcesses.Except(tasklistProcesses).Where(p => p > 4));

            if (discrepancies.Count > 0)
            {
                AddDetection("HiddenProcess", "MEDIUM",
                    $"Discrepancy between process enumeration methods: {discrepancies.Count} processes differ");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Hidden process check error: {ex.Message}");
        }

        Console.WriteLine("    Hidden process check complete.");
    }

    static void CheckR77NetworkConnections()
    {
        Console.WriteLine("[*] Checking network connections for anomalies...");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                var connectionPids = new HashSet<int>();
                foreach (var line in output.Split('\n'))
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 5 && int.TryParse(parts[^1], out int pid))
                    {
                        connectionPids.Add(pid);
                    }
                }

                // Check if any connection PIDs don't exist in process list
                var processPids = Process.GetProcesses().Select(p => p.Id).ToHashSet();
                foreach (var pid in connectionPids.Except(processPids))
                {
                    if (pid > 4)
                    {
                        AddDetection("Network", "HIGH",
                            $"Network connection from non-existent process: PID {pid}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Network check error: {ex.Message}");
        }

        Console.WriteLine("    Network connection check complete.");
    }

    static void CheckR77Signatures()
    {
        Console.WriteLine("[*] Checking for r77 signatures and known indicators...");

        // Known r77 file hashes (SHA256) - these are example hashes, real ones should be updated
        // from threat intelligence sources
        var knownR77Hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Add known r77 file hashes here as they become available
            // These would come from threat intelligence or VirusTotal
        };

        // Known r77 strings/patterns in memory or files
        string[] knownPatterns = {
            "$77config",
            "r77-rootkit",
            "bytecode77",
            "Stager32.dll",
            "Stager64.dll",
            "r77-x64.dll",
            "r77-x86.dll",
            "Install.shellcode",
            "NtQuerySystemInformation hook",
            "NtQueryDirectoryFile hook",
            "NtEnumerateKey hook"
        };

        try
        {
            // Check common persistence locations for suspicious files
            string[] checkPaths = {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)),
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup))
            };

            foreach (var basePath in checkPaths)
            {
                if (!Directory.Exists(basePath)) continue;

                try
                {
                    foreach (var file in Directory.GetFiles(basePath, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        try
                        {
                            var fileInfo = new FileInfo(file);

                            // Check for suspiciously small DLL files (r77 is compact)
                            if (fileInfo.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
                                fileInfo.Length > 0 && fileInfo.Length < 500000)
                            {
                                // Check file content for patterns
                                var bytes = File.ReadAllBytes(file);
                                var content = Encoding.ASCII.GetString(bytes);

                                foreach (var pattern in knownPatterns)
                                {
                                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                    {
                                        AddDetection("Signature", "CRITICAL",
                                            $"r77 pattern '{pattern}' found in: {file}");
                                    }
                                }
                            }

                            // Check for .shellcode files
                            if (fileInfo.Extension.Equals(".shellcode", StringComparison.OrdinalIgnoreCase))
                            {
                                AddDetection("Signature", "CRITICAL",
                                    $"Shellcode file found: {file}");
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // Check running process memory for r77 strings (simplified check)
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                foreach (ProcessModule module in currentProcess.Modules)
                {
                    foreach (var pattern in knownPatterns)
                    {
                        if (module.FileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            AddDetection("Signature", "CRITICAL",
                                $"r77 pattern in loaded module: {module.FileName}");
                        }
                    }
                }
            }
            catch { }

            // Check for known r77 mutex names
            string[] knownMutexes = {
                "$77Mutex",
                "Global\\$77",
                "r77-rootkit"
            };

            foreach (var mutexName in knownMutexes)
            {
                try
                {
                    bool createdNew;
                    using var mutex = new System.Threading.Mutex(false, mutexName, out createdNew);
                    if (!createdNew)
                    {
                        AddDetection("Signature", "CRITICAL",
                            $"r77 mutex detected: {mutexName}");
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    // Mutex exists but we can't access it - suspicious
                    AddDetection("Signature", "HIGH",
                        $"Suspicious mutex (access denied): {mutexName}");
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Signature check error: {ex.Message}");
        }

        Console.WriteLine("    Signature scan complete.");
    }

    static IntPtr GetLoadedModule(string moduleName)
    {
        foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
        {
            if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
            {
                return module.BaseAddress;
            }
        }
        return IntPtr.Zero;
    }

    static (uint VirtualAddress, uint RawAddress, uint Size) GetTextSectionInfo(byte[] peBytes)
    {
        try
        {
            // Parse PE headers
            int e_lfanew = BitConverter.ToInt32(peBytes, 0x3C);
            int numberOfSections = BitConverter.ToInt16(peBytes, e_lfanew + 6);
            int sizeOfOptionalHeader = BitConverter.ToInt16(peBytes, e_lfanew + 20);
            int sectionHeadersOffset = e_lfanew + 24 + sizeOfOptionalHeader;

            for (int i = 0; i < numberOfSections; i++)
            {
                int sectionOffset = sectionHeadersOffset + (i * 40);
                var sectionName = Encoding.ASCII.GetString(peBytes, sectionOffset, 8).TrimEnd('\0');

                if (sectionName == ".text")
                {
                    uint virtualSize = BitConverter.ToUInt32(peBytes, sectionOffset + 8);
                    uint virtualAddress = BitConverter.ToUInt32(peBytes, sectionOffset + 12);
                    uint rawAddress = BitConverter.ToUInt32(peBytes, sectionOffset + 20);

                    return (virtualAddress, rawAddress, virtualSize);
                }
            }
        }
        catch { }

        return (0, 0, 0);
    }

    static void AddDetection(string category, string severity, string description)
    {
        Detections.Add(new Detection(category, severity, description));
    }

    static void PrintResults()
    {
        Console.WriteLine("\n" + new string('=', 70));
        Console.WriteLine("SCAN RESULTS");
        Console.WriteLine(new string('=', 70));

        if (Detections.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[+] No r77 rootkit indicators detected!");
            Console.ResetColor();
            Console.WriteLine("\nNote: This does not guarantee the system is clean.");
            Console.WriteLine("The rootkit may be using advanced evasion techniques.");
            return;
        }

        Console.WriteLine($"\n[!] Found {Detections.Count} potential indicator(s):\n");

        var grouped = Detections.GroupBy(d => d.Severity)
            .OrderByDescending(g => GetSeverityOrder(g.Key));

        foreach (var group in grouped)
        {
            var color = group.Key switch
            {
                "CRITICAL" => ConsoleColor.Red,
                "HIGH" => ConsoleColor.DarkRed,
                "MEDIUM" => ConsoleColor.Yellow,
                "LOW" => ConsoleColor.DarkYellow,
                _ => ConsoleColor.Gray
            };

            Console.ForegroundColor = color;
            Console.WriteLine($"[{group.Key}]");
            Console.ResetColor();

            foreach (var detection in group)
            {
                Console.WriteLine($"  [{detection.Category}] {detection.Description}");
            }
            Console.WriteLine();
        }

        // Recommendations
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\nRECOMMENDATIONS:");
        Console.ResetColor();

        if (Detections.Any(d => d.Severity == "CRITICAL"))
        {
            Console.WriteLine("  [!] CRITICAL indicators found - system likely compromised!");
            Console.WriteLine("  [!] Consider:");
            Console.WriteLine("      1. Disconnect from network immediately");
            Console.WriteLine("      2. Boot from clean media and scan");
            Console.WriteLine("      3. Consider full system reinstallation");
            Console.WriteLine("      4. Change all credentials accessed from this system");
        }
        else if (Detections.Any(d => d.Severity == "HIGH"))
        {
            Console.WriteLine("  [!] HIGH severity indicators found");
            Console.WriteLine("  [!] Further investigation recommended");
            Console.WriteLine("  [!] Run additional security scans with updated tools");
        }
        else
        {
            Console.WriteLine("  [*] Only low/medium indicators found");
            Console.WriteLine("  [*] May be false positives, but worth investigating");
        }
    }

    static int GetSeverityOrder(string severity) => severity switch
    {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0
    };
}

public record Detection(string Category, string Severity, string Description);

static class NativeMethods
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
}
