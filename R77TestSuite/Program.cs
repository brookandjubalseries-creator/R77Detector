using System;
using System.IO;
using System.Threading;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace R77TestSuite;

/// <summary>
/// R77 Rootkit Footprint Simulator
/// Creates all the indicators that r77 would create, WITHOUT any malicious functionality.
/// Use this to test the R77 Detector.
/// </summary>
class Program
{
    static readonly List<string> CreatedFiles = new();
    static readonly List<string> CreatedDirs = new();
    static readonly List<string> CreatedRegKeys = new();
    static readonly List<string> CreatedTasks = new();
    static readonly List<Mutex> HeldMutexes = new();

    static bool IsAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent())
        .IsInRole(WindowsBuiltInRole.Administrator);

    static void Main(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(@"
  ██████╗ ███████╗███████╗    ████████╗███████╗███████╗████████╗
  ██╔══██╗╚════██║╚════██║    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
  ██████╔╝    ██╔╝    ██╔╝       ██║   █████╗  ███████╗   ██║
  ██╔══██╗   ██╔╝    ██╔╝        ██║   ██╔══╝  ╚════██║   ██║
  ██║  ██║   ██║     ██║         ██║   ███████╗███████║   ██║
  ╚═╝  ╚═╝   ╚═╝     ╚═╝         ╚═╝   ╚══════╝╚══════╝   ╚═╝

         R77 ROOTKIT FOOTPRINT SIMULATOR v1.0
");
        Console.ResetColor();

        Console.WriteLine("  This tool creates HARMLESS indicators that mimic r77-rootkit's");
        Console.WriteLine("  footprint for testing detection tools.\n");

        if (!IsAdmin)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  [!] WARNING: Not running as Administrator");
            Console.WriteLine("  [!] Some tests (registry, services) will be limited\n");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  [+] Running as Administrator - full test suite available\n");
            Console.ResetColor();
        }

        Console.WriteLine("  Choose an option:");
        Console.WriteLine("    [1] Deploy all r77 indicators (simulate infection)");
        Console.WriteLine("    [2] Clean up all indicators (remove simulation)");
        Console.WriteLine("    [3] Deploy indicators, wait for scan, then clean up");
        Console.WriteLine("    [4] Exit\n");

        Console.Write("  > ");
        var choice = Console.ReadLine()?.Trim();

        switch (choice)
        {
            case "1":
                DeployAllIndicators();
                Console.WriteLine("\n  [+] Indicators deployed. Run the detector now!");
                Console.WriteLine("  [+] Run this tool again with option 2 to clean up.");
                break;
            case "2":
                CleanupAllIndicators();
                break;
            case "3":
                DeployAllIndicators();
                Console.WriteLine("\n  [+] Indicators deployed. Run the detector now.");
                Console.WriteLine("  [+] Press ENTER when done to clean up...");
                Console.ReadLine();
                CleanupAllIndicators();
                break;
            case "4":
                return;
            default:
                Console.WriteLine("  Invalid option.");
                break;
        }
    }

    static void DeployAllIndicators()
    {
        Console.WriteLine("\n" + new string('─', 60));
        Console.WriteLine("  DEPLOYING R77 INDICATORS");
        Console.WriteLine(new string('─', 60) + "\n");

        // 1. Registry indicators
        DeployRegistryIndicators();

        // 2. File system indicators
        DeployFileIndicators();

        // 3. Scheduled task indicators
        DeployScheduledTaskIndicators();

        // 4. Mutex indicators (hold them open)
        DeployMutexIndicators();

        // 5. Create a fake $77 process (just renames current process window)
        DeployProcessIndicators();

        Console.WriteLine("\n" + new string('─', 60));
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  DEPLOYMENT COMPLETE");
        Console.ResetColor();
        Console.WriteLine(new string('─', 60));

        PrintSummary();
    }

    static void DeployRegistryIndicators()
    {
        Console.WriteLine("  [*] Creating registry indicators...\n");

        if (IsAdmin)
        {
            try
            {
                // Create the main $77config key that r77 uses
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var software = hklm.OpenSubKey("SOFTWARE", true);

                if (software != null)
                {
                    // Create $77config key
                    using var configKey = software.CreateSubKey("$77config");
                    if (configKey != null)
                    {
                        // Add typical r77 config values
                        configKey.SetValue("pid_list", "1234,5678,9012", RegistryValueKind.String);
                        configKey.SetValue("path_list", @"C:\hidden\path", RegistryValueKind.String);
                        configKey.SetValue("service_names", "$77svc", RegistryValueKind.String);
                        configKey.SetValue("startup", 1, RegistryValueKind.DWord);

                        Console.WriteLine("      [+] Created: HKLM\\SOFTWARE\\$77config");
                        Console.WriteLine("          - pid_list = 1234,5678,9012");
                        Console.WriteLine("          - path_list = C:\\hidden\\path");
                        Console.WriteLine("          - service_names = $77svc");
                        Console.WriteLine("          - startup = 1");
                        CreatedRegKeys.Add(@"HKLM\SOFTWARE\$77config");
                    }

                    // Create a fake $77 service entry
                    using var services = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", true);
                    if (services != null)
                    {
                        using var svcKey = services.CreateSubKey("$77TestService");
                        if (svcKey != null)
                        {
                            svcKey.SetValue("DisplayName", "$77 Test Service", RegistryValueKind.String);
                            svcKey.SetValue("ImagePath", @"C:\Windows\System32\$77svc.exe", RegistryValueKind.String);
                            svcKey.SetValue("Start", 2, RegistryValueKind.DWord);
                            svcKey.SetValue("Type", 16, RegistryValueKind.DWord);

                            Console.WriteLine("      [+] Created: HKLM\\SYSTEM\\CurrentControlSet\\Services\\$77TestService");
                            CreatedRegKeys.Add(@"HKLM\SYSTEM\CurrentControlSet\Services\$77TestService");
                        }
                    }

                    // Create Run key entry
                    using var run = software.OpenSubKey(@"Microsoft\Windows\CurrentVersion\Run", true);
                    if (run != null)
                    {
                        run.SetValue("$77Startup", @"C:\Windows\$77startup.exe", RegistryValueKind.String);
                        Console.WriteLine("      [+] Created: HKLM\\...\\Run\\$77Startup");
                        CreatedRegKeys.Add(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\$77Startup");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"      [-] Registry error: {ex.Message}");
            }
        }
        else
        {
            // Non-admin: use HKCU
            try
            {
                using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
                using var software = hkcu.OpenSubKey("SOFTWARE", true);

                if (software != null)
                {
                    using var configKey = software.CreateSubKey("$77config");
                    if (configKey != null)
                    {
                        configKey.SetValue("test_value", "r77_simulation", RegistryValueKind.String);
                        Console.WriteLine("      [+] Created: HKCU\\SOFTWARE\\$77config (limited - not admin)");
                        CreatedRegKeys.Add(@"HKCU\SOFTWARE\$77config");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"      [-] Registry error: {ex.Message}");
            }
        }

        Console.WriteLine();
    }

    static void DeployFileIndicators()
    {
        Console.WriteLine("  [*] Creating file system indicators...\n");

        // Locations where r77 might place files
        var locations = new Dictionary<string, string>
        {
            { "Temp", Path.GetTempPath() },
            { "LocalAppData", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) },
            { "AppData", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) },
            { "Desktop", Environment.GetFolderPath(Environment.SpecialFolder.Desktop) },
        };

        if (IsAdmin)
        {
            locations.Add("ProgramData", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            locations.Add("System32", Environment.GetFolderPath(Environment.SpecialFolder.System));
        }

        foreach (var (name, basePath) in locations)
        {
            try
            {
                // Create $77 prefixed files
                var dllPath = Path.Combine(basePath, "$77service.dll");
                File.WriteAllText(dllPath, "// R77 Test File - Not actual malware\n// Created by R77TestSuite for detector testing");
                CreatedFiles.Add(dllPath);
                Console.WriteLine($"      [+] Created: {dllPath}");

                var exePath = Path.Combine(basePath, "$77helper.exe");
                File.WriteAllBytes(exePath, Encoding.ASCII.GetBytes("MZ - Fake PE header for testing"));
                CreatedFiles.Add(exePath);
                Console.WriteLine($"      [+] Created: {exePath}");

                // Create $77 prefixed directory with files inside
                var dirPath = Path.Combine(basePath, "$77cache");
                Directory.CreateDirectory(dirPath);
                CreatedDirs.Add(dirPath);
                Console.WriteLine($"      [+] Created: {dirPath}\\");

                var configFile = Path.Combine(dirPath, "config.dat");
                File.WriteAllText(configFile, "r77config:test_simulation");
                CreatedFiles.Add(configFile);

                var stagerFile = Path.Combine(dirPath, "Stager64.dll");
                File.WriteAllText(stagerFile, "// Fake stager DLL for testing");
                CreatedFiles.Add(stagerFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"      [-] {name}: {ex.Message}");
            }
        }

        // Create shellcode file (r77 uses this for fileless deployment)
        try
        {
            var shellcodePath = Path.Combine(Path.GetTempPath(), "Install.shellcode");
            File.WriteAllBytes(shellcodePath, new byte[] { 0x90, 0x90, 0x90, 0xC3 }); // NOP NOP NOP RET
            CreatedFiles.Add(shellcodePath);
            Console.WriteLine($"      [+] Created: {shellcodePath}");
        }
        catch { }

        // Create r77-specific named files
        try
        {
            var r77dll = Path.Combine(Path.GetTempPath(), "r77-x64.dll");
            File.WriteAllText(r77dll, "// Fake r77 DLL");
            CreatedFiles.Add(r77dll);
            Console.WriteLine($"      [+] Created: {r77dll}");

            var r77dll32 = Path.Combine(Path.GetTempPath(), "r77-x86.dll");
            File.WriteAllText(r77dll32, "// Fake r77 DLL");
            CreatedFiles.Add(r77dll32);
            Console.WriteLine($"      [+] Created: {r77dll32}");
        }
        catch { }

        Console.WriteLine();
    }

    static void DeployScheduledTaskIndicators()
    {
        Console.WriteLine("  [*] Creating scheduled task indicators...\n");

        if (!IsAdmin)
        {
            Console.WriteLine("      [-] Skipping (requires Administrator)\n");
            return;
        }

        try
        {
            // Create a harmless scheduled task with $77 prefix
            var taskName = "$77UpdateTask";
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = $"/Create /TN \"{taskName}\" /TR \"cmd.exe /c echo test\" /SC ONCE /ST 00:00 /F",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            process?.WaitForExit();

            if (process?.ExitCode == 0)
            {
                Console.WriteLine($"      [+] Created scheduled task: {taskName}");
                CreatedTasks.Add(taskName);
            }
            else
            {
                Console.WriteLine($"      [-] Failed to create scheduled task");
            }

            // Create another one
            taskName = "$77MaintenanceTask";
            psi.Arguments = $"/Create /TN \"{taskName}\" /TR \"cmd.exe /c echo maintenance\" /SC ONCE /ST 00:00 /F";

            using var process2 = Process.Start(psi);
            process2?.WaitForExit();

            if (process2?.ExitCode == 0)
            {
                Console.WriteLine($"      [+] Created scheduled task: {taskName}");
                CreatedTasks.Add(taskName);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"      [-] Task creation error: {ex.Message}");
        }

        Console.WriteLine();
    }

    static void DeployMutexIndicators()
    {
        Console.WriteLine("  [*] Creating mutex indicators...\n");

        string[] mutexNames = {
            "$77Mutex",
            "Global\\$77Mutex",
            "$77ServiceMutex",
            "r77-rootkit"
        };

        foreach (var name in mutexNames)
        {
            try
            {
                var mutex = new Mutex(true, name, out bool createdNew);
                if (createdNew)
                {
                    HeldMutexes.Add(mutex);
                    Console.WriteLine($"      [+] Created mutex: {name}");
                }
                else
                {
                    Console.WriteLine($"      [~] Mutex already exists: {name}");
                    mutex.Dispose();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"      [-] Mutex error ({name}): {ex.Message}");
            }
        }

        Console.WriteLine();
    }

    static void DeployProcessIndicators()
    {
        Console.WriteLine("  [*] Creating process indicators...\n");

        // We can't easily create a process named $77something, but we can create
        // a batch file that runs and stays open
        try
        {
            var batPath = Path.Combine(Path.GetTempPath(), "$77process.bat");
            File.WriteAllText(batPath, @"@echo off
title $77BackgroundService
echo R77 Test Process - Press Ctrl+C to exit
echo This is a harmless test process for detector validation.
pause >nul
");
            CreatedFiles.Add(batPath);
            Console.WriteLine($"      [+] Created: {batPath}");
            Console.WriteLine("      [i] Run this batch file to create a $77 prefixed window title");

            // Create a VBS that could be detected
            var vbsPath = Path.Combine(Path.GetTempPath(), "$77script.vbs");
            File.WriteAllText(vbsPath, @"' R77 Test Script - Harmless
WScript.Echo ""This is a test script for r77 detection""
");
            CreatedFiles.Add(vbsPath);
            Console.WriteLine($"      [+] Created: {vbsPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"      [-] Process indicator error: {ex.Message}");
        }

        Console.WriteLine();
    }

    static void CleanupAllIndicators()
    {
        Console.WriteLine("\n" + new string('─', 60));
        Console.WriteLine("  CLEANING UP R77 INDICATORS");
        Console.WriteLine(new string('─', 60) + "\n");

        // Release mutexes
        Console.WriteLine("  [*] Releasing mutexes...");
        foreach (var mutex in HeldMutexes)
        {
            try
            {
                mutex.ReleaseMutex();
                mutex.Dispose();
            }
            catch { }
        }
        HeldMutexes.Clear();
        Console.WriteLine("      [+] Mutexes released\n");

        // Delete files
        Console.WriteLine("  [*] Deleting files...");
        var filesToDelete = new List<string>(CreatedFiles);

        // Also search for any $77 files we might have created
        var searchPaths = new[] {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        };

        foreach (var searchPath in searchPaths)
        {
            try
            {
                foreach (var file in Directory.GetFiles(searchPath, "$77*"))
                    if (!filesToDelete.Contains(file)) filesToDelete.Add(file);
                foreach (var file in Directory.GetFiles(searchPath, "r77-*"))
                    if (!filesToDelete.Contains(file)) filesToDelete.Add(file);
                foreach (var file in Directory.GetFiles(searchPath, "*.shellcode"))
                    if (!filesToDelete.Contains(file)) filesToDelete.Add(file);
            }
            catch { }
        }

        foreach (var file in filesToDelete)
        {
            try
            {
                if (File.Exists(file))
                {
                    File.Delete(file);
                    Console.WriteLine($"      [+] Deleted: {file}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"      [-] Failed to delete {file}: {ex.Message}");
            }
        }
        CreatedFiles.Clear();
        Console.WriteLine();

        // Delete directories
        Console.WriteLine("  [*] Deleting directories...");
        var dirsToDelete = new List<string>(CreatedDirs);

        foreach (var searchPath in searchPaths)
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(searchPath, "$77*"))
                    if (!dirsToDelete.Contains(dir)) dirsToDelete.Add(dir);
            }
            catch { }
        }

        foreach (var dir in dirsToDelete)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    Directory.Delete(dir, true);
                    Console.WriteLine($"      [+] Deleted: {dir}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"      [-] Failed to delete {dir}: {ex.Message}");
            }
        }
        CreatedDirs.Clear();
        Console.WriteLine();

        // Delete registry keys
        Console.WriteLine("  [*] Deleting registry keys...");
        if (IsAdmin)
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

                using var software = hklm.OpenSubKey("SOFTWARE", true);
                if (software != null)
                {
                    try { software.DeleteSubKeyTree("$77config", false); Console.WriteLine("      [+] Deleted: HKLM\\SOFTWARE\\$77config"); } catch { }
                }

                using var services = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", true);
                if (services != null)
                {
                    try { services.DeleteSubKeyTree("$77TestService", false); Console.WriteLine("      [+] Deleted: HKLM\\...\\Services\\$77TestService"); } catch { }
                }

                using var run = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                if (run != null)
                {
                    try { run.DeleteValue("$77Startup", false); Console.WriteLine("      [+] Deleted: HKLM\\...\\Run\\$77Startup"); } catch { }
                }
            }
            catch { }
        }

        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
            using var software = hkcu.OpenSubKey("SOFTWARE", true);
            if (software != null)
            {
                try { software.DeleteSubKeyTree("$77config", false); Console.WriteLine("      [+] Deleted: HKCU\\SOFTWARE\\$77config"); } catch { }
            }
        }
        catch { }
        CreatedRegKeys.Clear();
        Console.WriteLine();

        // Delete scheduled tasks
        Console.WriteLine("  [*] Deleting scheduled tasks...");
        string[] tasksToDelete = { "$77UpdateTask", "$77MaintenanceTask" };
        foreach (var task in tasksToDelete)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/Delete /TN \"{task}\" /F",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var process = Process.Start(psi);
                process?.WaitForExit();
                if (process?.ExitCode == 0)
                    Console.WriteLine($"      [+] Deleted task: {task}");
            }
            catch { }
        }
        CreatedTasks.Clear();
        Console.WriteLine();

        Console.WriteLine(new string('─', 60));
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  CLEANUP COMPLETE");
        Console.ResetColor();
        Console.WriteLine(new string('─', 60));
    }

    static void PrintSummary()
    {
        Console.WriteLine("\n  Summary of created indicators:");
        Console.WriteLine($"    • Registry keys:    {CreatedRegKeys.Count}");
        Console.WriteLine($"    • Files:            {CreatedFiles.Count}");
        Console.WriteLine($"    • Directories:      {CreatedDirs.Count}");
        Console.WriteLine($"    • Scheduled tasks:  {CreatedTasks.Count}");
        Console.WriteLine($"    • Mutexes:          {HeldMutexes.Count}");
        Console.WriteLine("\n  The detector should find all of these indicators.");
    }
}
