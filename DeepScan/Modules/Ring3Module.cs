using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using DeepScan.Core;
using Microsoft.Win32;

namespace DeepScan.Modules;

/// <summary>
/// Ring 3 (User-mode) rootkit detection module
/// Detects: API hooks, hidden processes, hidden files, injected DLLs
/// </summary>
public class Ring3Module : IDetectionModule
{
    public string Name => "Ring 3 - User Mode";
    public string Description => "Detects user-mode rootkits via API hook detection, process hiding, and DLL injection";
    public RingLevel TargetRing => RingLevel.Ring3_UserMode;
    public bool IsSupported => true;

    private readonly List<Detection> _detections = new();

    public async Task<IEnumerable<Detection>> ScanAsync(IProgress<string>? progress = null)
    {
        _detections.Clear();

        progress?.Report("Checking for API hooks in ntdll.dll...");
        await Task.Run(CheckNtdllHooks);

        progress?.Report("Checking for AMSI bypass...");
        await Task.Run(CheckAmsiIntegrity);

        progress?.Report("Comparing process lists...");
        await Task.Run(CheckHiddenProcesses);

        progress?.Report("Scanning for suspicious prefixes...");
        await Task.Run(CheckSuspiciousPrefixes);

        progress?.Report("Checking for DLL injection indicators...");
        await Task.Run(CheckDllInjection);

        progress?.Report("Checking IAT hooks...");
        await Task.Run(CheckIATHooks);

        return _detections;
    }

    private void CheckNtdllHooks()
    {
        try
        {
            var ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            if (!File.Exists(ntdllPath)) return;

            var diskBytes = File.ReadAllBytes(ntdllPath);
            var textSection = GetTextSectionInfo(diskBytes);
            if (textSection.Size == 0) return;

            var ntdllModule = GetLoadedModuleBase("ntdll.dll");
            if (ntdllModule == IntPtr.Zero) return;

            var memoryBytes = new byte[textSection.Size];
            if (NativeMethods.ReadProcessMemory(
                NativeMethods.GetCurrentProcess(),
                ntdllModule + (int)textSection.VirtualAddress,
                memoryBytes,
                (uint)textSection.Size,
                out _))
            {
                int differences = 0;
                var hookedOffsets = new List<uint>();

                for (int i = 0; i < Math.Min(textSection.Size, diskBytes.Length - textSection.RawAddress); i++)
                {
                    if (i + textSection.RawAddress < diskBytes.Length &&
                        memoryBytes[i] != diskBytes[i + textSection.RawAddress])
                    {
                        differences++;
                        if (hookedOffsets.Count < 10)
                            hookedOffsets.Add((uint)i);
                    }
                }

                if (differences > 100)
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "API Hooks",
                        Severity = Severity.Critical,
                        Description = $"ntdll.dll is hooked - {differences} byte differences detected in .text section",
                        Ring = TargetRing,
                        TechnicalDetails = $"Hooked offsets (first 10): {string.Join(", ", hookedOffsets.Select(o => $"0x{o:X}"))}",
                        Remediation = "A user-mode rootkit is actively hooking system APIs. Boot from clean media to investigate."
                    });
                }
            }
        }
        catch { }
    }

    private void CheckAmsiIntegrity()
    {
        try
        {
            var amsiHandle = NativeMethods.LoadLibrary("amsi.dll");
            if (amsiHandle == IntPtr.Zero) return;

            var amsiScanBuffer = NativeMethods.GetProcAddress(amsiHandle, "AmsiScanBuffer");
            if (amsiScanBuffer == IntPtr.Zero) return;

            var bytes = new byte[16];
            if (NativeMethods.ReadProcessMemory(NativeMethods.GetCurrentProcess(), amsiScanBuffer, bytes, 16, out _))
            {
                string? bypassType = null;

                if (bytes[0] == 0xC3)
                    bypassType = "RET instruction at start";
                else if (bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
                    bypassType = "XOR EAX,EAX; RET (return S_OK)";
                else if (bytes[0] == 0xB8 && bytes[1] == 0x57 && bytes[2] == 0x00 && bytes[3] == 0x07 && bytes[4] == 0x80)
                    bypassType = "MOV EAX, E_INVALIDARG";
                else if (bytes[0] == 0xB8 && bytes[5] == 0xC3)
                    bypassType = "MOV EAX, <value>; RET";

                if (bypassType != null)
                {
                    _detections.Add(new Detection
                    {
                        Module = Name,
                        Category = "AMSI Bypass",
                        Severity = Severity.Critical,
                        Description = "AMSI (Antimalware Scan Interface) has been bypassed",
                        Ring = TargetRing,
                        TechnicalDetails = $"Bypass method: {bypassType}\nFirst bytes: {BitConverter.ToString(bytes.Take(8).ToArray())}",
                        Remediation = "Malware has disabled Windows' script scanning. Investigate recently executed scripts."
                    });
                }
            }
        }
        catch { }
    }

    private void CheckHiddenProcesses()
    {
        try
        {
            // Get processes via .NET (uses NtQuerySystemInformation internally, may be hooked)
            var apiProcesses = Process.GetProcesses().Select(p => p.Id).ToHashSet();

            // Get processes via direct syscall
            var directProcesses = GetProcessesDirect();
            var directPids = directProcesses.Select(p => p.pid).ToHashSet();

            // Hidden = visible to syscall but not API
            var hidden = directPids.Except(apiProcesses).Where(p => p > 4).ToList();

            foreach (var pid in hidden)
            {
                var info = directProcesses.FirstOrDefault(p => p.pid == pid);
                _detections.Add(new Detection
                {
                    Module = Name,
                    Category = "Hidden Process",
                    Severity = Severity.Critical,
                    Description = $"Process hidden from standard API: {info.name} (PID: {pid})",
                    Ring = TargetRing,
                    TechnicalDetails = "Process visible via NtQuerySystemInformation but hidden from higher-level APIs",
                    Remediation = "A rootkit is actively hiding this process. Investigate its origin and purpose."
                });
            }
        }
        catch { }
    }

    private void CheckSuspiciousPrefixes()
    {
        string[] suspiciousPrefixes = { "$77", "$$", "__hidden", ".hidden" };

        // Check processes
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                foreach (var prefix in suspiciousPrefixes)
                {
                    if (process.ProcessName.Contains(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Suspicious Process",
                            Severity = Severity.High,
                            Description = $"Process with suspicious prefix '{prefix}': {process.ProcessName} (PID: {process.Id})",
                            Ring = TargetRing
                        });
                    }
                }
            }
            catch { }
        }

        // Check files in common locations
        string[] searchPaths = {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath()
        };

        foreach (var basePath in searchPaths)
        {
            try
            {
                foreach (var file in Directory.GetFiles(basePath))
                {
                    var fileName = Path.GetFileName(file);
                    foreach (var prefix in suspiciousPrefixes)
                    {
                        if (fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Suspicious File",
                                Severity = Severity.High,
                                Description = $"File with suspicious prefix: {file}",
                                Ring = TargetRing
                            });
                        }
                    }
                }

                foreach (var dir in Directory.GetDirectories(basePath))
                {
                    var dirName = Path.GetFileName(dir);
                    foreach (var prefix in suspiciousPrefixes)
                    {
                        if (dirName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Suspicious Directory",
                                Severity = Severity.High,
                                Description = $"Directory with suspicious prefix: {dir}",
                                Ring = TargetRing
                            });
                        }
                    }
                }
            }
            catch { }
        }

        // Check registry
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var software = hklm.OpenSubKey("SOFTWARE");
            if (software != null)
            {
                foreach (var keyName in software.GetSubKeyNames())
                {
                    foreach (var prefix in suspiciousPrefixes)
                    {
                        if (keyName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Suspicious Registry",
                                Severity = Severity.Critical,
                                Description = $"Registry key with suspicious prefix: HKLM\\SOFTWARE\\{keyName}",
                                Ring = TargetRing
                            });
                        }
                    }
                }
            }
        }
        catch { }
    }

    private void CheckDllInjection()
    {
        try
        {
            var currentProcess = Process.GetCurrentProcess();
            var systemDir = Environment.SystemDirectory.ToLower();
            var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLower();
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLower();

            foreach (ProcessModule module in currentProcess.Modules)
            {
                try
                {
                    var modulePath = module.FileName.ToLower();

                    // Check for modules in suspicious locations
                    if (!modulePath.StartsWith(systemDir) &&
                        !modulePath.StartsWith(windowsDir) &&
                        !modulePath.StartsWith(programFiles) &&
                        !modulePath.StartsWith(programFilesX86))
                    {
                        // Module loaded from unusual location
                        if (modulePath.Contains("temp") || modulePath.Contains("appdata"))
                        {
                            _detections.Add(new Detection
                            {
                                Module = Name,
                                Category = "Suspicious Module",
                                Severity = Severity.Medium,
                                Description = $"Module loaded from unusual location: {module.FileName}",
                                Ring = TargetRing,
                                TechnicalDetails = $"Base address: 0x{module.BaseAddress:X}"
                            });
                        }
                    }

                    // Check for modules without valid signatures (would need Authenticode checking)
                    // For now, check for very small DLLs which might be injected shellcode loaders
                    var fileInfo = new FileInfo(module.FileName);
                    if (fileInfo.Exists && fileInfo.Length < 10000 && module.ModuleName.EndsWith(".dll"))
                    {
                        _detections.Add(new Detection
                        {
                            Module = Name,
                            Category = "Suspicious Module",
                            Severity = Severity.Low,
                            Description = $"Very small DLL loaded: {module.FileName} ({fileInfo.Length} bytes)",
                            Ring = TargetRing
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckIATHooks()
    {
        // Check for IAT (Import Address Table) hooks in common DLLs
        // This is a simplified check - real implementation would parse PE headers
        try
        {
            var process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
            {
                if (module.ModuleName.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase) ||
                    module.ModuleName.Equals("kernelbase.dll", StringComparison.OrdinalIgnoreCase))
                {
                    // Check a few critical functions
                    var createProcess = NativeMethods.GetProcAddress(module.BaseAddress, "CreateProcessW");
                    if (createProcess != IntPtr.Zero)
                    {
                        var bytes = new byte[5];
                        if (NativeMethods.ReadProcessMemory(NativeMethods.GetCurrentProcess(), createProcess, bytes, 5, out _))
                        {
                            // Check for JMP hook (E9 xx xx xx xx)
                            if (bytes[0] == 0xE9)
                            {
                                _detections.Add(new Detection
                                {
                                    Module = Name,
                                    Category = "IAT Hook",
                                    Severity = Severity.High,
                                    Description = $"CreateProcessW in {module.ModuleName} appears to be hooked",
                                    Ring = TargetRing,
                                    TechnicalDetails = $"First bytes: {BitConverter.ToString(bytes)}"
                                });
                            }
                        }
                    }
                }
            }
        }
        catch { }
    }

    #region Helper Methods

    private static IntPtr GetLoadedModuleBase(string moduleName)
    {
        foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
        {
            if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                return module.BaseAddress;
        }
        return IntPtr.Zero;
    }

    private static (uint VirtualAddress, uint RawAddress, uint Size) GetTextSectionInfo(byte[] peBytes)
    {
        try
        {
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
                    return (
                        BitConverter.ToUInt32(peBytes, sectionOffset + 12),
                        BitConverter.ToUInt32(peBytes, sectionOffset + 20),
                        BitConverter.ToUInt32(peBytes, sectionOffset + 8)
                    );
                }
            }
        }
        catch { }
        return (0, 0, 0);
    }

    private static List<(int pid, string name)> GetProcessesDirect()
    {
        var processes = new List<(int pid, string name)>();
        int bufferSize = 1024 * 1024;
        IntPtr buffer = IntPtr.Zero;

        try
        {
            while (true)
            {
                buffer = Marshal.AllocHGlobal(bufferSize);
                int status = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SystemProcessInformation, buffer, bufferSize, out int returnLength);

                if (status == unchecked((int)0xC0000004)) // STATUS_INFO_LENGTH_MISMATCH
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    bufferSize = returnLength + 65536;
                    continue;
                }

                if (status != 0) break;

                IntPtr current = buffer;
                while (true)
                {
                    int nextOffset = Marshal.ReadInt32(current);
                    IntPtr pid = Marshal.ReadIntPtr(current, 0x50); // UniqueProcessId offset
                    IntPtr namePtr = Marshal.ReadIntPtr(current, 0x40); // ImageName.Buffer offset
                    ushort nameLen = (ushort)Marshal.ReadInt16(current, 0x38); // ImageName.Length

                    string name = "Unknown";
                    if (namePtr != IntPtr.Zero && nameLen > 0)
                        name = Marshal.PtrToStringUni(namePtr, nameLen / 2) ?? "Unknown";

                    processes.Add(((int)pid, name));

                    if (nextOffset == 0) break;
                    current = IntPtr.Add(current, nextOffset);
                }
                break;
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }

        return processes;
    }

    #endregion
}
