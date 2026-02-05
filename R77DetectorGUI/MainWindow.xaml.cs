using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Microsoft.Win32;
using System.Windows.Shapes;
using IOPath = System.IO.Path;
using R77Detector;

namespace R77DetectorGUI;

public partial class MainWindow : Window
{
    private ObservableCollection<DetectionItem> _detections = new();
    private bool _isScanning = false;
    private const string R77Prefix = "$77";
    private const string R77ConfigKey = @"SOFTWARE\$77config";

    // Colors for severity
    private static readonly Color CriticalColor = (Color)ColorConverter.ConvertFromString("#ff3a5c");
    private static readonly Color HighColor = (Color)ColorConverter.ConvertFromString("#ff9f43");
    private static readonly Color MediumColor = (Color)ColorConverter.ConvertFromString("#ffd93d");
    private static readonly Color LowColor = (Color)ColorConverter.ConvertFromString("#8888a0");
    private static readonly Color GreenColor = (Color)ColorConverter.ConvertFromString("#00ff88");
    private static readonly Color CyanColor = (Color)ColorConverter.ConvertFromString("#00ffd5");
    private static readonly Color DimColor = (Color)ColorConverter.ConvertFromString("#505068");

    public MainWindow()
    {
        InitializeComponent();
        DetectionList.ItemsSource = _detections;
        UpdateTimestamp();
    }

    #region Window Chrome

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            MaximizeButton_Click(sender, e);
        }
        else
        {
            DragMove();
        }
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void MaximizeButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void CloseButton_MouseEnter(object sender, MouseEventArgs e)
    {
        if (sender is Button btn)
            btn.Foreground = new SolidColorBrush(CriticalColor);
    }

    private void CloseButton_MouseLeave(object sender, MouseEventArgs e)
    {
        if (sender is Button btn)
            btn.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#8888a0"));
    }

    #endregion

    #region Scan Logic

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isScanning) return;

        _isScanning = true;
        _detections.Clear();
        ResetIndicators();
        EmptyState.Visibility = Visibility.Collapsed;

        ScanButton.IsEnabled = false;
        ScanButtonIcon.Text = "◼";
        ScanButtonText.Text = "SCANNING...";
        StatusTitle.Text = "SCANNING SYSTEM";
        StatusSubtitle.Text = "Deep analysis in progress...";

        // Show scan line animation
        ScanLineCanvas.Visibility = Visibility.Visible;
        var scanLineAnim = new DoubleAnimation(-50, ActualHeight, TimeSpan.FromSeconds(2.5))
        {
            RepeatBehavior = RepeatBehavior.Forever
        };
        ScanLine.BeginAnimation(Canvas.TopProperty, scanLineAnim);

        try
        {
            await RunAllScans();
        }
        finally
        {
            // Stop animation
            ScanLine.BeginAnimation(Canvas.TopProperty, null);
            ScanLineCanvas.Visibility = Visibility.Collapsed;

            _isScanning = false;
            ScanButton.IsEnabled = true;
            ScanButtonIcon.Text = "▶";
            ScanButtonText.Text = "SCAN AGAIN";

            UpdateResults();
            UpdateTimestamp();
        }
    }

    private async Task RunAllScans()
    {
        double progress = 0;
        double step = 100.0 / 10; // 10 scan phases

        // Registry Scan
        UpdateProgress("Scanning registry...", progress);
        SetIndicatorScanning(RegistryIndicator, RegistryStatus);
        await Task.Run(() => CheckR77Registry());
        progress += step;
        SetIndicatorComplete(RegistryIndicator, RegistryStatus);

        // Process Scan
        UpdateProgress("Analyzing processes...", progress);
        SetIndicatorScanning(ProcessIndicator, ProcessStatus);
        await Task.Run(() => CheckR77Processes());
        progress += step;
        SetIndicatorComplete(ProcessIndicator, ProcessStatus);

        // Service Scan
        UpdateProgress("Checking services...", progress);
        await Task.Run(() => CheckR77Services());
        progress += step;

        // Filesystem Scan
        UpdateProgress("Scanning filesystem...", progress);
        SetIndicatorScanning(FileSystemIndicator, FileSystemStatus);
        await Task.Run(() => CheckR77Files());
        progress += step;
        SetIndicatorComplete(FileSystemIndicator, FileSystemStatus);

        // Scheduled Tasks
        UpdateProgress("Checking scheduled tasks...", progress);
        await Task.Run(() => CheckR77ScheduledTasks());
        progress += step;

        // Integrity Checks
        UpdateProgress("Verifying ntdll.dll integrity...", progress);
        SetIndicatorScanning(IntegrityIndicator, IntegrityStatus);
        await Task.Run(() => CheckNtdllIntegrity());
        progress += step;

        UpdateProgress("Verifying AMSI integrity...", progress);
        await Task.Run(() => CheckAmsiIntegrity());
        progress += step;
        SetIndicatorComplete(IntegrityIndicator, IntegrityStatus);

        // Module Check
        UpdateProgress("Scanning loaded modules...", progress);
        await Task.Run(() => CheckInjectedModules());
        progress += step;

        // Signature Scan
        UpdateProgress("Checking signatures...", progress);
        SetIndicatorScanning(SignatureIndicator, SignatureStatus);
        await Task.Run(() => CheckR77Signatures());
        progress += step;
        SetIndicatorComplete(SignatureIndicator, SignatureStatus);

        // Advanced Syscall Detection
        UpdateProgress("Running syscall analysis...", progress);
        SetIndicatorScanning(SyscallIndicator, SyscallStatus);
        await Task.Run(() => RunAdvancedDetection());
        progress = 100;
        SetIndicatorComplete(SyscallIndicator, SyscallStatus);

        UpdateProgress("Scan complete", 100);
    }

    private void UpdateProgress(string text, double progress)
    {
        Dispatcher.Invoke(() =>
        {
            ProgressText.Text = text;
            var animation = new DoubleAnimation(progress / 100 * (ActualWidth - 64 - 200), TimeSpan.FromMilliseconds(200));
            ProgressBar.BeginAnimation(WidthProperty, animation);
        });
    }

    private void SetIndicatorScanning(Ellipse indicator, TextBlock status)
    {
        Dispatcher.Invoke(() =>
        {
            indicator.Fill = new SolidColorBrush(CyanColor);
            status.Text = "SCANNING";
            status.Foreground = new SolidColorBrush(CyanColor);

            var pulse = new DoubleAnimation(0.4, 1, TimeSpan.FromMilliseconds(500))
            {
                RepeatBehavior = RepeatBehavior.Forever,
                AutoReverse = true
            };
            indicator.BeginAnimation(OpacityProperty, pulse);
        });
    }

    private void SetIndicatorComplete(Ellipse indicator, TextBlock status)
    {
        Dispatcher.Invoke(() =>
        {
            indicator.BeginAnimation(OpacityProperty, null);
            indicator.Opacity = 1;
            indicator.Fill = new SolidColorBrush(GreenColor);
            status.Text = "COMPLETE";
            status.Foreground = new SolidColorBrush(GreenColor);
        });
    }

    private void ResetIndicators()
    {
        var indicators = new[] { RegistryIndicator, ProcessIndicator, FileSystemIndicator,
                                  IntegrityIndicator, SyscallIndicator, SignatureIndicator };
        var statuses = new[] { RegistryStatus, ProcessStatus, FileSystemStatus,
                               IntegrityStatus, SyscallStatus, SignatureStatus };

        for (int i = 0; i < indicators.Length; i++)
        {
            indicators[i].Fill = new SolidColorBrush(DimColor);
            statuses[i].Text = "PENDING";
            statuses[i].Foreground = new SolidColorBrush(DimColor);
        }
    }

    private void UpdateResults()
    {
        int critical = _detections.Count(d => d.Severity == "CRITICAL");
        int high = _detections.Count(d => d.Severity == "HIGH");
        int medium = _detections.Count(d => d.Severity == "MEDIUM");
        int low = _detections.Count(d => d.Severity == "LOW" || d.Severity == "INFO");

        CriticalCount.Text = critical.ToString();
        HighCount.Text = high.ToString();
        MediumCount.Text = medium.ToString();
        LowCount.Text = low.ToString();

        DetectionCount.Text = $"{_detections.Count} entries";

        if (_detections.Count == 0)
        {
            StatusTitle.Text = "SYSTEM CLEAN";
            StatusTitle.Foreground = new SolidColorBrush(GreenColor);
            StatusSubtitle.Text = "No r77-rootkit indicators detected";
            EmptyState.Visibility = Visibility.Visible;
        }
        else if (critical > 0)
        {
            StatusTitle.Text = "THREATS DETECTED";
            StatusTitle.Foreground = new SolidColorBrush(CriticalColor);
            StatusSubtitle.Text = $"Found {critical} critical indicator(s) - immediate action recommended";
        }
        else if (high > 0)
        {
            StatusTitle.Text = "WARNINGS FOUND";
            StatusTitle.Foreground = new SolidColorBrush(HighColor);
            StatusSubtitle.Text = $"Found {high} high severity indicator(s) - investigation recommended";
        }
        else
        {
            StatusTitle.Text = "SCAN COMPLETE";
            StatusTitle.Foreground = new SolidColorBrush(MediumColor);
            StatusSubtitle.Text = "Minor indicators found - review results below";
        }
    }

    private void UpdateTimestamp()
    {
        TimestampText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    }

    private void AddDetection(string category, string severity, string description)
    {
        var severityColor = severity switch
        {
            "CRITICAL" => CriticalColor,
            "HIGH" => HighColor,
            "MEDIUM" => MediumColor,
            _ => LowColor
        };

        var borderColor = severity switch
        {
            "CRITICAL" => Color.FromArgb(60, CriticalColor.R, CriticalColor.G, CriticalColor.B),
            "HIGH" => Color.FromArgb(40, HighColor.R, HighColor.G, HighColor.B),
            _ => Color.FromArgb(20, 255, 255, 255)
        };

        Dispatcher.Invoke(() =>
        {
            _detections.Add(new DetectionItem
            {
                Category = category.ToUpper(),
                Severity = severity,
                Description = description,
                SeverityColor = severityColor,
                BorderColor = borderColor
            });
            EmptyState.Visibility = Visibility.Collapsed;
        });
    }

    #endregion

    #region Detection Methods

    private void CheckR77Registry()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var configKey = hklm.OpenSubKey(R77ConfigKey);
            if (configKey != null)
            {
                AddDetection("Registry", "CRITICAL", $"r77 config key found: HKLM\\{R77ConfigKey}");
                foreach (var valueName in configKey.GetValueNames())
                {
                    var value = configKey.GetValue(valueName);
                    AddDetection("Registry", "HIGH", $"Config value: {valueName} = {value}");
                }
            }
        }
        catch { }

        string[] registryPaths = {
            @"SOFTWARE",
            @"SYSTEM\CurrentControlSet\Services",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
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
                            AddDetection("Registry", "HIGH", $"$77 prefixed key: HKLM\\{path}\\{subKeyName}");
                    }
                }
            }
            catch { }
        }
    }

    private void CheckR77Processes()
    {
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    if (process.ProcessName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                        AddDetection("Process", "CRITICAL", $"$77 prefixed process: {process.ProcessName} (PID: {process.Id})");

                    var path = process.MainModule?.FileName;
                    if (path != null && path.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                        AddDetection("Process", "CRITICAL", $"Process with $77 in path: {path}");
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckR77Services()
    {
        try
        {
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

                string currentServiceName = "";
                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("SERVICE_NAME:", StringComparison.OrdinalIgnoreCase))
                        currentServiceName = trimmed.Substring(13).Trim();
                    else if (trimmed.StartsWith("DISPLAY_NAME:", StringComparison.OrdinalIgnoreCase))
                    {
                        var displayName = trimmed.Substring(13).Trim();
                        if (currentServiceName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase) ||
                            displayName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                            AddDetection("Service", "CRITICAL", $"$77 service: {currentServiceName}");
                    }
                }
            }
        }
        catch { }
    }

    private void CheckR77Files()
    {
        string[] searchPaths = {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            IOPath.GetTempPath()
        };

        foreach (var searchPath in searchPaths)
        {
            SearchDirectory(searchPath, 2);
        }
    }

    private void SearchDirectory(string path, int maxDepth, int currentDepth = 0)
    {
        if (currentDepth > maxDepth) return;

        try
        {
            foreach (var file in System.IO.Directory.GetFiles(path))
            {
                var fileName = IOPath.GetFileName(file);
                if (fileName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                    AddDetection("File", "HIGH", $"$77 prefixed file: {file}");
            }

            foreach (var dir in System.IO.Directory.GetDirectories(path))
            {
                var dirName = IOPath.GetFileName(dir);
                if (dirName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                    AddDetection("Directory", "HIGH", $"$77 prefixed directory: {dir}");
                SearchDirectory(dir, maxDepth, currentDepth + 1);
            }
        }
        catch { }
    }

    private void CheckR77ScheduledTasks()
    {
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
                        AddDetection("Task", "HIGH", $"$77 scheduled task found");
                }
            }
        }
        catch { }
    }

    private void CheckNtdllIntegrity()
    {
        try
        {
            var ntdllPath = IOPath.Combine(Environment.SystemDirectory, "ntdll.dll");
            if (!System.IO.File.Exists(ntdllPath)) return;

            var diskBytes = System.IO.File.ReadAllBytes(ntdllPath);
            var textSection = GetTextSectionInfo(diskBytes);
            if (textSection.Size == 0) return;

            var ntdllModule = GetLoadedModule("ntdll.dll");
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
                for (int i = 0; i < Math.Min(textSection.Size, diskBytes.Length - textSection.RawAddress); i++)
                {
                    if (i + textSection.RawAddress < diskBytes.Length &&
                        memoryBytes[i] != diskBytes[i + textSection.RawAddress])
                        differences++;
                }

                if (differences > 100)
                    AddDetection("Integrity", "CRITICAL", $"ntdll.dll appears hooked ({differences} byte differences)");
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
                if (bytes[0] == 0xC3)
                    AddDetection("AMSI", "CRITICAL", "AmsiScanBuffer starts with RET - AMSI bypassed!");
                else if (bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
                    AddDetection("AMSI", "CRITICAL", "AmsiScanBuffer patched to return 0 - AMSI bypassed!");
                else if (bytes[0] == 0xB8 && bytes[1] == 0x57 && bytes[2] == 0x00 && bytes[3] == 0x07 && bytes[4] == 0x80)
                    AddDetection("AMSI", "CRITICAL", "AmsiScanBuffer returns E_INVALIDARG - AMSI bypassed!");
            }
        }
        catch { }
    }

    private void CheckInjectedModules()
    {
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        if (module.ModuleName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase) ||
                            module.FileName.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                            AddDetection("Module", "CRITICAL", $"$77 module in {process.ProcessName}: {module.FileName}");
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckR77Signatures()
    {
        string[] knownMutexes = { "$77Mutex", "Global\\$77", "r77-rootkit" };

        foreach (var mutexName in knownMutexes)
        {
            try
            {
                using var mutex = new System.Threading.Mutex(false, mutexName, out bool createdNew);
                if (!createdNew)
                    AddDetection("Signature", "CRITICAL", $"r77 mutex detected: {mutexName}");
            }
            catch (UnauthorizedAccessException)
            {
                AddDetection("Signature", "HIGH", $"Suspicious mutex (access denied): {mutexName}");
            }
            catch { }
        }
    }

    private void RunAdvancedDetection()
    {
        try
        {
            // Compare process lists
            var apiProcesses = Process.GetProcesses().Select(p => p.Id).ToHashSet();
            var directProcesses = DirectSyscalls.GetProcessListDirect();
            var directPids = directProcesses.Select(p => p.Pid).ToHashSet();

            var hidden = directPids.Except(apiProcesses).Where(p => p > 4).ToList();
            foreach (var pid in hidden)
            {
                var info = directProcesses.FirstOrDefault(p => p.Pid == pid);
                AddDetection("Hidden", "CRITICAL", $"Hidden process: PID {pid} ({info.Name})");
            }

            foreach (var (pid, name) in directProcesses)
            {
                if (name.Contains(R77Prefix, StringComparison.OrdinalIgnoreCase))
                    AddDetection("Process", "CRITICAL", $"$77 process via syscall: {name} (PID: {pid})");
            }

            // Compare registry
            var apiSubkeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var software = hklm.OpenSubKey("SOFTWARE");
                if (software != null)
                    foreach (var name in software.GetSubKeyNames())
                        apiSubkeys.Add(name);
            }
            catch { }

            var directSubkeys = DirectSyscalls.EnumerateSubKeysDirect(@"HKLM\SOFTWARE");
            var hiddenKeys = directSubkeys.Except(apiSubkeys, StringComparer.OrdinalIgnoreCase).ToList();

            foreach (var key in hiddenKeys)
            {
                AddDetection("Registry", "CRITICAL", $"Hidden registry key: HKLM\\SOFTWARE\\{key}");
            }

            if (DirectSyscalls.RegistryKeyExistsDirect(@"HKLM\SOFTWARE\$77config"))
                AddDetection("Registry", "CRITICAL", "r77 config key found via direct syscall!");
        }
        catch { }
    }

    private IntPtr GetLoadedModule(string moduleName)
    {
        foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                return module.BaseAddress;
        return IntPtr.Zero;
    }

    private (uint VirtualAddress, uint RawAddress, uint Size) GetTextSectionInfo(byte[] peBytes)
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

    #endregion
}

public class DetectionItem
{
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Description { get; set; } = "";
    public Color SeverityColor { get; set; }
    public Color BorderColor { get; set; }
}

internal static class NativeMethods
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
}
