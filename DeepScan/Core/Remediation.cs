using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace DeepScan.Core;

/// <summary>
/// Remediation engine that can clean or quarantine detected threats
/// </summary>
public class RemediationEngine
{
    private readonly string _quarantinePath;
    private readonly string _logPath;
    private readonly List<RemediationAction> _actions = new();
    private readonly List<string> _logs = new();

    public RemediationEngine()
    {
        var basePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DeepScan");
        _quarantinePath = Path.Combine(basePath, "Quarantine");
        _logPath = Path.Combine(basePath, "Logs");

        Directory.CreateDirectory(_quarantinePath);
        Directory.CreateDirectory(_logPath);
    }

    public IReadOnlyList<RemediationAction> Actions => _actions.AsReadOnly();

    /// <summary>
    /// Analyze detections and generate remediation actions
    /// </summary>
    public List<RemediationAction> GenerateRemediationPlan(IEnumerable<Detection> detections)
    {
        _actions.Clear();

        foreach (var detection in detections.Where(d => d.Severity >= Severity.Medium))
        {
            var actions = GenerateActionsForDetection(detection);
            _actions.AddRange(actions);
        }

        return _actions.ToList();
    }

    private List<RemediationAction> GenerateActionsForDetection(Detection detection)
    {
        var actions = new List<RemediationAction>();

        switch (detection.Ring)
        {
            case RingLevel.Ring3_UserMode:
                actions.AddRange(GenerateRing3Actions(detection));
                break;
            case RingLevel.Ring0_Kernel:
                actions.AddRange(GenerateRing0Actions(detection));
                break;
            case RingLevel.RingMinus1_Hypervisor:
                actions.AddRange(GenerateHypervisorActions(detection));
                break;
            case RingLevel.RingMinus2_Firmware:
                actions.AddRange(GenerateFirmwareActions(detection));
                break;
            case RingLevel.RingMinus3_ManagementEngine:
                actions.AddRange(GenerateMEActions(detection));
                break;
        }

        return actions;
    }

    #region Ring 3 Actions (Automated)

    private List<RemediationAction> GenerateRing3Actions(Detection detection)
    {
        var actions = new List<RemediationAction>();

        switch (detection.Category)
        {
            case "Suspicious File":
            case "Suspicious Directory":
                var path = ExtractPath(detection.Description);
                if (!string.IsNullOrEmpty(path))
                {
                    actions.Add(new RemediationAction
                    {
                        Detection = detection,
                        Type = RemediationType.QuarantineFile,
                        Description = $"Quarantine: {Path.GetFileName(path)}",
                        TargetPath = path,
                        CanAutomate = true,
                        Risk = RemediationRisk.Low
                    });
                }
                break;

            case "Suspicious Registry":
                var keyPath = ExtractRegistryPath(detection.Description);
                if (!string.IsNullOrEmpty(keyPath))
                {
                    actions.Add(new RemediationAction
                    {
                        Detection = detection,
                        Type = RemediationType.DeleteRegistryKey,
                        Description = $"Delete registry key: {keyPath}",
                        TargetPath = keyPath,
                        CanAutomate = true,
                        Risk = RemediationRisk.Medium
                    });
                }
                break;

            case "Hidden Process":
            case "Suspicious Process":
                var pid = ExtractPID(detection.Description);
                if (pid > 0)
                {
                    actions.Add(new RemediationAction
                    {
                        Detection = detection,
                        Type = RemediationType.TerminateProcess,
                        Description = $"Terminate process PID: {pid}",
                        TargetPID = pid,
                        CanAutomate = true,
                        Risk = RemediationRisk.Medium
                    });
                }
                break;

            case "API Hooks":
            case "AMSI Bypass":
                actions.Add(new RemediationAction
                {
                    Detection = detection,
                    Type = RemediationType.RestartRequired,
                    Description = "Reboot into Safe Mode and run antimalware scan",
                    CanAutomate = false,
                    Risk = RemediationRisk.Low,
                    ManualSteps = new[]
                    {
                        "1. Save all work and close applications",
                        "2. Run: shutdown /r /o /t 0",
                        "3. Select Troubleshoot > Advanced > Startup Settings > Restart",
                        "4. Press 4 or F4 for Safe Mode",
                        "5. Run Windows Defender offline scan or Malwarebytes",
                        "6. Delete any suspicious files found",
                        "7. Restart normally"
                    }
                });
                break;

            case "Suspicious Module":
                var modulePath = ExtractPath(detection.Description);
                if (!string.IsNullOrEmpty(modulePath))
                {
                    actions.Add(new RemediationAction
                    {
                        Detection = detection,
                        Type = RemediationType.QuarantineFile,
                        Description = $"Quarantine module: {Path.GetFileName(modulePath)}",
                        TargetPath = modulePath,
                        CanAutomate = true,
                        Risk = RemediationRisk.Medium
                    });
                }
                break;
        }

        return actions;
    }

    #endregion

    #region Ring 0 Actions (Mostly Manual)

    private List<RemediationAction> GenerateRing0Actions(Detection detection)
    {
        var actions = new List<RemediationAction>();

        switch (detection.Category)
        {
            case "Suspicious Driver":
            case "Unsigned Driver":
            case "Suspicious Driver Location":
                actions.Add(new RemediationAction
                {
                    Detection = detection,
                    Type = RemediationType.DisableDriver,
                    Description = "Disable suspicious driver",
                    CanAutomate = false,
                    Risk = RemediationRisk.High,
                    ManualSteps = new[]
                    {
                        "1. Note the driver name from the detection",
                        "2. Open Device Manager (devmgmt.msc)",
                        "3. View > Show hidden devices",
                        "4. Find the driver and right-click > Disable",
                        "5. If needed, boot into Safe Mode first",
                        "6. Run: sc query <drivername> to check status",
                        "7. Run: sc config <drivername> start=disabled"
                    }
                });
                break;

            case "Boot Configuration":
                if (detection.Description.Contains("testsigning"))
                {
                    actions.Add(new RemediationAction
                    {
                        Detection = detection,
                        Type = RemediationType.FixBootConfig,
                        Description = "Disable test signing mode",
                        CanAutomate = true,
                        Risk = RemediationRisk.Medium,
                        Command = "bcdedit /set testsigning off"
                    });
                }
                if (detection.Description.Contains("debug"))
                {
                    actions.Add(new RemediationAction
                    {
                        Detection = detection,
                        Type = RemediationType.FixBootConfig,
                        Description = "Disable kernel debugging",
                        CanAutomate = true,
                        Risk = RemediationRisk.Low,
                        Command = "bcdedit /debug off"
                    });
                }
                break;

            case "Code Integrity":
                actions.Add(new RemediationAction
                {
                    Detection = detection,
                    Type = RemediationType.Manual,
                    Description = "Re-enable Code Integrity",
                    CanAutomate = false,
                    Risk = RemediationRisk.Medium,
                    ManualSteps = new[]
                    {
                        "1. Open Command Prompt as Administrator",
                        "2. Run: bcdedit /set nointegritychecks off",
                        "3. Run: bcdedit /set loadoptions ENABLE_INTEGRITY_CHECKS",
                        "4. Restart the computer",
                        "5. Verify with: bcdedit /enum"
                    }
                });
                break;

            case "Kernel Debugger":
                actions.Add(new RemediationAction
                {
                    Detection = detection,
                    Type = RemediationType.FixBootConfig,
                    Description = "Disable kernel debugger",
                    CanAutomate = true,
                    Risk = RemediationRisk.Low,
                    Command = "bcdedit /debug off"
                });
                break;

            case "Vulnerable Driver":
                actions.Add(new RemediationAction
                {
                    Detection = detection,
                    Type = RemediationType.Manual,
                    Description = "Update or remove vulnerable driver",
                    CanAutomate = false,
                    Risk = RemediationRisk.Medium,
                    ManualSteps = new[]
                    {
                        "1. Identify the driver from the detection details",
                        "2. Check manufacturer website for updates",
                        "3. Update via Device Manager if available",
                        "4. If no update, consider disabling if not needed",
                        "5. Monitor for related security advisories"
                    }
                });
                break;
        }

        return actions;
    }

    #endregion

    #region Hypervisor Actions

    private List<RemediationAction> GenerateHypervisorActions(Detection detection)
    {
        var actions = new List<RemediationAction>();

        if (detection.Severity >= Severity.High)
        {
            actions.Add(new RemediationAction
            {
                Detection = detection,
                Type = RemediationType.Manual,
                Description = "Investigate potential rogue hypervisor",
                CanAutomate = false,
                Risk = RemediationRisk.Critical,
                ManualSteps = new[]
                {
                    "⚠️ CRITICAL: Potential 'Blue Pill' style rootkit detected",
                    "",
                    "1. DO NOT trust any scan results from this OS",
                    "2. Boot from a clean USB/DVD (Windows PE or Linux Live)",
                    "3. Run offline antimalware scan",
                    "4. Check BIOS/UEFI settings for virtualization options",
                    "5. If VT-x/AMD-V is enabled but you don't use VMs, consider disabling",
                    "6. Flash BIOS/UEFI to latest version",
                    "7. If threat persists, consider clean OS reinstall",
                    "8. Contact security professional if unsure"
                }
            });
        }

        return actions;
    }

    #endregion

    #region Firmware Actions

    private List<RemediationAction> GenerateFirmwareActions(Detection detection)
    {
        var actions = new List<RemediationAction>();

        switch (detection.Category)
        {
            case "Secure Boot":
                if (detection.Description.Contains("DISABLED"))
                {
                    actions.Add(new RemediationAction
                    {
                        Detection = detection,
                        Type = RemediationType.Manual,
                        Description = "Enable Secure Boot",
                        CanAutomate = false,
                        Risk = RemediationRisk.Low,
                        ManualSteps = new[]
                        {
                            "1. Restart computer and enter BIOS/UEFI setup",
                            "   (Usually Del, F2, F10, or F12 during boot)",
                            "2. Navigate to Security or Boot section",
                            "3. Find Secure Boot option",
                            "4. Enable Secure Boot",
                            "5. Save and exit (usually F10)",
                            "6. Note: May need to set UEFI boot mode first"
                        }
                    });
                }
                break;

            case "Known UEFI Threat":
            case "Bootloader Integrity":
                actions.Add(new RemediationAction
                {
                    Detection = detection,
                    Type = RemediationType.Manual,
                    Description = "Firmware-level threat requires special handling",
                    CanAutomate = false,
                    Risk = RemediationRisk.Critical,
                    ManualSteps = new[]
                    {
                        "⚠️ CRITICAL: Firmware-level threat detected",
                        "",
                        "This type of threat survives OS reinstallation!",
                        "",
                        "1. Contact your IT security team or a professional",
                        "2. Document all findings for forensic analysis",
                        "3. Do NOT attempt to fix without expertise",
                        "",
                        "If proceeding independently:",
                        "4. Download UEFI firmware from manufacturer (verify hash!)",
                        "5. Boot from clean USB with firmware update tool",
                        "6. Flash UEFI firmware",
                        "7. Enable Secure Boot",
                        "8. Perform clean OS installation",
                        "9. Change all passwords from a different device"
                    }
                });
                break;

            case "Outdated Firmware":
                actions.Add(new RemediationAction
                {
                    Detection = detection,
                    Type = RemediationType.Manual,
                    Description = "Update system firmware",
                    CanAutomate = false,
                    Risk = RemediationRisk.Medium,
                    ManualSteps = new[]
                    {
                        "1. Identify your motherboard/system model",
                        "2. Visit manufacturer's support website",
                        "3. Download latest BIOS/UEFI update",
                        "4. Read update instructions carefully",
                        "5. Backup current BIOS if tool allows",
                        "6. Apply update (DO NOT interrupt!)",
                        "7. Verify version after restart"
                    }
                });
                break;
        }

        return actions;
    }

    #endregion

    #region ME/PSP Actions

    private List<RemediationAction> GenerateMEActions(Detection detection)
    {
        var actions = new List<RemediationAction>();

        switch (detection.Category)
        {
            case "Intel AMT":
                if (detection.Description.Contains("listening"))
                {
                    actions.Add(new RemediationAction
                    {
                        Detection = detection,
                        Type = RemediationType.Manual,
                        Description = "Secure or disable Intel AMT",
                        CanAutomate = false,
                        Risk = RemediationRisk.Medium,
                        ManualSteps = new[]
                        {
                            "Intel AMT is a powerful remote management feature.",
                            "If you don't use it, disable it:",
                            "",
                            "1. Restart and enter BIOS/UEFI setup",
                            "2. Navigate to Advanced > AMT Configuration",
                            "3. Disable AMT or set to 'UnConfigure'",
                            "4. Save and exit",
                            "",
                            "If you need AMT:",
                            "5. Ensure strong password is set",
                            "6. Configure network isolation",
                            "7. Keep ME firmware updated"
                        }
                    });
                }
                break;

            case "ME Vulnerability":
                actions.Add(new RemediationAction
                {
                    Detection = detection,
                    Type = RemediationType.Manual,
                    Description = "Update Intel ME firmware",
                    CanAutomate = false,
                    Risk = RemediationRisk.Medium,
                    ManualSteps = new[]
                    {
                        "1. Check your system manufacturer's website",
                        "2. Look for 'Intel ME Firmware Update' or similar",
                        "3. Download the update for your specific model",
                        "4. Run the update tool as Administrator",
                        "5. Restart when prompted",
                        "6. Verify new version with Intel ME tools"
                    }
                });
                break;
        }

        return actions;
    }

    #endregion

    #region Execute Actions

    /// <summary>
    /// Execute a single remediation action
    /// </summary>
    public RemediationResult ExecuteAction(RemediationAction action)
    {
        Log($"Executing: {action.Description}");

        try
        {
            return action.Type switch
            {
                RemediationType.QuarantineFile => QuarantineFile(action),
                RemediationType.DeleteRegistryKey => DeleteRegistryKey(action),
                RemediationType.TerminateProcess => TerminateProcess(action),
                RemediationType.FixBootConfig => ExecuteCommand(action),
                _ => new RemediationResult
                {
                    Success = false,
                    Message = "This action requires manual intervention",
                    Action = action
                }
            };
        }
        catch (Exception ex)
        {
            Log($"Error: {ex.Message}");
            return new RemediationResult
            {
                Success = false,
                Message = ex.Message,
                Action = action
            };
        }
    }

    private RemediationResult QuarantineFile(RemediationAction action)
    {
        if (string.IsNullOrEmpty(action.TargetPath))
            return new RemediationResult { Success = false, Message = "No target path", Action = action };

        if (!File.Exists(action.TargetPath) && !Directory.Exists(action.TargetPath))
            return new RemediationResult { Success = false, Message = "Target not found", Action = action };

        var quarantineName = $"{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(action.TargetPath)}.quarantine";
        var quarantineDest = Path.Combine(_quarantinePath, quarantineName);

        // Create quarantine info file
        var infoPath = quarantineDest + ".info";
        var info = new
        {
            OriginalPath = action.TargetPath,
            QuarantineTime = DateTime.Now,
            Detection = action.Detection.Description,
            Severity = action.Detection.Severity.ToString()
        };
        File.WriteAllText(infoPath, JsonSerializer.Serialize(info, new JsonSerializerOptions { WriteIndented = true }));

        if (File.Exists(action.TargetPath))
        {
            File.Move(action.TargetPath, quarantineDest);
        }
        else if (Directory.Exists(action.TargetPath))
        {
            Directory.Move(action.TargetPath, quarantineDest);
        }

        Log($"Quarantined: {action.TargetPath} -> {quarantineDest}");

        return new RemediationResult
        {
            Success = true,
            Message = $"Quarantined to: {quarantineName}",
            Action = action
        };
    }

    private RemediationResult DeleteRegistryKey(RemediationAction action)
    {
        if (string.IsNullOrEmpty(action.TargetPath))
            return new RemediationResult { Success = false, Message = "No registry path", Action = action };

        var parts = action.TargetPath.Split('\\', 2);
        if (parts.Length < 2)
            return new RemediationResult { Success = false, Message = "Invalid registry path", Action = action };

        var hive = parts[0].ToUpper() switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
            _ => throw new ArgumentException("Unknown registry hive")
        };

        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        var subKeyPath = parts[1];
        var parentPath = Path.GetDirectoryName(subKeyPath)?.Replace('/', '\\') ?? "";
        var keyName = Path.GetFileName(subKeyPath);

        using var parentKey = baseKey.OpenSubKey(parentPath, true);
        if (parentKey == null)
            return new RemediationResult { Success = false, Message = "Parent key not found", Action = action };

        parentKey.DeleteSubKeyTree(keyName, false);
        Log($"Deleted registry key: {action.TargetPath}");

        return new RemediationResult
        {
            Success = true,
            Message = "Registry key deleted",
            Action = action
        };
    }

    private RemediationResult TerminateProcess(RemediationAction action)
    {
        if (action.TargetPID <= 0)
            return new RemediationResult { Success = false, Message = "Invalid PID", Action = action };

        try
        {
            var process = Process.GetProcessById(action.TargetPID);
            var name = process.ProcessName;
            process.Kill();
            process.WaitForExit(5000);

            Log($"Terminated process: {name} (PID: {action.TargetPID})");

            return new RemediationResult
            {
                Success = true,
                Message = $"Process {name} terminated",
                Action = action
            };
        }
        catch (ArgumentException)
        {
            return new RemediationResult
            {
                Success = true,
                Message = "Process already terminated",
                Action = action
            };
        }
    }

    private RemediationResult ExecuteCommand(RemediationAction action)
    {
        if (string.IsNullOrEmpty(action.Command))
            return new RemediationResult { Success = false, Message = "No command specified", Action = action };

        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c {action.Command}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null)
            return new RemediationResult { Success = false, Message = "Failed to start command", Action = action };

        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        Log($"Executed: {action.Command} (Exit: {process.ExitCode})");

        return new RemediationResult
        {
            Success = process.ExitCode == 0,
            Message = process.ExitCode == 0 ? "Command executed successfully" : error,
            Action = action
        };
    }

    #endregion

    #region Reporting

    public string GenerateReport(ScanResult scanResult, List<RemediationResult>? remediationResults = null)
    {
        var sb = new StringBuilder();

        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine("                    DEEPSCAN SECURITY REPORT                    ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine();
        sb.AppendLine($"Report Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Computer Name: {Environment.MachineName}");
        sb.AppendLine($"User: {Environment.UserName}");
        sb.AppendLine($"OS: {Environment.OSVersion}");
        sb.AppendLine($"Scan Duration: {scanResult.ScanDuration.TotalSeconds:F1} seconds");
        sb.AppendLine();

        // Summary
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine("THREAT SUMMARY");
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine($"  Critical: {scanResult.CriticalCount}");
        sb.AppendLine($"  High:     {scanResult.HighCount}");
        sb.AppendLine($"  Medium:   {scanResult.MediumCount}");
        sb.AppendLine($"  Low:      {scanResult.LowCount}");
        sb.AppendLine($"  Info:     {scanResult.InfoCount}");
        sb.AppendLine();

        // Detailed findings
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine("DETAILED FINDINGS");
        sb.AppendLine("───────────────────────────────────────────────────────────────");

        foreach (var detection in scanResult.Detections.OrderByDescending(d => d.Severity))
        {
            sb.AppendLine();
            sb.AppendLine($"[{detection.Severity}] {detection.Category}");
            sb.AppendLine($"  Ring: {detection.Ring}");
            sb.AppendLine($"  Description: {detection.Description}");
            if (!string.IsNullOrEmpty(detection.TechnicalDetails))
                sb.AppendLine($"  Details: {detection.TechnicalDetails}");
            if (!string.IsNullOrEmpty(detection.Remediation))
                sb.AppendLine($"  Remediation: {detection.Remediation}");
        }

        // Remediation results
        if (remediationResults?.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine("REMEDIATION ACTIONS TAKEN");
            sb.AppendLine("───────────────────────────────────────────────────────────────");

            foreach (var result in remediationResults)
            {
                var status = result.Success ? "✓" : "✗";
                sb.AppendLine($"  [{status}] {result.Action.Description}");
                sb.AppendLine($"      Result: {result.Message}");
            }
        }

        sb.AppendLine();
        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine("                         END OF REPORT                          ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");

        return sb.ToString();
    }

    public void SaveReport(string report, string? customPath = null)
    {
        var fileName = $"DeepScan_Report_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
        var path = customPath ?? Path.Combine(_logPath, fileName);
        File.WriteAllText(path, report);
    }

    #endregion

    #region Helpers

    private void Log(string message)
    {
        var entry = $"[{DateTime.Now:HH:mm:ss}] {message}";
        _logs.Add(entry);
        Console.WriteLine($"  {entry}");
    }

    private static string? ExtractPath(string description)
    {
        // Extract file path from description like "Suspicious file: C:\path\file.exe"
        var colonIndex = description.LastIndexOf(": ");
        if (colonIndex > 0 && colonIndex < description.Length - 2)
        {
            var path = description[(colonIndex + 2)..].Trim();
            if (path.Contains(":\\") || path.StartsWith("\\\\"))
                return path;
        }
        return null;
    }

    private static string? ExtractRegistryPath(string description)
    {
        // Extract registry path from description
        if (description.Contains("HKLM\\") || description.Contains("HKCU\\"))
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                description, @"(HK[A-Z]+\\[^\s]+)");
            if (match.Success)
                return match.Groups[1].Value;
        }
        return null;
    }

    private static int ExtractPID(string description)
    {
        var match = System.Text.RegularExpressions.Regex.Match(description, @"PID[:\s]+(\d+)");
        if (match.Success && int.TryParse(match.Groups[1].Value, out int pid))
            return pid;
        return 0;
    }

    #endregion
}

public class RemediationAction
{
    public required Detection Detection { get; init; }
    public required RemediationType Type { get; init; }
    public required string Description { get; init; }
    public bool CanAutomate { get; init; }
    public RemediationRisk Risk { get; init; }
    public string? TargetPath { get; init; }
    public int TargetPID { get; init; }
    public string? Command { get; init; }
    public string[]? ManualSteps { get; init; }
}

public class RemediationResult
{
    public bool Success { get; init; }
    public required string Message { get; init; }
    public required RemediationAction Action { get; init; }
}

public enum RemediationType
{
    QuarantineFile,
    DeleteFile,
    DeleteRegistryKey,
    TerminateProcess,
    DisableDriver,
    FixBootConfig,
    RestartRequired,
    Manual
}

public enum RemediationRisk
{
    Low,
    Medium,
    High,
    Critical
}
