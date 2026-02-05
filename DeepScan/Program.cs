using System.Security.Principal;
using DeepScan.Core;
using DeepScan.Modules;

namespace DeepScan;

class Program
{
    static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        PrintBanner();

        // Check admin privileges
        bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);

        if (!isAdmin)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ⚠ WARNING: Not running as Administrator");
            Console.WriteLine("    Some detection capabilities will be limited.");
            Console.WriteLine("    For full deep scan, restart as Administrator.\n");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ Running with Administrator privileges\n");
            Console.ResetColor();
        }

        // Initialize detection engine
        var engine = new DetectionEngine();

        // Register all modules
        // Order: User-mode detection first, then kernel trust verification (if driver available),
        // then remaining Ring 0 checks, followed by deeper ring levels
        engine.RegisterModule(new Ring3Module());
        engine.RegisterModule(new KernelTrustModule());  // Uses kernel driver for trusted enumeration
        engine.RegisterModule(new Ring0Module());
        engine.RegisterModule(new HypervisorModule());
        engine.RegisterModule(new FirmwareModule());
        engine.RegisterModule(new ManagementEngineModule());

        Console.WriteLine($"  Loaded {engine.Modules.Count} detection modules:\n");
        foreach (var module in engine.Modules)
        {
            var supported = module.IsSupported ? "✓" : "✗";
            var color = module.IsSupported ? ConsoleColor.Green : ConsoleColor.DarkGray;
            Console.ForegroundColor = color;
            Console.WriteLine($"    [{supported}] {module.Name}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"        {module.Description}\n");
        }
        Console.ResetColor();

        Console.WriteLine(new string('─', 70));
        Console.WriteLine("  Press ENTER to start deep scan...");
        Console.ReadLine();

        // Run scan with progress
        try { Console.Clear(); } catch { }
        PrintBanner();
        Console.WriteLine("  SCANNING IN PROGRESS\n");

        string lastModule = "";
        var progress = new Progress<ScanProgress>(p =>
        {
            if (p.CurrentModule != lastModule)
            {
                lastModule = p.CurrentModule;
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine($"  [{p.PercentComplete:F0}%] {p.CurrentModule}");
                Console.ResetColor();
            }
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"        {p.Status}");
            Console.ResetColor();
        });

        var result = await engine.RunFullScanAsync(progress);

        // Print results
        try { Console.Clear(); } catch { }
        PrintBanner();
        PrintResults(result);

        // Offer remediation if threats found
        if (result.CriticalCount > 0 || result.HighCount > 0 || result.MediumCount > 0)
        {
            await ShowRemediationMenu(result, isAdmin);
        }
        else
        {
            Console.WriteLine("\n  Press ENTER to exit...");
            Console.ReadLine();
        }
    }

    static async Task ShowRemediationMenu(ScanResult result, bool isAdmin)
    {
        var remediation = new RemediationEngine();
        var actions = remediation.GenerateRemediationPlan(result.Detections);

        while (true)
        {
            Console.WriteLine("\n" + new string('─', 70));
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  REMEDIATION OPTIONS");
            Console.ResetColor();
            Console.WriteLine(new string('─', 70));

            Console.WriteLine("\n  What would you like to do?\n");
            Console.WriteLine("    [1] View remediation plan");
            Console.WriteLine("    [2] Auto-fix safe issues (Ring 3 only)");
            Console.WriteLine("    [3] View manual remediation steps");
            Console.WriteLine("    [4] Generate & save report");
            Console.WriteLine("    [5] Exit\n");

            Console.Write("  Select option: ");
            var choice = Console.ReadLine()?.Trim();

            switch (choice)
            {
                case "1":
                    ShowRemediationPlan(actions);
                    break;
                case "2":
                    if (!isAdmin)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("\n  ⚠ Some actions require Administrator privileges.");
                        Console.WriteLine("    Restart as Administrator for full remediation.\n");
                        Console.ResetColor();
                    }
                    await ExecuteAutoRemediation(remediation, actions);
                    break;
                case "3":
                    ShowManualSteps(actions);
                    break;
                case "4":
                    SaveReport(remediation, result);
                    break;
                case "5":
                    return;
                default:
                    Console.WriteLine("  Invalid option.");
                    break;
            }
        }
    }

    static void ShowRemediationPlan(List<RemediationAction> actions)
    {
        Console.WriteLine("\n" + new string('─', 70));
        Console.WriteLine("  REMEDIATION PLAN");
        Console.WriteLine(new string('─', 70) + "\n");

        var automated = actions.Where(a => a.CanAutomate).ToList();
        var manual = actions.Where(a => !a.CanAutomate).ToList();

        if (automated.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  AUTOMATED ACTIONS ({automated.Count}):");
            Console.ResetColor();

            foreach (var action in automated)
            {
                var risk = action.Risk switch
                {
                    RemediationRisk.Low => ("Low", ConsoleColor.Green),
                    RemediationRisk.Medium => ("Med", ConsoleColor.Yellow),
                    RemediationRisk.High => ("High", ConsoleColor.DarkYellow),
                    _ => ("Crit", ConsoleColor.Red)
                };

                Console.Write("    [");
                Console.ForegroundColor = risk.Item2;
                Console.Write(risk.Item1);
                Console.ResetColor();
                Console.WriteLine($"] {action.Description}");
            }
        }

        if (manual.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n  MANUAL ACTIONS REQUIRED ({manual.Count}):");
            Console.ResetColor();

            foreach (var action in manual)
            {
                Console.WriteLine($"    • {action.Description}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"      Ring: {action.Detection.Ring}");
                Console.ResetColor();
            }
        }

        Console.WriteLine("\n  Press ENTER to continue...");
        Console.ReadLine();
    }

    static async Task ExecuteAutoRemediation(RemediationEngine remediation, List<RemediationAction> actions)
    {
        var safeActions = actions
            .Where(a => a.CanAutomate && a.Risk <= RemediationRisk.Medium)
            .ToList();

        if (safeActions.Count == 0)
        {
            Console.WriteLine("\n  No automated actions available.");
            Console.WriteLine("  All detected issues require manual remediation.");
            return;
        }

        Console.WriteLine($"\n  Found {safeActions.Count} action(s) that can be automated:\n");

        foreach (var action in safeActions)
        {
            Console.WriteLine($"    • {action.Description}");
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n  ⚠ WARNING: This will modify your system.");
        Console.ResetColor();
        Console.Write("  Type 'YES' to proceed: ");

        var confirm = Console.ReadLine()?.Trim();
        if (confirm != "YES")
        {
            Console.WriteLine("  Cancelled.");
            return;
        }

        Console.WriteLine("\n  Executing remediation...\n");

        var results = new List<RemediationResult>();
        foreach (var action in safeActions)
        {
            var result = remediation.ExecuteAction(action);
            results.Add(result);

            var status = result.Success ? "✓" : "✗";
            var color = result.Success ? ConsoleColor.Green : ConsoleColor.Red;

            Console.ForegroundColor = color;
            Console.Write($"  [{status}] ");
            Console.ResetColor();
            Console.WriteLine($"{action.Description}: {result.Message}");

            await Task.Delay(100); // Small delay for visual feedback
        }

        var succeeded = results.Count(r => r.Success);
        var failed = results.Count(r => !r.Success);

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  Remediation complete: {succeeded} succeeded, {failed} failed");
        Console.ResetColor();

        if (succeeded > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n  ⚠ A system restart is recommended to complete remediation.");
            Console.ResetColor();
        }

        Console.WriteLine("\n  Press ENTER to continue...");
        Console.ReadLine();
    }

    static void ShowManualSteps(List<RemediationAction> actions)
    {
        var manualActions = actions.Where(a => a.ManualSteps?.Length > 0).ToList();

        if (manualActions.Count == 0)
        {
            Console.WriteLine("\n  No manual steps available for current detections.");
            return;
        }

        Console.WriteLine("\n" + new string('─', 70));
        Console.WriteLine("  MANUAL REMEDIATION STEPS");
        Console.WriteLine(new string('─', 70));

        int stepNum = 1;
        foreach (var action in manualActions)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n  [{stepNum}] {action.Description}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"      Severity: {action.Detection.Severity} | Ring: {action.Detection.Ring}");
            Console.ResetColor();

            if (action.ManualSteps != null)
            {
                Console.WriteLine();
                foreach (var step in action.ManualSteps)
                {
                    if (step.StartsWith("⚠"))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"      {step}");
                        Console.ResetColor();
                    }
                    else if (string.IsNullOrWhiteSpace(step))
                    {
                        Console.WriteLine();
                    }
                    else
                    {
                        Console.WriteLine($"      {step}");
                    }
                }
            }

            stepNum++;
        }

        Console.WriteLine("\n  Press ENTER to continue...");
        Console.ReadLine();
    }

    static void SaveReport(RemediationEngine remediation, ScanResult result)
    {
        Console.Write("\n  Enter report path (or press ENTER for default): ");
        var customPath = Console.ReadLine()?.Trim();

        if (string.IsNullOrEmpty(customPath))
            customPath = null;

        var report = remediation.GenerateReport(result);
        remediation.SaveReport(report, customPath);

        var savedPath = customPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DeepScan", "Logs");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"\n  ✓ Report saved to: {savedPath}");
        Console.ResetColor();

        Console.WriteLine("\n  Press ENTER to continue...");
        Console.ReadLine();
    }

    static void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
  ██████╗ ███████╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║  ██║█████╗  █████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
  ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║
  ██████╔╝███████╗███████╗██║         ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝ ╚══════╝╚══════╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
");
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.WriteLine("         Multi-Ring Rootkit Detection System v1.0");
        Console.WriteLine("         Ring 3 → Ring 0 → Ring -1 → Ring -2 → Ring -3\n");
        Console.ResetColor();
    }

    static void PrintResults(ScanResult result)
    {
        Console.WriteLine(new string('═', 70));
        Console.WriteLine("  SCAN RESULTS");
        Console.WriteLine(new string('═', 70));

        Console.WriteLine($"\n  Scan completed in {result.ScanDuration.TotalSeconds:F1} seconds");
        Console.WriteLine($"  Modules executed: {result.ModulesRun}\n");

        // Summary by ring level
        Console.WriteLine("  ┌────────────────────────┬──────────┬───────┬────────┬──────┐");
        Console.WriteLine("  │ Ring Level             │ Critical │ High  │ Medium │ Low  │");
        Console.WriteLine("  ├────────────────────────┼──────────┼───────┼────────┼──────┤");

        foreach (RingLevel ring in Enum.GetValues<RingLevel>())
        {
            var ringDetections = result.Detections.Where(d => d.Ring == ring).ToList();
            if (ringDetections.Count == 0) continue;

            int critical = ringDetections.Count(d => d.Severity == Severity.Critical);
            int high = ringDetections.Count(d => d.Severity == Severity.High);
            int medium = ringDetections.Count(d => d.Severity == Severity.Medium);
            int low = ringDetections.Count(d => d.Severity == Severity.Low);

            string ringName = ring switch
            {
                RingLevel.Ring3_UserMode => "Ring 3 (User)",
                RingLevel.Ring0_Kernel => "Ring 0 (Kernel)",
                RingLevel.RingMinus1_Hypervisor => "Ring -1 (Hypervisor)",
                RingLevel.RingMinus2_Firmware => "Ring -2 (Firmware)",
                RingLevel.RingMinus3_ManagementEngine => "Ring -3 (ME/PSP)",
                _ => ring.ToString()
            };

            Console.Write($"  │ {ringName,-22} │");
            PrintColoredCount(critical, ConsoleColor.Red);
            Console.Write("│");
            PrintColoredCount(high, ConsoleColor.DarkYellow);
            Console.Write("│");
            PrintColoredCount(medium, ConsoleColor.Yellow);
            Console.Write("│");
            PrintColoredCount(low, ConsoleColor.Gray);
            Console.WriteLine("│");
        }

        Console.WriteLine("  └────────────────────────┴──────────┴───────┴────────┴──────┘");

        // Overall threat level
        Console.WriteLine();
        if (result.CriticalCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ████████████████████████████████████████████████████████████");
            Console.WriteLine("  █  THREAT LEVEL: CRITICAL - Immediate action required!    █");
            Console.WriteLine("  ████████████████████████████████████████████████████████████");
        }
        else if (result.HighCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("  ████████████████████████████████████████████████████████████");
            Console.WriteLine("  █  THREAT LEVEL: HIGH - Investigation recommended         █");
            Console.WriteLine("  ████████████████████████████████████████████████████████████");
        }
        else if (result.MediumCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ████████████████████████████████████████████████████████████");
            Console.WriteLine("  █  THREAT LEVEL: MEDIUM - Review findings                 █");
            Console.WriteLine("  ████████████████████████████████████████████████████████████");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ████████████████████████████████████████████████████████████");
            Console.WriteLine("  █  SYSTEM APPEARS CLEAN - No significant threats found    █");
            Console.WriteLine("  ████████████████████████████████████████████████████████████");
        }
        Console.ResetColor();

        // Detailed findings
        if (result.Detections.Any(d => d.Severity >= Severity.Medium))
        {
            Console.WriteLine("\n" + new string('─', 70));
            Console.WriteLine("  DETAILED FINDINGS\n");

            var significantDetections = result.Detections
                .Where(d => d.Severity >= Severity.Medium)
                .OrderByDescending(d => d.Severity)
                .ThenBy(d => d.Ring);

            foreach (var detection in significantDetections)
            {
                var severityColor = detection.Severity switch
                {
                    Severity.Critical => ConsoleColor.Red,
                    Severity.High => ConsoleColor.DarkYellow,
                    Severity.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                Console.ForegroundColor = severityColor;
                Console.Write($"  [{detection.Severity.ToString().ToUpper()}]");
                Console.ResetColor();
                Console.WriteLine($" {detection.Category}");
                Console.WriteLine($"    {detection.Description}");

                if (!string.IsNullOrEmpty(detection.TechnicalDetails))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    var details = detection.TechnicalDetails.Split('\n');
                    foreach (var line in details.Take(3))
                    {
                        Console.WriteLine($"    > {line}");
                    }
                    Console.ResetColor();
                }

                if (!string.IsNullOrEmpty(detection.Remediation))
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"    → {detection.Remediation}");
                    Console.ResetColor();
                }

                Console.WriteLine();
            }
        }

        // Info findings (collapsed)
        var infoCount = result.Detections.Count(d => d.Severity <= Severity.Low);
        if (infoCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  + {infoCount} informational finding(s) not shown");
            Console.ResetColor();
        }
    }

    static void PrintColoredCount(int count, ConsoleColor color)
    {
        if (count > 0)
            Console.ForegroundColor = color;
        else
            Console.ForegroundColor = ConsoleColor.DarkGray;

        Console.Write($" {count,6}  ");
        Console.ResetColor();
    }
}
