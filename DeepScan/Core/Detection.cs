namespace DeepScan.Core;

/// <summary>
/// Represents a single detection finding
/// </summary>
public record Detection
{
    public required string Module { get; init; }
    public required string Category { get; init; }
    public required Severity Severity { get; init; }
    public required string Description { get; init; }
    public required RingLevel Ring { get; init; }
    public string? TechnicalDetails { get; init; }
    public string? Remediation { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.Now;
}

public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum RingLevel
{
    Ring3_UserMode,
    Ring0_Kernel,
    RingMinus1_Hypervisor,
    RingMinus2_Firmware,
    RingMinus3_ManagementEngine
}

/// <summary>
/// Interface for all detection modules
/// </summary>
public interface IDetectionModule
{
    string Name { get; }
    string Description { get; }
    RingLevel TargetRing { get; }
    bool IsSupported { get; }
    Task<IEnumerable<Detection>> ScanAsync(IProgress<string>? progress = null);
}

/// <summary>
/// Central detection engine that orchestrates all modules
/// </summary>
public class DetectionEngine
{
    private readonly List<IDetectionModule> _modules = new();
    private readonly List<Detection> _detections = new();

    public IReadOnlyList<Detection> Detections => _detections.AsReadOnly();
    public IReadOnlyList<IDetectionModule> Modules => _modules.AsReadOnly();

    public void RegisterModule(IDetectionModule module)
    {
        _modules.Add(module);
    }

    public async Task<ScanResult> RunFullScanAsync(IProgress<ScanProgress>? progress = null)
    {
        _detections.Clear();
        var startTime = DateTime.Now;
        int completedModules = 0;

        foreach (var module in _modules.Where(m => m.IsSupported))
        {
            progress?.Report(new ScanProgress
            {
                CurrentModule = module.Name,
                ModulesCompleted = completedModules,
                TotalModules = _modules.Count(m => m.IsSupported),
                Status = $"Running {module.Name}..."
            });

            try
            {
                var moduleProgress = new Progress<string>(msg =>
                {
                    progress?.Report(new ScanProgress
                    {
                        CurrentModule = module.Name,
                        ModulesCompleted = completedModules,
                        TotalModules = _modules.Count(m => m.IsSupported),
                        Status = msg
                    });
                });

                var results = await module.ScanAsync(moduleProgress);
                _detections.AddRange(results);
            }
            catch (Exception ex)
            {
                _detections.Add(new Detection
                {
                    Module = module.Name,
                    Category = "Error",
                    Severity = Severity.Info,
                    Description = $"Module failed: {ex.Message}",
                    Ring = module.TargetRing
                });
            }

            completedModules++;
        }

        return new ScanResult
        {
            Detections = _detections.ToList(),
            ScanDuration = DateTime.Now - startTime,
            ModulesRun = completedModules
        };
    }
}

public class ScanProgress
{
    public required string CurrentModule { get; init; }
    public required int ModulesCompleted { get; init; }
    public required int TotalModules { get; init; }
    public required string Status { get; init; }
    public double PercentComplete => TotalModules > 0 ? (double)ModulesCompleted / TotalModules * 100 : 0;
}

public class ScanResult
{
    public required List<Detection> Detections { get; init; }
    public required TimeSpan ScanDuration { get; init; }
    public required int ModulesRun { get; init; }

    public int CriticalCount => Detections.Count(d => d.Severity == Severity.Critical);
    public int HighCount => Detections.Count(d => d.Severity == Severity.High);
    public int MediumCount => Detections.Count(d => d.Severity == Severity.Medium);
    public int LowCount => Detections.Count(d => d.Severity == Severity.Low);
    public int InfoCount => Detections.Count(d => d.Severity == Severity.Info);

    public bool IsClean => CriticalCount == 0 && HighCount == 0;
}
