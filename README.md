# R77Detector

A multi-ring rootkit detection system for Windows that scans from Ring 3 (User Mode) down to Ring -3 (Intel ME/AMD PSP). Originally designed to detect the [r77-rootkit](https://github.com/bytecode77/r77-rootkit), it has evolved into a comprehensive deep system scanner.

## Features

### Detection Capabilities

| Ring Level | Description | Detection Methods |
|------------|-------------|-------------------|
| **Ring 3** | User Mode | API hook detection, AMSI bypass detection, hidden process comparison, DLL injection indicators, `$77` prefix scanning |
| **Ring 0** | Kernel Mode | Driver signature verification (WinVerifyTrust), kernel debugger detection, Code Integrity status, DKOM indicators, DSE bypass detection |
| **Ring -1** | Hypervisor | CPUID inspection, timing anomaly analysis, Red Pill detection, VT-x/AMD-V verification |
| **Ring -2** | Firmware/UEFI | Secure Boot status, UEFI variable analysis, bootloader integrity, known UEFI threat signatures |
| **Ring -3** | Management Engine | Intel ME/AMD PSP status, AMT configuration, known ME vulnerabilities |

### Components

- **R77Detector** - Console-based detector with direct syscalls to bypass usermode API hooks
- **R77DetectorGUI** - WPF GUI with cybersecurity-themed interface
- **DeepScan** - Advanced multi-ring scanner with remediation capabilities
- **R77TestSuite** - Deploys harmless mock indicators to test detection

## Building

Requires .NET 8.0 SDK.

```bash
# Build all projects
dotnet build

# Build DeepScan (Release)
cd DeepScan
dotnet build --configuration Release
```

## Usage

### DeepScan (Recommended)

```bash
cd DeepScan/bin/Release/net8.0-windows
./DeepScan.exe
```

For full detection capabilities, run as Administrator.

### Console Detector

```bash
cd bin/Release/net8.0-windows
./R77Detector.exe
```

### GUI Version

```bash
cd R77DetectorGUI/bin/Release/net8.0-windows
./R77DetectorGUI.exe
```

### Test Suite

Deploy mock r77 indicators to test the detector:

```bash
cd R77TestSuite
dotnet run
```

## r77-Rootkit Detection

The scanner specifically detects r77-rootkit indicators:

- Files/directories with `$77` prefix
- Registry keys at `HKLM\SOFTWARE\$77config` and `HKCU\SOFTWARE\$77config`
- r77 DLLs (`r77-x64.dll`, `r77-x86.dll`)
- Shellcode files (`Install.shellcode`)
- Associated mutexes (`$77Mutex`, `r77-rootkit`)

## Remediation

DeepScan includes remediation capabilities:

- **Auto-fix** - Automatically quarantine Ring 3 threats (files, registry keys, processes)
- **Manual guidance** - Step-by-step instructions for deeper threats (Ring 0 and below)
- **Quarantine** - Suspicious files are moved to `%LOCALAPPDATA%\DeepScan\Quarantine`

## Technical Details

### Direct Syscalls

The detector uses direct NT API calls (`NtQuerySystemInformation`, `NtOpenKey`) to bypass potential usermode API hooks that rootkits may install:

```csharp
// Compare hooked API results vs direct syscall results
var apiProcesses = Process.GetProcesses();
var syscallProcesses = DirectSyscalls.GetProcessList();
// Discrepancies indicate hidden processes
```

### Driver Signature Verification

Uses `WinVerifyTrust` API for proper Authenticode verification, handling both embedded and catalog-signed drivers to avoid false positives on legitimate Windows drivers.

## Screenshots

```
  ██████╗ ███████╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║  ██║█████╗  █████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
  ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
  ██████╔╝███████╗███████╗██║     ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

         Multi-Ring Rootkit Detection System v1.0
         Ring 3 → Ring 0 → Ring -1 → Ring -2 → Ring -3

  ┌─────────────────────────┬──────────┬────────┬────────┬───────┐
  │ Ring Level              │ Critical │ High   │ Medium │ Low   │
  ├─────────────────────────┼──────────┼────────┼────────┼───────┤
  │ Ring 3 (User)           │      0   │      8 │      0 │     0 │
  │ Ring 0 (Kernel)         │      0   │      3 │      0 │     0 │
  │ Ring -2 (Firmware)      │      0   │      2 │      0 │     0 │
  │ Ring -3 (ME/PSP)        │      0   │      1 │      1 │     0 │
  └─────────────────────────┴──────────┴────────┴────────┴───────┘
```

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning systems you do not own.

## License

MIT License
