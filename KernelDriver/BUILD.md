# R77 Detector Kernel Driver - Build Instructions

## Prerequisites

1. **Windows Driver Kit (WDK)** - Install from Microsoft
   - Download: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
   - Version: Windows 10 WDK or later

2. **Visual Studio 2019/2022** with:
   - Desktop development with C++
   - Windows 10/11 SDK

3. **Driver Signing** (for testing):
   - Enable test signing: `bcdedit /set testsigning on`
   - Or use a valid code signing certificate for production

## Building with Visual Studio

1. Open `R77Driver.vcxproj` in Visual Studio
2. Select configuration (Debug/Release) and platform (x64/Win32)
3. Build Solution (Ctrl+Shift+B)
4. Output: `x64\Debug\R77Driver.sys` or `x64\Release\R77Driver.sys`

## Building with WDK Command Line

1. Open "Developer Command Prompt for VS" or WDK build environment
2. Navigate to KernelDriver directory
3. Run: `build -cZg`

## Installation

### Manual Installation (Test)

```cmd
rem Copy driver to system32\drivers
copy R77Driver.sys %SystemRoot%\system32\drivers\

rem Create service
sc create R77Driver type= kernel binPath= %SystemRoot%\system32\drivers\R77Driver.sys

rem Start service
sc start R77Driver

rem Stop service
sc stop R77Driver

rem Delete service
sc delete R77Driver
```

### INF Installation

```cmd
rem Install using INF
pnputil /add-driver R77Driver.inf /install

rem Remove
pnputil /delete-driver R77Driver.inf /uninstall
```

## Testing

1. Enable kernel debugging (optional):
   ```cmd
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```

2. View debug output:
   - Use DebugView from Sysinternals
   - Or WinDbg kernel debugger

3. Use the user-mode test application to send IOCTLs:
   ```cmd
   R77Test.exe
   ```

## IOCTL Interface

| IOCTL Code | Description |
|------------|-------------|
| IOCTL_R77_ENUM_PROCESSES | Enumerate all processes from EPROCESS list |
| IOCTL_R77_GET_HIDDEN_PROCESSES | Get only hidden processes |
| IOCTL_R77_ENUM_DRIVERS | Enumerate loaded drivers |
| IOCTL_R77_DETECT_SSDT_HOOKS | Detect SSDT hooks |
| IOCTL_R77_ENUM_CALLBACKS | Enumerate system callbacks |
| IOCTL_R77_GET_VERSION | Get driver version info |

## Notes

- This driver uses undocumented kernel structures
- EPROCESS offsets vary by Windows version
- Test thoroughly on target Windows builds
- Always test in a VM first
- Production use requires proper driver signing
