using System.Runtime.InteropServices;
using System.Text;

namespace DeepScan.Core;

/// <summary>
/// Native Windows API declarations for deep system inspection
/// </summary>
internal static class NativeMethods
{
    #region Kernel32

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
        uint nSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFirmwareType(out FirmwareType firmwareType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetFirmwareEnvironmentVariable(
        string lpName, string lpGuid, IntPtr pBuffer, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsProcessorFeaturePresent(uint processorFeature);

    [DllImport("kernel32.dll")]
    public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool QueryPerformanceFrequency(out long lpFrequency);

    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_READ = 0x0010;

    #endregion

    #region Ntdll

    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(
        int SystemInformationClass, IntPtr SystemInformation,
        int SystemInformationLength, out int ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle, int ProcessInformationClass,
        IntPtr ProcessInformation, int ProcessInformationLength, out int ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtOpenKey(
        out IntPtr KeyHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    public static extern int NtClose(IntPtr Handle);

    [DllImport("ntdll.dll")]
    public static extern void RtlInitUnicodeString(
        ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

    // System information classes
    public const int SystemModuleInformation = 11;
    public const int SystemProcessInformation = 5;
    public const int SystemKernelDebuggerInformation = 35;
    public const int SystemCodeIntegrityInformation = 103;
    public const int SystemSecureBootInformation = 145;

    #endregion

    #region Advapi32

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle, int TokenInformationClass,
        IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(
        string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, int BufferLength,
        IntPtr PreviousState, IntPtr ReturnLength);

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const int SE_PRIVILEGE_ENABLED = 0x00000002;

    #endregion

    #region Psapi

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumDeviceDrivers(
        [Out] IntPtr[] lpImageBase, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetDeviceDriverBaseName(
        IntPtr ImageBase, StringBuilder lpFilename, uint nSize);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetDeviceDriverFileName(
        IntPtr ImageBase, StringBuilder lpFilename, uint nSize);

    #endregion

    #region SetupAPI

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr SetupDiGetClassDevs(
        ref Guid ClassGuid, string? Enumerator, IntPtr hwndParent, uint Flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    #endregion

    #region Structures

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_MODULE_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr Reserved2;
        public IntPtr ImageBase;
        public uint ImageSize;
        public uint Flags;
        public ushort LoadOrderIndex;
        public ushort InitOrderIndex;
        public ushort LoadCount;
        public ushort ModuleNameOffset;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ImageName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_CODEINTEGRITY_INFORMATION
    {
        public uint Length;
        public uint CodeIntegrityOptions;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_SECUREBOOT_INFORMATION
    {
        public byte SecureBootEnabled;
        public byte SecureBootCapable;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_KERNEL_DEBUGGER_INFORMATION
    {
        public byte KernelDebuggerEnabled;
        public byte KernelDebuggerNotPresent;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    public enum FirmwareType : uint
    {
        Unknown = 0,
        Bios = 1,
        Uefi = 2,
        Max = 3
    }

    #endregion

    #region WinTrust (Authenticode signature verification)

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);

    // GUID for Authenticode verification
    public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    // WinVerifyTrust return codes
    public const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    public const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    public const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
    public const int CRYPT_E_SECURITY_SETTINGS = unchecked((int)0x80092026);

    // WTD_UI values
    public const uint WTD_UI_ALL = 1;
    public const uint WTD_UI_NONE = 2;
    public const uint WTD_UI_NOBAD = 3;
    public const uint WTD_UI_NOGOOD = 4;

    // WTD_REVOKE values
    public const uint WTD_REVOKE_NONE = 0;
    public const uint WTD_REVOKE_WHOLECHAIN = 1;

    // WTD_CHOICE values
    public const uint WTD_CHOICE_FILE = 1;
    public const uint WTD_CHOICE_CATALOG = 2;

    // WTD_STATEACTION values
    public const uint WTD_STATEACTION_IGNORE = 0;
    public const uint WTD_STATEACTION_VERIFY = 1;
    public const uint WTD_STATEACTION_CLOSE = 2;
    public const uint WTD_STATEACTION_AUTO_CACHE = 3;
    public const uint WTD_STATEACTION_AUTO_CACHE_FLUSH = 4;

    // Flags
    public const uint WTD_SAFER_FLAG = 0x100;
    public const uint WTD_HASH_ONLY_FLAG = 0x200;
    public const uint WTD_USE_DEFAULT_OSVER_CHECK = 0x400;
    public const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // WINTRUST_FILE_INFO*
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    #endregion

    #region CPU Instructions (via inline assembly or intrinsics)

    // CPUID wrapper
    [DllImport("kernel32.dll")]
    public static extern bool IsProcessorFeaturePresent(int ProcessorFeature);

    public const int PF_VIRT_FIRMWARE_ENABLED = 21;
    public const int PF_SECOND_LEVEL_ADDRESS_TRANSLATION = 20;

    #endregion
}

/// <summary>
/// Utility methods for native operations
/// </summary>
public static class NativeUtils
{
    public static bool EnablePrivilege(string privilegeName)
    {
        if (!NativeMethods.OpenProcessToken(
            NativeMethods.GetCurrentProcess(),
            NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY,
            out IntPtr tokenHandle))
        {
            return false;
        }

        try
        {
            if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out var luid))
                return false;

            var tp = new NativeMethods.TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = NativeMethods.SE_PRIVILEGE_ENABLED
            };

            return NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            NativeMethods.CloseHandle(tokenHandle);
        }
    }
}
