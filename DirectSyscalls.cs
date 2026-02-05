using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;

namespace R77Detector;

/// <summary>
/// Direct syscall implementations to bypass usermode hooks.
/// These read directly from kernel structures when possible.
/// </summary>
public static class DirectSyscalls
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_PROCESS_INFORMATION
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;
        public long WorkingSetPrivateSize;
        public uint HardFaultCount;
        public uint NumberOfThreadsHighWatermark;
        public ulong CycleTime;
        public long CreateTime;
        public long UserTime;
        public long KernelTime;
        public UNICODE_STRING ImageName;
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
        public uint HandleCount;
        public uint SessionId;
        public IntPtr UniqueProcessKey;
        public IntPtr PeakVirtualSize;
        public IntPtr VirtualSize;
        public uint PageFaultCount;
        public IntPtr PeakWorkingSetSize;
        public IntPtr WorkingSetSize;
        public IntPtr QuotaPeakPagedPoolUsage;
        public IntPtr QuotaPagedPoolUsage;
        public IntPtr QuotaPeakNonPagedPoolUsage;
        public IntPtr QuotaNonPagedPoolUsage;
        public IntPtr PagefileUsage;
        public IntPtr PeakPagefileUsage;
        public IntPtr PrivatePageCount;
        public long ReadOperationCount;
        public long WriteOperationCount;
        public long OtherOperationCount;
        public long ReadTransferCount;
        public long WriteTransferCount;
        public long OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEY_BASIC_INFORMATION
    {
        public long LastWriteTime;
        public uint TitleIndex;
        public uint NameLength;
        // Name follows
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

    // NtQuerySystemInformation - get process list directly from kernel
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        int SystemInformationLength,
        out int ReturnLength);

    // NtOpenKey - open registry key directly
    [DllImport("ntdll.dll")]
    public static extern int NtOpenKey(
        out IntPtr KeyHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    // NtEnumerateKey - enumerate registry subkeys
    [DllImport("ntdll.dll")]
    public static extern int NtEnumerateKey(
        IntPtr KeyHandle,
        uint Index,
        int KeyInformationClass,
        IntPtr KeyInformation,
        uint Length,
        out uint ResultLength);

    // NtClose
    [DllImport("ntdll.dll")]
    public static extern int NtClose(IntPtr Handle);

    // RtlInitUnicodeString
    [DllImport("ntdll.dll")]
    public static extern void RtlInitUnicodeString(
        ref UNICODE_STRING DestinationString,
        [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

    private const int SystemProcessInformation = 5;
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    private const int STATUS_SUCCESS = 0;
    private const uint KEY_READ = 0x20019;
    private const uint KEY_ENUMERATE_SUB_KEYS = 0x0008;
    private const int KeyBasicInformation = 0;

    /// <summary>
    /// Get all processes using NtQuerySystemInformation (bypasses usermode hooks)
    /// </summary>
    public static List<(int Pid, string Name)> GetProcessListDirect()
    {
        var processes = new List<(int Pid, string Name)>();
        int bufferSize = 1024 * 1024; // Start with 1MB
        IntPtr buffer = IntPtr.Zero;

        try
        {
            while (true)
            {
                buffer = Marshal.AllocHGlobal(bufferSize);
                int status = NtQuerySystemInformation(
                    SystemProcessInformation,
                    buffer,
                    bufferSize,
                    out int returnLength);

                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    bufferSize = returnLength + 65536; // Add some extra space
                    continue;
                }

                if (status != STATUS_SUCCESS)
                {
                    break;
                }

                // Parse the process information
                IntPtr current = buffer;
                while (true)
                {
                    var processInfo = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(current);

                    string processName = "Unknown";
                    if (processInfo.ImageName.Buffer != IntPtr.Zero && processInfo.ImageName.Length > 0)
                    {
                        processName = Marshal.PtrToStringUni(
                            processInfo.ImageName.Buffer,
                            processInfo.ImageName.Length / 2);
                    }

                    processes.Add(((int)processInfo.UniqueProcessId, processName));

                    if (processInfo.NextEntryOffset == 0)
                        break;

                    current = IntPtr.Add(current, (int)processInfo.NextEntryOffset);
                }

                break;
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return processes;
    }

    /// <summary>
    /// Check if a registry key exists using NtOpenKey (bypasses usermode hooks)
    /// </summary>
    public static bool RegistryKeyExistsDirect(string keyPath)
    {
        // Convert to NT path format
        string ntPath = keyPath;
        if (keyPath.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) ||
            keyPath.StartsWith("HKEY_LOCAL_MACHINE\\", StringComparison.OrdinalIgnoreCase))
        {
            ntPath = "\\Registry\\Machine\\" + keyPath.Substring(keyPath.IndexOf('\\') + 1);
        }
        else if (keyPath.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase) ||
                 keyPath.StartsWith("HKEY_CURRENT_USER\\", StringComparison.OrdinalIgnoreCase))
        {
            ntPath = "\\Registry\\User\\" + keyPath.Substring(keyPath.IndexOf('\\') + 1);
        }

        UNICODE_STRING objectName = new();
        RtlInitUnicodeString(ref objectName, ntPath);

        IntPtr objectNamePtr = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
        try
        {
            Marshal.StructureToPtr(objectName, objectNamePtr, false);

            OBJECT_ATTRIBUTES objectAttributes = new()
            {
                Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                RootDirectory = IntPtr.Zero,
                ObjectName = objectNamePtr,
                Attributes = 0x40, // OBJ_CASE_INSENSITIVE
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };

            int status = NtOpenKey(out IntPtr keyHandle, KEY_READ, ref objectAttributes);

            if (status == STATUS_SUCCESS)
            {
                NtClose(keyHandle);
                return true;
            }

            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(objectNamePtr);
        }
    }

    /// <summary>
    /// Get subkey names using NtEnumerateKey (bypasses usermode hooks)
    /// </summary>
    public static List<string> EnumerateSubKeysDirect(string keyPath)
    {
        var subkeys = new List<string>();

        // Convert to NT path format
        string ntPath = keyPath;
        if (keyPath.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) ||
            keyPath.StartsWith("HKEY_LOCAL_MACHINE\\", StringComparison.OrdinalIgnoreCase))
        {
            ntPath = "\\Registry\\Machine\\" + keyPath.Substring(keyPath.IndexOf('\\') + 1);
        }

        UNICODE_STRING objectName = new();
        RtlInitUnicodeString(ref objectName, ntPath);

        IntPtr objectNamePtr = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
        try
        {
            Marshal.StructureToPtr(objectName, objectNamePtr, false);

            OBJECT_ATTRIBUTES objectAttributes = new()
            {
                Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                RootDirectory = IntPtr.Zero,
                ObjectName = objectNamePtr,
                Attributes = 0x40,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };

            int status = NtOpenKey(out IntPtr keyHandle, KEY_READ | KEY_ENUMERATE_SUB_KEYS, ref objectAttributes);

            if (status != STATUS_SUCCESS)
            {
                return subkeys;
            }

            try
            {
                uint index = 0;
                IntPtr infoBuffer = Marshal.AllocHGlobal(4096);

                try
                {
                    while (true)
                    {
                        status = NtEnumerateKey(
                            keyHandle,
                            index,
                            KeyBasicInformation,
                            infoBuffer,
                            4096,
                            out uint resultLength);

                        if (status != STATUS_SUCCESS)
                            break;

                        var info = Marshal.PtrToStructure<KEY_BASIC_INFORMATION>(infoBuffer);
                        if (info.NameLength > 0)
                        {
                            IntPtr namePtr = IntPtr.Add(infoBuffer, Marshal.SizeOf<KEY_BASIC_INFORMATION>());
                            string name = Marshal.PtrToStringUni(namePtr, (int)(info.NameLength / 2));
                            subkeys.Add(name);
                        }

                        index++;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(infoBuffer);
                }
            }
            finally
            {
                NtClose(keyHandle);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(objectNamePtr);
        }

        return subkeys;
    }
}
