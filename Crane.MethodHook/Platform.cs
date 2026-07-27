using System;
using System.Runtime.InteropServices;

namespace Crane.MethodHook
{
    internal static class Platform
    {
        public enum Arch
        {
            X86,
            X64,
            ARM32,
            ARM64,
            Unknown
        }

        private static readonly Lazy<Arch> _current = new Lazy<Arch>(Detect);

        public static Arch Current => _current.Value;

        public static bool Is64Bit => Current == Arch.X64 || Current == Arch.ARM64;

        private static readonly Lazy<bool> _isWindows = new Lazy<bool>(() =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows));
        private static readonly Lazy<bool> _isLinux = new Lazy<bool>(() =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux));
        private static readonly Lazy<bool> _isMacOS = new Lazy<bool>(() =>
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX));

        /// <summary>True on Windows. Used to branch precode/fixup-thunk patterns
        /// and calling-convention logic that differs between Windows x64 and
        /// Unix (System V AMD64) x64.</summary>
        public static bool IsWindows => _isWindows.Value;

        /// <summary>True on Linux. Used to select the CoreCLR Unix x64 precode
        /// format (MOV RDX, RSI; MOV RSI, dict) and System V register shifts.</summary>
        public static bool IsLinux => _isLinux.Value;

        /// <summary>True on macOS. Same CoreCLR Unix x64 precode format as Linux,
        /// but mmap MAP_ANONYMOUS uses a different numeric value (0x1000).</summary>
        public static bool IsMacOS => _isMacOS.Value;

        /// <summary>True on any non-Windows OS (Linux, macOS, etc.).
        /// CoreCLR uses the same Unix x64 managed calling convention on all
        /// of these platforms.</summary>
        public static bool IsUnix => _isLinux.Value || _isMacOS.Value;

        public static int PatchSize => Current switch
        {
            Arch.X64 => 12,
            Arch.X86 => 5,
            Arch.ARM64 => 16,
            Arch.ARM32 => 12,
            _ => 12,
        };

        private static Arch Detect()
        {
            try
            {
                switch (RuntimeInformation.ProcessArchitecture)
                {
                    case Architecture.X86:
                        return Arch.X86;
                    case Architecture.X64:
                        return Arch.X64;
                    case Architecture.Arm:
                        return Arch.ARM32;
                    case Architecture.Arm64:
                        return Arch.ARM64;
                }
            }
            catch
            {
            }
            return (IntPtr.Size == 8) ? Arch.X64 : Arch.X86;
        }
    }
}
