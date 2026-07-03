using System;
using System.Runtime.InteropServices;

namespace DynamicHook
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
