using System;
using System.Collections.Generic;

namespace Crane.MethodHook
{
    internal static class MethodEntryResolver
    {
        public static IntPtr ResolveRealEntry(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }
            Platform.Arch current = Platform.Current;
            IntPtr intPtr = ptr;
            for (int i = 0; i < 10; i++)
            {
                IntPtr intPtr2;
                try
                {
                    switch (current)
                    {
                        case Platform.Arch.X64:
                            intPtr2 = ResolveOneX64(intPtr);
                            break;
                        case Platform.Arch.X86:
                            intPtr2 = ResolveOneX86(intPtr);
                            break;
                        default:
                            return intPtr;
                    }
                }
                catch
                {
                    return intPtr;
                }
                if (intPtr2 == intPtr || intPtr2 == IntPtr.Zero)
                {
                    return intPtr;
                }
                intPtr = intPtr2;
            }
            return intPtr;
        }

        /// <summary>
        /// Returns ALL intermediate addresses in the resolution chain starting
        /// from <paramref name="ptr"/>. For a generic method precode on .NET 8,
        /// the chain is typically:
        ///   precode (FF 25) → fixup thunk (48 B8 ... FF E0) → stub (E9) → JIT code
        /// The generic dictionary slot may hold ANY of these addresses (not just
        /// the first or last), so callers must search for all of them.
        /// </summary>
        public static List<IntPtr> ResolveChain(IntPtr ptr)
        {
            var chain = new List<IntPtr>();
            if (ptr == IntPtr.Zero) return chain;
            Platform.Arch current = Platform.Current;
            IntPtr intPtr = ptr;
            chain.Add(intPtr);
            for (int i = 0; i < 10; i++)
            {
                IntPtr intPtr2;
                try
                {
                    switch (current)
                    {
                        case Platform.Arch.X64:
                            intPtr2 = ResolveOneX64(intPtr);
                            break;
                        case Platform.Arch.X86:
                            intPtr2 = ResolveOneX86(intPtr);
                            break;
                        default:
                            return chain;
                    }
                }
                catch
                {
                    return chain;
                }
                if (intPtr2 == intPtr || intPtr2 == IntPtr.Zero)
                {
                    return chain;
                }
                chain.Add(intPtr2);
                intPtr = intPtr2;
            }
            return chain;
        }

        public static bool IsJump(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return false;
            }
            try
            {
                return Platform.Current switch
                {
                    Platform.Arch.X64 => IsJumpX64(ptr),
                    Platform.Arch.X86 => IsJumpX86(ptr),
                    _ => false,
                };
            }
            catch
            {
                return false;
            }
        }

        private unsafe static bool IsJumpX64(IntPtr ptr)
        {
            if (!Memory.IsReadable(ptr, 12)) return false;
            byte* ptr2 = (byte*)(void*)ptr;
            byte b = *ptr2;
            byte b2 = ptr2[1];
            if (b == byte.MaxValue && b2 == 37)
            {
                return true;
            }
            switch (b)
            {
                case 233:
                    return true;
                case 72:
                    if (b2 == 184 && ptr2[10] == byte.MaxValue && ptr2[11] == 224)
                    {
                        return true;
                    }
                    break;
            }
            switch (b)
            {
                case 232:
                    return true;
                case 76:
                    if (b2 == 141)
                    {
                        return true;
                    }
                    break;
            }
            if (b == 76 && b2 == 139 && ptr2[2] == 21)
            {
                return true;
            }
            if (b == 76 && b2 == 139 && ptr2[2] == 208)
            {
                return true;
            }
            if (b == 72 && b2 == 137 && ptr2[2] == 242)
            {
                return true;
            }
            return false;
        }

        private unsafe static bool IsJumpX86(IntPtr ptr)
        {
            if (!Memory.IsReadable(ptr, 6)) return false;
            byte* ptr2 = (byte*)(void*)ptr;
            byte b = *ptr2;
            byte b2 = ptr2[1];
            if (b == byte.MaxValue && b2 == 37)
            {
                return true;
            }
            return b switch
            {
                233 => true,
                232 => true,
                _ => false,
            };
        }

        private unsafe static IntPtr ResolveOneX64(IntPtr ptr)
        {
            // .NET 6+ does NOT allow catching AccessViolationException from
            // unmapped memory reads — the process is terminated. Always check
            // readability before dereferencing.
            if (!Memory.IsReadable(ptr, 64))
            {
                return ptr;
            }
            byte* ptr2 = (byte*)(void*)ptr;
            byte b = *ptr2;
            byte b2 = ptr2[1];
            if (b == byte.MaxValue && b2 == 37)
            {
                int num = *(int*)(ptr2 + 2);
                long num2 = ptr.ToInt64() + 6 + num;
                if (!Memory.IsReadable(new IntPtr(num2), 8))
                {
                    return ptr;
                }
                long value = *(long*)num2;
                return new IntPtr(value);
            }
            switch (b)
            {
                case 233:
                    {
                        int num3 = *(int*)(ptr2 + 1);
                        return new IntPtr(ptr.ToInt64() + 5 + num3);
                    }
                case 72:
                    if (b2 == 184 && ptr2[10] == byte.MaxValue && ptr2[11] == 224)
                    {
                        long value2 = *(long*)(ptr2 + 2);
                        return new IntPtr(value2);
                    }
                    break;
            }
            if (b == 76 && b2 == 141)
            {
                byte* ptr3 = ptr2 + 7;
                if (*ptr3 == byte.MaxValue && ptr3[1] == 37)
                {
                    int num4 = *(int*)(ptr3 + 2);
                    long num5 = (long)ptr3 + 6L + num4;
                    if (!Memory.IsReadable(new IntPtr(num5), 8))
                    {
                        return ptr;
                    }
                    long value3 = *(long*)num5;
                    return new IntPtr(value3);
                }
            }
            if (b == 232 && ptr2[5] == 94)
            {
                return ptr;
            }
            if (b == 76 && b2 == 139 && ptr2[2] == 21)
            {
                byte* ptr4 = ptr2 + 7;
                if (*ptr4 == byte.MaxValue && ptr4[1] == 37)
                {
                    int num6 = *(int*)(ptr4 + 2);
                    long num7 = (long)ptr4 + 6L + num6;
                    if (!Memory.IsReadable(new IntPtr(num7), 8))
                    {
                        return ptr;
                    }
                    long value4 = *(long*)num7;
                    return new IntPtr(value4);
                }
            }
            for (int i = 0; i <= 24; i++)
            {
                if (ptr2[i] == 72 && ptr2[i + 1] == 184 && i + 11 < 64 && ptr2[i + 10] == byte.MaxValue && ptr2[i + 11] == 224)
                {
                    long value5 = *(long*)(ptr2 + i + 2);
                    return new IntPtr(value5);
                }
            }
            return ptr;
        }

        private unsafe static IntPtr ResolveOneX86(IntPtr ptr)
        {
            if (!Memory.IsReadable(ptr, 20))
            {
                return ptr;
            }
            byte* ptr2 = (byte*)(void*)ptr;
            byte b = *ptr2;
            byte b2 = ptr2[1];
            if (b == byte.MaxValue && b2 == 37)
            {
                int num = *(int*)(ptr2 + 2);
                if (!Memory.IsReadable(new IntPtr(num), 4))
                {
                    return ptr;
                }
                int value = *(int*)num;
                return new IntPtr(value);
            }
            if (b == 233)
            {
                int num2 = *(int*)(ptr2 + 1);
                return new IntPtr(ptr.ToInt32() + 5 + num2);
            }
            // B8 precode (.NET Framework 4.x x86 fixup precode):
            //   B8 <MethodDesc> [90] E8 <rel32> E9 <rel32>
            // The E9 (JMP rel32) at offset 10 or 11 is the backpatched jump to
            // the real JIT code. Follow it so callers reach the JIT entry point.
            if (b == 0xB8)
            {
                for (int i = 5; i <= 15; i++)
                {
                    if (ptr2[i] == 0xE9)
                    {
                        int rel = *(int*)(ptr2 + i + 1);
                        return new IntPtr(ptr.ToInt32() + i + 5 + rel);
                    }
                }
            }
            // E8 precode: treat as sentinel (don't follow). The caller
            // (InstallSecondaryJitPatchX86) handles E8 manually.
            return ptr;
        }
    }
}
