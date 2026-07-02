using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

[assembly: InternalsVisibleTo("DynamicHook.Tests")]

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
    internal static class Memory
    {
        private static readonly IntPtr CurrentProcess = new IntPtr(-1);

        private static int PageSize => 4096;

        public static IntPtr AlignToPage(IntPtr addr)
        {
            long num = PageSize;
            return new IntPtr(addr.ToInt64() / num * num);
        }

        public static UIntPtr AlignedSize(IntPtr addr, int size)
        {
            long num = PageSize;
            long num2 = AlignToPage(addr).ToInt64();
            long num3 = addr.ToInt64() + size;
            return (UIntPtr)(ulong)((num3 - num2 + num - 1) / num * num);
        }

        public static void ProtectWritable(IntPtr addr, int size)
        {
            IntPtr addr2 = AlignToPage(addr);
            UIntPtr uIntPtr = AlignedSize(addr, size);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                VirtualProtect(addr2, uIntPtr, 64u, out var _);
            }
            else
            {
                mprotect(addr2, uIntPtr, 7);
            }
        }

        public static void ProtectExecutable(IntPtr addr, int size)
        {
            IntPtr addr2 = AlignToPage(addr);
            UIntPtr uIntPtr = AlignedSize(addr, size);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                VirtualProtect(addr2, uIntPtr, 64u, out var _);
                FlushInstructionCache(CurrentProcess, addr, (UIntPtr)(ulong)size);
            }
            else
            {
                mprotect(addr2, uIntPtr, 7);
            }
        }

        public static void ProtectReadWrite(IntPtr addr, int size)
        {
            IntPtr addr2 = AlignToPage(addr);
            UIntPtr uIntPtr = AlignedSize(addr, size);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                VirtualProtect(addr2, uIntPtr, 64u, out var _);
            }
            else
            {
                mprotect(addr2, uIntPtr, 7);
            }
        }

        public static IntPtr AllocExec(int size)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)size, 12288u, 64u);
            }
            return mmap(IntPtr.Zero, (UIntPtr)(ulong)size, 7, 34, -1, 0L);
        }

        public static IntPtr AllocExecNear(IntPtr nearAddr, int size)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                long num = nearAddr.ToInt64();
                long num2 = (size + 4095) & -4096;
                long num3 = num - 2147418112;
                if (num3 < 65536)
                {
                    num3 = 65536L;
                }
                long num4 = num + 2147418112;
                for (long num5 = 0L; num5 < 2147418112; num5 += 65536)
                {
                    long num6 = num + num5;
                    if (num6 >= num3 && num6 + num2 <= num4)
                    {
                        IntPtr intPtr = VirtualAlloc(new IntPtr(num6), (UIntPtr)(ulong)num2, 12288u, 64u);
                        if (intPtr != IntPtr.Zero)
                        {
                            long num7 = intPtr.ToInt64() - num;
                            if (num7 >= -2147483647 && num7 <= int.MaxValue)
                            {
                                return intPtr;
                            }
                            VirtualFree(intPtr, UIntPtr.Zero, 32768u);
                        }
                    }
                    if (num5 <= 0)
                    {
                        continue;
                    }
                    num6 = num - num5;
                    if (num6 < num3 || num6 + num2 > num4)
                    {
                        continue;
                    }
                    IntPtr intPtr2 = VirtualAlloc(new IntPtr(num6), (UIntPtr)(ulong)num2, 12288u, 64u);
                    if (intPtr2 != IntPtr.Zero)
                    {
                        long num8 = intPtr2.ToInt64() - num;
                        if (num8 >= -2147483647 && num8 <= int.MaxValue)
                        {
                            return intPtr2;
                        }
                        VirtualFree(intPtr2, UIntPtr.Zero, 32768u);
                    }
                }
                return VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)size, 12288u, 64u);
            }
            long num9 = nearAddr.ToInt64();
            long num10 = 4096L;
            long num11 = (size + 4095) & -4096;
            long num12 = num9 - 2147418112;
            if (num12 < 0)
            {
                num12 = 65536L;
            }
            long num13 = num9 + 2147418112;
            for (long num14 = 0L; num14 < 2147418112; num14 += num10)
            {
                long num15 = num9 + num14;
                if (num15 >= num12 && num15 + num11 <= num13)
                {
                    IntPtr intPtr3 = mmap(new IntPtr(num15), (UIntPtr)(ulong)num11, 7, 50, -1, 0L);
                    if (intPtr3.ToInt64() != -1 && intPtr3 != IntPtr.Zero)
                    {
                        long num16 = intPtr3.ToInt64() - num9;
                        if (num16 >= -2147483647 && num16 <= int.MaxValue)
                        {
                            return intPtr3;
                        }
                        munmap(intPtr3, (UIntPtr)(ulong)num11);
                    }
                }
                if (num14 <= 0)
                {
                    continue;
                }
                num15 = num9 - num14;
                if (num15 < num12 || num15 + num11 > num13)
                {
                    continue;
                }
                IntPtr intPtr4 = mmap(new IntPtr(num15), (UIntPtr)(ulong)num11, 7, 50, -1, 0L);
                if (intPtr4.ToInt64() != -1 && intPtr4 != IntPtr.Zero)
                {
                    long num17 = intPtr4.ToInt64() - num9;
                    if (num17 >= -2147483647 && num17 <= int.MaxValue)
                    {
                        return intPtr4;
                    }
                    munmap(intPtr4, (UIntPtr)(ulong)num11);
                }
            }
            return AllocExec(size);
        }

        public static void FreeExec(IntPtr ptr, int size)
        {
            if (!(ptr == IntPtr.Zero))
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    VirtualFree(ptr, UIntPtr.Zero, 32768u);
                }
                else
                {
                    munmap(ptr, (UIntPtr)(ulong)size);
                }
            }
        }

        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        /// <summary>
        /// Checks whether the memory at the given address is committed and readable.
        /// Prevents AccessViolationException (uncatchable in .NET 8) when scanning
        /// MethodDesc/MethodTable regions that may extend into unmapped memory.
        /// </summary>
        public static bool IsReadable(IntPtr addr, int size)
        {
            if (addr == IntPtr.Zero)
            {
                return false;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                MEMORY_BASIC_INFORMATION mbi;
                IntPtr ret = VirtualQuery(addr, out mbi, (UIntPtr)System.Runtime.InteropServices.Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                if (ret == IntPtr.Zero)
                {
                    return false;
                }
                // State == MEM_COMMIT (0x1000) and readable protection flags
                if (mbi.State != 0x1000)
                {
                    return false;
                }
                // Check the region covers the requested size
                long regionEnd = mbi.BaseAddress.ToInt64() + (long)mbi.RegionSize.ToUInt64();
                long readEnd = addr.ToInt64() + size;
                if (readEnd > regionEnd)
                {
                    return false;
                }
                // Protection must allow read: PAGE_READONLY(2), PAGE_READWRITE(4),
                // PAGE_WRITECOPY(8), PAGE_EXECUTE_READ(0x20), PAGE_EXECUTE_READWRITE(0x40),
                // PAGE_EXECUTE_WRITECOPY(0x80)
                uint p = mbi.Protect & 0xFF;
                return p == 2 || p == 4 || p == 8 || p == 0x20 || p == 0x40 || p == 0x80;
            }
            // Non-Windows: assume readable (mmap'd pages are readable until munmap'd)
            return true;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualProtect(IntPtr addr, UIntPtr size, uint prot, out uint old);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint prot);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint type);

        [DllImport("kernel32.dll")]
        private static extern void FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

        [DllImport("libc", SetLastError = true)]
        private static extern int mprotect(IntPtr addr, UIntPtr len, int prot);

        [DllImport("libc", SetLastError = true)]
        private static extern IntPtr mmap(IntPtr addr, UIntPtr len, int prot, int flags, int fd, long off);

        [DllImport("libc", SetLastError = true)]
        private static extern int munmap(IntPtr addr, UIntPtr len);
    }
    internal static class Jumper
    {
        public static byte[] BuildJump(IntPtr fromAddr, IntPtr toAddr)
        {
            return Platform.Current switch
            {
                Platform.Arch.X64 => JumpX64(toAddr),
                Platform.Arch.X86 => JumpX86(fromAddr, toAddr),
                Platform.Arch.ARM64 => JumpARM64(toAddr),
                Platform.Arch.ARM32 => JumpARM32(toAddr),
                _ => JumpX64(toAddr),
            };
        }

        public static byte[] Install(IntPtr target, IntPtr replacement)
        {
            byte[] array = BuildJump(target, replacement);
            byte[] array2 = new byte[array.Length];
            Marshal.Copy(target, array2, 0, array.Length);
            Memory.ProtectWritable(target, array.Length);
            Marshal.Copy(array, 0, target, array.Length);
            Memory.ProtectExecutable(target, array.Length);
            return array2;
        }

        public static void WriteJump(IntPtr target, IntPtr replacement)
        {
            byte[] array = BuildJump(target, replacement);
            Memory.ProtectWritable(target, array.Length);
            Marshal.Copy(array, 0, target, array.Length);
            Memory.ProtectExecutable(target, array.Length);
        }

        public static void Restore(IntPtr target, byte[] original)
        {
            Memory.ProtectWritable(target, original.Length);
            Marshal.Copy(original, 0, target, original.Length);
            Memory.ProtectExecutable(target, original.Length);
        }

        private static byte[] JumpX64(IntPtr to)
        {
            byte[] array = new byte[12]
            {
            72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0
            };
            BitConverter.GetBytes(to.ToInt64()).CopyTo(array, 2);
            array[10] = byte.MaxValue;
            array[11] = 224;
            return array;
        }

        private static byte[] JumpX86(IntPtr from, IntPtr to)
        {
            byte[] array = new byte[5] { 233, 0, 0, 0, 0 };
            BitConverter.GetBytes(to.ToInt32() - (from.ToInt32() + 5)).CopyTo(array, 1);
            return array;
        }

        private static byte[] JumpARM64(IntPtr to)
        {
            byte[] array = new byte[16]
            {
            80, 0, 0, 88, 0, 2, 31, 214, 0, 0,
            0, 0, 0, 0, 0, 0
            };
            BitConverter.GetBytes(to.ToInt64()).CopyTo(array, 8);
            return array;
        }

        private static byte[] JumpARM32(IntPtr to)
        {
            byte[] array = new byte[12]
            {
            4, 192, 159, 229, 28, 240, 47, 225, 0, 0,
            0, 0
            };
            BitConverter.GetBytes(to.ToInt32()).CopyTo(array, 8);
            return array;
        }
    }
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
    internal static class SlotPatcher
    {
        public static List<IntPtr> FindSlots(IntPtr methodDesc, IntPtr methodTable, IntPtr value)
        {
            List<IntPtr> list = new List<IntPtr>();
            int size = IntPtr.Size;
            long num = value.ToInt64();
            long num2 = MethodEntryResolver.ResolveRealEntry(value).ToInt64();
            if (methodDesc != IntPtr.Zero)
            {
                for (int i = 0; i < 128; i += size)
                {
                    if (!Memory.IsReadable(methodDesc + i, size))
                    {
                        break;
                    }
                    try
                    {
                        long num3 = ReadPointer(methodDesc + i);
                        if (num3 == num || num3 == num2)
                        {
                            list.Add(methodDesc + i);
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }
            if (methodTable != IntPtr.Zero)
            {
                int consecutiveUnreadable = 0;
                for (int j = 0; j < 65536; j += size)
                {
                    if (!Memory.IsReadable(methodTable + j, size))
                    {
                        // Skip unreadable regions instead of breaking. The MethodTable
                        // may span non-contiguous pages (e.g. on x86 where the vtable
                        // extends past a page boundary). Allow up to 4096 bytes of
                        // consecutive unreadable memory before giving up.
                        consecutiveUnreadable += size;
                        if (consecutiveUnreadable >= 4096)
                            break;
                        continue;
                    }
                    consecutiveUnreadable = 0;
                    try
                    {
                        long num4 = ReadPointer(methodTable + j);
                        if (num4 == num || num4 == num2)
                        {
                            list.Add(methodTable + j);
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }
            return list;
        }

        public static void ReplaceSlot(IntPtr slot, IntPtr newValue)
        {
            int size = IntPtr.Size;
            Memory.ProtectReadWrite(slot, size);
            WritePointer(slot, newValue.ToInt64());
        }

        private static long ReadPointer(IntPtr addr)
        {
            if (IntPtr.Size == 8)
            {
                return Marshal.ReadInt64(addr);
            }
            return Marshal.ReadInt32(addr);
        }

        private static void WritePointer(IntPtr addr, long value)
        {
            if (IntPtr.Size == 8)
            {
                Marshal.WriteInt64(addr, value);
            }
            else
            {
                Marshal.WriteInt32(addr, (int)value);
            }
        }
    }
    internal static class GenericAdapter
    {
        public static IntPtr Create(IntPtr hookEntry, MethodBase targetMethod, IntPtr nearAddr)
        {
            Platform.Arch current = Platform.Current;
            if (current != Platform.Arch.X64)
            {
                return hookEntry;
            }
            bool isStatic = targetMethod.IsStatic;
            int userParamCount = targetMethod.GetParameters().Length;
            bool flag = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
            List<byte> list = new List<byte>();
            if (flag)
            {
                BuildSystemVAdapter(list, isStatic, userParamCount);
            }
            else
            {
                BuildWindowsX64Adapter(list, isStatic, userParamCount);
            }
            list.Add(72);
            list.Add(184);
            list.AddRange(BitConverter.GetBytes(hookEntry.ToInt64()));
            list.Add(byte.MaxValue);
            list.Add(224);
            IntPtr intPtr = Memory.AllocExecNear(nearAddr, list.Count);
            if (intPtr == IntPtr.Zero || intPtr == new IntPtr(-1))
            {
                return IntPtr.Zero;
            }
            Marshal.Copy(list.ToArray(), 0, intPtr, list.Count);
            Memory.ProtectExecutable(intPtr, list.Count);
            return intPtr;
        }

        private static void BuildWindowsX64Adapter(List<byte> code, bool isStatic, int userParamCount)
        {
            int num = ((!isStatic) ? 1 : 0);
            int num2 = (isStatic ? 1 : 2) + userParamCount;
            int num3 = Math.Min(num2 - 2, 3);
            for (int i = num; i <= num3; i++)
            {
                int num4 = i + 1;
                if (num4 < 4)
                {
                    EmitMovRegReg(code, i, num4);
                    continue;
                }
                int offset = 32 + (num4 - 3) * 8;
                EmitMovRegFromStack(code, i, offset);
            }
            if (num2 > 4)
            {
                int num5 = num2 - 5;
                for (int j = 0; j < num5; j++)
                {
                    int value = 40 + j * 8;
                    int value2 = 48 + j * 8;
                    code.Add(72);
                    code.Add(139);
                    code.Add(132);
                    code.Add(36);
                    code.AddRange(BitConverter.GetBytes(value2));
                    code.Add(72);
                    code.Add(137);
                    code.Add(132);
                    code.Add(36);
                    code.AddRange(BitConverter.GetBytes(value));
                }
            }
            int num6 = Math.Min(num2 - 1, 4);
            for (int num7 = Math.Min(3, num6 - 1); num7 >= 0; num7--)
            {
                int offset2 = 8 + num7 * 8;
                EmitMovShadowFromReg(code, num7, offset2);
            }
        }

        private static void EmitMovRegReg(List<byte> code, int dst, int src)
        {
            byte b = 72;
            if (src >= 2)
            {
                b |= 0x44;
            }
            if (dst >= 2)
            {
                b |= 1;
            }
            code.Add(b);
            code.Add(137);
            int num = src & 3;
            int num2 = dst & 3;
            code.Add((byte)(0xC0 | (num << 3) | num2));
        }

        private static void EmitMovRegFromStack(List<byte> code, int reg, int offset)
        {
            byte b = 72;
            if (reg >= 2)
            {
                b |= 1;
            }
            code.Add(b);
            code.Add(139);
            int num = reg & 3;
            code.Add((byte)(4 | (num << 3)));
            code.Add(36);
            code.Add((byte)offset);
        }

        private static void EmitMovShadowFromReg(List<byte> code, int reg, int offset)
        {
            byte b = 72;
            if (reg >= 2)
            {
                b |= 0x44;
            }
            code.Add(b);
            code.Add(137);
            int num = reg & 3;
            code.Add((byte)(0x44 | (num << 3)));
            code.Add(36);
            code.Add((byte)offset);
        }

        private static void BuildSystemVAdapter(List<byte> code, bool isStatic, int userParamCount)
        {
            int num = ((!isStatic) ? 1 : 0);
            int num2 = (isStatic ? 1 : 2) + userParamCount;
            int num3 = Math.Min(num2 - 2, 5);
            for (int i = num; i <= num3; i++)
            {
                int num4 = i + 1;
                if (num4 < 6)
                {
                    EmitMovRegRegSystemV(code, i, num4);
                    continue;
                }
                int offset = (num4 - 6) * 8;
                EmitMovRegFromStackSystemV(code, i, offset);
            }
            if (num2 > 6)
            {
                int num5 = num2 - 7;
                for (int j = 0; j < num5; j++)
                {
                    int value = j * 8;
                    int value2 = (j + 1) * 8;
                    code.Add(72);
                    code.Add(139);
                    code.Add(132);
                    code.Add(36);
                    code.AddRange(BitConverter.GetBytes(value2));
                    code.Add(72);
                    code.Add(137);
                    code.Add(132);
                    code.Add(36);
                    code.AddRange(BitConverter.GetBytes(value));
                }
            }
        }

        private static void EmitMovRegRegSystemV(List<byte> code, int dst, int src)
        {
            byte b = 72;
            if (src >= 4)
            {
                b |= 0x44;
            }
            if (dst >= 4)
            {
                b |= 1;
            }
            code.Add(b);
            code.Add(137);
            int num = src & 3;
            int num2 = dst & 3;
            code.Add((byte)(0xC0 | (num << 3) | num2));
        }

        private static void EmitMovRegFromStackSystemV(List<byte> code, int reg, int offset)
        {
            byte b = 72;
            if (reg >= 4)
            {
                b |= 1;
            }
            code.Add(b);
            code.Add(139);
            int num = reg & 3;
            code.Add((byte)(4 | (num << 3)));
            code.Add(36);
            code.Add((byte)offset);
        }
    }

    /// <summary>
    /// Minimal x86-64 instruction length decoder. Handles common prologue instructions
    /// to determine how many bytes of complete instructions must be relocated to a
    /// call-original trampoline. Returns 0 on any instruction it cannot safely decode
    /// (including RIP-relative and relative-jump instructions, which cannot be blindly
    /// copied to a different address without relocation).
    /// </summary>
    internal static class X64Decoder
    {
        /// <summary>
        /// Accumulates complete x86-64 instruction lengths starting at <paramref name="code"/>
        /// until the total is at least <paramref name="minBytes"/>. Returns 0 if decoding
        /// fails or a non-relocatable instruction is encountered.
        /// </summary>
        public unsafe static int CopyCompleteInstructions(byte* code, int minBytes, int maxBytes)
        {
            int total = 0;
            while (total < minBytes)
            {
                if (total >= maxBytes) return 0;
                int len = InstructionLength(code + total, maxBytes - total);
                if (len <= 0) return 0;
                total += len;
            }
            return total;
        }

        private unsafe static int InstructionLength(byte* code, int maxLen)
        {
            if (maxLen < 1) return 0;
            int pos = 0;

            // Legacy prefixes
            while (pos < maxLen)
            {
                byte b = code[pos];
                if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                    b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 ||
                    b == 0x66 || b == 0x67)
                {
                    pos++;
                    if (pos >= maxLen) return 0;
                }
                else break;
            }

            // REX prefix
            bool rexW = false;
            if (pos < maxLen && code[pos] >= 0x40 && code[pos] <= 0x4F)
            {
                rexW = (code[pos] & 0x08) != 0;
                pos++;
                if (pos >= maxLen) return 0;
            }

            byte opcode = code[pos++];

            // 0x50-0x5F: push/pop r64 (1 byte)
            if (opcode >= 0x50 && opcode <= 0x5F) return pos;
            // 0x90: nop
            if (opcode == 0x90) return pos;
            // 0xC3: ret, 0xCC: int3, 0x9C: pushfq, 0x9D: popfq
            if (opcode == 0xC3 || opcode == 0xCC || opcode == 0x9C || opcode == 0x9D) return pos;

            // 0xB8-0xBF: mov r64, imm64 (with REX.W) or mov r32, imm32
            if (opcode >= 0xB8 && opcode <= 0xBF) return pos + (rexW ? 8 : 4);
            // 0xB0-0xB7: mov r8, imm8
            if (opcode >= 0xB0 && opcode <= 0xB7) return pos + 1;

            // 0x68: push imm32, 0x6A: push imm8
            if (opcode == 0x68) return pos + 4;
            if (opcode == 0x6A) return pos + 1;

            // Relative jumps/calls — NOT relocatable, fail
            if (opcode == 0xE8 || opcode == 0xE9) return 0; // call/jmp rel32
            if (opcode == 0xEB) return 0; // jmp rel8
            if (opcode >= 0x70 && opcode <= 0x7F) return 0; // jcc rel8
            if (opcode >= 0xE0 && opcode <= 0xE3) return 0; // loop/jcxz

            // 0x0F: two-byte opcode
            if (opcode == 0x0F)
            {
                if (pos >= maxLen) return 0;
                byte op2 = code[pos++];
                // 0F 80-8F: jcc rel32 — NOT relocatable
                if (op2 >= 0x80 && op2 <= 0x8F) return 0;
                // Most other 0F xx have ModRM
                int modrmLen = ModRMLength(code + pos, maxLen - pos);
                if (modrmLen < 0) return 0;
                return pos + modrmLen;
            }

            // Opcodes with ModRM + optional immediate
            bool hasModRM = false;
            int immLen = 0;

            // Arithmetic group 0x00-0x3F
            if (opcode <= 0x3D)
            {
                int low3 = opcode & 0x07;
                if (low3 == 0x04) return pos + 1; // imm8 (e.g. add al, imm8)
                if (low3 == 0x05) return pos + 4; // imm32 (e.g. add eax, imm32)
                if (low3 <= 0x03) hasModRM = true;
            }

            switch (opcode)
            {
                case 0x81: hasModRM = true; immLen = 4; break;
                case 0x83: hasModRM = true; immLen = 1; break;
                case 0x69: hasModRM = true; immLen = 4; break;
                case 0x6B: hasModRM = true; immLen = 1; break;
                case 0xC1: hasModRM = true; immLen = 1; break;
                case 0xC7: hasModRM = true; immLen = 4; break;
                case 0x89:
                case 0x8B:
                case 0x8D:
                case 0xFF:
                case 0x85:
                case 0x63:
                case 0x03:
                case 0x0B:
                case 0x13:
                case 0x1B:
                case 0x23:
                case 0x2B:
                case 0x33:
                case 0x3B:
                case 0xD1:
                case 0xD3:
                case 0xF6:
                case 0xF7:
                case 0x86:
                case 0x87:
                case 0x88:
                case 0x8A:
                case 0x00:
                case 0x01:
                case 0x08:
                case 0x09:
                case 0x10:
                case 0x11:
                case 0x18:
                case 0x19:
                case 0x20:
                case 0x21:
                case 0x28:
                case 0x29:
                case 0x30:
                case 0x31:
                case 0x38:
                case 0x39:
                case 0x62:
                    hasModRM = true; break;
                default:
                    return 0; // unknown opcode
            }

            if (!hasModRM) return 0;

            int mrmLen = ModRMLength(code + pos, maxLen - pos);
            if (mrmLen < 0) return 0;
            pos += mrmLen;

            return pos + immLen;
        }

        /// <summary>
        /// Decodes ModRM byte + optional SIB + optional displacement.
        /// Returns total length (including ModRM byte), or -1 on failure.
        /// Returns -1 for RIP-relative addressing (mod=00, rm=101) since it is
        /// not safely relocatable.
        /// </summary>
        private unsafe static int ModRMLength(byte* p, int maxLen)
        {
            if (maxLen < 1) return -1;
            byte modrm = p[0];
            int mod = (modrm >> 6) & 0x03;
            int rm = modrm & 0x07;
            int len = 1;

            if (mod == 0x03) return len; // register operand

            if (rm == 0x04) // SIB byte follows
            {
                if (len >= maxLen) return -1;
                byte sib = p[len];
                len++;
                int base_ = sib & 0x07;
                if (mod == 0x00 && base_ == 0x05) len += 4;      // disp32
                else if (mod == 0x01) len += 1;                    // disp8
                else if (mod == 0x02) len += 4;                    // disp32
            }
            else if (rm == 0x05 && mod == 0x00)
            {
                return -1; // RIP-relative — not relocatable
            }
            else if (mod == 0x01) len += 1;  // disp8
            else if (mod == 0x02) len += 4;  // disp32

            if (len > maxLen) return -1;
            return len;
        }
    }

    public sealed class MethodHook : IDisposable
    {
        private class OverridePatch
        {
            public IntPtr Entry;

            public byte[] OriginalBytes;

            public List<IntPtr> Slots;
        }

        private readonly MethodBase _targetMethod;

        private readonly MethodBase _hookMethod;

        private List<IntPtr> _slotAddresses;

        private IntPtr _originalSlotValue;

        private IntPtr _newSlotValue;

        private int _patchType;

        private IntPtr _patchAddress;

        private byte[] _originalBytes;

        private IntPtr _indirectTargetLoc;

        private IntPtr _originalIndirectTarget;

        /// <summary>
        /// For generic FixupPrecode: the first FF 25's indirect target location and
        /// original value. After PrepareMethod, the first FF 25 points directly to JIT
        /// code, bypassing the second FF 25 (where _indirectTargetLoc is patched).
        /// We redirect the first FF 25 to offset 6 (the MOV R10 instruction) so calls
        /// flow through: first FF 25 -> offset 6 (MOV R10) -> second FF 25 -> hook.
        /// This avoids patching JIT code entirely.
        /// </summary>
        private IntPtr _firstIndirectLoc;

        private IntPtr _originalFirstIndirect;

        private bool _hasFirstIndirectPatch;

        private IntPtr _nearTrampoline;

        private bool _hasSecondaryPatch;

        private IntPtr _secondaryJitAddress;

        private byte[] _secondaryJitOriginalBytes;

        private IntPtr _secondaryTrampoline;

        private bool _hasTarget1Patch;

        private IntPtr _target1Address;

        private byte[] _target1OriginalBytes;

        private bool _hasInnerCodePatch;

        private IntPtr _innerCodeAddress;

        private byte[] _innerCodeOriginalBytes;

        /// <summary>
        /// Full (32-byte) copy of the original bytes at the inner code address,
        /// saved BEFORE the 12-byte patch is applied. Used by the call-original
        /// trampoline to copy/relocate the original prologue.
        /// </summary>
        private byte[] _innerCodeOriginalBytesFull;

        private bool _hasTarget2Patch;

        private IntPtr _target2Loc;

        private IntPtr _target2OriginalValue;

        private IntPtr _callOrigTrampoline;

        private int _callOrigTrampSize;

        /// <summary>
        /// True when the call-original trampoline contains a copy of the original
        /// JIT prologue (copy-prologue trampoline). When true, CallOriginal can
        /// invoke the trampoline WITHOUT RestoreAll/ReapplyAll, because the
        /// trampoline bypasses the E9 patch by executing the copied prologue and
        /// jumping past the patched bytes.
        /// </summary>
        private bool _callOrigUseCopyPrologue;

        private IntPtr _precodeAddr;

        /// <summary>
        /// Strongly-typed delegate to the original method, created BEFORE patching.
        /// The delegate's Invoke method is JIT-compiled with knowledge of the method's
        /// generic arguments, so it sets up R10 (generic dictionary) correctly and calls
        /// the precode directly — bypassing RuntimeMethodHandle.InvokeMethod (which
        /// crashes with 0x80131506 for hooked generic methods).
        /// </summary>
        private Delegate _originalDelegate;

        /// <summary>
        /// Function pointer of the delegate's Invoke method. The Invoke method is
        /// non-generic (it lives on a constructed generic delegate type but has no
        /// type parameters of its own), so calling it via delegate* bypasses
        /// RuntimeMethodHandle.InvokeMethod entirely — avoiding the 0x80131506 crash
        /// that affects MethodInfo.Invoke on generic methods after JIT code patching.
        /// </summary>
        private IntPtr _delegateInvokeFptr;

        /// <summary>
        /// Flat argument count of the hooked method (instance + declared parameters).
        /// The delegate's Invoke method takes one extra slot for the delegate itself
        /// (as 'this'), so the total native arg count is _delegateFlatArgCount + 1.
        /// </summary>
        private int _delegateFlatArgCount;

        private IntPtr _genericAdapter;

        private bool _needsGenericAdapter;

        private List<OverridePatch> _overridePatches;

        private bool _isInstalled;

        private bool _isDisposed;

        public bool IsInstalled => _isInstalled;

        public HookDiagInfo DiagInfo { get; private set; }

        public MethodHook(MethodBase targetMethod, MethodBase hookMethod)
        {
            _targetMethod = targetMethod ?? throw new ArgumentNullException("targetMethod");
            _hookMethod = hookMethod ?? throw new ArgumentNullException("hookMethod");
        }

        /// <summary>
        /// 诊断方法：扫描指定方法的 JIT 代码，查找 E8 (CALL rel32) 指令，
        /// 返回所有调用目标地址。用于诊断泛型方法 hook 不生效的问题。
        /// </summary>
        public static unsafe List<long> ScanCallTargets(MethodBase method, int maxScanBytes)
        {
            List<long> result = new List<long>();
            try
            {
                RuntimeHelpers.PrepareMethod(method.MethodHandle);
                IntPtr entry = method.MethodHandle.GetFunctionPointer();
                if (entry == IntPtr.Zero) return result;
                // Resolve through precode to get actual JIT code
                IntPtr jitEntry = MethodEntryResolver.ResolveRealEntry(entry);
                if (jitEntry != IntPtr.Zero) entry = jitEntry;
                byte* p = (byte*)entry;
                for (int i = 0; i < maxScanBytes - 5; i++)
                {
                    // E8 xx xx xx xx = CALL rel32
                    if (p[i] == 0xE8)
                    {
                        int rel = *(int*)(p + i + 1);
                        long target = (long)(p + i) + 5 + rel;
                        result.Add(target);
                    }
                    // FF 15 xx xx xx xx = CALL [rip+disp32]  (indirect call)
                    if (p[i] == 0xFF && p[i + 1] == 0x15)
                    {
                        int rel = *(int*)(p + i + 2);
                        long dataAddr = (long)(p + i) + 6 + rel;
                        try
                        {
                            long target = *(long*)dataAddr;
                            result.Add(target);
                            result.Add(dataAddr); // also add data addr for diagnostics
                        }
                        catch { }
                    }
                    // 41 FF xx = CALL R8-R15 (indirect register call, used for generic methods)
                    if (p[i] == 0x41 && p[i + 1] == 0xFF)
                    {
                        result.Add(-2); // marker for indirect register call
                        result.Add(i);  // offset
                    }
                    // FF D0-FF D7 = CALL RAX-RDI (indirect register call)
                    if (p[i] == 0xFF && (p[i + 1] >= 0xD0 && p[i + 1] <= 0xD7))
                    {
                        result.Add(-1); // marker for register call
                        result.Add(i);  // offset
                    }
                }
            }
            catch { }
            return result;
        }

        /// <summary>
        /// Scans a method's JIT code for FF 15 (CALL [rip+disp32]) indirect calls.
        /// Returns a list of (offset, cellAddr, cellValue) tuples.
        /// </summary>
        public string VerifyPatches()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("--- Patch Verification ---");
            // Check precode target1 data cell
            if (_indirectTargetLoc != IntPtr.Zero)
            {
                try
                {
                    long cur = Marshal.ReadInt64(_indirectTargetLoc);
                    long want = _newSlotValue.ToInt64();
                    long orig = _originalIndirectTarget.ToInt64();
                    sb.AppendLine($"PrecodeT1 cell @0x{_indirectTargetLoc.ToInt64():X16}: cur=0x{cur:X16} want=0x{want:X16} orig=0x{orig:X16} {(cur == want ? "OK" : "OVERWRITTEN")}");
                }
                catch (Exception ex) { sb.AppendLine($"PrecodeT1 cell: read error: {ex.Message}"); }
            }
            // Check JIT code E9 patch
            if (_hasSecondaryPatch && _secondaryJitAddress != IntPtr.Zero)
            {
                try
                {
                    byte b0 = Marshal.ReadByte(_secondaryJitAddress);
                    byte b1 = Marshal.ReadByte(_secondaryJitAddress + 1);
                    byte b2 = Marshal.ReadByte(_secondaryJitAddress + 2);
                    byte b3 = Marshal.ReadByte(_secondaryJitAddress + 3);
                    byte b4 = Marshal.ReadByte(_secondaryJitAddress + 4);
                    bool isE9 = (b0 == 0xE9);
                    sb.AppendLine($"JIT E9 @0x{_secondaryJitAddress.ToInt64():X16}: {b0:X2} {b1:X2} {b2:X2} {b3:X2} {b4:X2} {(isE9 ? "OK" : "OVERWRITTEN")}");
                }
                catch (Exception ex) { sb.AppendLine($"JIT E9: read error: {ex.Message}"); }
            }
            // Check target1 fixup thunk
            if (_hasTarget1Patch && _target1Address != IntPtr.Zero)
            {
                try
                {
                    byte b0 = Marshal.ReadByte(_target1Address);
                    byte b1 = Marshal.ReadByte(_target1Address + 1);
                    bool ok = (b0 == 0x48 && b1 == 0xB8);
                    sb.AppendLine($"Target1 thunk @0x{_target1Address.ToInt64():X16}: {b0:X2} {b1:X2} {(ok ? "OK" : "OVERWRITTEN")}");
                }
                catch (Exception ex) { sb.AppendLine($"Target1 thunk: read error: {ex.Message}"); }
            }
            // Check inner code
            if (_hasInnerCodePatch && _innerCodeAddress != IntPtr.Zero)
            {
                try
                {
                    byte b0 = Marshal.ReadByte(_innerCodeAddress);
                    byte b1 = Marshal.ReadByte(_innerCodeAddress + 1);
                    bool ok = (b0 == 0x48 && b1 == 0xB8);
                    sb.AppendLine($"InnerCode @0x{_innerCodeAddress.ToInt64():X16}: {b0:X2} {b1:X2} {(ok ? "OK" : "OVERWRITTEN")}");
                }
                catch (Exception ex) { sb.AppendLine($"InnerCode: read error: {ex.Message}"); }
            }
            // Check target2 data cell
            if (_hasTarget2Patch && _target2Loc != IntPtr.Zero)
            {
                try
                {
                    long cur = Marshal.ReadInt64(_target2Loc);
                    long want = _newSlotValue.ToInt64();
                    long orig = _target2OriginalValue.ToInt64();
                    sb.AppendLine($"Target2 cell @0x{_target2Loc.ToInt64():X16}: cur=0x{cur:X16} want=0x{want:X16} orig=0x{orig:X16} {(cur == want ? "OK" : "OVERWRITTEN")}");
                }
                catch (Exception ex) { sb.AppendLine($"Target2 cell: read error: {ex.Message}"); }
            }
            // Check slot replacements
            if (_slotAddresses != null)
            {
                foreach (IntPtr slot in _slotAddresses)
                {
                    try
                    {
                        long cur = Marshal.ReadInt64(slot);
                        long want = _newSlotValue.ToInt64();
                        long orig = _originalSlotValue.ToInt64();
                        sb.AppendLine($"Slot @0x{slot.ToInt64():X16}: cur=0x{cur:X16} want=0x{want:X16} orig=0x{orig:X16} {(cur == want ? "OK" : (cur == orig ? "RESTORED" : "OTHER"))}");
                    }
                    catch (Exception ex) { sb.AppendLine($"Slot @0x{slot.ToInt64():X16}: read error: {ex.Message}"); }
                }
            }
            return sb.ToString();
        }

        /// <summary>
        /// Scans a memory region (starting at baseAddr, for scanBytes) for 8-byte
        /// values that look like code pointers (in the executable range).
        /// Returns (offset, cellAddr, cellValue) tuples.
        /// </summary>
        public static unsafe List<(int offset, long cellAddr, long cellValue)> ScanRegionForCodePointers(IntPtr baseAddr, int scanBytes, long codeMin, long codeMax)
        {
            var result = new List<(int, long, long)>();
            try
            {
                byte* p = (byte*)baseAddr;
                for (int i = 0; i < scanBytes - 8; i += 8)
                {
                    try
                    {
                        long val = *(long*)(p + i);
                        if (val >= codeMin && val <= codeMax)
                        {
                            result.Add((i, baseAddr.ToInt64() + i, val));
                        }
                    }
                    catch { break; }
                }
            }
            catch { }
            return result;
        }

        public static unsafe List<(int offset, long cellAddr, long cellValue)> ScanIndirectCalls(MethodBase method, int maxScanBytes)
        {
            var result = new List<(int, long, long)>();
            try
            {
                RuntimeHelpers.PrepareMethod(method.MethodHandle);
                IntPtr entry = method.MethodHandle.GetFunctionPointer();
                if (entry == IntPtr.Zero) return result;
                IntPtr jitEntry = MethodEntryResolver.ResolveRealEntry(entry);
                if (jitEntry != IntPtr.Zero) entry = jitEntry;
                byte* p = (byte*)entry;
                for (int i = 0; i < maxScanBytes - 6; i++)
                {
                    if (p[i] == 0xFF && p[i + 1] == 0x15)
                    {
                        int rel = *(int*)(p + i + 2);
                        long dataAddr = (long)(p + i) + 6 + rel;
                        try
                        {
                            long target = *(long*)dataAddr;
                            result.Add((i, dataAddr, target));
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return result;
        }

        /// <summary>
        /// Scans the JIT code of a method for MOV reg, [rip+disp32] instructions
        /// (48 8B xx or 4C 8B xx) and reports the memory cell address and loaded value.
        /// This is used to find dictionary slots used by generic method call sites.
        /// </summary>
        public static unsafe List<(int offset, int reg, long cellAddr, long cellValue)> ScanMovRipRelative(MethodBase method, int maxScanBytes)
        {
            var result = new List<(int, int, long, long)>();
            try
            {
                RuntimeHelpers.PrepareMethod(method.MethodHandle);
                IntPtr entry = method.MethodHandle.GetFunctionPointer();
                if (entry == IntPtr.Zero) return result;
                IntPtr jitEntry = MethodEntryResolver.ResolveRealEntry(entry);
                if (jitEntry != IntPtr.Zero) entry = jitEntry;
                byte* p = (byte*)entry;
                // ModR/M bytes for [rip+disp32]: 05,0D,15,1D,25,2D,35,3D
                // maps to registers: RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI (for REX.W=48)
                // or R8-R15 (for REX.W+REX.R=4C)
                int[] modrmBytes = { 0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D };
                for (int i = 0; i < maxScanBytes - 7; i++)
                {
                    byte b0 = p[i];
                    if (b0 != 0x48 && b0 != 0x4C) continue;
                    if (p[i + 1] != 0x8B) continue;
                    byte modrm = p[i + 2];
                    bool found = false;
                    int regIdx = 0;
                    for (int r = 0; r < modrmBytes.Length; r++)
                    {
                        if (modrm == modrmBytes[r]) { found = true; regIdx = r; break; }
                    }
                    if (!found) continue;
                    int rel = *(int*)(p + i + 3);
                    long dataAddr = (long)(p + i) + 7 + rel;
                    try
                    {
                        long val = *(long*)dataAddr;
                        int regNum = (b0 == 0x4C) ? regIdx + 8 : regIdx;
                        result.Add((i, regNum, dataAddr, val));
                    }
                    catch { }
                }
            }
            catch { }
            return result;
        }

        public void Install()
        {
            if (_isInstalled)
            {
                return;
            }
            if (_isDisposed)
            {
                throw new ObjectDisposedException("MethodHook");
            }
            HookDiagInfo hookDiagInfo = new HookDiagInfo();
            hookDiagInfo.TargetMethod = _targetMethod.ToString();
            hookDiagInfo.HookMethod = _hookMethod.ToString();
            PrepareMethod(_targetMethod);
            PrepareMethod(_hookMethod);
            // Create a delegate to the original method BEFORE any patching.
            // The delegate's Invoke method is JIT-compiled with the correct generic
            // dictionary setup (R10), bypassing RuntimeMethodHandle.InvokeMethod
            // which crashes (0x80131506) for hooked generic methods.
            CreateOriginalDelegate();
            IntPtr functionPointer = _targetMethod.MethodHandle.GetFunctionPointer();
            IntPtr functionPointer2 = _hookMethod.MethodHandle.GetFunctionPointer();
            hookDiagInfo.PrecodeAddr = functionPointer;
            hookDiagInfo.PrecodeBytes = ReadBytesSafe(functionPointer, 32);
            _originalSlotValue = functionPointer;
            if (_targetMethod is MethodInfo { IsGenericMethod: not false } methodInfo)
            {
                // 泛型方法调用点绕过 precode，直接调用 JIT 代码。
                // 需要 patch JIT 代码（E9）重定向调用到 hook。
                // 同时 patch precode target1，使 delegate.Invoke 也被重定向。
                // CallOriginal 通过 RestoreAll 恢复两者 → 委托调用 → ReapplyAll 重新打补丁。
                hookDiagInfo.DelegateStatus = "Precode indirect + JIT E9 patch";
            }
            _needsGenericAdapter = _targetMethod.IsGenericMethod;
            hookDiagInfo.NeedsGenericAdapter = _needsGenericAdapter;
            // Resolve to the hook's real JIT code entry so that patched call sites
            // jump directly to the hook body. Using the precode address would route
            // the call through the hook's own fixup thunk, which clobbers RDX (moves
            // arg2 to R8 and loads the generic dict into RDX) and breaks the standard
            // calling convention expected by the hook body.
            IntPtr intPtr = MethodEntryResolver.ResolveRealEntry(functionPointer2);
            if (intPtr == IntPtr.Zero) intPtr = functionPointer2;
            if (_needsGenericAdapter)
            {
                // CoreCLR: generic dictionary is in R10 (loaded by precode/callsite).
                // User args are already in correct registers (RCX=this, RDX=arg1, ...).
                // The adapter's MOV RCX,R10 would overwrite 'this' with the generic dict.
                // Skip adapter and jump directly to hook.
                _genericAdapter = IntPtr.Zero;
                hookDiagInfo.AdapterAddr = IntPtr.Zero;
                hookDiagInfo.AdapterBytes = null;
            }
            _newSlotValue = intPtr;
            hookDiagInfo.JumpTargetAddr = intPtr;
            InstallSlotReplacement(functionPointer, intPtr, hookDiagInfo);
            // Set _isInstalled before InstallCodePatch so that if the hook is triggered
            // during patch installation (e.g., by String.Format or other BCL methods),
            // CallOriginal can correctly restore/invoke/reapply instead of throwing.
            _isInstalled = true;
            InstallCodePatch(functionPointer, intPtr, hookDiagInfo);
            DiagInfo = hookDiagInfo;
        }

        private void PrepareMethod(MethodBase method)
        {
            RuntimeHelpers.PrepareMethod(method.MethodHandle);
            if (!method.IsGenericMethod)
            {
                return;
            }
            try
            {
                Type[] genericArguments = method.GetGenericArguments();
                RuntimeTypeHandle[] instantiation = genericArguments.Select((Type t) => t.TypeHandle).ToArray();
                RuntimeHelpers.PrepareMethod(method.MethodHandle, instantiation);
            }
            catch
            {
            }
        }

        /// <summary>
        /// Creates an open delegate to the target method and captures the function
        /// pointer of the delegate's Invoke method. Must be called BEFORE any patching.
        ///
        /// The delegate's Invoke method is JIT-compiled by the CLR with full
        /// knowledge of the method's generic arguments. For generic methods, it
        /// sets up R10 (generic dictionary) before calling the precode — something
        /// that RuntimeMethodHandle.InvokeMethod fails to do after JIT code patching
        /// (causing 0x80131506). By calling Invoke via delegate* (function pointer),
        /// we bypass RuntimeMethodHandle.InvokeMethod entirely. The Invoke method is
        /// non-generic (it lives on a constructed generic delegate type but has no
        /// type parameters of its own), so this path is safe for hooked generics.
        /// </summary>
        private void CreateOriginalDelegate()
        {
            MethodInfo methodInfo = _targetMethod as MethodInfo;
            if (methodInfo == null)
            {
                return;
            }
            try
            {
                ParameterInfo[] parameters = methodInfo.GetParameters();
                Type returnType = methodInfo.ReturnType;
                bool isVoid = returnType == typeof(void);

                // Build the type argument list for the delegate.
                // For instance methods, the first type arg is the declaring type (open delegate).
                int extraForInstance = methodInfo.IsStatic ? 0 : 1;
                int totalTypeArgs = parameters.Length + extraForInstance + (isVoid ? 0 : 1);

                Type[] typeArgs = new Type[totalTypeArgs];
                int idx = 0;
                if (!methodInfo.IsStatic)
                {
                    typeArgs[idx++] = methodInfo.DeclaringType;
                }
                for (int i = 0; i < parameters.Length; i++)
                {
                    typeArgs[idx++] = parameters[i].ParameterType;
                }
                if (!isVoid)
                {
                    typeArgs[idx++] = returnType;
                }

                // Get the open delegate type (Func<...> or Action<...>)
                string delegateName = isVoid ? "System.Action`" : "System.Func`";
                Type openDelegateType = Type.GetType(delegateName + totalTypeArgs);
                if (openDelegateType == null)
                {
                    return;
                }
                Type delegateType = openDelegateType.MakeGenericType(typeArgs);

                // Create an open delegate (null target). For instance methods, the
                // instance is passed as the first argument when invoking the delegate.
                _originalDelegate = Delegate.CreateDelegate(delegateType, null, methodInfo);

                // Record the flat argument count (instance + declared params).
                _delegateFlatArgCount = parameters.Length + extraForInstance;

                // Capture the function pointer of the delegate's Invoke method.
                // Invoke is an instance method whose native arg count is
                // _delegateFlatArgCount + 1 (the +1 is the delegate itself as 'this').
                // It is non-generic, so GetFunctionPointer works and delegate* calls
                // bypass RuntimeMethodHandle.InvokeMethod (avoiding 0x80131506).
                MethodInfo invokeMethod = delegateType.GetMethod("Invoke");
                if (invokeMethod == null)
                {
                    _originalDelegate = null;
                    return;
                }
                RuntimeMethodHandle invokeHandle = invokeMethod.MethodHandle;
                try
                {
                    RuntimeHelpers.PrepareMethod(invokeHandle);
                }
                catch
                {
                    // PrepareMethod may fail for some constructed generic delegate
                    // types; the Invoke method is still callable via its entry point.
                }
                _delegateInvokeFptr = invokeHandle.GetFunctionPointer();
            }
            catch
            {
                _originalDelegate = null;
                _delegateInvokeFptr = IntPtr.Zero;
                _delegateFlatArgCount = 0;
            }
        }

        private void InstallSlotReplacement(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            // Try slot replacement in addition to precode/JIT patches. The CLR may use
            // MethodDesc/MethodTable slots to dispatch method calls (esp. generic methods
            // whose call sites bypass the precode and call JIT code directly).
            try
            {
                IntPtr methodDesc = _targetMethod.MethodHandle.Value;
                IntPtr methodTable = IntPtr.Zero;
                Type declaringType = _targetMethod.DeclaringType;
                if (declaringType != null)
                {
                    methodTable = declaringType.TypeHandle.Value;
                }
                // For non-generic methods, skip MethodDesc scan (offsets 8/16 are
                // entry-point fields — corrupting them breaks dispatch). The MethodTable
                // scan (65536 bytes) may still overlap MethodDesc memory, so filter out
                // any found slots that fall within the MethodDesc region afterwards.
                IntPtr mdForScan = _needsGenericAdapter ? methodDesc : IntPtr.Zero;
                _slotAddresses = SlotPatcher.FindSlots(mdForScan, methodTable, targetPtr);
                if (!_needsGenericAdapter && methodDesc != IntPtr.Zero)
                {
                    long mdStart = methodDesc.ToInt64();
                    long mdEnd = mdStart + 128;
                    _slotAddresses = _slotAddresses.FindAll(s =>
                    {
                        long a = s.ToInt64();
                        return a < mdStart || a >= mdEnd;
                    });
                }

                // For generic methods, also scan the generic dictionary for the
                // method's code pointer. On .NET 8, call sites for generic methods
                // load the code pointer from the generic dictionary and call it
                // indirectly (CALL RAX). Patching the dictionary slot redirects
                // these indirect calls to the hook.
                if (_targetMethod.IsGenericMethod)
                {
                    IntPtr genDictAddr = ExtractGenericDictionaryFromFixup(targetPtr);
                    diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; GenDictAddr=0x" + genDictAddr.ToInt64().ToString("X");
                    if (genDictAddr != IntPtr.Zero)
                    {
                        IntPtr jitCode = MethodEntryResolver.ResolveRealEntry(targetPtr);
                        List<IntPtr> dictSlots = SlotPatcher.FindSlots(genDictAddr, IntPtr.Zero, targetPtr);
                        // Also scan for the JIT code address
                        List<IntPtr> dictSlots2 = SlotPatcher.FindSlots(genDictAddr, IntPtr.Zero, jitCode);
                        foreach (IntPtr s in dictSlots2)
                        {
                            if (!dictSlots.Contains(s)) dictSlots.Add(s);
                        }
                        foreach (IntPtr s in dictSlots)
                        {
                            if (!_slotAddresses.Contains(s)) _slotAddresses.Add(s);
                        }
                        diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; GenDictScan at 0x" + genDictAddr.ToInt64().ToString("X") + " found " + dictSlots.Count + " slots";
                    }
                }

                diag.SlotCount = _slotAddresses.Count;
                diag.SlotAddresses = (from a in _slotAddresses.Take(10)
                                      select a.ToInt64()).ToList();
                foreach (IntPtr slotAddress in _slotAddresses)
                {
                    SlotPatcher.ReplaceSlot(slotAddress, jumpTarget);
                }
            }
            catch (Exception ex)
            {
                diag.SlotError = ex.Message;
            }
        }

        /// <summary>
        /// 从 FixupPrecode 的第一个 FF 25 目标（fixup thunk）中提取泛型字典地址。
        /// fixup thunk 格式: 49 89 D0 48 BA <dict> 48 B8 <code> FF E0
        /// 泛型字典地址在偏移 5 处 (48 BA 的操作数)。
        /// </summary>
        private unsafe IntPtr ExtractGenericDictionaryFromFixup(IntPtr precodeAddr)
        {
            if (!Memory.IsReadable(precodeAddr, 6)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)precodeAddr;
                if (p[0] != 0xFF || p[1] != 0x25) return IntPtr.Zero;
                // Read first FF 25's target (the fixup thunk)
                int disp = *(int*)(p + 2);
                long fixupLoc = precodeAddr.ToInt64() + 6 + disp;
                if (!Memory.IsReadable(new IntPtr(fixupLoc), 8)) return IntPtr.Zero;
                long fixupAddr = *(long*)fixupLoc;
                if (fixupAddr == 0) return IntPtr.Zero;
                if (!Memory.IsReadable(new IntPtr(fixupAddr), 23)) return IntPtr.Zero;
                byte* f = (byte*)fixupAddr;
                // Check fixup thunk pattern: 49 89 D0 48 BA <8-byte dict> 48 B8 <8-byte code> FF E0
                if (f[0] != 0x49 || f[1] != 0x89 || f[2] != 0xD0) return IntPtr.Zero;
                if (f[3] != 0x48 || f[4] != 0xBA) return IntPtr.Zero;
                long dictAddr = *(long*)(f + 5);
                if (dictAddr == 0) return IntPtr.Zero;
                return new IntPtr(dictAddr);
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        private void InstallCodePatch(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            try
            {
                switch (Platform.Current)
                {
                    case Platform.Arch.X64:
                        InstallCodePatchX64(targetPtr, jumpTarget, diag);
                        return;
                    case Platform.Arch.X86:
                        InstallCodePatchX86(targetPtr, jumpTarget, diag);
                        return;
                }
                _patchType = 3;
                _patchAddress = targetPtr;
                _originalBytes = Jumper.Install(targetPtr, jumpTarget);
                diag.InstalledBytes = ReadBytesSafe(targetPtr, _originalBytes.Length);
            }
            catch (Exception ex)
            {
                diag.PatchError = ex.Message;
            }
        }

        private unsafe void InstallCodePatchX64(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            _precodeAddr = targetPtr;
            if (!Memory.IsReadable(targetPtr, 20))
            {
                diag.PatchError = "targetPtr not readable for x64 code patch";
                return;
            }
            byte* ptr = (byte*)(void*)targetPtr;
            byte b = *ptr;
            byte b2 = ptr[1];
            if (b == byte.MaxValue && b2 == 37)
            {
                bool flag = ptr[6] == 76 && ptr[7] == 139 && ptr[8] == 21 && ptr[13] == byte.MaxValue && ptr[14] == 37;
                // Read first FF 25's indirect target for diagnostics
                int disp1 = *(int*)(ptr + 2);
                long target1Loc = targetPtr.ToInt64() + 6 + disp1;
                if (!Memory.IsReadable(new IntPtr(target1Loc), 8))
                {
                    diag.PatchError = "target1Loc not readable";
                    return;
                }
                diag.PrecodeFirstTargetAddr = new IntPtr(*(long*)target1Loc);
                if (flag)
                {
                    int disp2 = *(int*)(ptr + 15);
                    long target2Loc = targetPtr.ToInt64() + 19 + disp2;
                    if (Memory.IsReadable(new IntPtr(target2Loc), 8))
                    {
                        diag.PrecodeSecondTargetAddr = new IntPtr(*(long*)target2Loc);
                    }
                }
                // Dump bytes at target1 and MethodDesc for diagnostics
                try { diag.Target1Bytes = ReadBytesSafe(diag.PrecodeFirstTargetAddr, 32); } catch { }
                try { diag.MethodDescDump = ReadBytesSafe(_targetMethod.MethodHandle.Value, 64); } catch { }
                // For generic methods, call sites bypass the precode and call the JIT
                // code directly. So we MUST patch the JIT code to redirect calls.
                // We also patch the precode's target1 so that delegate.Invoke (which
                // may go through the precode) is also redirected. Both patches are
                // restored/reapplied by RestoreAll/ReapplyAll during CallOriginal.
                if (flag && _needsGenericAdapter)
                {
                    // Patch precode target1 → hook (for delegate.Invoke path)
                    int num2g = *(int*)(ptr + 2);
                    long num3g = targetPtr.ToInt64() + 6 + num2g;
                    _patchType = 1;
                    _patchAddress = targetPtr;
                    _indirectTargetLoc = new IntPtr(num3g);
                    _originalIndirectTarget = new IntPtr(*(long*)num3g);
                    Memory.ProtectReadWrite(_indirectTargetLoc, 8);
                    *(long*)num3g = jumpTarget.ToInt64();
                    diag.PatchType = "Indirect(FF 25 1st) + JIT(E9, generic) + Target1(12-byte)";
                    diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
                    // NOTE: InstallSecondaryJitPatch is intentionally NOT called here.
                    // Patching JIT code with a 5-byte E9 causes delegate invocation to
                    // hang on .NET 8. The precode + target1 + target2 patches are
                    // sufficient for delegate.Invoke to trigger the hook. Direct call
                    // sites bypass the precode via JIT backpatching on .NET 8, so they
                    // won't trigger the hook regardless. A copy-prologue trampoline is
                    // installed below (after target2) to enable CallOriginal without
                    // RestoreAll/ReapplyAll.
                    // Also patch target1 (the fixup thunk at PrecodeFirstTargetAddr)
                    // with a 12-byte absolute jump to the hook. The call site for
                    // generic methods may call target1 directly (bypassing the precode),
                    // so patching the precode's data pointer alone is not enough.
                    InstallTarget1Patch(diag.PrecodeFirstTargetAddr, jumpTarget, diag);
                    // Also patch target2 (Precode2ndTarget). For generic methods, the
                    // call site may enter the precode at offset 6 (MOV R10, MethodDesc),
                    // which sets up the generic dictionary, then JMP [target2]. If
                    // target2 still points to the original code, the hook is bypassed.
                    // Patch the target2 data cell to redirect to the hook.
                    InstallTarget2Patch(targetPtr, ptr, jumpTarget, diag);
                    // Install a call-original trampoline using the inner code's original
                    // prologue. The trampoline sets up R10 (generic dict), executes the
                    // relocated original prologue, then JMPs past the 12-byte patch.
                    // This lets CallOriginal bypass RestoreAll/ReapplyAll entirely,
                    // avoiding the 0x80131506 CLR crash for generic methods on .NET 8.
                    if (_innerCodeAddress != IntPtr.Zero && _innerCodeOriginalBytesFull != null)
                    {
                        InstallCallOriginalTrampoline(_innerCodeAddress, _innerCodeOriginalBytesFull, diag, 12);
                    }
                }
                else
                {
                    // Non-generic: patch the FF 25's indirect target data pointer.
                    int num = 0;  // Always patch the first FF 25 (the normal call entry)
                    byte* ptr2 = ptr + num;
                    int num2 = *(int*)(ptr2 + 2);
                    long num3 = targetPtr.ToInt64() + num + 6 + num2;
                    _patchType = 1;
                    _patchAddress = targetPtr;
                    _indirectTargetLoc = new IntPtr(num3);
                    _originalIndirectTarget = new IntPtr(*(long*)num3);
                    Memory.ProtectReadWrite(_indirectTargetLoc, 8);
                    *(long*)num3 = jumpTarget.ToInt64();
                    diag.PatchType = (flag ? "Indirect(FF 25 1st, FixupPrecode)" : "Indirect(FF 25)");
                    diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
                }
            }
            else if (b == 232 || b == 233)
            {
                // For generic methods, patch JIT code BEFORE patching precode.
                // ResolveRealEntry must see the original precode to find the real JIT code.
                if (_needsGenericAdapter)
                {
                    InstallSecondaryJitPatch(targetPtr, jumpTarget, diag);
                }
                // E8/E9 precode: patch the precode itself with a 5-byte relative
                // jump to a near trampoline. This works for both generic and
                // non-generic methods because it modifies the precode (not JIT code).
                _nearTrampoline = Memory.AllocExecNear(targetPtr, 12);
                if (_nearTrampoline == IntPtr.Zero || _nearTrampoline == new IntPtr(-1))
                {
                    diag.PatchError = "Failed to allocate near trampoline for E8/E9 patch";
                    return;
                }
                byte[] array = new byte[12]
                {
                72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0
                };
                BitConverter.GetBytes(jumpTarget.ToInt64()).CopyTo(array, 2);
                array[10] = byte.MaxValue;
                array[11] = 224;
                Marshal.Copy(array, 0, _nearTrampoline, 12);
                Memory.ProtectExecutable(_nearTrampoline, 12);
                _patchType = 2;
                _patchAddress = targetPtr;
                _originalBytes = new byte[6];
                Marshal.Copy(targetPtr, _originalBytes, 0, 6);
                int value = (int)(_nearTrampoline.ToInt64() - (targetPtr.ToInt64() + 5));
                byte[] array2 = new byte[5] { 233, 0, 0, 0, 0 };
                BitConverter.GetBytes(value).CopyTo(array2, 1);
                Memory.ProtectWritable(targetPtr, 5);
                Marshal.Copy(array2, 0, targetPtr, 5);
                Memory.ProtectExecutable(targetPtr, 5);
                diag.PatchType = ((b == 232) ? "FixupPrecode(E8->E9)" : "DirectJump(E9)");
                diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
            }
            else if (!MethodEntryResolver.IsJump(targetPtr))
            {
                _patchType = 3;
                _patchAddress = targetPtr;
                _originalBytes = Jumper.Install(targetPtr, jumpTarget);
                diag.PatchType = "JitCode(12-byte)";
                diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
            }
            else
            {
                IntPtr intPtr = MethodEntryResolver.ResolveRealEntry(targetPtr);
                if (intPtr != IntPtr.Zero && intPtr != targetPtr && !MethodEntryResolver.IsJump(intPtr))
                {
                    _patchType = 3;
                    _patchAddress = intPtr;
                    _originalBytes = Jumper.Install(intPtr, jumpTarget);
                    diag.PatchType = "ResolvedJitCode(12-byte)";
                    diag.InstalledBytes = ReadBytesSafe(intPtr, 16);
                }
                else
                {
                    diag.PatchType = "None(relies on slot replacement)";
                }
            }
        }

        private void InstallSecondaryJitPatch(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            try
            {
                IntPtr intPtr = MethodEntryResolver.ResolveRealEntry(targetPtr);
                // .NET Framework 4.x E8 precode: ResolveRealEntry treats E8+5E as a
                // precode sentinel and returns without following. Manually follow
                // the E8 rel32 to the fixup code, then extract the JIT code address.
                if (intPtr == targetPtr)
                {
                    unsafe
                    {
                        if (!Memory.IsReadable(targetPtr, 6))
                        {
                            diag.SlotError += "; targetPtr not readable for E8 check";
                            return;
                        }
                        byte* p = (byte*)targetPtr;
                        if (p[0] == 0xE8)
                        {
                            int rel32 = *(int*)(p + 1);
                            long fixupAddr = targetPtr.ToInt64() + 5 + rel32;
                            IntPtr fixupJit = TryResolveFixupToJitCode(new IntPtr(fixupAddr));
                            if (fixupJit != IntPtr.Zero) intPtr = fixupJit;
                        }
                    }
                }
                if (intPtr == IntPtr.Zero || intPtr == targetPtr)
                {
                    diag.SlotError += "; cannot resolve JIT entry for secondary patch";
                    return;
                }
                // On .NET Framework 4.x, the resolved entry may be the "fixup code" that
                // sets up the generic dictionary and jumps to the real JIT code.
                // Pattern: 49 89 D0 48 BA <dict> 48 B8 <jit_addr> FF E0
                // If detected, extract the real JIT code address from the 48 B8 operand.
                IntPtr realJit = TryResolveFixupToJitCode(intPtr);
                if (realJit != IntPtr.Zero && realJit != intPtr)
                {
                    diag.SlotError += "; resolved fixup code -> real JIT at 0x" + realJit.ToInt64().ToString("X");
                    intPtr = realJit;
                }
                InstallSecondaryJitPatchAt(intPtr, jumpTarget, diag);
            }
            catch (Exception ex)
            {
                diag.SlotError = diag.SlotError + "; SecondaryJitPatch error: " + ex.Message;
            }
        }

        /// <summary>
        /// Detects the .NET Framework generic method fixup code pattern and extracts
        /// the real JIT code address from it.
        /// Pattern: 49 89 D0 | 48 BA <8-byte dict> | 48 B8 <8-byte jit_addr> | FF E0
        /// The JIT code address is at offset 15 (after 48 B8 at offset 13).
        /// </summary>
        private unsafe IntPtr TryResolveFixupToJitCode(IntPtr addr)
        {
            if (addr == IntPtr.Zero) return IntPtr.Zero;
            // In .NET 6+, AV from unmapped memory is uncatchable. Check readability.
            if (!Memory.IsReadable(addr, 23)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)addr;
                // Check for 49 89 D0 48 BA at the start
                if (p[0] != 0x49 || p[1] != 0x89 || p[2] != 0xD0) return IntPtr.Zero;
                if (p[3] != 0x48 || p[4] != 0xBA) return IntPtr.Zero;
                // Check for 48 B8 at offset 13
                if (p[13] != 0x48 || p[14] != 0xB8) return IntPtr.Zero;
                // Read the JIT code address at offset 15
                long jitAddr = *(long*)(p + 15);
                if (jitAddr == 0) return IntPtr.Zero;
                return new IntPtr(jitAddr);
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        /// <summary>
        /// Detects the .NET Framework x86 generic method fixup code pattern and
        /// extracts the real JIT code address from it. The fixup code typically
        /// loads the generic dictionary (via MOV EDX/B8 or similar) then:
        ///   B8 <jit_addr32>   ; MOV EAX, jit_addr
        ///   FF E0              ; JMP EAX
        /// We scan the first 32 bytes for this B8..FF E0 pattern.
        /// </summary>
        private unsafe IntPtr TryResolveFixupToJitCodeX86(IntPtr addr)
        {
            if (addr == IntPtr.Zero) return IntPtr.Zero;
            // In .NET 6+, AV from unmapped memory is uncatchable. Check readability.
            if (!Memory.IsReadable(addr, 33)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)addr;
                // Scan for B8 <4 bytes> FF E0 within the first 32 bytes
                for (int i = 0; i <= 26; i++)
                {
                    if (p[i] == 0xB8 && p[i + 5] == 0xFF && p[i + 6] == 0xE0)
                    {
                        int jitAddr = *(int*)(p + i + 1);
                        if (jitAddr != 0) return new IntPtr(jitAddr);
                    }
                }
                return IntPtr.Zero;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        private void InstallSecondaryJitPatchAt(IntPtr intPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            try
            {
                if (intPtr == IntPtr.Zero)
                {
                    diag.SlotError += "; cannot patch null JIT entry";
                    return;
                }
                diag.JitCodeAddr = intPtr;
                diag.JitCodeOriginalBytes = ReadBytesSafe(intPtr, 32);

                // Use a 5-byte relative jump (E9) with a near trampoline instead of a 12-byte
                // absolute jump. This overwrites only 5 bytes of the prologue, minimizing GC
                // info corruption. The trampoline is allocated within 2GB of the patch site.
                IntPtr trampoline = Memory.AllocExecNear(intPtr, 12);
                if (trampoline == IntPtr.Zero || trampoline == new IntPtr(-1))
                {
                    diag.SlotError += "; failed to allocate near trampoline for JIT patch";
                    return;
                }
                // Trampoline: MOV RAX, jumpTarget; JMP RAX (12 bytes)
                byte[] trampBytes = new byte[12]
                {
                72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
                byte.MaxValue, 224
                };
                BitConverter.GetBytes(jumpTarget.ToInt64()).CopyTo(trampBytes, 2);
                Marshal.Copy(trampBytes, 0, trampoline, 12);
                Memory.ProtectExecutable(trampoline, 12);

                // Patch JIT code with 5-byte relative jump to trampoline
                _secondaryJitAddress = intPtr;
                int patchSize = 5;
                _secondaryJitOriginalBytes = new byte[patchSize];
                Marshal.Copy(intPtr, _secondaryJitOriginalBytes, 0, patchSize);
                int rel32 = (int)(trampoline.ToInt64() - (intPtr.ToInt64() + 5));
                byte[] patch = new byte[5] { 233, 0, 0, 0, 0 };
                BitConverter.GetBytes(rel32).CopyTo(patch, 1);
                // Build diagnostic string BEFORE patching to avoid triggering hook via String.Format
                string diagMsg = "; SecondaryJitPatch(5-byte) at 0x" + intPtr.ToInt64().ToString("X") + " -> tramp 0x" + trampoline.ToInt64().ToString("X");
                Memory.ProtectWritable(intPtr, 5);
                Marshal.Copy(patch, 0, intPtr, 5);
                Memory.ProtectExecutable(intPtr, 5);
                _hasSecondaryPatch = true;
                _secondaryTrampoline = trampoline;
                diag.JitCodePatchedBytes = ReadBytesSafe(intPtr, 16);
                diag.SlotError += diagMsg;
            }
            catch (Exception ex)
            {
                diag.SlotError = diag.SlotError + "; SecondaryJitPatch error: " + ex.Message;
            }
        }

        /// <summary>
        /// x86 secondary JIT patch for generic methods. Follows the E8/E9 precode
        /// to the fixup code, extracts the real JIT address, and patches it with
        /// a 5-byte E9 relative jump. On x86, no near trampoline is needed since
        /// E9 rel32 can reach any 32-bit address.
        /// </summary>
        private unsafe void InstallSecondaryJitPatchX86(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            try
            {
                if (!Memory.IsReadable(targetPtr, 6))
                {
                    diag.SlotError += "; targetPtr not readable for x86 secondary patch";
                    return;
                }
                byte* p = (byte*)targetPtr;
                IntPtr fixupAddr = IntPtr.Zero;

                if (p[0] == 0xE9 || p[0] == 0xE8)
                {
                    int rel32 = *(int*)(p + 1);
                    fixupAddr = new IntPtr(targetPtr.ToInt32() + 5 + rel32);
                }

                if (fixupAddr == IntPtr.Zero)
                {
                    diag.SlotError += "; cannot resolve fixup code for x86 secondary patch";
                    return;
                }

                // Follow the jump chain to find the real JIT code. The fixup code
                // may have multiple layers: precode thunk (POP/PUSH/JMP) → fixup
                // code (MOV EDX,dict; MOV EAX,jit; JMP EAX) → JIT code.
                IntPtr jitAddr = IntPtr.Zero;
                IntPtr cur = fixupAddr;
                for (int hop = 0; hop < 8 && cur != IntPtr.Zero; hop++)
                {
                    // TryResolveFixupToJitCodeX86 already checks readability.
                    jitAddr = TryResolveFixupToJitCodeX86(cur);
                    if (jitAddr != IntPtr.Zero) break;

                    // Scan for an E9 rel32 within the next 32 bytes and follow it
                    IntPtr next = IntPtr.Zero;
                    if (Memory.IsReadable(cur, 32))
                    {
                        byte* bp = (byte*)cur;
                        for (int i = 0; i < 28; i++)
                        {
                            if (bp[i] == 0xE9)
                            {
                                int rel = *(int*)(bp + i + 1);
                                next = new IntPtr(cur.ToInt32() + i + 5 + rel);
                                break;
                            }
                        }
                    }
                    if (next == IntPtr.Zero || next == cur) break;
                    cur = next;
                }

                if (jitAddr == IntPtr.Zero)
                {
                    // Fall back to the last address we found (might be JIT code directly)
                    jitAddr = cur;
                }

                if (jitAddr == IntPtr.Zero)
                {
                    diag.SlotError += "; cannot resolve JIT entry for x86 secondary patch";
                    return;
                }

                diag.JitCodeAddr = jitAddr;
                diag.JitCodeOriginalBytes = ReadBytesSafe(jitAddr, 32);

                // Patch JIT code with 5-byte E9 relative jump (no trampoline needed on x86)
                _secondaryJitAddress = jitAddr;
                _secondaryJitOriginalBytes = new byte[5];
                Marshal.Copy(jitAddr, _secondaryJitOriginalBytes, 0, 5);
                int rel2 = jumpTarget.ToInt32() - (jitAddr.ToInt32() + 5);
                byte[] patch = new byte[5] { 0xE9, 0, 0, 0, 0 };
                BitConverter.GetBytes(rel2).CopyTo(patch, 1);
                Memory.ProtectWritable(jitAddr, 5);
                Marshal.Copy(patch, 0, jitAddr, 5);
                Memory.ProtectExecutable(jitAddr, 5);
                _hasSecondaryPatch = true;
                _secondaryTrampoline = IntPtr.Zero; // no trampoline on x86
                diag.JitCodePatchedBytes = ReadBytesSafe(jitAddr, 16);
                diag.SlotError += "; SecondaryJitPatchX86(5-byte) at 0x" + jitAddr.ToInt32().ToString("X");
            }
            catch (Exception ex)
            {
                diag.SlotError = diag.SlotError + "; SecondaryJitPatchX86 error: " + ex.Message;
            }
        }

        /// <summary>
        /// Patches the target1 fixup thunk (the address stored in the precode's
        /// first FF 25 data pointer) with a 12-byte absolute jump to the hook.
        ///
        /// For generic methods on .NET 8, the call site may call target1 directly
        /// (bypassing the precode). The target1 thunk typically looks like:
        ///   MOV R8, RDX; MOV RDX, <dict>; MOV RAX, <code>; JMP RAX  (25 bytes)
        /// Overwriting the first 12 bytes with MOV RAX, hook; JMP RAX redirects
        /// any call to target1 directly to the hook.
        ///
        /// Additionally, extracts the inner code address (from MOV RAX, <code>)
        /// and patches that too — the call site may use it as the "stable entry
        /// point" directly.
        /// </summary>
        private unsafe void InstallTarget1Patch(IntPtr target1Addr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            if (target1Addr == IntPtr.Zero) return;
            try
            {
                // Read the fixup code to extract the inner code address
                byte[] fixupBytes = ReadBytesSafe(target1Addr, 25);
                IntPtr innerCodeAddr = IntPtr.Zero;
                if (fixupBytes != null && fixupBytes.Length >= 25 &&
                    fixupBytes[0] == 0x49 && fixupBytes[1] == 0x89 && fixupBytes[2] == 0xD0 &&
                    fixupBytes[3] == 0x48 && fixupBytes[4] == 0xBA &&
                    fixupBytes[13] == 0x48 && fixupBytes[14] == 0xB8 &&
                    fixupBytes[23] == 0xFF && fixupBytes[24] == 0xE0)
                {
                    long innerAddr = BitConverter.ToInt64(fixupBytes, 15);
                    if (innerAddr != 0)
                    {
                        innerCodeAddr = new IntPtr(innerAddr);
                        diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; InnerCodeAddr: 0x" + innerAddr.ToString("X");
                        // On .NET 8, the fixup thunk's target may point to another
                        // FixupPrecode (FF 25 + 4C 8B 15 + FF 25) rather than the
                        // real JIT code. Resolve through all jump/precode layers
                        // to find the actual JIT code entry. This MUST be done
                        // before patching target1, otherwise ResolveRealEntry would
                        // follow our patch and resolve to the hook address.
                        IntPtr realJit = MethodEntryResolver.ResolveRealEntry(innerCodeAddr);
                        if (realJit != IntPtr.Zero && realJit != innerCodeAddr)
                        {
                            diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; ResolvedInner->RealJit 0x" + realJit.ToInt64().ToString("X");
                            innerCodeAddr = realJit;
                        }
                    }
                }

                // Patch target1 (fixup thunk) with 12-byte absolute jump to hook
                if (!Memory.IsReadable(target1Addr, 12))
                {
                    diag.SlotError += "; target1Addr not readable for patch";
                    return;
                }
                _target1Address = target1Addr;
                _target1OriginalBytes = new byte[12];
                Marshal.Copy(target1Addr, _target1OriginalBytes, 0, 12);
                byte[] patch = new byte[12]
                {
                72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
                byte.MaxValue, 224
                };
                BitConverter.GetBytes(jumpTarget.ToInt64()).CopyTo(patch, 2);
                Memory.ProtectWritable(target1Addr, 12);
                Marshal.Copy(patch, 0, target1Addr, 12);
                Memory.ProtectExecutable(target1Addr, 12);
                _hasTarget1Patch = true;
                diag.SlotError += "; Target1Patch(12-byte) at 0x" + target1Addr.ToInt64().ToString("X");

                // Also patch the inner code address (the address the fixup code jumps to)
                if (innerCodeAddr != IntPtr.Zero)
                {
                    try
                    {
                        byte[] innerBytes = ReadBytesSafe(innerCodeAddr, 16);
                        // Only patch if it looks like code (not already patched)
                        if (innerBytes != null && innerBytes.Length >= 12 &&
                            (innerBytes[0] != 0x48 || innerBytes[1] != 0xB8))
                        {
                            _innerCodeAddress = innerCodeAddr;
                            _innerCodeOriginalBytes = new byte[12];
                            Marshal.Copy(innerCodeAddr, _innerCodeOriginalBytes, 0, 12);
                            // Save a larger copy for the call-original trampoline.
                            // Must be read BEFORE patching. The trampoline needs enough
                            // bytes to cover the 12-byte patch and reach an instruction
                            // boundary (which may be > 12 bytes).
                            _innerCodeOriginalBytesFull = ReadBytesSafe(innerCodeAddr, 32);
                            byte[] innerPatch = new byte[12]
                            {
                            72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
                            byte.MaxValue, 224
                            };
                            BitConverter.GetBytes(jumpTarget.ToInt64()).CopyTo(innerPatch, 2);
                            Memory.ProtectWritable(innerCodeAddr, 12);
                            Marshal.Copy(innerPatch, 0, innerCodeAddr, 12);
                            Memory.ProtectExecutable(innerCodeAddr, 12);
                            _hasInnerCodePatch = true;
                            diag.SlotError += "; InnerCodePatch(12-byte) at 0x" + innerCodeAddr.ToInt64().ToString("X");
                        }
                    }
                    catch (Exception ex)
                    {
                        diag.SlotError += "; InnerCodePatch error: " + ex.Message;
                    }
                }
            }
            catch (Exception ex)
            {
                diag.SlotError = diag.SlotError + "; Target1Patch error: " + ex.Message;
            }
        }

        /// <summary>
        /// Patches the precode's second FF 25 data cell (Precode2ndTarget).
        /// For generic methods with FixupPrecode, the precode layout is:
        ///   FF 25 <disp1>  JMP [target1]   (offset 0)
        ///   4C 8B 15 <d2>  MOV R10,[MD]    (offset 6)
        ///   FF 25 <disp3>  JMP [target2]   (offset 13)
        /// Call sites that enter at offset 6 set up R10 (generic dictionary)
        /// then JMP to target2. Patching target2's data cell to point to the
        /// hook redirects this path.
        /// </summary>
        private unsafe void InstallTarget2Patch(IntPtr precodeAddr, byte* ptr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            try
            {
                // target2 data cell is at precodeAddr + 19 + disp3, where disp3
                // is the 4-byte signed int at precode offset 15.
                int disp3 = *(int*)(ptr + 15);
                long target2Loc = precodeAddr.ToInt64() + 19 + disp3;
                IntPtr target2LocPtr = new IntPtr(target2Loc);
                if (!Memory.IsReadable(target2LocPtr, 8))
                {
                    diag.SlotError += "; target2Loc not readable";
                    return;
                }
                IntPtr originalTarget2 = new IntPtr(*(long*)target2Loc);
                _target2Loc = target2LocPtr;
                _target2OriginalValue = originalTarget2;
                Memory.ProtectReadWrite(target2LocPtr, 8);
                *(long*)target2Loc = jumpTarget.ToInt64();
                _hasTarget2Patch = true;
                diag.SlotError += "; Target2Patch(data cell) at 0x" + target2LocPtr.ToInt64().ToString("X") + " orig=0x" + originalTarget2.ToInt64().ToString("X");
            }
            catch (Exception ex)
            {
                diag.SlotError = diag.SlotError + "; Target2Patch error: " + ex.Message;
            }
        }

        /// <summary>
        /// Creates a copy-prologue trampoline for CallOriginal. The trampoline:
        ///   1. Sets R10 = generic dictionary (for generic methods on CoreCLR)
        ///   2. Executes a copy of the original JIT prologue (relocated for RIP-relative)
        ///   3. JMPs to JIT code + copyLen (past the 5-byte E9 patch)
        ///
        /// Because the trampoline contains its own copy of the prologue and jumps
        /// PAST the patched bytes, NO RestoreAll/ReapplyAll is needed. This avoids
        /// the CLR state corruption (0x80131506) that occurs when restoring and
        /// re-patching JIT code for generic methods on .NET 8.
        ///
        /// Layout: [MOV R10, genericDict]? + [copied prologue] + [MOV RAX, jit+copyLen; JMP RAX]
        /// </summary>
        private void InstallCallOriginalTrampoline(IntPtr jitCodeAddr, byte[] origBytes, HookDiagInfo diag, int patchSize = 5)
        {
            if (Platform.Current != Platform.Arch.X64)
            {
                diag.CallOrigStatus = "Trampoline only supported on X64";
                return;
            }
            try
            {
                // For generic methods, extract the generic dictionary.
                IntPtr genericDict = IntPtr.Zero;
                if (_needsGenericAdapter)
                {
                    genericDict = ExtractGenericDictionary(_precodeAddr);
                    if (genericDict == IntPtr.Zero)
                    {
                        // Try .NET Framework 4.x fixup code pattern
                        genericDict = TryExtractGenericDictFromFixupCode(jitCodeAddr);
                    }
                    if (genericDict == IntPtr.Zero)
                    {
                        diag.CallOrigStatus = "Failed to extract generic dictionary";
                        return;
                    }
                }

                // Compute prologue copy length: must cover the patch and
                // end on an instruction boundary.
                int copyLen = ComputePrologueCopyLen(origBytes, patchSize);
                if (copyLen < 0 || copyLen > origBytes.Length)
                {
                    diag.CallOrigStatus = "Failed to compute prologue copy length (origBytes=" +
                        BytesToHex(origBytes) + ")";
                    return;
                }

                // Build the trampoline:
                // [MOV R10, genericDict]?  (10 bytes, generic only)
                // [copied prologue]        (copyLen bytes, RIP-relative relocated)
                // [MOV RAX, jit+copyLen]   (10 bytes)
                // [JMP RAX]                (2 bytes)
                int prefixLen = _needsGenericAdapter ? 10 : 0;
                int trampSize = prefixLen + copyLen + 12;
                _callOrigTrampSize = trampSize;

                IntPtr tramp = Memory.AllocExecNear(jitCodeAddr, trampSize);
                if (tramp == IntPtr.Zero || tramp == new IntPtr(-1))
                {
                    diag.CallOrigStatus = "Failed to allocate trampoline memory";
                    return;
                }

                byte[] trampBytes = new byte[trampSize];
                int offset = 0;

                if (_needsGenericAdapter)
                {
                    // MOV R10, imm64: 49 BA <8 bytes>
                    trampBytes[0] = 0x49;
                    trampBytes[1] = 0xBA;
                    BitConverter.GetBytes(genericDict.ToInt64()).CopyTo(trampBytes, 2);
                    offset = 10;
                }

                // Copy the original prologue bytes into the trampoline.
                Array.Copy(origBytes, 0, trampBytes, offset, copyLen);

                // Relocate RIP-relative instructions in the copied prologue.
                // The copied instructions now live at (tramp + offset) but were
                // originally at (jitCodeAddr + 0). RIP-relative displacements must
                // be adjusted by (origAddr - newAddr).
                IntPtr copyDestAddr = tramp + offset;
                RelocateRipRelative(trampBytes, offset, copyLen, jitCodeAddr, copyDestAddr);
                offset += copyLen;

                // MOV RAX, jitCodeAddr + copyLen: 48 B8 <8 bytes>; JMP RAX: FF E0
                trampBytes[offset] = 0x48;
                trampBytes[offset + 1] = 0xB8;
                BitConverter.GetBytes(jitCodeAddr.ToInt64() + copyLen).CopyTo(trampBytes, offset + 2);
                trampBytes[offset + 10] = 0xFF;
                trampBytes[offset + 11] = 0xE0;

                Marshal.Copy(trampBytes, 0, tramp, trampSize);
                Memory.ProtectExecutable(tramp, trampSize);

                _callOrigTrampoline = tramp;
                _callOrigUseCopyPrologue = true;
                diag.CallOrigStatus = "CopyPrologueTramp at 0x" + tramp.ToInt64().ToString("X") +
                    " (jitCode=0x" + jitCodeAddr.ToInt64().ToString("X") +
                    ", copyLen=" + copyLen +
                    (_needsGenericAdapter ? ", genDict=0x" + genericDict.ToInt64().ToString("X") : "") + ")";
            }
            catch (Exception ex)
            {
                diag.CallOrigStatus = "Trampoline error: " + ex.Message;
            }
        }

        /// <summary>
        /// Tries to extract the generic dictionary from the .NET Framework 4.x
        /// generic method fixup code pattern:
        ///   49 89 D0 48 BA <8-byte dict> 48 B8 <8-byte jit_addr> FF E0
        /// The dictionary value is the 8-byte operand of MOV RDX (48 BA) at offset 5.
        /// On .NET Framework 4.x, the generic dictionary is passed in RDX (not R10),
        /// but the JIT code reads it from R10 after the precode sets it up. We
        /// extract the value and set R10 in our trampoline to match CoreCLR's
        /// convention.
        /// </summary>
        private unsafe IntPtr TryExtractGenericDictFromFixupCode(IntPtr jitCodeAddr)
        {
            // The fixup code is at the address that jumps to jitCodeAddr.
            // We need to find it by scanning backwards from jitCodeAddr, or by
            // re-resolving from the precode. Instead, we scan the precode area.
            if (_precodeAddr == IntPtr.Zero) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)_precodeAddr;
                // If precode is E9, follow it to the fixup code
                if (p[0] == 0xE9)
                {
                    int rel32 = *(int*)(p + 1);
                    long fixupAddr = _precodeAddr.ToInt64() + 5 + rel32;
                    byte* fp = (byte*)fixupAddr;
                    // Check for 49 89 D0 48 BA pattern
                    if (fp[0] == 0x49 && fp[1] == 0x89 && fp[2] == 0xD0 &&
                        fp[3] == 0x48 && fp[4] == 0xBA)
                    {
                        // Dictionary is the 8-byte operand of MOV RDX at offset 5
                        long dict = *(long*)(fp + 5);
                        if (dict != 0) return new IntPtr(dict);
                    }
                }
                // If precode is FF 25 (CoreCLR FixupPrecode), ExtractGenericDictionary
                // should have already handled it. But try the fixup code path anyway.
            }
            catch
            {
            }
            return IntPtr.Zero;
        }

        /// <summary>
        /// Computes the number of prologue bytes to copy. Must be >= minLen (5 for
        /// the E9 patch) and end on an instruction boundary. Returns -1 on failure.
        /// </summary>
        private static int ComputePrologueCopyLen(byte[] code, int minLen)
        {
            int offset = 0;
            while (offset < minLen)
            {
                int len = X64InstructionLength(code, offset);
                if (len <= 0) return -1;
                offset += len;
                if (offset > code.Length) return -1;
            }
            return offset;
        }

        /// <summary>
        /// Minimal x64 instruction length decoder for common .NET JIT prologue
        /// instructions. Returns instruction length, or 0 if unknown.
        /// </summary>
        private static int X64InstructionLength(byte[] code, int offset)
        {
            if (offset >= code.Length) return 0;
            byte b = code[offset];

            // Single-byte: push r64 (50-57), pop r64 (58-5F), nop (90), int3 (CC), ret (C3)
            if ((b >= 0x50 && b <= 0x5F) || b == 0x90 || b == 0xCC || b == 0xC3) return 1;
            if (b == 0x9C) return 1; // pushfq

            // REX prefix (0x40-0x4F)
            bool hasRex = b >= 0x40 && b <= 0x4F;
            int idx = hasRex ? 1 : 0;
            if (offset + idx >= code.Length) return 0;
            byte op = code[offset + idx];

            // 83: sub/add/cmp r/m, imm8
            if (op == 0x83)
            {
                if (offset + idx + 2 >= code.Length) return 0;
                byte modrm = code[offset + idx + 1];
                int mod = (modrm >> 6) & 3;
                int rm = modrm & 7;
                if (mod == 3) return idx + 3; // register + imm8
                bool hasSib83 = rm == 4; // SIB byte follows when R/M == 4 and Mod != 3
                int sibLen83 = hasSib83 ? 1 : 0;
                if (mod == 0)
                {
                    if (rm == 5) return idx + 7; // RIP+disp32 + imm8
                    return idx + 2 + sibLen83 + 1; // [reg]+imm8 or SIB+imm8
                }
                if (mod == 1) return idx + 2 + sibLen83 + 1 + 1; // disp8+imm8 (or SIB+disp8+imm8)
                if (mod == 2) return idx + 2 + sibLen83 + 4 + 1; // disp32+imm8 (or SIB+disp32+imm8)
                return idx + 3;
            }

            // 81: sub/add/cmp r/m, imm32
            if (op == 0x81)
            {
                if (offset + idx + 2 >= code.Length) return 0;
                byte modrm = code[offset + idx + 1];
                int mod = (modrm >> 6) & 3;
                int rm = modrm & 7;
                if (mod == 3) return idx + 6; // register + imm32
                bool hasSib81 = rm == 4; // SIB byte follows when R/M == 4 and Mod != 3
                int sibLen81 = hasSib81 ? 1 : 0;
                if (mod == 0)
                {
                    if (rm == 5) return idx + 10; // RIP+disp32 + imm32
                    return idx + 2 + sibLen81 + 4; // [reg]+imm32 or SIB+imm32
                }
                if (mod == 1) return idx + 2 + sibLen81 + 1 + 4; // disp8+imm32 (or SIB+disp8+imm32)
                if (mod == 2) return idx + 2 + sibLen81 + 4 + 4; // disp32+imm32 (or SIB+disp32+imm32)
                return idx + 6;
            }

            // 89/8B/8D: mov/lea with ModRM
            if (op == 0x89 || op == 0x8B || op == 0x8D)
            {
                if (offset + idx + 1 >= code.Length) return 0;
                byte modrm = code[offset + idx + 1];
                int mod = (modrm >> 6) & 3;
                int rm = modrm & 7;
                if (mod == 3) return idx + 2; // register
                bool hasSib89 = rm == 4; // SIB byte follows when R/M == 4 and Mod != 3
                int sibLen89 = hasSib89 ? 1 : 0;
                if (mod == 0)
                {
                    if (rm == 5) return idx + 6; // RIP+disp32 (no SIB)
                    return idx + 2 + sibLen89; // [reg] or SIB
                }
                if (mod == 1) return idx + 2 + sibLen89 + 1; // [reg+disp8] or SIB+disp8
                if (mod == 2) return idx + 2 + sibLen89 + 4; // [reg+disp32] or SIB+disp32
                return idx + 2;
            }

            return 0; // unknown
        }

        /// <summary>
        /// Relocates RIP-relative instructions in copied bytes. Adjusts the 32-bit
        /// displacement to account for the address change from origAddr to newAddr.
        /// </summary>
        private static void RelocateRipRelative(byte[] code, int start, int len, IntPtr origAddr, IntPtr newAddr)
        {
            int offset = start;
            int end = start + len;
            while (offset < end)
            {
                int lenInstr = X64InstructionLength(code, offset);
                if (lenInstr <= 0) break;

                byte b = code[offset];
                bool hasRex = b >= 0x40 && b <= 0x4F;
                int idx = hasRex ? 1 : 0;
                if (offset + idx < end)
                {
                    byte op = code[offset + idx];
                    if (op == 0x89 || op == 0x8B || op == 0x8D || op == 0x83 || op == 0x81)
                    {
                        int modrmOff = offset + idx + 1;
                        if (modrmOff < end)
                        {
                            byte modrm = code[modrmOff];
                            int mod = (modrm >> 6) & 3;
                            int rm = modrm & 7;
                            if (mod == 0 && rm == 5 && modrmOff + 1 + 4 <= code.Length)
                            {
                                // RIP-relative: adjust disp32
                                int oldDisp = BitConverter.ToInt32(code, modrmOff + 1);
                                long adjustment = origAddr.ToInt64() + (offset - start) - newAddr.ToInt64() - (offset - start);
                                int newDisp = (int)(oldDisp + adjustment);
                                BitConverter.GetBytes(newDisp).CopyTo(code, modrmOff + 1);
                            }
                        }
                    }
                }
                offset += lenInstr;
            }
        }

        /// <summary>
        /// Extracts the generic dictionary pointer value from a FixupPrecode.
        /// The precode layout is:
        ///   FF 25 disp1          ; JMP [rip+disp1]  (fixup code)
        ///   4C 8B 15 disp2       ; MOV R10, [rip+disp2]  (generic dictionary)
        ///   FF 25 disp3          ; JMP [rip+disp3]
        /// The MOV R10 instruction is at offset 6. RIP at its end is precode+13.
        /// The dictionary pointer is stored at precode+13+disp2.
        /// </summary>
        private unsafe IntPtr ExtractGenericDictionary(IntPtr precodeAddr)
        {
            if (precodeAddr == IntPtr.Zero) return IntPtr.Zero;
            if (!Memory.IsReadable(precodeAddr, 13)) return IntPtr.Zero;
            byte* p = (byte*)precodeAddr;
            // Verify 4C 8B 15 at offset 6
            if (p[6] != 0x4C || p[7] != 0x8B || p[8] != 0x15) return IntPtr.Zero;
            int disp32 = *(int*)(p + 9);
            long dictAddr = precodeAddr.ToInt64() + 13 + disp32;
            if (!Memory.IsReadable(new IntPtr(dictAddr), IntPtr.Size)) return IntPtr.Zero;
            try
            {
                return Marshal.ReadIntPtr(new IntPtr(dictAddr));
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        private static string BytesToHex(byte[] bytes)
        {
            if (bytes == null)
            {
                return "null";
            }
            StringBuilder stringBuilder = new StringBuilder(bytes.Length * 3);
            foreach (byte b in bytes)
            {
                stringBuilder.Append(b.ToString("X2")).Append(" ");
            }
            return stringBuilder.ToString().TrimEnd(Array.Empty<char>());
        }

        private unsafe void InstallCodePatchX86(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            if (!Memory.IsReadable(targetPtr, 20))
            {
                diag.SlotError += "; targetPtr not readable for x86 code patch";
                return;
            }
            byte* ptr = (byte*)(void*)targetPtr;
            byte b = *ptr;
            byte b2 = ptr[1];
            if (b == byte.MaxValue && b2 == 37)
            {
                int num = *(int*)(ptr + 2);
                _patchType = 1;
                _patchAddress = targetPtr;
                _indirectTargetLoc = new IntPtr(num);
                _originalIndirectTarget = new IntPtr(*(int*)num);
                Memory.ProtectReadWrite(_indirectTargetLoc, 4);
                *(int*)num = jumpTarget.ToInt32();
                diag.PatchType = "Indirect(FF 25) x86";
                diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
            }
            else if (b == 232 || b == 233)
            {
                // For generic methods, patch the JIT code BEFORE patching the
                // precode. Direct calls to generic methods go through the generic
                // dictionary cached entry point, bypassing the precode entirely.
                if (_needsGenericAdapter)
                {
                    InstallSecondaryJitPatchX86(targetPtr, jumpTarget, diag);
                }
                _patchType = 2;
                _patchAddress = targetPtr;
                _originalBytes = new byte[5];
                Marshal.Copy(targetPtr, _originalBytes, 0, 5);
                byte[] array = Jumper.BuildJump(targetPtr, jumpTarget);
                Memory.ProtectWritable(targetPtr, array.Length);
                Marshal.Copy(array, 0, targetPtr, array.Length);
                Memory.ProtectExecutable(targetPtr, array.Length);
                diag.PatchType = ((b == 232) ? "FixupPrecode(E8->E9) x86" : "DirectJump(E9) x86");
                diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
            }
            else if (b == 0xB8)
            {
                // .NET Framework 4.x x86 fixup precode:
                //   B8 <MethodDesc> [90] E8 <rel32> E9 <rel32>
                // Call sites dispatch through the JIT code (via indirect cells),
                // NOT through the precode. Follow the E9 to find the real JIT code
                // and patch IT, not the precode. This ensures all call paths
                // (indirect cell, MethodTable slot, precode) are intercepted.
                IntPtr jitAddr = IntPtr.Zero;
                for (int i = 5; i <= 15; i++)
                {
                    if (ptr[i] == 0xE9)
                    {
                        int rel = *(int*)(ptr + i + 1);
                        jitAddr = new IntPtr(targetPtr.ToInt32() + i + 5 + rel);
                        break;
                    }
                }
                if (jitAddr != IntPtr.Zero && !MethodEntryResolver.IsJump(jitAddr))
                {
                    _patchType = 3;
                    _patchAddress = jitAddr;
                    _originalBytes = Jumper.Install(jitAddr, jumpTarget);
                    diag.PatchType = "B8Precode->JitCode(5-byte) x86";
                    diag.InstalledBytes = ReadBytesSafe(jitAddr, 16);
                }
                else
                {
                    // Fallback: patch the precode itself
                    _patchType = 3;
                    _patchAddress = targetPtr;
                    _originalBytes = Jumper.Install(targetPtr, jumpTarget);
                    diag.PatchType = "B8Precode(fallback 5-byte) x86";
                    diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
                }
            }
            else if (!MethodEntryResolver.IsJump(targetPtr))
            {
                _patchType = 3;
                _patchAddress = targetPtr;
                _originalBytes = Jumper.Install(targetPtr, jumpTarget);
                diag.PatchType = "JitCode(5-byte) x86";
                diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
            }
            else
            {
                IntPtr intPtr = MethodEntryResolver.ResolveRealEntry(targetPtr);
                if (intPtr != IntPtr.Zero && intPtr != targetPtr && !MethodEntryResolver.IsJump(intPtr))
                {
                    _patchType = 3;
                    _patchAddress = intPtr;
                    _originalBytes = Jumper.Install(intPtr, jumpTarget);
                    diag.PatchType = "ResolvedJitCode(5-byte) x86";
                    diag.InstalledBytes = ReadBytesSafe(intPtr, 16);
                }
                else
                {
                    diag.PatchType = "None(relies on slot replacement) x86";
                }
            }
        }

        public object CallOriginal(object instance, params object[] args)
        {
            if (!_isInstalled)
            {
                throw new InvalidOperationException("Hook is not installed");
            }
            MethodInfo methodInfo = _targetMethod as MethodInfo;
            if (methodInfo == null)
            {
                throw new NotSupportedException("Cannot call original for constructor or void method");
            }

            ParameterInfo[] parameters = methodInfo.GetParameters();
            Type returnType = methodInfo.ReturnType;
            bool isVoid = returnType == typeof(void);

            int argCount = parameters.Length;
            if (!methodInfo.IsStatic)
            {
                argCount++;
            }
            if (argCount > 4)
            {
                throw new NotSupportedException("CallOriginal supports at most 4 arguments; actual: " + argCount);
            }

            // Path 0: for generic methods, use RestoreAll + MethodInfo.Invoke on a
            // clean thread + ReapplyAll. The trampoline (delegate*) approach crashes
            // because delegate* does not GC-track object references held in registers
            // during execution - when the method allocates (e.g. ConvertAll creates a
            // new List<TOutput>), GC may move objects and invalidate the raw references,
            // causing NullReferenceException. MethodInfo.Invoke properly tracks GC roots.
            // Running on a clean thread avoids re-entrancy (hook would re-trigger).
            if (_needsGenericAdapter)
            {
                RestoreAll();
                try
                {
                    if (methodInfo.IsStatic)
                        return InvokeOnCleanThread(() => methodInfo.Invoke(null, args));
                    return InvokeOnCleanThread(() => methodInfo.Invoke(instance, args));
                }
                finally
                {
                    ReapplyAll();
                }
            }

            // Path 0b: call-original trampoline (copy-prologue) for non-generic methods.
            // The trampoline has its own copy of the original prologue and JMPs
            // past the 5-byte patch, so NO RestoreAll/ReapplyAll is needed.
            if (_callOrigTrampoline != IntPtr.Zero && CanUseTrampoline(methodInfo))
            {
                return InvokeViaTrampoline(methodInfo, instance, args);
            }

            // Path 1: cached delegate's Invoke via function pointer.
            // For generic methods, DynamicInvoke goes through
            // RuntimeMethodHandle.InvokeMethod which crashes (0x80131506).
            // Using delegate* to call the delegate's Invoke method bypasses
            // reflection entirely. The Invoke method is non-generic and sets
            // up the generic dictionary (R10) before calling the target.
            if (_originalDelegate != null)
            {
                RestoreAll();
                try
                {
                    // delegate*<object, ...> passes all args as object references.
                    // This works for reference types but NOT for value types (int,
                    // bool, etc.) — a boxed object pointer is passed instead of the
                    // raw value, corrupting the parameter. Fall back to DynamicInvoke
                    // (which correctly boxes/unboxes) when value-type params exist.
                    if (_delegateInvokeFptr != IntPtr.Zero && CanUseTrampoline(methodInfo))
                    {
                        return InvokeViaDelegateFptr(methodInfo, instance, args);
                    }
                    // Fallback: DynamicInvoke (may crash for generic methods)
                    object[] invokeArgs;
                    if (methodInfo.IsStatic)
                    {
                        invokeArgs = args ?? Array.Empty<object>();
                    }
                    else
                    {
                        invokeArgs = new object[(args?.Length ?? 0) + 1];
                        invokeArgs[0] = instance;
                        if (args != null)
                        {
                            Array.Copy(args, 0, invokeArgs, 1, args.Length);
                        }
                    }
                    return _originalDelegate.DynamicInvoke(invokeArgs);
                }
                finally
                {
                    ReapplyAll();
                }
            }

            // Path 2: RestoreAll + MethodInfo.Invoke on a clean thread + ReapplyAll.
            RestoreAll();
            try
            {
                if (methodInfo.IsStatic)
                {
                    return InvokeOnCleanThread(() => methodInfo.Invoke(null, args));
                }
                return InvokeOnCleanThread(() => methodInfo.Invoke(instance, args));
            }
            finally
            {
                ReapplyAll();
            }
        }

        /// <summary>
        /// Checks whether all parameters and the return type are reference types
        /// (or IntPtr/UIntPtr), which is required for the delegate* trampoline path.
        /// </summary>
        private static bool CanUseTrampoline(MethodInfo methodInfo)
        {
            Type returnType = methodInfo.ReturnType;
            if (returnType != typeof(void) && !IsReferenceCompatible(returnType))
            {
                return false;
            }
            foreach (ParameterInfo p in methodInfo.GetParameters())
            {
                if (!IsReferenceCompatible(p.ParameterType))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Invokes a function on a clean thread (no hook frames on the stack).
        /// This avoids GC stack-walking issues when calling the original method
        /// from within a hook. The hook's stack frame has a return address that
        /// points to the patched JIT code area, which can confuse the GC.
        /// </summary>
        private object InvokeOnCleanThread(Func<object> func)
        {
            Exception ex = null;
            object result = null;
            var thread = new System.Threading.Thread(() =>
            {
                try
                {
                    result = func();
                }
                catch (Exception e)
                {
                    ex = e;
                }
            });
            thread.IsBackground = true;
            thread.Start();
            thread.Join();
            if (ex != null)
            {
                throw ex;
            }
            return result;
        }

        /// <summary>
        /// Invokes the method via Delegate.CreateDelegate + DynamicInvoke.
        /// This avoids RuntimeMethodHandle.InvokeMethod (used by MethodInfo.Invoke)
        /// which crashes with 0x80131506 for generic methods after hook patching.
        /// Delegate.DynamicInvoke uses a different code path that calls the
        /// delegate's Invoke method directly.
        /// </summary>
        private object InvokeViaDelegate(MethodInfo methodInfo, object instance, object[] args)
        {
            ParameterInfo[] parameters = methodInfo.GetParameters();
            Type returnType = methodInfo.ReturnType;
            bool isVoid = returnType == typeof(void);

            // Build the type argument list for the delegate.
            // For instance methods, the first type arg is the declaring type (open delegate).
            int extraForInstance = methodInfo.IsStatic ? 0 : 1;
            int totalTypeArgs = parameters.Length + extraForInstance + (isVoid ? 0 : 1);

            Type[] typeArgs = new Type[totalTypeArgs];
            int idx = 0;
            if (!methodInfo.IsStatic)
            {
                typeArgs[idx++] = methodInfo.DeclaringType;
            }
            for (int i = 0; i < parameters.Length; i++)
            {
                typeArgs[idx++] = parameters[i].ParameterType;
            }
            if (!isVoid)
            {
                typeArgs[idx++] = returnType;
            }

            // Get the generic delegate type (Func<...> or Action<...>)
            string delegateName = isVoid ? "System.Action`" : "System.Func`";
            Type openDelegateType = Type.GetType(delegateName + totalTypeArgs);
            if (openDelegateType == null)
            {
                // Fallback to MethodInfo.Invoke for unsupported arities
                return methodInfo.IsStatic
                    ? methodInfo.Invoke(null, args)
                    : methodInfo.Invoke(instance, args);
            }

            Type delegateType = openDelegateType.MakeGenericType(typeArgs);

            // Create an open delegate (null target). For instance methods, the
            // instance is passed as the first DynamicInvoke argument.
            Delegate del = Delegate.CreateDelegate(delegateType, null, methodInfo);

            // Build the argument array for DynamicInvoke
            object[] invokeArgs;
            if (methodInfo.IsStatic)
            {
                invokeArgs = args ?? Array.Empty<object>();
            }
            else
            {
                invokeArgs = new object[(args?.Length ?? 0) + 1];
                invokeArgs[0] = instance;
                if (args != null)
                {
                    Array.Copy(args, 0, invokeArgs, 1, args.Length);
                }
            }

            return del.DynamicInvoke(invokeArgs);
        }

        /// <summary>
        /// CallOriginal path for generic methods: restores ONLY slots + inner code
        /// patch (NOT precode patches), calls via MethodInfo.Invoke on a clean
        /// thread, then re-applies. Precode patches are left untouched to avoid
        /// 0x80131506 (ExecutionEngineException) on .NET 8.
        /// </summary>
        private object CallOriginalGenericViaRestore(MethodInfo methodInfo, object instance, object[] args)
        {
            if (_callOrigTrampoline != IntPtr.Zero)
            {
                return InvokeViaTrampolineNative(methodInfo, instance, args);
            }
            RestoreAll();
            try
            {
                if (methodInfo.IsStatic)
                    return InvokeOnCleanThread(() => methodInfo.Invoke(null, args));
                return InvokeOnCleanThread(() => methodInfo.Invoke(instance, args));
            }
            finally
            {
                ReapplyAll();
            }
        }

        /// <summary>
        /// Calls the copy-prologue trampoline via Marshal.GetDelegateForFunctionPointer
        /// (native delegate) instead of delegate* (managed function pointer). This
        /// avoids the SEHException that occurs when calling raw VirtualAlloc'd memory
        /// via delegate* on .NET 8. The trampoline sets up R10 (generic dict), runs
        /// the copied prologue, and JMPs to the original JIT code past the patch.
        /// No RestoreAll/ReapplyAll is needed.
        /// </summary>
        private object InvokeViaTrampolineNative(MethodInfo methodInfo, object instance, object[] args)
        {
            ParameterInfo[] parameters = methodInfo.GetParameters();
            bool isVoid = methodInfo.ReturnType == typeof(void);

            int argCount = parameters.Length;
            if (!methodInfo.IsStatic)
                argCount++;
            if (argCount > 4)
                throw new NotSupportedException("Trampoline supports at most 4 arguments; actual: " + argCount);

            object[] flatArgs = new object[argCount];
            int slot = 0;
            if (!methodInfo.IsStatic)
                flatArgs[slot++] = instance;
            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                    flatArgs[slot++] = args[i];
            }

            return InvokeViaIntPtrDelegate(_callOrigTrampoline, flatArgs, isVoid);
        }

        /// <summary>
        /// Invokes the original method via the call-original trampoline using
        /// Marshal.GetDelegateForFunctionPointer. The delegate calls the trampoline
        /// directly (a native function pointer), which sets up R10 for generic methods,
        /// executes the relocated original prologue, then jumps to the rest of the
        /// JIT code (past the 5-byte patch). No RestoreAll/ReapplyAll is needed.
        /// </summary>
        /// <remarks>
        /// Marshal.GetDelegateForFunctionPointer rejects generic delegate types (e.g.
        /// Func&lt;T1,T2,TResult&gt;), so we use a fixed set of non-generic delegates
        /// declared with <c>object</c> parameters. Because every reference type shares
        /// the same native representation (an object pointer), an <c>object</c>-typed
        /// delegate parameter faithfully passes any reference-type argument. This
        /// therefore requires every parameter and the return type to be a reference
        /// type (or the method must be void-returning); value-type signatures are not
        /// supported by this path and the caller falls back to restore/invoke/reapply.
        /// </remarks>
        private object InvokeViaTrampoline(MethodInfo methodInfo, object instance, object[] args)
        {
            ParameterInfo[] parameters = methodInfo.GetParameters();
            Type returnType = methodInfo.ReturnType;
            bool isVoid = returnType == typeof(void);

            // Total native argument count: instance (for non-static) + declared params.
            int argCount = parameters.Length;
            if (!methodInfo.IsStatic)
            {
                argCount++;
            }

            // Verify every argument slot and the return are reference-compatible.
            if (!isVoid && !IsReferenceCompatible(returnType))
            {
                throw new NotSupportedException(
                    "Trampoline invocation requires a reference-type return; actual: " + returnType);
            }
            for (int i = 0; i < parameters.Length; i++)
            {
                if (!IsReferenceCompatible(parameters[i].ParameterType))
                {
                    throw new NotSupportedException(
                        "Trampoline invocation requires reference-type parameters; param " + i + " is " + parameters[i].ParameterType);
                }
            }
            if (argCount > 4)
            {
                throw new NotSupportedException(
                    "Trampoline invocation supports at most 4 arguments; actual: " + argCount);
            }

            // Build the flat argument list (instance first for non-static methods).
            object[] flatArgs = new object[argCount];
            int slot = 0;
            if (!methodInfo.IsStatic)
            {
                flatArgs[slot++] = instance;
            }
            for (int i = 0; i < args.Length; i++)
            {
                flatArgs[slot++] = args[i];
            }

            // On .NET 5+ we can use delegate* (managed function pointers) which keep
            // the thread in cooperative GC mode and properly track object references.
            // This is essential for methods that trigger GC (e.g. ConvertAll allocates).
            // Marshal.GetDelegateForFunctionPointer would use a preemptive-GC native
            // transition, corrupting object references on compaction.
            if (Environment.Version.Major >= 5)
            {
                return InvokeViaFptr(_callOrigTrampoline, flatArgs, isVoid);
            }

            // Fallback for older runtimes: IntPtr delegate (GC-unsafe, may crash for
            // methods that trigger GC). Object references are passed as raw IntPtr
            // values and are NOT tracked by the GC during the call.
            return InvokeViaIntPtrDelegate(_callOrigTrampoline, flatArgs, isVoid);
        }

        /// <summary>
        /// Calls the trampoline via delegate* (managed function pointer). The managed
        /// calling convention keeps the thread in cooperative GC mode, so object
        /// references passed as arguments and return values are properly GC-tracked.
        /// Requires .NET 5+ runtime; the containing methods are only JIT-compiled when
        /// actually called on .NET 5+, so they never fail to load on older runtimes.
        /// </summary>
        private static unsafe object InvokeViaFptr(IntPtr fptr, object[] args, bool isVoid)
        {
            object result;
            switch (args.Length)
            {
                case 0:
                    if (isVoid) { ((delegate*<void>)fptr)(); result = null; }
                    else result = ((delegate*<object>)fptr)();
                    break;
                case 1:
                    if (isVoid) { ((delegate*<object, void>)fptr)(args[0]); result = null; }
                    else result = ((delegate*<object, object>)fptr)(args[0]);
                    break;
                case 2:
                    if (isVoid) { ((delegate*<object, object, void>)fptr)(args[0], args[1]); result = null; }
                    else result = ((delegate*<object, object, object>)fptr)(args[0], args[1]);
                    break;
                case 3:
                    if (isVoid) { ((delegate*<object, object, object, void>)fptr)(args[0], args[1], args[2]); result = null; }
                    else result = ((delegate*<object, object, object, object>)fptr)(args[0], args[1], args[2]);
                    break;
                case 4:
                    if (isVoid) { ((delegate*<object, object, object, object, void>)fptr)(args[0], args[1], args[2], args[3]); result = null; }
                    else result = ((delegate*<object, object, object, object, object>)fptr)(args[0], args[1], args[2], args[3]);
                    break;
                default:
                    throw new NotSupportedException("delegate* path supports at most 4 arguments");
            }
            return result;
        }

        /// <summary>
        /// Calls the delegate's Invoke method via delegate* (function pointer), bypassing
        /// RuntimeMethodHandle.InvokeMethod. The Invoke method is non-generic and sets up
        /// the generic dictionary (R10) before calling the target. The first arg is the
        /// delegate object itself (as 'this' for the instance Invoke method).
        /// </summary>
        private unsafe object InvokeViaDelegateFptr(MethodInfo methodInfo, object instance, object[] args)
        {
            bool isVoid = methodInfo.ReturnType == typeof(void);

            // Build the flat argument list: [delegate, instance?, params...]
            // The delegate's Invoke method is an instance method, so the delegate
            // object is passed as the first argument (this).
            int flatArgCount = _delegateFlatArgCount;
            int totalArgs = flatArgCount + 1; // +1 for the delegate as 'this'
            if (totalArgs > 4)
            {
                throw new NotSupportedException(
                    "Delegate Invoke delegate* path supports at most 4 total arguments; actual: " + totalArgs);
            }

            object[] invokeArgs = new object[totalArgs];
            invokeArgs[0] = _originalDelegate;
            int slot = 1;
            if (!methodInfo.IsStatic)
            {
                invokeArgs[slot++] = instance;
            }
            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    invokeArgs[slot++] = args[i];
                }
            }

            return InvokeViaFptr(_delegateInvokeFptr, invokeArgs, isVoid);
        }

        /// <summary>
        /// Fallback: calls the trampoline via Marshal.GetDelegateForFunctionPointer with
        /// non-generic IntPtr delegate types. This creates a managed-to-native transition
        /// (preemptive GC mode), so object references passed as IntPtr are NOT GC-tracked.
        /// Safe only for methods that do not trigger GC; may crash (0x80131506) otherwise.
        /// </summary>
        private static object InvokeViaIntPtrDelegate(IntPtr fptr, object[] args, bool isVoid)
        {
            Type delegateType = PickIntPtrDelegateType(args.Length, isVoid);
            if (delegateType == null)
            {
                throw new NotSupportedException(
                    "No non-generic IntPtr delegate type for arity " + args.Length + " (max 4).");
            }

            Delegate del = Marshal.GetDelegateForFunctionPointer(fptr, delegateType);

            // Convert each object argument to IntPtr (raw object pointer).
            object[] invokeArgs = new object[args.Length];
            for (int i = 0; i < args.Length; i++)
            {
                invokeArgs[i] = ObjPtr.From(args[i]);
            }

            object rawResult = del.DynamicInvoke(invokeArgs);

            if (isVoid)
            {
                return null;
            }
            return ObjPtr.To((IntPtr)rawResult);
        }

        private static bool IsReferenceCompatible(Type t)
        {
            // IntPtr is blittable and the same width as a native pointer on every
            // platform, so it can also be passed through an IntPtr-typed delegate slot.
            if (!t.IsValueType)
            {
                return true;
            }
            return t == typeof(IntPtr) || t == typeof(UIntPtr);
        }

        private static Type PickIntPtrDelegateType(int argCount, bool isVoid)
        {
            switch (argCount)
            {
                case 0: return isVoid ? typeof(ActionIntPtr0) : typeof(FuncIntPtr0);
                case 1: return isVoid ? typeof(ActionIntPtr1) : typeof(FuncIntPtr1);
                case 2: return isVoid ? typeof(ActionIntPtr2) : typeof(FuncIntPtr2);
                case 3: return isVoid ? typeof(ActionIntPtr3) : typeof(FuncIntPtr3);
                case 4: return isVoid ? typeof(ActionIntPtr4) : typeof(FuncIntPtr4);
                default: return null;
            }
        }

        public void Uninstall()
        {
            if (!_isInstalled)
            {
                return;
            }
            RestoreAll();
            if (_nearTrampoline != IntPtr.Zero)
            {
                try
                {
                    Memory.FreeExec(_nearTrampoline, 12);
                }
                catch
                {
                }
                _nearTrampoline = IntPtr.Zero;
            }
            if (_secondaryTrampoline != IntPtr.Zero)
            {
                try
                {
                    Memory.FreeExec(_secondaryTrampoline, 12);
                }
                catch
                {
                }
                _secondaryTrampoline = IntPtr.Zero;
            }
            if (_genericAdapter != IntPtr.Zero)
            {
                try
                {
                    Memory.FreeExec(_genericAdapter, 128);
                }
                catch
                {
                }
                _genericAdapter = IntPtr.Zero;
            }
            if (_callOrigTrampoline != IntPtr.Zero)
            {
                try
                {
                    Memory.FreeExec(_callOrigTrampoline, _callOrigTrampSize);
                }
                catch
                {
                }
                _callOrigTrampoline = IntPtr.Zero;
            }
            _isInstalled = false;
        }

        private void RestoreAll()
        {
            if (_slotAddresses != null)
            {
                foreach (IntPtr slotAddress in _slotAddresses)
                {
                    try
                    {
                        SlotPatcher.ReplaceSlot(slotAddress, _originalSlotValue);
                    }
                    catch
                    {
                    }
                }
            }
            RestoreCodePatch();
            if (_overridePatches == null)
            {
                return;
            }
            foreach (OverridePatch overridePatch in _overridePatches)
            {
                try
                {
                    Jumper.Restore(overridePatch.Entry, overridePatch.OriginalBytes);
                }
                catch
                {
                }
            }
        }

        private void RestoreCodePatch()
        {
            switch (_patchType)
            {
                case 1:
                    if (!(_indirectTargetLoc != IntPtr.Zero))
                    {
                        break;
                    }
                    try
                    {
                        int size = IntPtr.Size;
                        Memory.ProtectReadWrite(_indirectTargetLoc, size);
                        if (size == 8)
                        {
                            Marshal.WriteInt64(_indirectTargetLoc, _originalIndirectTarget.ToInt64());
                        }
                        else
                        {
                            Marshal.WriteInt32(_indirectTargetLoc, _originalIndirectTarget.ToInt32());
                        }
                    }
                    catch
                    {
                    }
                    break;
                case 2:
                    if (_patchAddress != IntPtr.Zero && _originalBytes != null)
                    {
                        try
                        {
                            Jumper.Restore(_patchAddress, _originalBytes);
                        }
                        catch
                        {
                        }
                    }
                    break;
                case 3:
                    if (_patchAddress != IntPtr.Zero && _originalBytes != null)
                    {
                        try
                        {
                            Jumper.Restore(_patchAddress, _originalBytes);
                        }
                        catch
                        {
                        }
                    }
                    break;
            }
            if (_hasSecondaryPatch && _secondaryJitAddress != IntPtr.Zero && _secondaryJitOriginalBytes != null)
            {
                try
                {
                    Jumper.Restore(_secondaryJitAddress, _secondaryJitOriginalBytes);
                }
                catch
                {
                }
            }
            // Restore the target1 fixup thunk to its original bytes
            if (_hasTarget1Patch && _target1Address != IntPtr.Zero && _target1OriginalBytes != null)
            {
                try
                {
                    Jumper.Restore(_target1Address, _target1OriginalBytes);
                }
                catch
                {
                }
            }
            // Restore the inner code address (fixup target) to its original bytes
            if (_hasInnerCodePatch && _innerCodeAddress != IntPtr.Zero && _innerCodeOriginalBytes != null)
            {
                try
                {
                    Jumper.Restore(_innerCodeAddress, _innerCodeOriginalBytes);
                }
                catch
                {
                }
            }
            // Restore the target2 data cell to its original value (Precode2ndTarget)
            if (_hasTarget2Patch && _target2Loc != IntPtr.Zero)
            {
                try
                {
                    int size = IntPtr.Size;
                    Memory.ProtectReadWrite(_target2Loc, size);
                    if (size == 8)
                    {
                        Marshal.WriteInt64(_target2Loc, _target2OriginalValue.ToInt64());
                    }
                    else
                    {
                        Marshal.WriteInt32(_target2Loc, _target2OriginalValue.ToInt32());
                    }
                }
                catch
                {
                }
            }
            // Restore the first FF 25's indirect target to its original value
            // (the JIT code address backpatched by PrepareMethod).
            if (_hasFirstIndirectPatch && _firstIndirectLoc != IntPtr.Zero)
            {
                try
                {
                    int size = IntPtr.Size;
                    Memory.ProtectReadWrite(_firstIndirectLoc, size);
                    if (size == 8)
                    {
                        Marshal.WriteInt64(_firstIndirectLoc, _originalFirstIndirect.ToInt64());
                    }
                    else
                    {
                        Marshal.WriteInt32(_firstIndirectLoc, _originalFirstIndirect.ToInt32());
                    }
                }
                catch
                {
                }
            }
        }

        private void ReapplyAll()
        {
            if (_slotAddresses != null)
            {
                foreach (IntPtr slotAddress in _slotAddresses)
                {
                    try
                    {
                        SlotPatcher.ReplaceSlot(slotAddress, _newSlotValue);
                    }
                    catch
                    {
                    }
                }
            }
            ReapplyCodePatch();
            if (_overridePatches == null)
            {
                return;
            }
            foreach (OverridePatch overridePatch in _overridePatches)
            {
                try
                {
                    Jumper.WriteJump(overridePatch.Entry, _newSlotValue);
                }
                catch
                {
                }
            }
        }

        private void ReapplyCodePatch()
        {
            switch (_patchType)
            {
                case 1:
                    if (!(_indirectTargetLoc != IntPtr.Zero))
                    {
                        break;
                    }
                    try
                    {
                        int size = IntPtr.Size;
                        Memory.ProtectReadWrite(_indirectTargetLoc, size);
                        if (size == 8)
                        {
                            Marshal.WriteInt64(_indirectTargetLoc, _newSlotValue.ToInt64());
                        }
                        else
                        {
                            Marshal.WriteInt32(_indirectTargetLoc, _newSlotValue.ToInt32());
                        }
                    }
                    catch
                    {
                    }
                    break;
                case 2:
                    if (_patchAddress != IntPtr.Zero && _nearTrampoline != IntPtr.Zero)
                    {
                        try
                        {
                            int value = (int)(_nearTrampoline.ToInt64() - (_patchAddress.ToInt64() + 5));
                            byte[] array = new byte[5] { 233, 0, 0, 0, 0 };
                            BitConverter.GetBytes(value).CopyTo(array, 1);
                            Memory.ProtectWritable(_patchAddress, 5);
                            Marshal.Copy(array, 0, _patchAddress, 5);
                            Memory.ProtectExecutable(_patchAddress, 5);
                        }
                        catch
                        {
                        }
                    }
                    break;
                case 3:
                    if (_patchAddress != IntPtr.Zero)
                    {
                        try
                        {
                            Jumper.WriteJump(_patchAddress, _newSlotValue);
                        }
                        catch
                        {
                        }
                    }
                    break;
            }
            if (_hasSecondaryPatch && _secondaryJitAddress != IntPtr.Zero)
            {
                try
                {
                    int rel;
                    if (_secondaryTrampoline != IntPtr.Zero)
                    {
                        // x64: jump to near trampoline which jumps to hook
                        rel = (int)(_secondaryTrampoline.ToInt64() - (_secondaryJitAddress.ToInt64() + 5));
                    }
                    else
                    {
                        // x86: direct jump to hook (no trampoline needed)
                        rel = _newSlotValue.ToInt32() - (_secondaryJitAddress.ToInt32() + 5);
                    }
                    byte[] patch = new byte[5] { 233, 0, 0, 0, 0 };
                    BitConverter.GetBytes(rel).CopyTo(patch, 1);
                    Memory.ProtectWritable(_secondaryJitAddress, 5);
                    Marshal.Copy(patch, 0, _secondaryJitAddress, 5);
                    Memory.ProtectExecutable(_secondaryJitAddress, 5);
                }
                catch
                {
                }
            }
            // Reapply the target1 fixup thunk patch (12-byte absolute jump to hook)
            if (_hasTarget1Patch && _target1Address != IntPtr.Zero)
            {
                try
                {
                    byte[] patch = new byte[12]
                    {
                    72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
                    byte.MaxValue, 224
                    };
                    BitConverter.GetBytes(_newSlotValue.ToInt64()).CopyTo(patch, 2);
                    Memory.ProtectWritable(_target1Address, 12);
                    Marshal.Copy(patch, 0, _target1Address, 12);
                    Memory.ProtectExecutable(_target1Address, 12);
                }
                catch
                {
                }
            }
            // Reapply the inner code patch (12-byte absolute jump to hook)
            if (_hasInnerCodePatch && _innerCodeAddress != IntPtr.Zero)
            {
                try
                {
                    byte[] patch = new byte[12]
                    {
                    72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
                    byte.MaxValue, 224
                    };
                    BitConverter.GetBytes(_newSlotValue.ToInt64()).CopyTo(patch, 2);
                    Memory.ProtectWritable(_innerCodeAddress, 12);
                    Marshal.Copy(patch, 0, _innerCodeAddress, 12);
                    Memory.ProtectExecutable(_innerCodeAddress, 12);
                }
                catch
                {
                }
            }
            // Reapply the target2 data cell patch (Precode2ndTarget -> hook)
            if (_hasTarget2Patch && _target2Loc != IntPtr.Zero)
            {
                try
                {
                    int size = IntPtr.Size;
                    Memory.ProtectReadWrite(_target2Loc, size);
                    if (size == 8)
                    {
                        Marshal.WriteInt64(_target2Loc, _newSlotValue.ToInt64());
                    }
                    else
                    {
                        Marshal.WriteInt32(_target2Loc, _newSlotValue.ToInt32());
                    }
                }
                catch
                {
                }
            }
            // Reapply the first FF 25 redirect to offset 6 (precodeAddr + 6).
            if (_hasFirstIndirectPatch && _firstIndirectLoc != IntPtr.Zero && _precodeAddr != IntPtr.Zero)
            {
                try
                {
                    int size = IntPtr.Size;
                    long redirectTarget = _precodeAddr.ToInt64() + 6;
                    Memory.ProtectReadWrite(_firstIndirectLoc, size);
                    if (size == 8)
                    {
                        Marshal.WriteInt64(_firstIndirectLoc, redirectTarget);
                    }
                    else
                    {
                        Marshal.WriteInt32(_firstIndirectLoc, (int)redirectTarget);
                    }
                }
                catch
                {
                }
            }
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                Uninstall();
                _isDisposed = true;
            }
        }

        private void PatchVirtualOverrides(IntPtr jumpTarget)
        {
            try
            {
                MethodInfo methodInfo = _targetMethod as MethodInfo;
                Type type = methodInfo?.DeclaringType;
                if (type == null)
                {
                    return;
                }
                Type[] types = (from p in methodInfo.GetParameters()
                                select p.ParameterType).ToArray();
                List<MethodInfo> list = new List<MethodInfo>();
                Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
                foreach (Assembly assembly in assemblies)
                {
                    if (assembly.IsDynamic)
                    {
                        continue;
                    }
                    Type[] types2;
                    try
                    {
                        types2 = assembly.GetTypes();
                    }
                    catch
                    {
                        continue;
                    }
                    Type[] array = types2;
                    foreach (Type type2 in array)
                    {
                        if (type2 == type || !type.IsAssignableFrom(type2) || !type2.IsClass || type2.IsAbstract)
                        {
                            continue;
                        }
                        MethodInfo method;
                        try
                        {
                            method = type2.GetMethod(methodInfo.Name, BindingFlags.Instance | BindingFlags.Public, null, types, null);
                        }
                        catch
                        {
                            continue;
                        }
                        if (method == null || method.DeclaringType == type)
                        {
                            continue;
                        }
                        try
                        {
                            if (method.GetBaseDefinition() == methodInfo)
                            {
                                list.Add(method);
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                if (list.Count == 0)
                {
                    return;
                }
                _overridePatches = new List<OverridePatch>();
                foreach (MethodInfo item in list)
                {
                    RuntimeHelpers.PrepareMethod(item.MethodHandle);
                    IntPtr functionPointer = item.MethodHandle.GetFunctionPointer();
                    IntPtr value = item.MethodHandle.Value;
                    IntPtr methodTable = IntPtr.Zero;
                    if (item.DeclaringType != null)
                    {
                        methodTable = item.DeclaringType.TypeHandle.Value;
                    }
                    List<IntPtr> list2 = SlotPatcher.FindSlots(value, methodTable, functionPointer);
                    foreach (IntPtr item2 in list2)
                    {
                        SlotPatcher.ReplaceSlot(item2, jumpTarget);
                    }
                    byte[] originalBytes = Jumper.Install(functionPointer, jumpTarget);
                    _overridePatches.Add(new OverridePatch
                    {
                        Entry = functionPointer,
                        OriginalBytes = originalBytes,
                        Slots = list2
                    });
                }
            }
            catch
            {
            }
        }

        private static byte[] ReadBytesSafe(IntPtr addr, int count)
        {
            if (addr == IntPtr.Zero) return null;
            if (!Memory.IsReadable(addr, count)) return null;
            try
            {
                byte[] array = new byte[count];
                Marshal.Copy(addr, array, 0, count);
                return array;
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Non-generic delegate types used to invoke native function pointers via
    /// Marshal.GetDelegateForFunctionPointer, which rejects generic delegate types
    /// (e.g. Func&lt;T1,T2,TResult&gt;) and delegates that return or accept "variant"
    /// types such as <c>object</c>. Every reference type shares the same native
    /// representation (an object pointer, 8 bytes on x64), so a delegate declared
    /// with <c>IntPtr</c> parameters and <c>IntPtr</c> return can faithfully call a
    /// native function whose real signature uses any reference types; the caller
    /// converts objects to/from raw pointer values via <see cref="ObjPtr"/>.
    /// Value-type parameters/returns are not covered by this path; callers fall
    /// back to the restore/invoke/reapply path for those signatures.
    /// </summary>
    internal delegate IntPtr FuncIntPtr0();
    internal delegate IntPtr FuncIntPtr1(IntPtr a);
    internal delegate IntPtr FuncIntPtr2(IntPtr a, IntPtr b);
    internal delegate IntPtr FuncIntPtr3(IntPtr a, IntPtr b, IntPtr c);
    internal delegate IntPtr FuncIntPtr4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
    internal delegate void ActionIntPtr0();
    internal delegate void ActionIntPtr1(IntPtr a);
    internal delegate void ActionIntPtr2(IntPtr a, IntPtr b);
    internal delegate void ActionIntPtr3(IntPtr a, IntPtr b, IntPtr c);
    internal delegate void ActionIntPtr4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);

    /// <summary>
    /// Overlays a managed <c>object</c> reference with a raw <c>IntPtr</c> so that
    /// an object pointer obtained from native code (via a IntPtr-returning delegate)
    /// can be reinterpreted back into a tracked managed reference. Conversion is
    /// implemented with <c>TypedReference</c> (<c>__makeref</c>/<c>__refvalue</c>)
    /// because the CLR forbids explicit-layout structs that overlap an object field
    /// with a non-object field, and <c>Marshal.GetDelegateForFunctionPointer</c>
    /// rejects delegates whose return/parameter type is <c>object</c>.
    /// </summary>
    internal static class ObjPtr
    {
        public static unsafe IntPtr From(object obj)
        {
            if (obj == null)
            {
                return IntPtr.Zero;
            }
            // __makeref yields a TypedReference whose first field is the raw
            // managed object reference (pointer to the object header).
            TypedReference tr = __makeref(obj);
            return *(IntPtr*)&tr;
        }

        public static unsafe object To(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return null;
            }
            // Build a TypedReference whose value field points to the object, then
            // dereference it as object. The type handle in the TypedReference is
            // irrelevant when the compile-time type is 'object'.
            object dummy = null;
            TypedReference tr = __makeref(dummy);
            *(IntPtr*)&tr = ptr;
            return __refvalue(tr, object);
        }
    }

    public class HookDiagInfo
    {
        public string TargetMethod;

        public string HookMethod;

        public IntPtr PrecodeAddr;

        public byte[] PrecodeBytes;

        public int SlotCount;

        public List<long> SlotAddresses;

        public string SlotError;

        public string PatchType;

        public string PatchError;

        public bool NeedsGenericAdapter;

        public IntPtr AdapterAddr;

        public byte[] AdapterBytes;

        public IntPtr JumpTargetAddr;

        public byte[] InstalledBytes;

        public IntPtr JitCodeAddr;

        public byte[] JitCodeOriginalBytes;

        public byte[] JitCodePatchedBytes;

        public IntPtr PrecodeFirstTargetAddr;

        public IntPtr PrecodeSecondTargetAddr;

        public byte[] Target1Bytes;

        public byte[] MethodDescDump;

        public string DelegateStatus;

        public string CallOrigStatus;

        public override string ToString()
        {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.AppendLine("Target: " + TargetMethod);
            stringBuilder.AppendLine("Hook:   " + HookMethod);
            stringBuilder.AppendLine($"Precode:       0x{PrecodeAddr.ToInt64():X16}  Bytes: {FormatBytes(PrecodeBytes)}");
            stringBuilder.AppendLine($"Slots found:   {SlotCount}");
            if (SlotAddresses != null && SlotAddresses.Count > 0)
            {
                stringBuilder.AppendLine("Slot addrs:    " + string.Join(", ", from a in SlotAddresses.Take(5)
                                                                               select $"0x{a:X16}"));
            }
            if (!string.IsNullOrEmpty(SlotError))
            {
                stringBuilder.AppendLine("Slot error:    " + SlotError);
            }
            stringBuilder.AppendLine("Patch type:    " + (PatchType ?? "none"));
            if (!string.IsNullOrEmpty(PatchError))
            {
                stringBuilder.AppendLine("Patch error:   " + PatchError);
            }
            stringBuilder.AppendLine($"NeedsAdapter:  {NeedsGenericAdapter}");
            if (NeedsGenericAdapter && AdapterAddr != IntPtr.Zero)
            {
                stringBuilder.AppendLine($"Adapter:       0x{AdapterAddr.ToInt64():X16}  Bytes: {FormatBytes(AdapterBytes)}");
            }
            stringBuilder.AppendLine($"JumpTarget:    0x{JumpTargetAddr.ToInt64():X16}");
            stringBuilder.AppendLine("Installed:     Bytes: " + FormatBytes(InstalledBytes));
            if (JitCodeAddr != IntPtr.Zero)
            {
                stringBuilder.AppendLine($"JitCode:       0x{JitCodeAddr.ToInt64():X16}");
                stringBuilder.AppendLine("JitCodeOrig:   " + FormatBytes(JitCodeOriginalBytes));
                stringBuilder.AppendLine("JitCodePatched:" + FormatBytes(JitCodePatchedBytes));
            }
            if (PrecodeFirstTargetAddr != IntPtr.Zero)
            {
                stringBuilder.AppendLine($"Precode1stTarget: 0x{PrecodeFirstTargetAddr.ToInt64():X16}");
            }
            if (Target1Bytes != null)
            {
                stringBuilder.AppendLine("Target1Bytes:  " + FormatBytes(Target1Bytes));
            }
            if (PrecodeSecondTargetAddr != IntPtr.Zero)
            {
                stringBuilder.AppendLine($"Precode2ndTarget: 0x{PrecodeSecondTargetAddr.ToInt64():X16}");
            }
            if (MethodDescDump != null)
            {
                stringBuilder.AppendLine("MethodDesc:    " + FormatBytes(MethodDescDump));
            }
            if (!string.IsNullOrEmpty(DelegateStatus))
            {
                stringBuilder.AppendLine("Delegate:      " + DelegateStatus);
            }
            if (!string.IsNullOrEmpty(CallOrigStatus))
            {
                stringBuilder.AppendLine("CallOrig:      " + CallOrigStatus);
            }
            return stringBuilder.ToString();
        }

        private static string FormatBytes(byte[] bytes)
        {
            if (bytes == null)
            {
                return "<null>";
            }
            return string.Join(" ", from b in bytes.Take(32)
                                    select $"{b:X2}") + ((bytes.Length > 32) ? " ..." : "");
        }
    }
}