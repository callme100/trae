using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;

namespace DynamicHook
{
    internal static class Memory
    {
        private static readonly IntPtr CurrentProcess = new IntPtr(-1);

        private static int PageSize => 4096;

        // Windows page protection constants (VirtualProtect dwNewProtect).
        // VirtualProtect REPLACES the page protection (it is not an OR), so the
        // target value must preserve execute for code pages and must not grant
        // execute to pure data pages.
        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_WRITECOPY = 0x08;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

        // POSIX protection constants (mprotect prot).
        private const int PROT_NONE = 0;
        private const int PROT_READ = 1;
        private const int PROT_WRITE = 2;
        private const int PROT_EXEC = 4;

        // Windows memory allocation type flags (VirtualAlloc/VirtualFree dwAllocationType).
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;

        // POSIX mmap flags.
        private const int MAP_PRIVATE = 0x02;
        private const int MAP_ANONYMOUS = 0x20;
        private const int MAP_FIXED = 0x10;

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

        /// <summary>
        /// Makes a region writable so its bytes can be patched.
        /// Code pages (PAGE_EXECUTE_*) are flipped to PAGE_EXECUTE_READWRITE so the
        /// execute bit is not stripped; pure data pages are flipped to PAGE_READWRITE
        /// to avoid unnecessarily granting execute permission.
        /// </summary>
        public static void ProtectWritable(IntPtr addr, int size)
        {
            IntPtr page = AlignToPage(addr);
            UIntPtr sizeAligned = AlignedSize(addr, size);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                uint target = IsExecutablePage(page) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
                if (VirtualProtect(page, sizeAligned, target, out _) == IntPtr.Zero)
                    throw new InvalidOperationException(
                        "VirtualProtect(Writable, prot=0x" + target.ToString("X") +
                        ") failed at 0x" + page.ToInt64().ToString("X"));
            }
            else
            {
                int target = IsExecutablePage(page)
                    ? (PROT_READ | PROT_WRITE | PROT_EXEC)
                    : (PROT_READ | PROT_WRITE);
                if (mprotect(page, sizeAligned, target) != 0)
                    throw new InvalidOperationException(
                        "mprotect(Writable, prot=" + target +
                        ") failed at 0x" + page.ToInt64().ToString("X"));
            }
        }

        /// <summary>
        /// Restores a region to executable (PAGE_EXECUTE_READWRITE) and flushes the
        /// instruction cache. Used after ProtectWritable to make patched code runnable.
        /// </summary>
        public static void ProtectExecutable(IntPtr addr, int size)
        {
            IntPtr page = AlignToPage(addr);
            UIntPtr sizeAligned = AlignedSize(addr, size);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (VirtualProtect(page, sizeAligned, PAGE_EXECUTE_READWRITE, out _) == IntPtr.Zero)
                    throw new InvalidOperationException(
                        "VirtualProtect(Executable) failed at 0x" + page.ToInt64().ToString("X"));
                FlushInstructionCache(CurrentProcess, addr, (UIntPtr)(ulong)size);
            }
            else
            {
                if (mprotect(page, sizeAligned, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
                    throw new InvalidOperationException(
                        "mprotect(Executable) failed at 0x" + page.ToInt64().ToString("X"));
            }
        }

        /// <summary>
        /// Makes a data region readable and writable (for slot/cell patches that stay
        /// writable after the write). Code pages keep execute permission
        /// (PAGE_EXECUTE_READWRITE), pure data pages get PAGE_READWRITE only.
        /// </summary>
        public static void ProtectReadWrite(IntPtr addr, int size)
        {
            ProtectWritable(addr, size);
        }

        public static IntPtr AllocExec(int size)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            }
            return mmap(IntPtr.Zero, (UIntPtr)(ulong)size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0L);
        }

        /// <summary>
        /// Tries to allocate executable memory at a specific address. If the allocation
        /// succeeds but falls outside the rel32 range of <paramref name="nearAddr"/>,
        /// the allocation is freed and IntPtr.Zero is returned.
        /// </summary>
        private static IntPtr TryAllocNearAt(IntPtr addr, UIntPtr sizeAligned, IntPtr nearAddr, bool isWindows)
        {
            IntPtr ptr;
            if (isWindows)
            {
                ptr = VirtualAlloc(addr, sizeAligned, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (ptr == IntPtr.Zero) return IntPtr.Zero;
            }
            else
            {
                ptr = mmap(addr, sizeAligned, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0L);
                if (ptr.ToInt64() == -1 || ptr == IntPtr.Zero) return IntPtr.Zero;
            }

            long delta = ptr.ToInt64() - nearAddr.ToInt64();
            if (delta >= -2147483647 && delta <= int.MaxValue) return ptr;

            if (isWindows)
                VirtualFree(ptr, UIntPtr.Zero, MEM_RELEASE);
            else
                munmap(ptr, sizeAligned);
            return IntPtr.Zero;
        }

        public static IntPtr AllocExecNear(IntPtr nearAddr, int size)
        {
            const long MaxRel32Range = 2147418112;
            long near = nearAddr.ToInt64();
            UIntPtr sizeAligned = (UIntPtr)(ulong)((size + 4095) & -4096);
            bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

            long minAddr = near - MaxRel32Range;
            long maxAddr = near + MaxRel32Range;
            long step = isWindows ? 65536 : 4096;

            if (isWindows)
            {
                if (minAddr < 65536) minAddr = 65536;
            }
            else
            {
                if (minAddr < 0) minAddr = 65536;
            }

            for (long offset = 0; offset < MaxRel32Range; offset += step)
            {
                // Forward: near + offset
                long fwd = near + offset;
                if (fwd >= minAddr && fwd + (long)sizeAligned.ToUInt64() <= maxAddr)
                {
                    IntPtr r = TryAllocNearAt(new IntPtr(fwd), sizeAligned, nearAddr, isWindows);
                    if (r != IntPtr.Zero) return r;
                }

                // Backward: near - offset
                if (offset > 0)
                {
                    long bwd = near - offset;
                    if (bwd >= minAddr && bwd + (long)sizeAligned.ToUInt64() <= maxAddr)
                    {
                        IntPtr r = TryAllocNearAt(new IntPtr(bwd), sizeAligned, nearAddr, isWindows);
                        if (r != IntPtr.Zero) return r;
                    }
                }
            }

            // Fallback: allocate anywhere
            if (isWindows)
                return VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            return AllocExec(size);
        }

        public static void FreeExec(IntPtr ptr, int size)
        {
            if (!(ptr == IntPtr.Zero))
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    VirtualFree(ptr, UIntPtr.Zero, MEM_RELEASE);
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
                return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY
                    || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
            }
            // Non-Windows (Linux/macOS): consult /proc/self/maps to verify the
            // address range lies within a readable mapping. Unlike mincore (which
            // only reports whether a page is mapped, not its protection), the maps
            // file distinguishes PROT_NONE pages (perms "---p") from genuinely
            // readable ones ("r--p"/"r-xp"). This prevents AccessViolationException
            // (uncatchable in .NET 8, terminates the process) when MethodTable/
            // MethodDesc scans or candidate-code dereferences reach a PROT_NONE
            // guard page. The parsed region list is cached for 1s to amortize the
            // cost of reading /proc/self/maps across the thousands of per-slot
            // checks performed by SlotPatcher.FindSlots.
            var regions = GetReadableRegions(force: false);
            if (regions == null || regions.Count == 0)
            {
                // Could not parse maps: fall back to the optimistic assumption.
                return true;
            }
            if (IsInReadableRegion(regions, addr.ToInt64(), size)) return true;
            // Cache miss: return true (optimistic). The address may belong to a
            // region mapped after the cache was last parsed (e.g. freshly JIT-
            // compiled code in a new code heap). Returning false here would cause
            // hook installation to fail for recently-compiled methods. PROT_NONE
            // guard pages are typically present from process start (so they're in
            // the cached maps and correctly return false above); newly-mapped
            // regions are almost always readable code/data heaps, not guard pages.
            return true;
        }

        // ===== /proc/self/maps readable-region cache (Linux) =====
        //
        // /proc/self/maps lists every mapped region with its protection. We keep
        // the readable ones (perms start with 'r') in a sorted list and binary-
        // search it from IsReadable. The list is cached for 1s to amortize the
        // cost of reading /proc/self/maps across the thousands of per-slot checks
        // performed by SlotPatcher.FindSlots. On cache miss IsReadable returns
        // true (optimistic) so freshly-JITted code in new heaps is not rejected.

        private static List<(long Start, long End)> s_readableRegions;
        private static long s_readableRegionsTicks;
        private static readonly object s_readableLock = new object();

        private static List<(long Start, long End)> GetReadableRegions(bool force)
        {
            lock (s_readableLock)
            {
                long now = Environment.TickCount;
                if (!force && s_readableRegions != null && (now - s_readableRegionsTicks) < 1000)
                {
                    return s_readableRegions;
                }
                s_readableRegions = ParseReadableRegions();
                s_readableRegionsTicks = now;
                return s_readableRegions;
            }
        }

        private static List<(long Start, long End)> ParseReadableRegions()
        {
            var list = new List<(long Start, long End)>();
            try
            {
                // /proc/self/maps is Linux-specific; on macOS this file does not
                // exist and ParseReadableRegions returns an empty list, causing
                // IsReadable to fall back to the optimistic assumption.
                using (var fs = new FileStream("/proc/self/maps", FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(fs))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        // Format: start-end perms offset dev inode pathname
                        // e.g.  7f68b9d60000-7f68b9e80000 r-xp 00000000 00:00 0 /path
                        int space = line.IndexOf(' ');
                        if (space <= 0) continue;
                        // perms immediately follow the range + space; readable iff 'r'.
                        if (space + 1 >= line.Length || line[space + 1] != 'r') continue;
                        int dash = line.IndexOf('-');
                        if (dash <= 0 || dash >= space) continue;
                        if (!long.TryParse(line.Substring(0, dash), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long start)) continue;
                        if (!long.TryParse(line.Substring(dash + 1, space - dash - 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long end)) continue;
                        list.Add((start, end));
                    }
                }
                list.Sort((a, b) => a.Start.CompareTo(b.Start));
            }
            catch
            {
                // File missing or unreadable: return empty so callers fall back.
            }
            return list;
        }

        private static bool IsInReadableRegion(List<(long Start, long End)> regions, long addr, int size)
        {
            long end = addr + size;
            int lo = 0, hi = regions.Count - 1;
            while (lo <= hi)
            {
                int mid = lo + (hi - lo) / 2;
                var r = regions[mid];
                if (end <= r.Start)
            {
                hi = mid - 1;
            }
            else if (addr >= r.End)
            {
                lo = mid + 1;
            }
            else if (addr >= r.Start && end <= r.End)
            {
                return true;
            }
            else
            {
                // Overlaps a region boundary: not fully contained in one readable
                // mapping, treat as unreadable.
                return false;
            }
            }
            return false;
        }

        /// <summary>
        /// Determines whether the page containing <paramref name="addr"/> is currently
        /// executable. Used to choose the right target protection for VirtualProtect/
        /// mprotect so that code pages keep execute permission (required, otherwise the
        /// precode/JIT code on the same page becomes non-executable and crashes) while
        /// pure data pages (MethodDesc/MethodTable slots) avoid being granted execute.
        /// </summary>
        private static bool IsExecutablePage(IntPtr addr)
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
                    // Could not query: assume executable to be safe (avoids stripping
                    // execute from a code page we failed to inspect).
                    return true;
                }
                uint p = mbi.Protect & 0xFF;
                return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ
                    || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
            }
            // Non-Windows: cannot cheaply query per-page protection. Assume executable
            // to be safe so we never strip execute from a code page.
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

        [StructLayout(LayoutKind.Sequential)]
        private struct CFG_CALL_TARGET_INFO
        {
            public IntPtr Offset;
            public IntPtr Flags;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetProcessValidCallTargets(
            IntPtr hProcess,
            IntPtr baseAddress,
            UIntPtr regionSize,
            uint numberOfOffsets,
            ref CFG_CALL_TARGET_INFO offsetInformation);

        private static readonly IntPtr CurrentProcessHandle = new IntPtr(-1);

        private const int CFG_CALL_TARGET_VALID = 1;

        /// <summary>
        /// Registers an executable address as a valid indirect call target for
        /// Control Flow Guard (CFG). On .NET 6+, the runtime (coreclr.dll) is built
        /// with CFG enabled, so every indirect call (including managed <c>calli</c>
        /// emitted for <c>delegate*</c>) is validated against the CFG bitmap. Memory
        /// allocated via <c>VirtualAlloc</c> is NOT in the bitmap by default, so an
        /// indirect call to a trampoline living in such memory raises
        /// <c>STATUS_ACCESS_VIOLATION</c> (0xC0000005). This call marks the address
        /// as a valid target so CFG permits the indirect call.
        /// On systems where CFG is not enabled, this is a harmless no-op.
        /// </summary>
        public static void RegisterValidCallTarget(IntPtr addr, int size)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
            if (IntPtr.Size != 8) return; // CFG bitmap is only meaningful on x64

            CFG_CALL_TARGET_INFO info = new CFG_CALL_TARGET_INFO
            {
                Offset = IntPtr.Zero,
                Flags = new IntPtr(CFG_CALL_TARGET_VALID)
            };
            try
            {
                SetProcessValidCallTargets(CurrentProcessHandle, addr, (UIntPtr)(ulong)size, 1, ref info);
            }
            catch
            {
                // Older Windows versions (pre-Win8.1) don't have this API; ignore.
            }
        }

        [DllImport("libc", SetLastError = true)]
        private static extern int mprotect(IntPtr addr, UIntPtr len, int prot);

        [DllImport("libc", SetLastError = true)]
        private static extern IntPtr mmap(IntPtr addr, UIntPtr len, int prot, int flags, int fd, long off);

        [DllImport("libc", SetLastError = true)]
        private static extern int munmap(IntPtr addr, UIntPtr len);
    }
}
