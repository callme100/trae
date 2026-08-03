using System;
using System.Runtime.InteropServices;

namespace Crane.MethodHook
{
    internal static class Memory
    {
        private static readonly IntPtr CurrentProcess = new IntPtr(-1);

        private static int PageSize => HookConstants.PageSize;

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

        // POSIX mmap flags. MAP_PRIVATE and MAP_FIXED have the same value on
        // Linux and macOS/BSD. MAP_ANONYMOUS differs: 0x20 on Linux, 0x1000 on
        // macOS/BSD — using the wrong value causes mmap to fail with EINVAL.
        private const int MAP_PRIVATE = 0x02;
        private const int MAP_FIXED = 0x10;
        // Linux: MAP_ANONYMOUS = 0x20; macOS/BSD: MAP_ANON = 0x1000.
        private static int MAP_ANONYMOUS => RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? 0x1000 : 0x20;

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
        ///
        /// CRITICAL: On non-Windows (Linux/macOS), <paramref name="addr"/> MUST point
        /// to a genuinely FREE address. Using mmap with MAP_FIXED at an already-mapped
        /// address SILENTLY OVERWRITES the existing mapping — corrupting JIT code,
        /// MethodTable, or precode memory and causing SIGSEGV. Callers must verify
        /// the address is free (e.g. via /proc/self/maps on Linux) before calling
        /// this method with <paramref name="useFixed"/> = true. When
        /// <paramref name="useFixed"/> is false, mmap is called WITHOUT MAP_FIXED so
        /// the address is only a hint (the kernel will never overwrite an existing
        /// mapping); the result is checked against the rel32 range and returned if in
        /// range, otherwise freed.
        /// </summary>
        private static IntPtr TryAllocNearAt(IntPtr addr, UIntPtr sizeAligned, IntPtr nearAddr, bool isWindows, bool useFixed)
        {
            IntPtr ptr;
            if (isWindows)
            {
                // VirtualAlloc with a non-zero address returns NULL if the region
                // is already in use — it never overwrites an existing mapping.
                ptr = VirtualAlloc(addr, sizeAligned, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (ptr == IntPtr.Zero) return IntPtr.Zero;
            }
            else
            {
                int flags = MAP_PRIVATE | MAP_ANONYMOUS;
                if (useFixed) flags |= MAP_FIXED;
                ptr = mmap(addr, sizeAligned, PROT_READ | PROT_WRITE | PROT_EXEC,
                    flags, -1, 0L);
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
            long near = nearAddr.ToInt64();
            UIntPtr sizeAligned = (UIntPtr)(ulong)((size + HookConstants.PageSize - 1) & -HookConstants.PageSize);
            bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

            long minAddr = near - HookConstants.MaxRel32Range;
            long maxAddr = near + HookConstants.MaxRel32Range;

            if (isWindows)
            {
                if (minAddr < 65536) minAddr = 65536;
                long step = 65536;
                for (long offset = 0; offset < HookConstants.MaxRel32Range; offset += step)
                {
                    // Forward: near + offset
                    long fwd = near + offset;
                    if (fwd >= minAddr && fwd + (long)sizeAligned.ToUInt64() <= maxAddr)
                    {
                        IntPtr r = TryAllocNearAt(new IntPtr(fwd), sizeAligned, nearAddr, true, true);
                        if (r != IntPtr.Zero) return r;
                    }
                    // Backward: near - offset
                    if (offset > 0)
                    {
                        long bwd = near - offset;
                        if (bwd >= minAddr && bwd + (long)sizeAligned.ToUInt64() <= maxAddr)
                        {
                            IntPtr r = TryAllocNearAt(new IntPtr(bwd), sizeAligned, nearAddr, true, true);
                            if (r != IntPtr.Zero) return r;
                        }
                    }
                }
                // Fallback: allocate anywhere
                return VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            }

            // ----- Linux / macOS -----
            // On Linux, find a genuinely FREE address gap near `near` by parsing
            // /proc/self/maps, then mmap that gap with MAP_FIXED (safe because it's
            // unmapped). Without this, MAP_FIXED would silently overwrite existing
            // mappings (JIT code / MethodTable / precode), causing SIGSEGV.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                IntPtr freeAddr = FindFreeAddressNearLinux(near, size, HookConstants.MaxRel32Range);
                if (freeAddr != IntPtr.Zero)
                {
                    IntPtr r = TryAllocNearAt(freeAddr, sizeAligned, nearAddr, false, true);
                    if (r != IntPtr.Zero) return r;
                }
            }

            // macOS or Linux fallback: scan candidate addresses without MAP_FIXED
            // (the address is only a hint; the kernel never overwrites an existing
            // mapping). Each successful mmap is checked against the rel32 range.
            if (minAddr < 65536) minAddr = 65536;
            long psStep = HookConstants.PageSize;
            for (long offset = 0; offset < HookConstants.MaxRel32Range; offset += psStep)
            {
                long fwd = near + offset;
                if (fwd >= minAddr && fwd + (long)sizeAligned.ToUInt64() <= maxAddr)
                {
                    IntPtr r = TryAllocNearAt(new IntPtr(fwd), sizeAligned, nearAddr, false, false);
                    if (r != IntPtr.Zero) return r;
                }
                if (offset > 0)
                {
                    long bwd = near - offset;
                    if (bwd >= minAddr && bwd + (long)sizeAligned.ToUInt64() <= maxAddr)
                    {
                        IntPtr r = TryAllocNearAt(new IntPtr(bwd), sizeAligned, nearAddr, false, false);
                        if (r != IntPtr.Zero) return r;
                    }
                }
            }
            // Final fallback: allocate anywhere (may be out of rel32 range).
            return AllocExec(size);
        }

        /// <summary>
        /// A mapped memory region from /proc/self/maps (any permission).
        /// Used to find FREE (unmapped) address gaps for near allocation.
        /// </summary>
        private struct LinuxMappedRegion
        {
            public long Start;
            public long End;
        }

        /// <summary>
        /// Parses /proc/self/maps and returns ALL mapped regions (regardless of
        /// permission). Unlike ParseLinuxMaps (which only returns readable
        /// regions), this returns every mapped region so callers can identify
        /// unmapped gaps suitable for mmap with MAP_FIXED.
        /// Regions in /proc/self/maps are sorted by start address ascending.
        /// Returns an empty array if /proc/self/maps cannot be read.
        /// </summary>
        private static LinuxMappedRegion[] ParseAllLinuxMappedRegions()
        {
            var regions = new System.Collections.Generic.List<LinuxMappedRegion>();
            try
            {
                using (var fs = new System.IO.FileStream(
                           "/proc/self/maps", System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read))
                using (var sr = new System.IO.StreamReader(fs))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        int dash = line.IndexOf('-');
                        if (dash <= 0) continue;
                        int space = line.IndexOf(' ', dash);
                        if (space <= dash) continue;
                        long start, end;
                        if (!long.TryParse(line.Substring(0, dash), System.Globalization.NumberStyles.HexNumber,
                            System.Globalization.CultureInfo.InvariantCulture, out start))
                            continue;
                        if (!long.TryParse(line.Substring(dash + 1, space - dash - 1), System.Globalization.NumberStyles.HexNumber,
                            System.Globalization.CultureInfo.InvariantCulture, out end))
                            continue;
                        regions.Add(new LinuxMappedRegion { Start = start, End = end });
                    }
                }
            }
            catch
            {
                // /proc/self/maps unavailable
            }
            return regions.ToArray();
        }

        /// <summary>
        /// Finds a FREE (unmapped) address gap of at least <paramref name="size"/>
        /// bytes within ±<paramref name="range"/> of <paramref name="nearAddr"/> on
        /// Linux, by parsing /proc/self/maps. The returned address is page-aligned
        /// and guaranteed to be within the rel32 range of <paramref name="nearAddr"/>
        /// so a 5-byte E9 relative jump can reach it.
        ///
        /// This is REQUIRED before calling mmap with MAP_FIXED: MAP_FIXED at an
        /// already-mapped address SILENTLY OVERWRITES the existing mapping,
        /// corrupting JIT code / MethodTable / precode and causing SIGSEGV.
        ///
        /// Returns IntPtr.Zero if no suitable gap is found or /proc/self/maps is
        /// unavailable (caller falls back to the non-MAP_FIXED scan).
        /// </summary>
        private static IntPtr FindFreeAddressNearLinux(long nearAddr, long size, long range)
        {
            long pageSize = PageSize;
            long allocSize = ((size + pageSize - 1) / pageSize) * pageSize;
            // Avoid page 0; keep min within rel32 range of nearAddr.
            long minAddr = Math.Max(nearAddr - range, pageSize);
            long maxAddr = nearAddr + range - allocSize;
            if (maxAddr < minAddr) return IntPtr.Zero;

            var mapped = ParseAllLinuxMappedRegions();
            if (mapped == null || mapped.Length == 0)
                return IntPtr.Zero; // cannot determine free space safely

            // /proc/self/maps is sorted by start address ascending. Walk through
            // and find the first gap >= allocSize within [minAddr, maxAddr].
            long searchStart = minAddr;
            for (int i = 0; i < mapped.Length; i++)
            {
                long rStart = mapped[i].Start;
                long rEnd = mapped[i].End;
                if (rEnd <= searchStart) continue;       // region entirely before window
                if (rStart > maxAddr) break;             // region entirely after window
                // Gap between searchStart and rStart
                if (rStart > searchStart)
                {
                    long gap = rStart - searchStart;
                    if (gap >= allocSize)
                    {
                        // Page-align the candidate address.
                        long addr = (searchStart + pageSize - 1) & ~(pageSize - 1);
                        if (addr + allocSize <= rStart &&
                            addr >= minAddr &&
                            addr + allocSize - 1 <= maxAddr + allocSize - 1)
                        {
                            long delta = addr - nearAddr;
                            if (delta >= -2147483647L && delta <= (long)int.MaxValue)
                                return new IntPtr(addr);
                        }
                    }
                }
                searchStart = Math.Max(searchStart, rEnd);
            }
            // Check the gap after the last mapped region.
            if (searchStart <= maxAddr)
            {
                long addr = (searchStart + pageSize - 1) & ~(pageSize - 1);
                if (addr + allocSize - 1 <= maxAddr + allocSize - 1)
                {
                    long delta = addr - nearAddr;
                    if (delta >= -2147483647L && delta <= (long)int.MaxValue)
                        return new IntPtr(addr);
                }
            }
            return IntPtr.Zero;
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
        public static unsafe bool IsReadable(IntPtr addr, int size)
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
            // Linux: parse /proc/self/maps to verify the address range is both
            // mapped AND readable. mincore(2) only checks mapping — it reports
            // PROT_NONE guard pages (placed by the CLR at the end of MethodTable
            // allocations on .NET 6 Linux) as "mapped", causing uncatchable
            // AccessViolationException inside Marshal.ReadInt64 when the
            // MethodTable scan walks past the live data into the guard page.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return IsReadableLinux(addr, size);
            }
            // macOS / other Unix: fall back to mincore. macOS does not use
            // PROT_NONE guard pages near CLR regions like Linux does, so mincore
            // is sufficient there.
            return IsReadableUnixMincore(addr, size);
        }

        /// <summary>
        /// A memory region from /proc/self/maps with its start/end addresses.
        /// Only regions whose permissions include 'r' (PROT_READ) are stored.
        /// </summary>
        private struct LinuxMemoryRegion
        {
            public long Start;
            public long End;
        }

        /// <summary>
        /// Cached snapshot of readable memory regions parsed from /proc/self/maps.
        /// Built lazily on first IsReadableLinux call and refreshed when an
        /// address is not found (maps may change due to JIT/GC activity).
        /// Volatile so the lock-free fast path reads the most recent reference.
        /// </summary>
        private static volatile LinuxMemoryRegion[] _linuxReadableRegions;
        private static readonly object _linuxMapsLock = new object();

        private static LinuxMemoryRegion[] GetLinuxReadableRegions()
        {
            var cached = _linuxReadableRegions;
            if (cached != null) return cached;
            lock (_linuxMapsLock)
            {
                if (_linuxReadableRegions != null) return _linuxReadableRegions;
                _linuxReadableRegions = ParseLinuxMaps();
                return _linuxReadableRegions;
            }
        }

        /// <summary>
        /// Parses /proc/self/maps and returns an array of regions whose
        /// permissions include read access (the 'r' permission bit).
        /// Returns an empty array if /proc/self/maps cannot be read.
        /// </summary>
        private static LinuxMemoryRegion[] ParseLinuxMaps()
        {
            var regions = new System.Collections.Generic.List<LinuxMemoryRegion>();
            try
            {
                using (var fs = new System.IO.FileStream(
                           "/proc/self/maps", System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read))
                using (var sr = new System.IO.StreamReader(fs))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        // Format: start-end perm offset dev inode pathname
                        // Example: 7f8b0c000000-7f8b0c021000 rw-p 00000000 00:00 0
                        int dash = line.IndexOf('-');
                        if (dash <= 0) continue;
                        int space = line.IndexOf(' ', dash);
                        if (space <= dash) continue;
                        // Parse hex start and end addresses
                        long start, end;
                        if (!long.TryParse(line.Substring(0, dash), System.Globalization.NumberStyles.HexNumber,
                            System.Globalization.CultureInfo.InvariantCulture, out start))
                            continue;
                        if (!long.TryParse(line.Substring(dash + 1, space - dash - 1), System.Globalization.NumberStyles.HexNumber,
                            System.Globalization.CultureInfo.InvariantCulture, out end))
                            continue;
                        // Permission string starts at space+1; readable iff first char is 'r'
                        int permIdx = space + 1;
                        if (permIdx < line.Length && line[permIdx] == 'r')
                        {
                            regions.Add(new LinuxMemoryRegion { Start = start, End = end });
                        }
                    }
                }
            }
            catch
            {
                // /proc/self/maps not available or unreadable — return empty so
                // callers fall through to the conservative mincore path.
            }
            return regions.ToArray();
        }

        private static bool IsReadableLinux(IntPtr addr, int size)
        {
            long addrStart = addr.ToInt64();
            long addrEnd = addrStart + size;

            // Fast path: check the cached readable regions.
            var regions = GetLinuxReadableRegions();
            if (regions != null && regions.Length > 0)
            {
                if (IsInReadableRegions(regions, addrStart, addrEnd))
                    return true;
            }
            else
            {
                // /proc/self/maps was unavailable — fall back to mincore so we
                // don't regress compared to the previous "always readable" code.
                return IsReadableUnixMincore(addr, size);
            }

            // Miss: the address may be in a region allocated after the cache was
            // built (JIT/GC can allocate new code pages). Refresh once and retry.
            lock (_linuxMapsLock)
            {
                _linuxReadableRegions = null;
            }
            regions = GetLinuxReadableRegions();
            if (IsInReadableRegions(regions, addrStart, addrEnd))
                return true;

            return false;
        }

        private static bool IsInReadableRegions(LinuxMemoryRegion[] regions, long addrStart, long addrEnd)
        {
            // Linear scan: region count is typically a few hundred, and IsReadable
            // is called in tight scan loops. If this proves too slow, switch to
            // binary search on a sorted array.
            for (int i = 0; i < regions.Length; i++)
            {
                if (addrStart >= regions[i].Start && addrEnd <= regions[i].End)
                    return true;
            }
            return false;
        }

        private static unsafe bool IsReadableUnixMincore(IntPtr addr, int size)
        {
            long pageSize = PageSize;
            IntPtr page = AlignToPage(addr);
            long start = page.ToInt64();
            long end = addr.ToInt64() + size;
            // Round length up to a page boundary so mincore covers the full range.
            long length = ((end - start + pageSize - 1) / pageSize) * pageSize;
            if (length <= 0)
            {
                return true;
            }
            int pageCount = (int)(length / pageSize);
            if (pageCount <= 0)
            {
                return true;
            }
            // stackalloc avoids per-call heap allocation in tight scan loops.
            byte* vec = stackalloc byte[pageCount];
            try
            {
                int rc = mincore(page, (UIntPtr)(ulong)length, vec);
                return rc == 0;
            }
            catch
            {
                // mincore P/Invoke unavailable — preserve old "assume readable".
                return true;
            }
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

        // mincore(2): returns 0 if every page in [addr, addr+len) is mapped,
        // -1 with errno=ENOMEM if any page is unmapped. Used by IsReadable on
        // Linux/macOS to avoid uncatchable AccessViolationException when scanning
        // past the end of mapped CLR regions (MethodDesc/MethodTable).
        [DllImport("libc", SetLastError = true)]
        private static extern unsafe int mincore(IntPtr addr, UIntPtr len, byte* vec);
    }
}
