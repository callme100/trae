using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

namespace DynamicHook
{
    public sealed partial class MethodHook
    {
        /// <summary>
        /// 准备方法并解析到真实 JIT 代码入口指针。返回 IntPtr.Zero 表示失败。
        /// 抽取自 ScanCallTargets/ScanIndirectCalls/ScanMovRipRelative 共享的 prologue。
        /// </summary>
        private static unsafe byte* ResolveJitCodePtr(MethodBase method)
        {
            RuntimeHelpers.PrepareMethod(method.MethodHandle);
            IntPtr entry = method.MethodHandle.GetFunctionPointer();
            if (entry == IntPtr.Zero) return null;
            IntPtr jitEntry = MethodEntryResolver.ResolveRealEntry(entry);
            if (jitEntry != IntPtr.Zero) entry = jitEntry;
            return (byte*)entry;
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
                byte* p = ResolveJitCodePtr(method);
                if (p == null) return result;
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
                    long cur = MemOps.ReadInt64(_indirectTargetLoc);
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
                    byte b0 = MemOps.ReadByte(_secondaryJitAddress);
                    byte b1 = MemOps.ReadByte(_secondaryJitAddress + 1);
                    byte b2 = MemOps.ReadByte(_secondaryJitAddress + 2);
                    byte b3 = MemOps.ReadByte(_secondaryJitAddress + 3);
                    byte b4 = MemOps.ReadByte(_secondaryJitAddress + 4);
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
                    byte b0 = MemOps.ReadByte(_target1Address);
                    byte b1 = MemOps.ReadByte(_target1Address + 1);
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
                    byte b0 = MemOps.ReadByte(_innerCodeAddress);
                    byte b1 = MemOps.ReadByte(_innerCodeAddress + 1);
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
                    long cur = MemOps.ReadInt64(_target2Loc);
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
                        long cur = MemOps.ReadInt64(slot);
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
                byte* p = ResolveJitCodePtr(method);
                if (p == null) return result;
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
                byte* p = ResolveJitCodePtr(method);
                if (p == null) return result;
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
    }
}
