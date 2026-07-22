using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DynamicHook
{
    public sealed partial class MethodHook : IDisposable
    {
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
                IntPtr mdForScan = !_needsGenericAdapter ? methodDesc : IntPtr.Zero;
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
                        // Search for multiple possible code pointer values in the
                        // generic dictionary:
                        // 1. targetPtr (precode address) — what the slot initially holds
                        // 2. ResolveRealEntry(targetPtr) — the fixup thunk address
                        // 3. TryResolveFixupToJitCode(fixup thunk) — the <jit_addr>
                        //    field, which may be PRESTUB (cold) or real JIT code (warm)
                        // Generic dictionaries can be large (hundreds of slots), so
                        // scan up to 8192 bytes.
                        const int dictScanSize = 8192;
                        IntPtr fixupThunk = MethodEntryResolver.ResolveRealEntry(targetPtr);
                        var dictSlots = SlotPatcher.FindSlots(genDictAddr, IntPtr.Zero, targetPtr, dictScanSize);
                        if (fixupThunk != IntPtr.Zero && fixupThunk != targetPtr)
                        {
                            foreach (IntPtr s in SlotPatcher.FindSlots(genDictAddr, IntPtr.Zero, fixupThunk, dictScanSize))
                                if (!dictSlots.Contains(s)) dictSlots.Add(s);
                        }
                        IntPtr jitFromFixup = TryResolveFixupToJitCode(fixupThunk);
                        if (jitFromFixup != IntPtr.Zero && jitFromFixup != targetPtr && jitFromFixup != fixupThunk)
                        {
                            foreach (IntPtr s in SlotPatcher.FindSlots(genDictAddr, IntPtr.Zero, jitFromFixup, dictScanSize))
                                if (!dictSlots.Contains(s)) dictSlots.Add(s);
                        }
                        // After tiered promotion on .NET 8+, the generic dictionary's
                        // code pointer slot may be updated to the tier-1 JIT code
                        // address, which is different from all three values above.
                        // Use _targetJitCode (resolved in Install() BEFORE slot
                        // replacement via ScanMethodDescForJitCode) to scan the
                        // dictionary for the tier-1 code address.
                        IntPtr tier1Jit = _targetJitCode;
                        if (tier1Jit != IntPtr.Zero && tier1Jit != targetPtr
                            && Memory.IsReadable(tier1Jit, 16) && LooksLikeRealJitCode(tier1Jit))
                        {
                            foreach (IntPtr s in SlotPatcher.FindSlots(genDictAddr, IntPtr.Zero, tier1Jit, dictScanSize))
                                if (!dictSlots.Contains(s)) dictSlots.Add(s);
                            if (dictSlots.Count > 0)
                            {
                                diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; GenDictTier1JitScan at 0x" + tier1Jit.ToInt64().ToString("X");
                            }
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
                // Save each slot's current value BEFORE patching. SlotPatcher.FindSlots
                // matches cells holding EITHER the precode address OR ResolveRealEntry
                // (the boxed→unboxed thunk for value-type instance methods), so different
                // slots can have different originals. Restoring all to a single shared
                // value corrupts the thunk-pointing slot and creates a circular dispatch
                // loop between the two precodes (hang on post-uninstall call).
                _originalSlotValues = new List<IntPtr>(_slotAddresses.Count);
                foreach (IntPtr slotAddress in _slotAddresses)
                {
                    IntPtr originalValue;
                    try
                    {
                        originalValue = MemOps.ReadIntPtr(slotAddress);
                    }
                    catch
                    {
                        // If we cannot read the current value, fall back to the
                        // shared precode address — preserves previous behavior for
                        // this slot and avoids breaking the install entirely.
                        originalValue = targetPtr;
                    }
                    _originalSlotValues.Add(originalValue);
                    SlotPatcher.ReplaceSlot(slotAddress, jumpTarget);
                }
            }
            catch (Exception ex)
            {
                diag.SlotError = ex.Message;
            }
        }

        /// <summary>
        /// Checks whether the bytes at <paramref name="f"/> match a CoreCLR x64
        /// generic-method fixup thunk prefix, and returns the byte offset of the
        /// generic dictionary operand (always 5) when it matches.
        ///
        /// Both Windows and Unix x64 use the same structural layout:
        ///   3-byte register shift | 2-byte MOV r64,imm64 | 8-byte dict |
        ///   2-byte MOV RAX,imm64 (48 B8) | 8-byte jit_addr | 2-byte JMP RAX (FF E0)
        /// Only the first 5 bytes differ:
        ///   Windows: 49 89 D0 48 BA  (MOV R10, RDX; MOV RDX, dict)
        ///   Unix:    48 89 F2 48 BE  (MOV RDX, RSI; MOV RSI, dict)
        /// The dictionary operand is at offset 5 and the JIT address at offset
        /// 15 in BOTH patterns, so callers can extract them positionally after
        /// this check passes.
        ///
        /// Returns 5 (the dict operand offset) on match, or -1 on no match.
        /// </summary>
        private static unsafe int MatchFixupThunkPrefix(byte* f)
        {
            // Windows x64: 49 89 D0 48 BA ... 48 B8 ...
            if (f[0] == 0x49 && f[1] == 0x89 && f[2] == 0xD0 &&
                f[3] == 0x48 && f[4] == 0xBA &&
                f[13] == 0x48 && f[14] == 0xB8)
                return 5;
            // Unix x64 (Linux/macOS): 48 89 F2 48 BE ... 48 B8 ...
            if (f[0] == 0x48 && f[1] == 0x89 && f[2] == 0xF2 &&
                f[3] == 0x48 && f[4] == 0xBE &&
                f[13] == 0x48 && f[14] == 0xB8)
                return 5;
            return -1;
        }

        /// <summary>
        /// Extracts the generic dictionary address from the fixup thunk referenced
        /// by a precode. Supports both FF 25 (indirect jump) and E9 (relative jump)
        /// precode formats, and both Windows and Unix x64 fixup thunk patterns.
        ///
        /// FF 25 precode (.NET 6+ FixupPrecode): FF 25 <disp32> -> [mem] = fixup thunk addr
        /// E9 precode (.NET Framework 4.x DirectJump): E9 <rel32> -> fixup thunk addr
        ///
        /// Windows fixup thunk:
        ///   49 89 D0 | 48 BA <8-byte dict> | 48 B8 <8-byte jit_addr> | FF E0
        ///   MOV R10, RDX; MOV RDX, dict; MOV RAX, jit_addr; JMP RAX
        /// Unix fixup thunk:
        ///   48 89 F2 | 48 BE <8-byte dict> | 48 B8 <8-byte jit_addr> | FF E0
        ///   MOV RDX, RSI; MOV RSI, dict; MOV RAX, jit_addr; JMP RAX
        /// The generic dictionary address is at offset 5 in both patterns.
        /// </summary>
        private unsafe IntPtr ExtractGenericDictionaryFromFixup(IntPtr precodeAddr)
        {
            if (!Memory.IsReadable(precodeAddr, 6)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)precodeAddr;
                byte op = p[0];
                long fixupAddr = 0;

                if (op == 0xFF && p[1] == 0x25)
                {
                    // FF 25 precode: indirect jump through [rip+disp32]
                    int disp = *(int*)(p + 2);
                    long fixupLoc = precodeAddr.ToInt64() + 6 + disp;
                    if (!Memory.IsReadable(new IntPtr(fixupLoc), 8)) return IntPtr.Zero;
                    fixupAddr = *(long*)fixupLoc;
                }
                else if (op == 0xE9)
                {
                    // E9 precode (.NET Framework 4.x): relative jump to fixup thunk
                    int rel32 = *(int*)(p + 1);
                    fixupAddr = precodeAddr.ToInt64() + 5 + rel32;
                }
                else
                {
                    return IntPtr.Zero;
                }

                if (fixupAddr == 0) return IntPtr.Zero;
                if (!Memory.IsReadable(new IntPtr(fixupAddr), 23)) return IntPtr.Zero;
                byte* f = (byte*)fixupAddr;
                if (MatchFixupThunkPrefix(f) < 0) return IntPtr.Zero;
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
                diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, _originalBytes.Length);
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
            byte* ptr = (byte*)targetPtr;
            byte b = *ptr;
            byte b2 = ptr[1];
            if (b == 0xFF && b2 == 0x25)
            {
                diag.PatchTarget = "Precode";
                bool flag = ptr[6] == 0x4C && ptr[7] == 0x8B && ptr[8] == 0x15 && ptr[13] == 0xFF && ptr[14] == 0x25;
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
                try { diag.Target1Bytes = MemOps.ReadBytesSafe(diag.PrecodeFirstTargetAddr, 32); } catch { }
                try { diag.MethodDescDump = MemOps.ReadBytesSafe(_targetMethod.MethodHandle.Value, 64); } catch { }
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
                    MemOps.WriteInt64Cell(_indirectTargetLoc, jumpTarget.ToInt64());
                    diag.PatchType = "Indirect(FF 25 1st) + JIT(E9, generic) + Target1(12-byte)";
                    diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, 16);
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
                }
                else
                {
                    // Non-generic: patch the FF 25's indirect target data pointer.
                    // On .NET 6/8 with tiered compilation, call sites are backpatched
                    // to call the JIT code directly, bypassing the precode. Install a
                    // secondary JIT patch BEFORE patching the indirect target, otherwise
                    // ResolveRealEntry would follow our patched pointer and resolve to
                    // the hook address instead of the real JIT code.
                    //
                    // NOTE: Only install the secondary JIT patch for non-generic methods.
                    // Generic methods in this else branch (flag=false) must NOT receive a
                    // secondary JIT patch — the original behavior (precode-only patch)
                    // works correctly for them, and patching JIT code causes AV crashes
                    // on .NET 6/8 due to generic-dictionary setup in the JIT prologue.
                    if (!_needsGenericAdapter)
                    {
                        InstallSecondaryJitPatch(targetPtr, jumpTarget, diag);
                    }
                    // Patch the FF 25's indirect target data cell. This catches
                    // calls that go through the precode via the FF 25 instruction.
                    int num = 0;  // Always patch the first FF 25 (the normal call entry)
                    byte* ptr2 = ptr + num;
                    int num2 = *(int*)(ptr2 + 2);
                    long num3 = targetPtr.ToInt64() + num + 6 + num2;
                    _indirectTargetLoc = new IntPtr(num3);
                    _originalIndirectTarget = new IntPtr(*(long*)num3);
                    MemOps.WriteInt64Cell(_indirectTargetLoc, jumpTarget.ToInt64());
                    _hasIndirectPatch = true;
                    // ALSO patch the FF 25 instruction itself with a 5-byte E9
                    // relative jump to a near trampoline. On .NET 8+, tiered
                    // compilation promotion can OVERWRITE the data cell (target1)
                    // to point to new tier-1 JIT code, silently bypassing the
                    // data cell patch. The instruction patch is immune to this
                    // because the CLR does not overwrite the precode instruction
                    // during tiered promotion — it only updates the data cell.
                    // The near trampoline does a 12-byte absolute jump to the hook.
                    _nearTrampoline = Memory.AllocExecNear(targetPtr, 12);
                    if (_nearTrampoline != IntPtr.Zero && _nearTrampoline != new IntPtr(-1))
                    {
                        byte[] absJump = Jumper.BuildAbsJumpX64(jumpTarget);
                        MemOps.WriteBytes(_nearTrampoline, absJump);
                        _patchType = 2;
                        _patchAddress = targetPtr;
                        _originalBytes = MemOps.ReadBytes(targetPtr, 6);
                        byte[] relJump = Jumper.BuildRelJump(targetPtr, _nearTrampoline);
                        MemOps.WriteBytesProtected(targetPtr, relJump);
                        diag.PatchType = "Instr(E9) + Indirect(FF 25 data) + JIT(E9)";
                    }
                    else
                    {
                        // Fallback: data cell patch only (less robust on .NET 8+)
                        _patchType = 1;
                        diag.PatchType = (flag ? "Indirect(FF 25 1st, FixupPrecode) + JIT(E9)" : "Indirect(FF 25) + JIT(E9)");
                        diag.PatchError += "; NearTrampoline alloc failed, data-cell patch only";
                    }
                    diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, 16);
                }
            }
            else if (b == 0xE8 || b == 0xE9)
            {
                diag.PatchTarget = "Precode";
                // Dump MethodDesc and fixup-target bytes for diagnostics
                try { diag.MethodDescDump = MemOps.ReadBytesSafe(_targetMethod.MethodHandle.Value, 64); } catch { }
                // E8/E9 precode: the precode jumps to either the fixup thunk
                // (generic methods on .NET Framework 4.x) or directly to JIT code
                // (non-generic methods, or after backpatching on .NET 6+).
                //
                // For generic instance methods on .NET Framework 4.x, the E9 target
                // is a fixup thunk: 49 89 D0 48 BA <dict> 48 B8 <jit_addr> FF E0.
                // The <jit_addr> field may point to a PRESTUB or data structure
                // (not directly to JIT code), so patching the TARGET would corrupt
                // it. Instead, we patch the <jit_addr> FIELD ITSELF (a data pointer
                // at offset 15 in the fixup thunk) to point to the hook adapter.
                // This redirects all calls through the fixup thunk to the hook.
                //
                // CRITICAL: After EnsureJitCompiled triggers JIT compilation via
                // DynamicInvoke, the CLR backpatches direct call sites to call the
                // JIT code directly (bypassing both the precode and fixup thunk).
                // So we must ALSO patch the JIT code itself with a 5-byte E9 jump.
                // We extract the JIT code address from <jit_addr> BEFORE patching
                // it, then patch both: the <jit_addr> field (for fixup thunk path)
                // and the JIT code (for backpatched call sites).
                //
                // For non-generic methods on .NET 6+, the E9 target is real JIT code.
                // We patch it with a secondary 5-byte E9 jump (InstallSecondaryJitPatch).
                if (_needsGenericAdapter && b == 0xE9)
                {
                    // For generic methods, call sites bypass the precode and call the
                    // JIT code directly (via backpatching on .NET 6+, or via MethodDesc
                    // on .NET Framework 4.x after PrepareMethod). We MUST patch both
                    // the fixup thunk (target1) and the inner JIT code to redirect all
                    // call paths to the hook.
                    //
                    // InstallTarget1Patch reads <jit_addr> from the fixup thunk,
                    // resolves it to real JIT code (handling DATA structure indirection
                    // on .NET Framework 4.x and chained precodes on .NET 8), and
                    // patches both with 12-byte absolute jumps to the hook adapter.
                    //
                    // CRITICAL: Do NOT use ResolveRealEntry to get the fixup thunk
                    // address — it follows the entire jump chain (including the
                    // fixup thunk's MOV RAX, <jit_addr>; JMP RAX), returning the
                    // <jit_addr> value instead of the fixup thunk address.
                    IntPtr fixupThunk = ResolveFixupThunkFromPrecode(targetPtr);
                    if (fixupThunk != IntPtr.Zero)
                    {
                        InstallTarget1Patch(fixupThunk, jumpTarget, diag);
                    }
                    else
                    {
                        // No fixup thunk pattern — the E9 target may be real JIT code
                        // (e.g., Array.ConvertAll on .NET Framework 4.x where the
                        // precode was backpatched to point directly to JIT code).
                        // Resolve the real entry and patch the JIT code directly.
                        IntPtr realJit = MethodEntryResolver.ResolveRealEntry(targetPtr);
                        if (realJit != IntPtr.Zero && realJit != targetPtr && LooksLikeRealJitCode(realJit))
                        {
                            _innerCodeAddress = realJit;
                            _innerCodeOriginalBytes = MemOps.ReadBytes(realJit, 12);
                            _innerCodeOriginalBytesFull = MemOps.ReadBytesSafe(realJit, 32);
                            byte[] innerPatch = Jumper.BuildAbsJumpX64(jumpTarget);
                            MemOps.WriteBytesProtected(realJit, innerPatch);
                            _hasInnerCodePatch = true;
                            diag.PatchError += "; InnerCodePatch(12-byte, direct E9) at 0x" + realJit.ToInt64().ToString("X");
                        }
                        else
                        {
                            // Fallback: patch <jit_addr> field only (old behavior).
                            TryPatchFixupThunkJitAddr(targetPtr, jumpTarget, diag);
                        }
                    }
                }
                else if (!_needsGenericAdapter && (Environment.Version.Major >= 6 || IsPrecodeBackpatched(targetPtr)))
                {
                    // Non-generic: patch the JIT code with a secondary 5-byte E9 jump.
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
                byte[] array = Jumper.BuildAbsJumpX64(jumpTarget);
                MemOps.WriteBytes(_nearTrampoline, array);
                _patchType = 2;
                _patchAddress = targetPtr;
                _originalBytes = MemOps.ReadBytes(targetPtr, 6);
                int value = (int)(_nearTrampoline.ToInt64() - (targetPtr.ToInt64() + 5));
                byte[] array2 = Jumper.BuildRelJump(targetPtr, _nearTrampoline);
                MemOps.WriteBytesProtected(targetPtr, array2);
                diag.PatchType = ((b == 0xE8) ? "FixupPrecode(E8->E9)" : "DirectJump(E9)");
                diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, 16);
            }
            else if (!MethodEntryResolver.IsJump(targetPtr))
            {
                // The address returned by GetFunctionPointer() is raw JIT code
                // (no precode detected). On .NET Framework 4.x, PrepareMethod
                // causes GetFunctionPointer() to return the JIT code entry point
                // directly — the bytes typically start with a 5-byte NOP pad
                // (0F 1F 44 00 00) for hot-patching, followed by the function
                // prologue. Patching here intercepts all non-inlined CALLs to
                // this address.
                //
                // LIMITATION: If the JIT inlines the target method into its
                // callers (common for small methods like DateTime.Compare on
                // .NET Framework 4.x), there is no CALL instruction to
                // intercept and the hook will not trigger. To verify the hook
                // works, call the method via a delegate (Func<...>) which the
                // JIT cannot inline.
                diag.PatchTarget = "JitCode";
                _patchType = 3;
                _patchAddress = targetPtr;
                // Save full 32-byte original for potential CallOriginal trampoline.
                _innerCodeAddress = targetPtr;
                _innerCodeOriginalBytesFull = MemOps.ReadBytesSafe(targetPtr, 32);
                _originalBytes = Jumper.Install(targetPtr, jumpTarget);
                diag.PatchType = "JitCode(12-byte)";
                diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, 16);
            }
            else
            {
                IntPtr intPtr = MethodEntryResolver.ResolveRealEntry(targetPtr);
                if (intPtr != IntPtr.Zero && intPtr != targetPtr && !MethodEntryResolver.IsJump(intPtr))
                {
                    diag.PatchTarget = "JitCode(resolved)";
                    _patchType = 3;
                    _patchAddress = intPtr;
                    _innerCodeAddress = intPtr;
                    _innerCodeOriginalBytesFull = MemOps.ReadBytesSafe(intPtr, 32);
                    _originalBytes = Jumper.Install(intPtr, jumpTarget);
                    diag.PatchType = "ResolvedJitCode(12-byte)";
                    diag.InstalledBytes = MemOps.ReadBytesSafe(intPtr, 16);
                }
                else
                {
                    diag.PatchTarget = "None";
                    diag.PatchType = "None(relies on slot replacement)";
                }
            }
        }

        /// <summary>
        /// Attempts to patch the &lt;jit_addr&gt; field in the fixup thunk referenced
        /// by an E9 precode. The fixup thunk has the pattern:
        ///   49 89 D0 48 BA <dict> 48 B8 <jit_addr> FF E0
        /// We overwrite the &lt;jit_addr&gt; field (8 bytes at offset 15) to point to
        /// the hook adapter trampoline. This is a DATA patch (not a code patch),
        /// so it doesn't corrupt the PRESTUB or data structure that &lt;jit_addr&gt;
        /// originally points to.
        /// </summary>
        /// <summary>
        /// Computes the fixup thunk address from an E9 precode. Do NOT use
        /// ResolveRealEntry for this — it follows the entire jump chain
        /// (including the fixup thunk's MOV RAX, &lt;jit_addr&gt;; JMP RAX),
        /// returning the &lt;jit_addr&gt; value instead of the fixup thunk address.
        /// </summary>
        private unsafe IntPtr ResolveFixupThunkFromPrecode(IntPtr precodeAddr)
        {
            if (!Memory.IsReadable(precodeAddr, 5)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)precodeAddr;
                if (p[0] != 0xE9) return IntPtr.Zero;
                int rel32 = *(int*)(p + 1);
                long fixupAddr = precodeAddr.ToInt64() + 5 + rel32;
                if (!Memory.IsReadable(new IntPtr(fixupAddr), 23)) return IntPtr.Zero;
                // Verify fixup thunk pattern (Windows: 49 89 D0 48 BA, Unix: 48 89 F2 48 BE)
                byte* f = (byte*)fixupAddr;
                if (MatchFixupThunkPrefix(f) < 0) return IntPtr.Zero;
                return new IntPtr(fixupAddr);
            }
            catch { return IntPtr.Zero; }
        }

        private unsafe bool TryPatchFixupThunkJitAddr(IntPtr precodeAddr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            if (!Memory.IsReadable(precodeAddr, 5)) return false;
            try
            {
                byte* p = (byte*)precodeAddr;
                if (p[0] != 0xE9) return false;
                int rel32 = *(int*)(p + 1);
                long fixupAddr = precodeAddr.ToInt64() + 5 + rel32;
                if (!Memory.IsReadable(new IntPtr(fixupAddr), 23)) return false;
                byte* f = (byte*)fixupAddr;
                // Check fixup thunk pattern (Windows: 49 89 D0 48 BA, Unix: 48 89 F2 48 BE)
                if (MatchFixupThunkPrefix(f) < 0) return false;
                // The <jit_addr> is at offset 15 (operand of MOV RAX, imm64)
                _fixupJitAddrLoc = new IntPtr(fixupAddr + 15);
                _fixupJitAddrOriginal = new IntPtr(*(long*)(f + 15));
                MemOps.WriteInt64Cell(_fixupJitAddrLoc, jumpTarget.ToInt64());
                _hasFixupJitAddrPatch = true;
                diag.PatchError += "; FixupThunk <jit_addr> patched at 0x" + _fixupJitAddrLoc.ToInt64().ToString("X") + " (orig=0x" + _fixupJitAddrOriginal.ToInt64().ToString("X") + ")";
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks whether the E8/E9 precode at <paramref name="precodeAddr"/> has been
        /// backpatched to point directly to JIT code, or still points to the fixup
        /// thunk (PRESTUB path).
        ///
        /// On .NET Framework 4.x, the precode initially has E9 → fixup thunk. After
        /// the method is called through the precode (first call), the fixup thunk
        /// JIT compiles the method and backpatches the precode to E9 → JIT code.
        ///
        /// If the precode has NOT been backpatched, TryResolveFixupToJitCode would
        /// extract &lt;jit_addr&gt; from the fixup thunk, which may point to a PRESTUB
        /// or data structure rather than real JIT code. Patching this address
        /// corrupts it, causing AccessViolationException.
        /// </summary>
        private unsafe bool IsPrecodeBackpatched(IntPtr precodeAddr)
        {
            if (!Memory.IsReadable(precodeAddr, 5)) return true; // assume backpatched
            byte* p = (byte*)precodeAddr;
            byte op = p[0];
            // Only E8/E9 precodes go through the fixup thunk. Other formats
            // (FF 25, etc.) are handled by different code paths.
            if (op != 0xE9 && op != 0xE8) return true;
            int rel32 = *(int*)(p + 1);
            long target = precodeAddr.ToInt64() + 5 + rel32;
            if (!Memory.IsReadable(new IntPtr(target), 23)) return true;
            byte* t = (byte*)target;
            // The fixup thunk pattern starts with either:
            //   Windows: 49 89 D0 48 BA (MOV R10, RDX; MOV RDX, ...)
            //   Unix:    48 89 F2 48 BE (MOV RDX, RSI; MOV RSI, ...)
            // If the target has either pattern, the precode still points to the fixup
            // thunk. On .NET Framework 4.x, the precode ALWAYS points to the fixup
            // thunk for generic methods — the fixup thunk's <jit_addr> field is what
            // gets updated (not the precode's E9 target). So we check <jit_addr> to
            // determine if the method has been JIT compiled.
            if (MatchFixupThunkPrefix(t) >= 0)
            {
                // Extract <jit_addr> from the fixup thunk (offset 15, after 48 B8 at offset 13)
                if (t[13] == 0x48 && t[14] == 0xB8)
                {
                    long jitAddr = *(long*)(t + 15);
                    if (jitAddr != 0 && Memory.IsReadable(new IntPtr(jitAddr), 16))
                    {
                        byte* jitBytes = (byte*)jitAddr;
                        // A PRESTUB is typically a very short stub (5-10 bytes) that
                        // calls the JIT compiler. Real JIT code starts with a function
                        // prologue. Heuristic: if the first byte is E8 (call) and the
                        // 6th byte is E9 (jmp), it's likely a PRESTUB.
                        bool looksLikePrestub = jitBytes[0] == 0xE8 && jitBytes[5] == 0xE9;
                        return !looksLikePrestub;
                    }
                }
                return false; // can't read jit_addr → assume not backpatched (safe)
            }
            return true; // no fixup pattern → backpatched (points to JIT code)
        }

        private void InstallSecondaryJitPatch(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            try
            {
                // Prefer the target JIT address resolved in Install() BEFORE slot
                // replacement. Calling ResolveRealEntry(targetPtr) here would follow
                // the now-modified MethodTable slot (which points to the hook) and
                // resolve to the HOOK's JIT code — patching that creates an infinite
                // loop. This happens when tiered compilation is disabled (debugger
                // attached / DOTNET_TieredCompilation=0) and precodes are not
                // backpatched, so the fixup helper reads the slot to find the entry.
                IntPtr intPtr = _targetJitCode;
                // Fall back to live resolution only if the saved value is unusable
                // (e.g. .NET Framework 4.x E8 precode where ResolveRealEntry returns
                // the input unchanged, so _targetJitCode == targetPtr).
                if (intPtr == IntPtr.Zero || intPtr == targetPtr)
                {
                    intPtr = MethodEntryResolver.ResolveRealEntry(targetPtr);
                }
                // .NET Framework 4.x E8 precode: ResolveRealEntry treats E8+5E as a
                // precode sentinel and returns without following. Manually follow
                // the E8 rel32 to the fixup code, then extract the JIT code address.
                if (intPtr == targetPtr)
                {
                    unsafe
                    {
                        if (!Memory.IsReadable(targetPtr, 6))
                        {
                            diag.PatchError += "; targetPtr not readable for E8 check";
                            return;
                        }
                        byte* p = (byte*)targetPtr;
                        if (p[0] == 0xE8)
                        {
                            int rel32 = *(int*)(p + 1);
                            long fixupAddr = targetPtr.ToInt64() + 5 + rel32;
                            // Dump fixup code bytes for diagnostics
                            try { diag.Target1Bytes = MemOps.ReadBytesSafe(new IntPtr(fixupAddr), 32); } catch { }
                            IntPtr fixupJit = TryResolveFixupToJitCode(new IntPtr(fixupAddr));
                            if (fixupJit != IntPtr.Zero) intPtr = fixupJit;
                            // For non-generic methods, the fixup code is a CLR helper
                            // without the dictionary setup pattern. Try ResolveRealEntry
                            // on the fixup code address — it scans for 48 B8 <addr> FF E0
                            // (MOV RAX, addr; JMP RAX) within the first 24 bytes.
                            if (intPtr == targetPtr)
                            {
                                IntPtr resolved = MethodEntryResolver.ResolveRealEntry(new IntPtr(fixupAddr));
                                if (resolved != IntPtr.Zero && resolved != new IntPtr(fixupAddr) && LooksLikeRealJitCode(resolved))
                                {
                                    intPtr = resolved;
                                    diag.PatchError += "; E8 fixup resolved=0x" + resolved.ToInt64().ToString("X");
                                }
                            }
                        }
                    }
                }
                // Fallback for .NET Framework 4.x E8 precode: scan the MethodDesc
                // for a JIT code address. After the method is JIT-compiled (by
                // PrepareMethod or a prior call), the MethodDesc's native code slot
                // holds the JIT code address. The exact offset varies by MethodDesc
                // type, so scan all 8-byte aligned values in the first 64 bytes.
                if (intPtr == targetPtr)
                {
                    IntPtr mdJit = ScanMethodDescForJitCode(_targetMethod.MethodHandle.Value, targetPtr);
                    if (mdJit != IntPtr.Zero)
                    {
                        intPtr = mdJit;
                        _targetJitCode = intPtr;
                        diag.PatchError += "; MethodDesc JIT=0x" + mdJit.ToInt64().ToString("X");
                    }
                }
                if (intPtr == IntPtr.Zero || intPtr == targetPtr)
                {
                    diag.PatchError += "; cannot resolve JIT entry for secondary patch";
                    return;
                }
                // Safety guard: if the resolved JIT address equals the jump target
                // (the hook's entry / adapter trampoline), we would be patching the
                // hook's own code with an E9 jump to itself — an infinite loop.
                // This can happen when ResolveRealEntry follows the fixup chain to
                // the hook. Skip the secondary patch entirely in that case; the
                // precode + slot patches are sufficient to redirect calls.
                if (intPtr == jumpTarget)
                {
                    diag.PatchError += "; skipped secondary JIT patch: resolved addr == jumpTarget (infinite loop guard)";
                    return;
                }
                // On .NET Framework 4.x, the resolved entry may be the "fixup code" that
                // sets up the generic dictionary and jumps to the real JIT code.
                // Pattern: 49 89 D0 48 BA <dict> 48 B8 <jit_addr> FF E0
                // If detected, extract the real JIT code address from the 48 B8 operand.
                IntPtr realJit = TryResolveFixupToJitCode(intPtr);
                if (realJit != IntPtr.Zero && realJit != intPtr)
                {
                    diag.PatchError += "; resolved fixup code -> real JIT at 0x" + realJit.ToInt64().ToString("X");
                    intPtr = realJit;
                }
                InstallSecondaryJitPatchAt(intPtr, jumpTarget, diag);
            }
            catch (Exception ex)
            {
                diag.PatchError = diag.PatchError + "; SecondaryJitPatch error: " + ex.Message;
            }
        }

        /// <summary>
        /// Scans the MethodDesc for a JIT code address. On .NET Framework 4.x,
        /// after the method is JIT-compiled (by PrepareMethod or a prior call),
        /// the MethodDesc's native code slot holds the JIT code address. The exact
        /// offset varies by MethodDesc type (typical offsets: 8, 16, 24, 32), so
        /// we scan all 8-byte aligned values in the first 64 bytes and return the
        /// first one that looks like real JIT code (validated by LooksLikeRealJitCode).
        /// The precode address is excluded to avoid false positives.
        /// </summary>
        private unsafe IntPtr ScanMethodDescForJitCode(IntPtr methodDesc, IntPtr precodeAddr)
        {
            if (methodDesc == IntPtr.Zero) return IntPtr.Zero;
            if (!Memory.IsReadable(methodDesc, 64)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)methodDesc;
                for (int i = 0; i <= 56; i += 8)
                {
                    long val = *(long*)(p + i);
                    if (val == 0) continue;
                    // Skip the precode address itself
                    if (val == precodeAddr.ToInt64()) continue;
                    IntPtr addr = new IntPtr(val);
                    if (LooksLikeRealJitCode(addr))
                    {
                        return addr;
                    }
                }
                return IntPtr.Zero;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        /// <summary>
        /// Detects the CoreCLR generic method fixup code pattern and extracts
        /// the real JIT code address from it. Recognizes both Windows and Unix
        /// x64 patterns:
        ///   Windows: 49 89 D0 | 48 BA <8-byte dict> | 48 B8 <8-byte jit_addr> | FF E0
        ///   Unix:    48 89 F2 | 48 BE <8-byte dict> | 48 B8 <8-byte jit_addr> | FF E0
        /// The JIT code address is at offset 15 (after 48 B8 at offset 13) in both.
        /// </summary>
        private unsafe IntPtr TryResolveFixupToJitCode(IntPtr addr)
        {
            if (addr == IntPtr.Zero) return IntPtr.Zero;
            // In .NET 6+, AV from unmapped memory is uncatchable. Check readability.
            if (!Memory.IsReadable(addr, 23)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)addr;
                if (MatchFixupThunkPrefix(p) < 0) return IntPtr.Zero;
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
        /// Checks whether the bytes at <paramref name="addr"/> look like real JIT
        /// code (function prologue) rather than a PRESTUB or data structure.
        ///
        /// A PRESTUB on .NET Framework 4.x typically starts with E8 (CALL) followed
        /// by E9 (JMP) at byte 5. Real JIT code starts with a function prologue:
        /// push reg (50-57), sub rsp (48 83 EC), mov [rsp+xx], reg (48 89 .. 24),
        /// or similar. Data structures (e.g. MethodDesc pointers) have arbitrary
        /// byte patterns that typically don't match a prologue.
        ///
        /// This is used to decide whether to patch the address directly with a
        /// 5-byte E9 jump. Patching a PRESTUB or data structure would corrupt it
        /// and cause AccessViolationException.
        /// </summary>
        private unsafe bool LooksLikeRealJitCode(IntPtr addr)
        {
            if (addr == IntPtr.Zero) return false;
            if (!Memory.IsReadable(addr, 16)) return false;
            try
            {
                byte* p = (byte*)addr;
                byte b0 = p[0];
                byte b1 = p[1];
                // PRESTUB pattern: E8 <rel32> E9 <rel32> (call helper, then jmp)
                if (b0 == 0xE8 && p[5] == 0xE9) return false;
                // Another PRESTUB variant: starts with E8 or E9 (call/jmp to helper)
                if (b0 == 0xE8 || b0 == 0xE9) return false;
                // Fixup helper pattern: 48 B8 <imm64> FF E0 (MOV RAX, addr; JMP RAX)
                // This is NOT JIT code — it's the precode fixup thunk that calls
                // Prestub. On .NET 8+, PrepareMethod may NOT backpatch the precode,
                // leaving target1 pointing to this fixup helper. If we mistake it
                // for JIT code, we use it as the jump target, which can cause
                // infinite loops or silent failures on .NET 8.
                if (b0 == 0x48 && b1 == 0xB8 && Memory.IsReadable(addr, 12))
                {
                    if (p[10] == 0xFF && p[11] == 0xE0) return false;  // JMP RAX
                }
                // Fixup helper variant: 49 B8 <imm64> 41 FF E0 (MOV R8, addr; JMP R8)
                if (b0 == 0x49 && b1 == 0xB8 && Memory.IsReadable(addr, 13))
                {
                    if (p[10] == 0x41 && p[11] == 0xFF && p[12] == 0xE0) return false;
                }
                // Common x64 function prologues:
                // 48 83 EC xx     SUB RSP, imm8
                // 48 81 EC xx..   SUB RSP, imm32
                // 48 89 5C 24 xx  MOV [RSP+xx], RBX
                // 4C 8B DC        MOV R11, RSP
                // 41 57           PUSH R15 (REX.B + 0x57)
                // 41 56           PUSH R14 (REX.B + 0x56)
                // All REX prefixes (0x40-0x4F) can start a function prologue.
                if (b0 >= 0x40 && b0 <= 0x4F) return true;  // REX prefix
                // PUSH reg (50-57): only valid as prologue if followed by another
                // PUSH or a REX prefix. A lone 50 followed by a non-prologue byte
                // is likely a DATA structure (e.g. pointer starting with 0x50).
                if (b0 >= 0x50 && b0 <= 0x57)
                {
                    if (b1 >= 0x50 && b1 <= 0x57) return true;  // another PUSH
                    if (b1 >= 0x40 && b1 <= 0x4F) return true;  // any REX prefix
                    return false;  // likely DATA structure
                }
                // Some JIT code starts with MOV or LEA
                if (b0 == 0x8B || b0 == 0x8D) return true;
                // If not recognized, be conservative — don't patch
                return false;
            }
            catch
            {
                return false;
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

        /// <summary>
        /// On .NET Framework 4.x x64, generic methods pass the generic dictionary
        /// in RDX (instance) or RCX (static), shifting user arguments one register
        /// position to the right. When a direct call site hits the secondary JIT
        /// patch and is redirected to the hook (non-generic, standard convention),
        /// the hook receives the generic dictionary pointer as its first user
        /// parameter — corrupting the call and causing AccessViolationException.
        ///
        /// An adapter trampoline is needed to shift registers from the generic
        /// calling convention back to the standard convention before jumping to
        /// the hook. On BOTH .NET Framework 4.x and .NET 6+ x64, generic methods
        /// pass the generic dictionary in RDX (instance) or RCX (static), which
        /// shifts user arguments to R8/R9/[stack]. Without this adapter, the hook
        /// receives the generic dictionary pointer as its first user argument
        /// instead of the real argument, causing parameter capture failures.
        /// (The precode on .NET 6+ also sets R10 via `49 BA`, but RDX still
        /// carries the generic dictionary at JIT entry, so the adapter is needed.)
        /// </summary>
        private bool NeedsGenericAdapter()
        {
            return Platform.Current == Platform.Arch.X64
                && _needsGenericAdapter;
        }

        /// <summary>
        /// Determines whether a value-type adapter trampoline is needed.
        ///
        /// On x64, instance methods on value types (structs) receive 'this' as a
        /// managed pointer (byref) in RCX — i.e., RCX = &amp;T. However, a static
        /// hook method with signature Hook(T self) expects the value by-value in
        /// RCX. Without an adapter, the hook receives the pointer value interpreted
        /// as struct data — producing garbage.
        ///
        /// The adapter dereferences the pointer: MOV RCX, [RCX], converting
        /// byref → byval. Only supported for structs ≤ 8 bytes (single register).
        /// </summary>
        private bool NeedsValueTypeAdapter()
        {
            if (Platform.Current != Platform.Arch.X64)
                return false;
            if (_targetMethod.IsStatic || _targetMethod.IsGenericMethod)
                return false;
            Type declaringType = _targetMethod.DeclaringType;
            if (declaringType == null || !declaringType.IsValueType)
                return false;
            // The hook method's first parameter must be the value type by-value
            // (not by-ref). If the user declared it as ref T, no adapter is needed.
            ParameterInfo[] hookParams = _hookMethod.GetParameters();
            if (hookParams.Length == 0)
                return false;
            Type firstParamType = hookParams[0].ParameterType;
            if (firstParamType.IsByRef)
                return false; // user used ref T — byref passes directly, no adapter
            if (firstParamType != declaringType)
                return false; // first param doesn't match declaring type
            // Only support structs that fit in 8 bytes (one register).
            // Use GetManagedSize instead of Marshal.SizeOf because DateTime and
            // other structs with LayoutKind.Auto cause Marshal.SizeOf to throw.
            return GetManagedSize(declaringType) <= 8;
        }

        /// <summary>
        /// Computes the managed size of a value type by summing its instance field
        /// sizes. Unlike Marshal.SizeOf, this works for structs with LayoutKind.Auto
        /// (e.g., DateTime) which cause Marshal.SizeOf to throw on some runtimes.
        /// Does not account for explicit layout padding; sufficient for the ≤ 8
        /// byte check in NeedsValueTypeAdapter.
        /// </summary>
        private static int GetManagedSize(Type type)
        {
            if (!type.IsValueType) return IntPtr.Size;
            if (type == typeof(byte) || type == typeof(sbyte)) return 1;
            if (type == typeof(short) || type == typeof(ushort) || type == typeof(char)) return 2;
            if (type == typeof(int) || type == typeof(uint) || type == typeof(float)) return 4;
            if (type == typeof(long) || type == typeof(ulong) || type == typeof(double)) return 8;
            if (type == typeof(bool)) return 1;
            if (type == typeof(IntPtr) || type == typeof(UIntPtr)) return IntPtr.Size;
            if (type.IsEnum) return GetManagedSize(Enum.GetUnderlyingType(type));
            // Sum instance field sizes for nested structs
            int size = 0;
            FieldInfo[] fields = type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
            foreach (FieldInfo f in fields)
            {
                size += GetManagedSize(f.FieldType);
            }
            return size;
        }

        /// <summary>
        /// Builds x64 adapter code that dereferences the 'this' pointer for
        /// value-type instance methods, converting byref → byval.
        ///
        /// Windows x64: 'this' is in RCX → MOV RCX, [RCX]  (48 8B 09)
        /// Unix x64:    'this' is in RDI → MOV RDI, [RDI]  (48 8B 3F)
        ///
        /// Only touches the 'this' register; all other argument registers are
        /// preserved, so methods with additional parameters work correctly.
        /// </summary>
        private static byte[] BuildValueTypeAdapterBytes()
        {
            if (Platform.IsUnix)
            {
                // 48 8B 3F = MOV RDI, [RDI]  (REX.W + MOV r64, [r/m64])
                return new byte[] { 0x48, 0x8B, 0x3F };
            }
            // 48 8B 09 = MOV RCX, [RCX]  (REX.W + MOV r64, [r/m64])
            return new byte[] { 0x48, 0x8B, 0x09 };
        }

        /// <summary>
        /// Builds x64 register-shift code that converts from the CoreCLR generic
        /// calling convention to the standard managed calling convention.
        ///
        /// Windows x64 (RCX=this, RDX=dict for instance; RCX=dict for static):
        ///   Instance: RCX=this(kept), RDX=dict(drop), R8=arg1, R9=arg2, [RSP+0x28]=arg3
        ///     → RCX=this, RDX=arg1, R8=arg2, R9=arg3
        ///   Static: RCX=dict(drop), RDX=arg1, R8=arg2, R9=arg3, [RSP+0x28]=arg4
        ///     → RCX=arg1, RDX=arg2, R8=arg3, R9=arg4
        ///
        /// Unix x64 / System V AMD64 (RDI=this, RSI=dict for instance; RDI=dict for static):
        ///   Instance: RDI=this(kept), RSI=dict(drop), RDX=arg1, RCX=arg2, R8=arg3,
        ///             R9=arg4, [RSP+8]=arg5
        ///     → RDI=this, RSI=arg1, RDX=arg2, RCX=arg3, R8=arg4, R9=arg5
        ///   Static: RDI=dict(drop), RSI=arg1, RDX=arg2, RCX=arg3, R8=arg4, R9=arg5,
        ///           [RSP+8]=arg6
        ///     → RDI=arg1, RSI=arg2, RDX=arg3, RCX=arg4, R8=arg5, R9=arg6
        ///
        /// Stack offset: Windows uses 0x28 (32-byte shadow space + 8-byte ret addr);
        /// Unix uses 0x08 (8-byte ret addr, no shadow space).
        /// </summary>
        private static byte[] BuildGenericAdapterBytes(bool isStatic, int userParamCount)
        {
            var bytes = new List<byte>();
            if (Platform.IsUnix)
            {
                // Unix x64 (System V AMD64): dict in RSI (instance) or RDI (static)
                byte stackOff = 0x08; // no shadow space on System V
                if (isStatic)
                {
                    // Dict in RDI; shift: RDI←RSI, RSI←RDX, RDX←RCX, RCX←R8, R8←R9
                    if (userParamCount >= 1)
                        bytes.AddRange(new byte[] { 0x48, 0x89, 0xF7 });       // MOV RDI, RSI
                    if (userParamCount >= 2)
                        bytes.AddRange(new byte[] { 0x48, 0x89, 0xD6 });       // MOV RSI, RDX
                    if (userParamCount >= 3)
                        bytes.AddRange(new byte[] { 0x48, 0x89, 0xCA });       // MOV RDX, RCX
                    if (userParamCount >= 4)
                        bytes.AddRange(new byte[] { 0x4C, 0x89, 0xC1 });       // MOV RCX, R8
                    if (userParamCount >= 5)
                        bytes.AddRange(new byte[] { 0x4D, 0x89, 0xC8 });       // MOV R8, R9
                    if (userParamCount >= 6)
                        bytes.AddRange(new byte[] { 0x4C, 0x8B, 0x4C, 0x24, stackOff }); // MOV R9, [RSP+0x08]
                }
                else
                {
                    // Dict in RSI (this stays in RDI); shift: RSI←RDX, RDX←RCX, RCX←R8, R8←R9
                    if (userParamCount >= 1)
                        bytes.AddRange(new byte[] { 0x48, 0x89, 0xD6 });       // MOV RSI, RDX
                    if (userParamCount >= 2)
                        bytes.AddRange(new byte[] { 0x48, 0x89, 0xCA });       // MOV RDX, RCX
                    if (userParamCount >= 3)
                        bytes.AddRange(new byte[] { 0x4C, 0x89, 0xC1 });       // MOV RCX, R8
                    if (userParamCount >= 4)
                        bytes.AddRange(new byte[] { 0x4D, 0x89, 0xC8 });       // MOV R8, R9
                    if (userParamCount >= 5)
                        bytes.AddRange(new byte[] { 0x4C, 0x8B, 0x4C, 0x24, stackOff }); // MOV R9, [RSP+0x08]
                }
            }
            else
            {
                // Windows x64: dict in RDX (instance) or RCX (static)
                if (isStatic)
                {
                    // Generic dict is in RCX; shift user args left: RCX←RDX, RDX←R8, R8←R9
                    if (userParamCount >= 1)
                        bytes.AddRange(new byte[] { 0x48, 0x89, 0xD1 });       // MOV RCX, RDX
                    if (userParamCount >= 2)
                        bytes.AddRange(new byte[] { 0x4C, 0x89, 0xC2 });       // MOV RDX, R8
                    if (userParamCount >= 3)
                        bytes.AddRange(new byte[] { 0x4D, 0x89, 0xC8 });       // MOV R8, R9
                    if (userParamCount >= 4)
                        bytes.AddRange(new byte[] { 0x4C, 0x8B, 0x4C, 0x24, 0x28 }); // MOV R9, [RSP+0x28]
                }
                else
                {
                    // Generic dict is in RDX (this stays in RCX); shift: RDX←R8, R8←R9
                    if (userParamCount >= 1)
                        bytes.AddRange(new byte[] { 0x4C, 0x89, 0xC2 });       // MOV RDX, R8
                    if (userParamCount >= 2)
                        bytes.AddRange(new byte[] { 0x4D, 0x89, 0xC8 });       // MOV R8, R9
                    if (userParamCount >= 3)
                        bytes.AddRange(new byte[] { 0x4C, 0x8B, 0x4C, 0x24, 0x28 }); // MOV R9, [RSP+0x28]
                }
            }
            return bytes.ToArray();
        }

        private void InstallSecondaryJitPatchAt(IntPtr intPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            try
            {
                if (intPtr == IntPtr.Zero)
                {
                    diag.PatchError += "; cannot patch null JIT entry";
                    return;
                }
                // Defense-in-depth: never patch the hook's own entry point.
                // This would create an E9 jump from the hook to itself — an
                // infinite loop that hangs the process.
                if (intPtr == jumpTarget)
                {
                    diag.PatchError += "; skipped InstallSecondaryJitPatchAt: intPtr == jumpTarget (infinite loop guard)";
                    return;
                }
                diag.JitCodeAddr = intPtr;
                diag.JitCodeOriginalBytes = MemOps.ReadBytesSafe(intPtr, 32);
                // Save the full 32-byte copy BEFORE the 5-byte E9 patch is applied.
                // Used by the call-original trampoline to copy/relocate the prologue.
                _secondaryJitOriginalBytesFull = diag.JitCodeOriginalBytes;

                // The adapter (register shift for generic calling convention) is now
                // built once in Install() and included in jumpTarget. This trampoline
                // just needs to jump to jumpTarget.
                int trampolineSize = 12; // MOV RAX,imm64; JMP RAX

                IntPtr trampoline = Memory.AllocExecNear(intPtr, trampolineSize);
                if (trampoline == IntPtr.Zero || trampoline == new IntPtr(-1))
                {
                    diag.PatchError += "; failed to allocate near trampoline for JIT patch";
                    return;
                }
                // Trampoline: MOV RAX, jumpTarget; JMP RAX
                byte[] jumpBytes = Jumper.BuildAbsJumpX64(jumpTarget);
                MemOps.WriteBytes(trampoline, jumpBytes);

                // Patch JIT code with 5-byte relative jump to trampoline
                _secondaryJitAddress = intPtr;
                int patchSize = 5;
                _secondaryJitOriginalBytes = MemOps.ReadBytes(intPtr, patchSize);
                byte[] patch = Jumper.BuildRelJump(intPtr, trampoline);
                // Build diagnostic string BEFORE patching to avoid triggering hook via String.Format
                string diagMsg = "; SecondaryJitPatch(5-byte) at 0x" + intPtr.ToInt64().ToString("X") + " -> tramp 0x" + trampoline.ToInt64().ToString("X");
                MemOps.WriteBytesProtected(intPtr, patch);
                _hasSecondaryPatch = true;
                _secondaryTrampoline = trampoline;
                diag.JitCodePatchedBytes = MemOps.ReadBytesSafe(intPtr, 16);
                diag.PatchError += diagMsg;
            }
            catch (Exception ex)
            {
                diag.PatchError = diag.PatchError + "; SecondaryJitPatch error: " + ex.Message;
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
                    diag.PatchError += "; targetPtr not readable for x86 secondary patch";
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
                    diag.PatchError += "; cannot resolve fixup code for x86 secondary patch";
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
                    diag.PatchError += "; cannot resolve JIT entry for x86 secondary patch";
                    return;
                }

                // Safety guard: if the resolved JIT address equals the jump target,
                // patching it would create an infinite loop. Skip the secondary patch.
                if (jitAddr == jumpTarget)
                {
                    diag.PatchError += "; skipped x86 secondary JIT patch: resolved addr == jumpTarget (infinite loop guard)";
                    return;
                }

                diag.JitCodeAddr = jitAddr;
                diag.JitCodeOriginalBytes = MemOps.ReadBytesSafe(jitAddr, 32);

                // Patch JIT code with 5-byte E9 relative jump (no trampoline needed on x86)
                _secondaryJitAddress = jitAddr;
                _secondaryJitOriginalBytes = MemOps.ReadBytes(jitAddr, 5);
                byte[] patch = Jumper.BuildRelJump(jitAddr, jumpTarget);
                MemOps.WriteBytesProtected(jitAddr, patch);
                _hasSecondaryPatch = true;
                _secondaryTrampoline = IntPtr.Zero; // no trampoline on x86
                diag.JitCodePatchedBytes = MemOps.ReadBytesSafe(jitAddr, 16);
                diag.PatchError += "; SecondaryJitPatchX86(5-byte) at 0x" + jitAddr.ToInt32().ToString("X");
            }
            catch (Exception ex)
            {
                diag.PatchError = diag.PatchError + "; SecondaryJitPatchX86 error: " + ex.Message;
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
                // Read the fixup code to extract the inner code address.
                // The fixup thunk prefix is either:
                //   Windows: 49 89 D0 48 BA <dict> 48 B8 <jit_addr> ...
                //   Unix:    48 89 F2 48 BE <dict> 48 B8 <jit_addr> ...
                // On .NET 8, it ends with FF E0 (JMP RAX). On .NET Framework 4.x,
                // it may have additional instructions after <jit_addr> (e.g. 48 8B ...).
                // We only require the prefix pattern to extract <jit_addr> at offset 15.
                byte[] fixupBytes = MemOps.ReadBytesSafe(target1Addr, 25);
                IntPtr innerCodeAddr = IntPtr.Zero;
                bool patternMatch = false;
                if (fixupBytes != null && fixupBytes.Length >= 23)
                {
                    fixed (byte* fb = fixupBytes)
                        patternMatch = MatchFixupThunkPrefix(fb) >= 0;
                }
                if (!patternMatch && fixupBytes != null)
                {
                    diag.PatchError += "; FixupThunk bytes: " + BitConverter.ToString(fixupBytes) + " (pattern mismatch)";
                }
                if (patternMatch)
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
                        //
                        // CRITICAL: Only accept the resolved address if it is
                        // READABLE and looks like JIT code. On .NET 8 without
                        // warmup, tiered promotion may have deallocated the tier-0
                        // JIT code — ResolveRealEntry follows the jump chain to
                        // the now-unmapped tier-0 address. Using that address
                        // causes InnerBytes=[null] looksJit=False, and the hook
                        // is never triggered. The warmup in EnsureJitCompiled
                        // should prevent this, but we validate defensively.
                        IntPtr realJit = MethodEntryResolver.ResolveRealEntry(innerCodeAddr);
                        if (realJit != IntPtr.Zero && realJit != innerCodeAddr
                            && Memory.IsReadable(realJit, 16) && LooksLikeRealJitCode(realJit))
                        {
                            diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; ResolvedInner->RealJit 0x" + realJit.ToInt64().ToString("X");
                            innerCodeAddr = realJit;
                        }
                        else if (realJit != IntPtr.Zero && realJit != innerCodeAddr)
                        {
                            diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; ResolvedInner->RealJit 0x" + realJit.ToInt64().ToString("X") + " UNREADABLE/skipped";
                        }
                        // On .NET Framework 4.x, <jit_addr> may point to a DATA
                        // structure (8-byte pointer to JIT code) rather than JIT
                        // code directly. If the resolved address doesn't look like
                        // JIT code, try dereferencing it (read the first 8 bytes as
                        // a pointer to the real JIT code).
                        if (!LooksLikeRealJitCode(innerCodeAddr))
                        {
                            try
                            {
                                if (Memory.IsReadable(innerCodeAddr, 8))
                                {
                                    long deref = Marshal.ReadInt64(innerCodeAddr);
                                    IntPtr derefPtr = new IntPtr(deref);
                                    if (deref != 0 && LooksLikeRealJitCode(derefPtr))
                                    {
                                        diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; DerefData->Jit 0x" + deref.ToString("X");
                                        innerCodeAddr = derefPtr;
                                    }
                                }
                            }
                            catch { }
                        }
                        // On .NET 8+, after tiered promotion, the fixup thunk's
                        // jit_addr may point to a STALE precode that references
                        // deallocated tier-0 code (unreadable). The REAL tier-1
                        // JIT code address was saved in _targetJitCode by Install()
                        // (resolved via ScanMethodDescForJitCode BEFORE slot
                        // replacement patched the MethodDesc). Use it as a fallback.
                        if (!LooksLikeRealJitCode(innerCodeAddr))
                        {
                            if (_targetJitCode != IntPtr.Zero && _targetJitCode != _precodeAddr
                                && Memory.IsReadable(_targetJitCode, 16)
                                && LooksLikeRealJitCode(_targetJitCode))
                            {
                                diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; TargetJitCode->Jit 0x" + _targetJitCode.ToInt64().ToString("X");
                                innerCodeAddr = _targetJitCode;
                            }
                            else
                            {
                                diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; TargetJitCode unusable (0x" + _targetJitCode.ToInt64().ToString("X") + ")";
                            }
                        }
                    }
                }

                // Patch target1 (fixup thunk) with 12-byte absolute jump to hook
                if (!Memory.IsReadable(target1Addr, 12))
                {
                    diag.PatchError += "; target1Addr not readable for patch";
                    return;
                }
                _target1Address = target1Addr;
                _target1OriginalBytes = MemOps.ReadBytes(target1Addr, 12);
                byte[] patch = Jumper.BuildAbsJumpX64(jumpTarget);
                MemOps.WriteBytesProtected(target1Addr, patch);
                _hasTarget1Patch = true;
                diag.PatchError += "; Target1Patch(12-byte) at 0x" + target1Addr.ToInt64().ToString("X");

                // Also patch the inner code address (the address the fixup code jumps to)
                if (innerCodeAddr != IntPtr.Zero)
                {
                    try
                    {
                        byte[] innerBytes = MemOps.ReadBytesSafe(innerCodeAddr, 16);
                        bool looksJit = LooksLikeRealJitCode(innerCodeAddr);
                        diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; InnerCode@0x" + innerCodeAddr.ToInt64().ToString("X") + " looksJit=" + looksJit;
                        // Only patch if it looks like JIT code (not already patched,
                        // and not a DATA structure). On .NET Framework 4.x, <jit_addr>
                        // may point to a DATA structure — patching it corrupts memory.
                        if (innerBytes != null && innerBytes.Length >= 12 &&
                            (innerBytes[0] != 0x48 || innerBytes[1] != 0xB8) &&
                            looksJit)
                        {
                            _innerCodeAddress = innerCodeAddr;
                            _innerCodeOriginalBytes = MemOps.ReadBytes(innerCodeAddr, 12);
                            // Save a larger copy for the call-original trampoline.
                            // Must be read BEFORE patching. The trampoline needs enough
                            // bytes to cover the 12-byte patch and reach an instruction
                            // boundary (which may be > 12 bytes).
                            _innerCodeOriginalBytesFull = MemOps.ReadBytesSafe(innerCodeAddr, 32);
                            byte[] innerPatch = Jumper.BuildAbsJumpX64(jumpTarget);
                            MemOps.WriteBytesProtected(innerCodeAddr, innerPatch);
                            _hasInnerCodePatch = true;
                            diag.PatchError += "; InnerCodePatch(12-byte) at 0x" + innerCodeAddr.ToInt64().ToString("X");
                        }
                        else
                        {
                            diag.PatchError += "; InnerCodePatch SKIPPED (conditions not met)";
                        }
                    }
                    catch (Exception ex)
                    {
                        diag.PatchError += "; InnerCodePatch error: " + ex.Message;
                    }
                }
                else
                {
                    diag.PatchError += "; InnerCodePatch SKIPPED (innerCodeAddr=Zero)";
                }
            }
            catch (Exception ex)
            {
                diag.PatchError = diag.PatchError + "; Target1Patch error: " + ex.Message;
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
                    diag.PatchError += "; target2Loc not readable";
                    return;
                }
                IntPtr originalTarget2 = new IntPtr(*(long*)target2Loc);
                _target2Loc = target2LocPtr;
                _target2OriginalValue = originalTarget2;
                MemOps.WriteInt64Cell(target2LocPtr, jumpTarget.ToInt64());
                _hasTarget2Patch = true;
                diag.PatchError += "; Target2Patch(data cell) at 0x" + target2LocPtr.ToInt64().ToString("X") + " orig=0x" + originalTarget2.ToInt64().ToString("X");
            }
            catch (Exception ex)
            {
                diag.PatchError = diag.PatchError + "; Target2Patch error: " + ex.Message;
            }
        }

        /// <summary>
        /// Re-applies patches at a new precode address after tiered promotion
        /// replaces the precode DURING Install(). This avoids the state corruption
        /// caused by Uninstall→Install retries.
        ///
        /// Reads the new precode's FF 25 instructions to find the new target1/target2
        /// data cells, patches them to point to the hook, and updates internal state
        /// (_precodeAddr, _indirectTargetLoc, _target1Address, _target2Loc, etc.)
        /// so that Uninstall and CallOriginal work correctly with the new addresses.
        ///
        /// Also re-scans MethodDesc/MethodTable slots for the new precode address
        /// and patches them to point to the hook.
        ///
        /// Returns true if the re-patch was applied successfully.
        /// </summary>
        private unsafe bool RepatchAtNewPrecode(IntPtr newPrecode, IntPtr oldPrecode, HookDiagInfo diag)
        {
            try
            {
                if (!Memory.IsReadable(newPrecode, 20))
                {
                    diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; Repatch: newPrecode not readable";
                    return false;
                }
                byte* ptr = (byte*)newPrecode;
                if (ptr[0] != 0xFF || ptr[1] != 0x25)
                {
                    diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; Repatch: newPrecode not FF 25";
                    return false;
                }

                IntPtr jumpTarget = _newSlotValue;
                bool isFixupPrecode = ptr[6] == 0x4C && ptr[7] == 0x8B && ptr[8] == 0x15
                    && ptr[13] == 0xFF && ptr[14] == 0x25;

                // 1. Patch the new target1 data cell (FF 25 1st indirect target).
                int disp1 = *(int*)(ptr + 2);
                long newTarget1Loc = newPrecode.ToInt64() + 6 + disp1;
                if (!Memory.IsReadable(new IntPtr(newTarget1Loc), 8))
                {
                    diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; Repatch: target1Loc not readable";
                    return false;
                }
                IntPtr newTarget1Value = new IntPtr(*(long*)newTarget1Loc);

                // Update _indirectTargetLoc and _originalIndirectTarget for the
                // new precode. The old values are kept for restoring the OLD
                // precode during Uninstall (though the old precode is no longer
                // used after tiered promotion, restoring it is still correct).
                _indirectTargetLoc = new IntPtr(newTarget1Loc);
                _originalIndirectTarget = newTarget1Value;
                MemOps.WriteInt64Cell(_indirectTargetLoc, jumpTarget.ToInt64());
                _hasIndirectPatch = true;
                _precodeAddr = newPrecode;

                // 2. For FixupPrecode (generic methods), also patch target1
                //    fixup code (12-byte abs jump) and target2 data cell.
                if (isFixupPrecode && _needsGenericAdapter)
                {
                    // Patch target1 fixup code with 12-byte absolute jump.
                    // The fixup code address is the value stored in the target1
                    // data cell (BEFORE we patched it above).
                    if (newTarget1Value != IntPtr.Zero && Memory.IsReadable(newTarget1Value, 12))
                    {
                        // Save old target1 patch state for Uninstall (the old
                        // target1 address is no longer used, but Uninstall needs
                        // to restore SOMETHING — we'll just skip restoring the
                        // old target1 since it's orphaned).
                        _target1Address = newTarget1Value;
                        _target1OriginalBytes = MemOps.ReadBytes(newTarget1Value, 12);
                        byte[] patch = Jumper.BuildAbsJumpX64(jumpTarget);
                        MemOps.WriteBytesProtected(newTarget1Value, patch);
                        _hasTarget1Patch = true;
                        diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; Repatch: Target1Patch at 0x" + newTarget1Value.ToInt64().ToString("X");
                    }

                    // Patch target2 data cell.
                    int disp3 = *(int*)(ptr + 15);
                    long newTarget2Loc = newPrecode.ToInt64() + 19 + disp3;
                    if (Memory.IsReadable(new IntPtr(newTarget2Loc), 8))
                    {
                        IntPtr newTarget2Value = new IntPtr(*(long*)newTarget2Loc);
                        _target2Loc = new IntPtr(newTarget2Loc);
                        _target2OriginalValue = newTarget2Value;
                        MemOps.WriteInt64Cell(_target2Loc, jumpTarget.ToInt64());
                        _hasTarget2Patch = true;
                        diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; Repatch: Target2Patch at 0x" + new IntPtr(newTarget2Loc).ToInt64().ToString("X");
                    }
                }

                // 3. Re-scan MethodDesc/MethodTable for slots containing the new
                //    precode address and patch them to point to the hook.
                try
                {
                    IntPtr methodDesc = _targetMethod.MethodHandle.Value;
                    IntPtr methodTable = IntPtr.Zero;
                    Type declaringType = _targetMethod.DeclaringType;
                    if (declaringType != null)
                    {
                        methodTable = declaringType.TypeHandle.Value;
                    }
                    IntPtr mdForScan = !_needsGenericAdapter ? methodDesc : IntPtr.Zero;
                    var newSlots = SlotPatcher.FindSlots(mdForScan, methodTable, newPrecode);
                    if (!_needsGenericAdapter && methodDesc != IntPtr.Zero)
                    {
                        long mdStart = methodDesc.ToInt64();
                        long mdEnd = mdStart + 128;
                        newSlots = newSlots.FindAll(s =>
                        {
                            long a = s.ToInt64();
                            return a < mdStart || a >= mdEnd;
                        });
                    }
                    foreach (IntPtr slot in newSlots)
                    {
                        if (_slotAddresses == null) _slotAddresses = new List<IntPtr>();
                        if (!_slotAddresses.Contains(slot))
                        {
                            _slotAddresses.Add(slot);
                            if (_originalSlotValues == null)
                                _originalSlotValues = new List<IntPtr>();
                            _originalSlotValues.Add(newPrecode); // original = new precode addr
                            SlotPatcher.ReplaceSlot(slot, jumpTarget);
                            diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; Repatch: slot at 0x" + slot.ToInt64().ToString("X");
                        }
                    }
                }
                catch (Exception ex)
                {
                    diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; Repatch: slot scan error: " + ex.Message;
                }

                diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; Repatch: SUCCESS at 0x" + newPrecode.ToInt64().ToString("X");
                return true;
            }
            catch (Exception ex)
            {
                diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; Repatch: EXCEPTION: " + ex.Message;
                return false;
            }
        }

        private unsafe void InstallCodePatchX86(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
        {
            if (!Memory.IsReadable(targetPtr, 20))
            {
                diag.PatchError += "; targetPtr not readable for x86 code patch";
                return;
            }
            byte* ptr = (byte*)targetPtr;
            byte b = *ptr;
            byte b2 = ptr[1];
            if (b == 0xFF && b2 == 0x25)
            {
                int num = *(int*)(ptr + 2);
                _patchType = 1;
                _patchAddress = targetPtr;
                _indirectTargetLoc = new IntPtr(num);
                if (!Memory.IsReadable(new IntPtr(num), 4))
                {
                    diag.PatchError += "; FF 25 indirect target not readable x86";
                    return;
                }
                _originalIndirectTarget = new IntPtr(*(int*)num);
                MemOps.WriteInt32Cell(_indirectTargetLoc, jumpTarget.ToInt32());
                diag.PatchType = "Indirect(FF 25) x86";
                diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, 16);
            }
            else if (b == 0xE8 || b == 0xE9)
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
                _originalBytes = MemOps.ReadBytes(targetPtr, 5);
                byte[] array = Jumper.BuildJump(targetPtr, jumpTarget);
                MemOps.WriteBytesProtected(targetPtr, array);
                diag.PatchType = ((b == 0xE8) ? "FixupPrecode(E8->E9) x86" : "DirectJump(E9) x86");
                diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, 16);
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
                    diag.InstalledBytes = MemOps.ReadBytesSafe(jitAddr, 16);
                }
                else
                {
                    // Fallback: patch the precode itself
                    _patchType = 3;
                    _patchAddress = targetPtr;
                    _originalBytes = Jumper.Install(targetPtr, jumpTarget);
                    diag.PatchType = "B8Precode(fallback 5-byte) x86";
                    diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, 16);
                }
            }
            else if (!MethodEntryResolver.IsJump(targetPtr))
            {
                _patchType = 3;
                _patchAddress = targetPtr;
                _originalBytes = Jumper.Install(targetPtr, jumpTarget);
                diag.PatchType = "JitCode(5-byte) x86";
                diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, 16);
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
                    diag.InstalledBytes = MemOps.ReadBytesSafe(intPtr, 16);
                }
                else
                {
                    diag.PatchType = "None(relies on slot replacement) x86";
                }
            }
        }
    }
}
