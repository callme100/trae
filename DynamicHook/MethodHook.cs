using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;

[assembly: InternalsVisibleTo("DynamicHook.Tests")]

namespace DynamicHook
{
    public sealed class MethodHook : IDisposable
    {
        private readonly MethodBase _targetMethod;

        private readonly MethodBase _hookMethod;

        private List<IntPtr> _slotAddresses;

        private IntPtr _originalSlotValue;

        private IntPtr _newSlotValue;

        /// <summary>
        /// Per-slot original value captured BEFORE each slot is overwritten in
        /// InstallSlotReplacement. Generic-dictionary slots may originally hold
        /// different code pointers (precode addr, fixup-thunk addr, or JIT code
        /// addr), so RestoreAll must restore each slot to ITS OWN original value
        /// rather than a uniform _originalSlotValue (which is just the precode
        /// address). Restoring a dict slot that held the JIT code address back to
        /// the precode address corrupts the generic dictionary and leaves the
        /// method uncallable after uninstall.
        /// </summary>
        private Dictionary<IntPtr, IntPtr> _slotOriginalValues;

        private int _patchType;

        private IntPtr _patchAddress;

        private byte[] _originalBytes;

        private IntPtr _indirectTargetLoc;

        private IntPtr _originalIndirectTarget;

        private IntPtr _nearTrampoline;

        /// <summary>
        /// Adapter trampoline that shifts registers from the generic calling
        /// convention (generic dict in RDX for instance / RCX for static) to the
        /// standard managed calling convention before jumping to the hook.
        /// Built once in Install() and used as the jump target for ALL patches
        /// (slot replacement, precode, target1, target2, secondary JIT).
        /// </summary>
        private IntPtr _hookAdapterTrampoline;

        private bool _hasSecondaryPatch;

        private IntPtr _secondaryJitAddress;

        private byte[] _secondaryJitOriginalBytes;

        /// <summary>
        /// Full (32-byte) copy of the original bytes at the secondary JIT address,
        /// saved BEFORE the 5-byte E9 patch is applied. Used by the call-original
        /// trampoline to copy/relocate the original prologue.
        /// </summary>
        private byte[] _secondaryJitOriginalBytesFull;

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

        /// <summary>
        /// On .NET Framework 4.x, generic instance methods have an E9 precode that
        /// jumps to a fixup thunk. The fixup thunk loads &lt;jit_addr&gt; into RAX
        /// and JMPs to it. The &lt;jit_addr&gt; may point to a PRESTUB or data
        /// structure (not directly to JIT code), so patching the TARGET would
        /// corrupt it. Instead, we patch the &lt;jit_addr&gt; FIELD ITSELF (a
        /// data pointer at offset 15 in the fixup thunk) to point to the hook
        /// adapter trampoline. This is a DATA patch (8-byte write), restored/
        /// reapplied by RestoreCodePatch/ReapplyCodePatch.
        /// </summary>
        private bool _hasFixupJitAddrPatch;

        private IntPtr _fixupJitAddrLoc;

        private IntPtr _fixupJitAddrOriginal;

        private IntPtr _callOrigTrampoline;

        private int _callOrigTrampSize;

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

        private bool _needsGenericAdapter;

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
            System.Console.Error.WriteLine($"[MethodHook] Install START: {_targetMethod.DeclaringType?.Name}.{_targetMethod.Name}");
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
            // RuntimeHelpers.PrepareMethod may not fully JIT compile generic methods
            // on .NET Framework 4.x — it can leave a PRESTUB that gets replaced on
            // first actual call, overwriting our patch and causing crashes.
            // Invoke the method once via the delegate's DynamicInvoke to force real
            // JIT compilation AND backpatch the precode. DynamicInvoke calls the
            // delegate's Invoke method, which calls the precode, which triggers the
            // fixup thunk → JIT → backpatch. MethodInfo.Invoke on the target method
            // uses RuntimeMethodHandle.InvokeMethod which bypasses the precode,
            // leaving it un-backpatched and causing crashes when we patch the
            // PRESTUB address extracted from the fixup thunk.
            EnsureJitCompiled(_targetMethod);
            IntPtr functionPointer = _targetMethod.MethodHandle.GetFunctionPointer();
            IntPtr functionPointer2 = _hookMethod.MethodHandle.GetFunctionPointer();
            hookDiagInfo.PrecodeAddr = functionPointer;
            hookDiagInfo.PrecodeBytes = MemOps.ReadBytesSafe(functionPointer, 32);
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
            if (NeedsGenericAdapter())
            {
                // On x64, generic instance methods pass the generic dictionary in
                // RDX (shifting user args to R8, R9, [stack]). Generic static
                // methods pass it in RCX (shifting user args to RDX, R8, R9, [stack]).
                // Build an adapter trampoline that shifts registers back to the
                // standard managed calling convention before jumping to the hook.
                // Without this, the hook receives the generic dictionary as its
                // first user argument and the real arguments are shifted by one.
                byte[] adapterBytes = BuildGenericAdapterBytes(_targetMethod.IsStatic, _targetMethod.GetParameters().Length);
                if (adapterBytes.Length > 0)
                {
                    int trampSize = adapterBytes.Length + 12; // adapter + MOV RAX,imm64; JMP RAX
                    _hookAdapterTrampoline = Memory.AllocExecNear(intPtr, trampSize);
                    if (_hookAdapterTrampoline != IntPtr.Zero && _hookAdapterTrampoline != new IntPtr(-1))
                    {
                        MemOps.WriteBytes(_hookAdapterTrampoline, adapterBytes);
                        byte[] jumpBytes = Jumper.BuildAbsJumpX64(intPtr);
                        MemOps.WriteBytes(_hookAdapterTrampoline + adapterBytes.Length, jumpBytes);
                        hookDiagInfo.AdapterAddr = _hookAdapterTrampoline;
                        hookDiagInfo.AdapterBytes = adapterBytes;
                        intPtr = _hookAdapterTrampoline; // all patches now jump to adapter → hook
                    }
                }
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
            System.Console.Error.WriteLine($"[MethodHook] Install END: {_targetMethod.DeclaringType?.Name}.{_targetMethod.Name}");
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
        /// Forces real JIT compilation of the target method AND backpatches the
        /// precode by invoking the method once with dummy arguments.
        ///
        /// RuntimeHelpers.PrepareMethod may leave a PRESTUB (pre-JIT stub) for
        /// generic methods on .NET Framework 4.x. The PRESTUB is replaced with
        /// real JIT code on first actual call through the precode — the fixup
        /// thunk runs, JIT compiles the method, updates the fixup code's
        /// &lt;jit_addr&gt; field, and backpatches the precode.
        ///
        /// MethodInfo.Invoke on the target method uses
        /// RuntimeMethodHandle.InvokeMethod which calls the JIT code directly,
        /// bypassing the precode. This leaves the precode un-backpatched and the
        /// fixup code's &lt;jit_addr&gt; still pointing to the PRESTUB. When we
        /// later extract this address via TryResolveFixupToJitCode and patch it,
        /// we corrupt the PRESTUB, causing AccessViolationException on call.
        ///
        /// Fix: invoke via the delegate's DynamicInvoke. DynamicInvoke calls the
        /// delegate's Invoke method, which calls the precode, which triggers the
        /// fixup thunk → JIT → backpatch. This ensures the fixup code's
        /// &lt;jit_addr&gt; is updated to point to real JIT code before we patch it.
        ///
        /// Exceptions from the invocation are expected and harmless — JIT
        /// compilation and backpatching occur before the method body executes.
        /// </summary>
        private void EnsureJitCompiled(MethodBase method)
        {
            if (!(method is MethodInfo mi)) return;
            // Skip DynamicInvoke for generic methods on .NET Framework 4.x.
            // DynamicInvoke goes through the precode → fixup thunk, which
            // backpatches direct call sites to call JIT code directly.
            // This bypasses our precode patch, and we can't find the JIT code
            // to patch it (because <jit_addr> in the fixup thunk points to a
            // data structure, not JIT code, on .NET Framework 4.x).
            // By skipping DynamicInvoke, the call site remains un-backpatched
            // and goes through the precode (which we patch), triggering the hook.
            // PrepareMethod (called earlier) already JIT-compiles the method,
            // so CallOriginal can still work via RestoreAll → delegate* Invoke
            // → ReapplyAll (the fixup thunk handles JIT compilation on demand).
            if (mi.IsGenericMethod && Environment.Version.Major < 6)
            {
                return;
            }
            try
            {
                ParameterInfo[] parameters = mi.GetParameters();
                object[] methodArgs = new object[parameters.Length];
                for (int i = 0; i < parameters.Length; i++)
                {
                    Type t = parameters[i].ParameterType;
                    if (t.IsValueType)
                    {
                        methodArgs[i] = Activator.CreateInstance(t);
                    }
                    else
                    {
                        methodArgs[i] = null;
                    }
                }

                // Build the args array for DynamicInvoke. For open instance
                // delegates, the first arg is the instance.
                object[] invokeArgs;
                object instance = null;
                if (!mi.IsStatic && mi.DeclaringType != null)
                {
                    Type declType = mi.DeclaringType;
                    if (declType.IsGenericTypeDefinition)
                    {
                        Type[] typeArgs = mi.ReflectedType?.GetGenericArguments();
                        if (typeArgs != null && typeArgs.Length > 0)
                        {
                            declType = declType.MakeGenericType(typeArgs);
                        }
                    }
                    if (declType.IsValueType)
                    {
                        instance = Activator.CreateInstance(declType);
                    }
                    else if (!declType.IsAbstract)
                    {
                        try { instance = Activator.CreateInstance(declType); }
                        catch { instance = FormatterServices.GetUninitializedObject(declType); }
                    }
                    else
                    {
                        instance = FormatterServices.GetUninitializedObject(declType);
                    }

                    invokeArgs = new object[methodArgs.Length + 1];
                    invokeArgs[0] = instance;
                    Array.Copy(methodArgs, 0, invokeArgs, 1, methodArgs.Length);
                }
                else
                {
                    invokeArgs = methodArgs;
                }

                // Prefer invoking via the delegate's DynamicInvoke, which calls
                // the delegate's Invoke method → precode → fixup thunk → JIT →
                // backpatch. This is critical on .NET Framework 4.x where
                // MethodInfo.Invoke bypasses the precode.
                bool invoked = false;
                if (_originalDelegate != null)
                {
                    try
                    {
                        _originalDelegate.DynamicInvoke(invokeArgs);
                        invoked = true;
                    }
                    catch
                    {
                        // Expected — dummy args cause exceptions in the method
                        // body, but JIT compilation and backpatching occur first.
                        invoked = true;
                    }
                }

                if (!invoked)
                {
                    // Fallback: MethodInfo.Invoke (may not backpatch precode on
                    // .NET Framework 4.x, but works on .NET 6+).
                    mi.Invoke(instance, methodArgs);
                }
            }
            catch
            {
                // JIT compilation/backpatching failures are non-fatal — the
                // fixup thunk handles on-demand compilation at call time.
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
                        foreach (IntPtr s in dictSlots)
                        {
                            if (!_slotAddresses.Contains(s)) _slotAddresses.Add(s);
                        }
                        diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; GenDictScan at 0x" + genDictAddr.ToInt64().ToString("X") + " found " + dictSlots.Count + " slots";
                    }
                }

                // Fallback (virtual methods only): on .NET 8, precode backpatching
                // can update the precode chain to a NEW JIT code address while
                // leaving a vtable slot still pointing to the OLD JIT code. The OLD
                // address is not in the precode resolution chain, so chain-based
                // FindSlots misses it. Virtual dispatch uses the vtable slot, so the
                // hook is bypassed. Identify the method's own vtable slot by the
                // MethodDesc reference that CoreCLR JIT code embeds in its prologue
                // (MOV RAX,[RIP+disp32] = 48 8B 05), which loads the method's
                // MethodDesc. This catches the stale-JIT slot without relying on
                // CoreCLR-internal slot-number layout. Gated to IsVirtual because
                // only virtual methods dispatch through vtable slots.
                if (_slotAddresses.Count == 0 && methodTable != IntPtr.Zero && methodDesc != IntPtr.Zero && _targetMethod.IsVirtual)
                {
                    foreach (IntPtr s in FindSlotsByEmbeddedMethodDesc(methodTable, methodDesc, targetPtr, 65536))
                    {
                        if (!_slotAddresses.Contains(s)) _slotAddresses.Add(s);
                    }
                }

                diag.SlotCount = _slotAddresses.Count;
                diag.SlotAddresses = (from a in _slotAddresses.Take(10)
                                      select a.ToInt64()).ToList();
                // Capture each slot's original value BEFORE overwriting. Generic-
                // dictionary slots may hold different code pointers (precode addr,
                // fixup-thunk addr, or JIT code addr), so each must be restored to
                // its own original value at uninstall — not a uniform precode addr.
                _slotOriginalValues = new Dictionary<IntPtr, IntPtr>();
                foreach (IntPtr slotAddress in _slotAddresses)
                {
                    IntPtr orig = IntPtr.Zero;
                    try { orig = MemOps.ReadIntPtr(slotAddress); } catch { }
                    _slotOriginalValues[slotAddress] = orig;
                    SlotPatcher.ReplaceSlot(slotAddress, jumpTarget);
                }
            }
            catch (Exception ex)
            {
                diag.SlotError = ex.Message;
            }
        }

        /// <summary>
        /// Extracts the generic dictionary address from the fixup thunk referenced
        /// by a precode. Supports both FF 25 (indirect jump) and E9 (relative jump)
        /// precode formats.
        ///
        /// FF 25 precode (.NET 6+ FixupPrecode): FF 25 <disp32> -> [mem] = fixup thunk addr
        /// E9 precode (.NET Framework 4.x DirectJump): E9 <rel32> -> fixup thunk addr
        ///
        /// Fixup thunk format (first 5 bytes differ by platform ABI; the dict operand
        /// is at offset 5 in both, the JIT address at offset 15):
        ///   Windows x64: 49 89 D0 48 BA <dict> 48 B8 <jit_addr> FF E0
        ///                (MOV R10,RDX; MOV RDX,dict) — dict in RDX
        ///   Linux x64:   48 89 F2 48 BE <dict> 48 B8 <jit_addr> FF E0
        ///                (MOV RDX,RSI; MOV RSI,dict) — dict in RSI
        /// The generic dictionary address is the 8-byte operand at offset 5.
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
                // Accept both Windows (49 89 D0 48 BA) and Linux (48 89 F2 48 BE) prefixes.
                if (!IsX64FixupThunkPrefix(f[0], f[1], f[2], f[3], f[4])) return IntPtr.Zero;
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
                    int num = 0;  // Always patch the first FF 25 (the normal call entry)
                    byte* ptr2 = ptr + num;
                    int num2 = *(int*)(ptr2 + 2);
                    long num3 = targetPtr.ToInt64() + num + 6 + num2;
                    _patchType = 1;
                    _patchAddress = targetPtr;
                    _indirectTargetLoc = new IntPtr(num3);
                    _originalIndirectTarget = new IntPtr(*(long*)num3);
                    MemOps.WriteInt64Cell(_indirectTargetLoc, jumpTarget.ToInt64());
                    diag.PatchType = (flag ? "Indirect(FF 25 1st, FixupPrecode) + JIT(E9)" : "Indirect(FF 25) + JIT(E9)");
                    diag.InstalledBytes = MemOps.ReadBytesSafe(targetPtr, 16);
                }
            }
            else if (b == 0xE8 || b == 0xE9)
            {
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
                    // Install a call-original trampoline using the inner code's
                    // original prologue (set by InstallTarget1Patch). The trampoline
                    // sets up R10 (generic dict), executes the relocated original
                    // prologue, then JMPs past the 12-byte patch.
                    if (_innerCodeAddress != IntPtr.Zero && _innerCodeOriginalBytesFull != null)
                    {
                        InstallCallOriginalTrampoline(_innerCodeAddress, _innerCodeOriginalBytesFull, diag, 12);
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
                _patchType = 3;
                _patchAddress = targetPtr;
                // Safety guard: if the JIT code already starts with E9 (relative
                // jump), a previous hook's uninstall failed to restore the original
                // bytes. Skip the patch to avoid capturing a residual hook as
                // "original" (which would create an infinite loop on uninstall).
                byte[] guardBytes = MemOps.ReadBytes(targetPtr, 1);
                if (guardBytes[0] == 0xE9)
                {
                    diag.PatchError += "; JitCodePatch SKIPPED: residual E9 detected at JIT code — previous uninstall may have failed";
                    _patchType = 0;
                    _patchAddress = IntPtr.Zero;
                    return;
                }
                _originalBytes = Jumper.Install(targetPtr, jumpTarget);
                diag.PatchType = "JitCode(12-byte)";
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
                    diag.PatchType = "ResolvedJitCode(12-byte)";
                    diag.InstalledBytes = MemOps.ReadBytesSafe(intPtr, 16);
                }
                else
                {
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
        /// The fixup thunk prefix differs by platform ABI; see
        /// <see cref="IsX64FixupThunkPrefix"/> (the 48 B8 + operand layout is shared).
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
                // Verify fixup thunk prefix (Windows or Linux) + 48 B8 <jit_addr>.
                byte* f = (byte*)fixupAddr;
                if (!IsX64FixupThunkPrefix(f[0], f[1], f[2], f[3], f[4])) return IntPtr.Zero;
                if (f[13] != 0x48 || f[14] != 0xB8) return IntPtr.Zero;
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
                // Check fixup thunk prefix (Windows or Linux) + 48 B8 <jit_addr>.
                if (!IsX64FixupThunkPrefix(f[0], f[1], f[2], f[3], f[4])) return false;
                if (f[13] != 0x48 || f[14] != 0xB8) return false;
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
            // The fixup thunk pattern starts with: 49 89 D0 48 BA (MOV R10, RDX; MOV RDX, ...)
            // If the target has this pattern, the precode still points to the fixup
            // thunk. On .NET Framework 4.x, the precode ALWAYS points to the fixup
            // thunk for generic methods — the fixup thunk's <jit_addr> field is what
            // gets updated (not the precode's E9 target). So we check <jit_addr> to
            // determine if the method has been JIT compiled.
            if (t[0] == 0x49 && t[1] == 0x89 && t[2] == 0xD0 && t[3] == 0x48 && t[4] == 0xBA)
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
                            diag.PatchError += "; targetPtr not readable for E8 check";
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
                    diag.PatchError += "; cannot resolve JIT entry for secondary patch";
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
        /// Detects the x64 generic method fixup code pattern and extracts the real
        /// JIT code address from it. The first 5 bytes (save + dict-register load)
        /// differ by platform ABI; see <see cref="IsX64FixupThunkPrefix"/>. The rest
        /// of the layout is identical on both ABIs:
        ///   &lt;prefix 5B&gt; | &lt;8-byte dict&gt; | 48 B8 &lt;8-byte jit_addr&gt; | FF E0
        /// The JIT code address is the 8-byte operand of MOV RAX at offset 15.
        /// </summary>
        private unsafe IntPtr TryResolveFixupToJitCode(IntPtr addr)
        {
            if (addr == IntPtr.Zero) return IntPtr.Zero;
            // In .NET 6+, AV from unmapped memory is uncatchable. Check readability.
            if (!Memory.IsReadable(addr, 23)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)addr;
                // Accept both Windows (49 89 D0 48 BA) and Linux (48 89 F2 48 BE) prefixes.
                if (!IsX64FixupThunkPrefix(p[0], p[1], p[2], p[3], p[4])) return IntPtr.Zero;
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
                    if (b1 == 0x48 || b1 == 0x4C) return true;  // REX prefix
                    if (b1 == 0x40) return true;                 // REX prefix
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
        /// True on non-Windows x64 (Linux/macOS/BSD), which all use the System V
        /// AMD64 calling convention (RDI, RSI, RDX, RCX, R8, R9, [RSP+8]) — as
        /// opposed to the Windows x64 convention (RCX, RDX, R8, R9, [RSP+0x28]).
        /// CoreCLR passes the generic dictionary in RSI (instance) / RDI (static)
        /// on System V, vs RDX / RCX on Windows.
        /// </summary>
        private static bool IsSystemVX64 =>
            Platform.Current == Platform.Arch.X64
            && !RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        /// <summary>
        /// Recognizes the x64 generic-method fixup thunk prefix. The thunk loads
        /// the generic dictionary into a register, then jumps to the JIT code:
        ///   &lt;save&gt; &lt;MOV dictReg, imm64 dict&gt; &lt;48 B8 imm64 jit&gt; &lt;FF E0&gt;
        /// Only the first 5 bytes (save + dictReg load) differ by ABI:
        ///   Windows x64: 49 89 D0 48 BA  (MOV R10,RDX; MOV RDX,dict)  — dict in RDX
        ///   Linux x64:   48 89 F2 48 BE  (MOV RDX,RSI; MOV RSI,dict)  — dict in RSI
        /// The dict operand is at offset 5, the 48 B8 (MOV RAX,jit) at offset 13,
        /// the jit operand at offset 15, and FF E0 (JMP RAX) at offset 21 — on both.
        /// </summary>
        private static bool IsX64FixupThunkPrefix(byte b0, byte b1, byte b2, byte b3, byte b4)
        {
            // Windows: 49 89 D0 48 BA
            if (b0 == 0x49 && b1 == 0x89 && b2 == 0xD0 && b3 == 0x48 && b4 == 0xBA) return true;
            // Linux / System V: 48 89 F2 48 BE
            if (b0 == 0x48 && b1 == 0x89 && b2 == 0xF2 && b3 == 0x48 && b4 == 0xBE) return true;
            return false;
        }

        /// <summary>
        /// Fallback slot finder for the .NET 8 precode-backpatching case where a
        /// vtable slot still holds the OLD JIT code address, which is no longer in
        /// the current precode→JIT resolution chain (so chain-based FindSlots misses
        /// it). CoreCLR JIT-compiled code begins its prologue with
        ///   48 8B 05 <disp32>   (MOV RAX, [RIP+disp32])
        /// which loads the method's own MethodDesc into RAX. By scanning the
        /// MethodTable for pointer-sized values that look like code addresses
        /// (same high byte range as the known precode/JIT code address), reading
        /// each candidate's prologue, computing the RIP-relative target, and
        /// matching it against the target method's MethodDesc, we identify the
        /// method's own vtable slot without relying on CoreCLR-internal slot
        /// layout. This catches the stale-JIT slot left behind by backpatching.
        /// </summary>
        private static unsafe List<IntPtr> FindSlotsByEmbeddedMethodDesc(IntPtr methodTable, IntPtr methodDesc, IntPtr hintCodeAddr, int scanSize)
        {
            var result = new List<IntPtr>();
            if (methodTable == IntPtr.Zero || methodDesc == IntPtr.Zero) return result;
            int size = IntPtr.Size;
            long mdLong = methodDesc.ToInt64();
            long hintLong = hintCodeAddr != IntPtr.Zero ? hintCodeAddr.ToInt64() : 0L;
            // Derive the expected high-byte range from the known code address so we
            // skip pointer values that clearly aren't code addresses (avoids the
            // per-candidate /proc/self/maps binary search for the common case of
            // non-code integers stored in the MethodTable). On Linux code is
            // typically in the 0x7F.. mmap range. Memory.IsReadable (backed by
            // /proc/self/maps on Linux) provides the authoritative safety check
            // before dereferencing the candidate prologue.
            const long highMask = 0xFF000000000000L;
            long highBits = (hintLong != 0) ? (hintLong & highMask) : 0x7F000000000000L;
            int consecutiveUnreadable = 0;
            for (int i = 0; i < scanSize; i += size)
            {
                IntPtr slotAddr = methodTable + i;
                if (!Memory.IsReadable(slotAddr, size))
                {
                    consecutiveUnreadable += size;
                    if (consecutiveUnreadable >= 4096) break;
                    continue;
                }
                consecutiveUnreadable = 0;
                long candidate;
                try { candidate = MemOps.ReadIntPtr(slotAddr).ToInt64(); }
                catch { break; }
                if ((candidate & highMask) != highBits) continue;
                // Skip values already covered by chain-based matching.
                if (candidate == hintLong) continue;
                // Read the prologue for the MethodDesc load: 48 8B 05 <disp32>.
                // Allow a couple of leading bytes (e.g. a prefix) by scanning the
                // first few instruction-start offsets. The loaded address equals
                // (prologue_loc + 7 + disp32) for a match at offset 0.
                if (!Memory.IsReadable(new IntPtr(candidate), 16)) continue;
                try
                {
                    byte* p = (byte*)candidate;
                    for (int off = 0; off <= 3; off++)
                    {
                        if (p[off] != 0x48 || p[off + 1] != 0x8B || p[off + 2] != 0x05) continue;
                        int disp = *(int*)(p + off + 3);
                        long loaded = candidate + off + 7 + disp;
                        if (loaded == mdLong)
                        {
                            if (!result.Contains(slotAddr)) result.Add(slotAddr);
                        }
                        break;
                    }
                }
                catch { }
            }
            return result;
        }

        /// <summary>
        /// Builds x64 register-shift code that converts from the generic calling
        /// convention to the standard managed calling convention.
        ///
        /// Windows x64 (RCX, RDX, R8, R9, [RSP+0x28]):
        ///   Instance: RCX=this (kept), RDX=genericDict (discarded),
        ///     R8=arg1, R9=arg2, [stack]=arg3 → RCX=this, RDX=arg1, R8=arg2, R9=arg3
        ///   Static: RCX=genericDict (discarded), RDX=arg1, R8=arg2,
        ///     R9=arg3, [stack]=arg4 → RCX=arg1, RDX=arg2, R8=arg3, R9=arg4
        ///
        /// System V AMD64 / Linux (RDI, RSI, RDX, RCX, R8, R9, [RSP+8]):
        ///   Instance: RDI=this (kept), RSI=genericDict (discarded),
        ///     RDX=arg1, RCX=arg2, R8=arg3, R9=arg4, [stack]=arg5
        ///     → RDI=this, RSI=arg1, RDX=arg2, RCX=arg3, R8=arg4, R9=arg5
        ///   Static: RDI=genericDict (discarded), RSI=arg0, RDX=arg1,
        ///     RCX=arg2, R8=arg3, R9=arg4 → RDI=arg0, RSI=arg1, RDX=arg2, ...
        /// </summary>
        private static byte[] BuildGenericAdapterBytes(bool isStatic, int userParamCount)
        {
            var bytes = new List<byte>();
            if (IsSystemVX64)
            {
                // System V AMD64: args in RDI, RSI, RDX, RCX, R8, R9, [RSP+8].
                // Generic dict occupies RSI (instance) / RDI (static); shift user
                // args left by one register position, dropping the dict.
                if (isStatic)
                {
                    // dict in RDI; shift user args left from RDI.
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
                }
                else
                {
                    // dict in RSI (this stays in RDI); shift user args left from RSI.
                    if (userParamCount >= 1)
                        bytes.AddRange(new byte[] { 0x48, 0x89, 0xD6 });       // MOV RSI, RDX
                    if (userParamCount >= 2)
                        bytes.AddRange(new byte[] { 0x48, 0x89, 0xCA });       // MOV RDX, RCX
                    if (userParamCount >= 3)
                        bytes.AddRange(new byte[] { 0x4C, 0x89, 0xC1 });       // MOV RCX, R8
                    if (userParamCount >= 4)
                        bytes.AddRange(new byte[] { 0x4D, 0x89, 0xC8 });       // MOV R8, R9
                    if (userParamCount >= 5)
                        bytes.AddRange(new byte[] { 0x4C, 0x8B, 0x4C, 0x24, 0x08 }); // MOV R9, [RSP+8]
                }
                return bytes.ToArray();
            }
            // Windows x64: args in RCX, RDX, R8, R9, [RSP+0x28].
            // Generic dict occupies RDX (instance) / RCX (static).
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
            return bytes.ToArray();
        }

        /// <summary>
        /// Builds x64 register-shift code that converts from the STANDARD managed
        /// calling convention to the GENERIC calling convention (reverse of
        /// BuildGenericAdapterBytes). This is needed by the call-original trampoline
        /// because delegate*/Marshal.GetDelegateForFunctionPointer passes args in
        /// the standard managed convention, but the original JIT code for generic
        /// methods expects them in the generic convention (dict inserted at the
        /// ABI's second/first arg register, user args shifted right by one).
        ///
        /// Windows x64 (RCX, RDX, R8, R9, [RSP+0x28]):
        ///   Instance: RCX=this, RDX=arg1, R8=arg2, R9=arg3
        ///     → RCX=this, RDX=genericDict, R8=arg1, R9=arg2, [stack]=arg3
        ///   Static: RCX=arg0, RDX=arg1, R8=arg2, R9=arg3
        ///     → RCX=genericDict, RDX=arg0, R8=arg1, R9=arg2, [stack]=arg3
        ///
        /// System V AMD64 / Linux (RDI, RSI, RDX, RCX, R8, R9, [RSP+8]):
        ///   Instance: RDI=this, RSI=arg1, RDX=arg2, RCX=arg3
        ///     → RDI=this, RSI=genericDict, RDX=arg1, RCX=arg2, R8=arg3
        ///   Static: RDI=arg0, RSI=arg1, RDX=arg2, RCX=arg3
        ///     → RDI=genericDict, RSI=arg0, RDX=arg1, RCX=arg2, R8=arg3
        ///
        /// R10 must already be set to genericDict before this code runs (it is a
        /// scratch register on both ABIs, not used for arg passing). The shift goes
        /// right-to-left (last arg first) to avoid overwriting, then the dict is
        /// loaded into the ABI's dict register from R10.
        /// </summary>
        private static byte[] BuildReverseGenericAdapterBytes(bool isStatic, int userParamCount)
        {
            var bytes = new List<byte>();
            if (IsSystemVX64)
            {
                // System V AMD64: shift user args right by one (from RSI for instance,
                // from RDI for static) to make room for the dict, then load the dict
                // from R10 into RSI (instance) / RDI (static). Right-to-left order so
                // no register is read after it has been overwritten.
                //
                // Standard:  RDI, RSI, RDX, RCX, R8, R9, [RSP+8]
                // The shared shift-right (applies to both instance and static) spills
                // the highest-register user arg first, then walks down.
                if (userParamCount >= 5)
                    bytes.AddRange(new byte[] { 0x4C, 0x89, 0x4C, 0x24, 0x08 }); // MOV [RSP+8], R9
                if (userParamCount >= 4)
                    bytes.AddRange(new byte[] { 0x4D, 0x89, 0xC1 });       // MOV R9, R8
                if (userParamCount >= 3)
                    bytes.AddRange(new byte[] { 0x49, 0x89, 0xC8 });       // MOV R8, RCX
                if (userParamCount >= 2)
                    bytes.AddRange(new byte[] { 0x48, 0x89, 0xD1 });       // MOV RCX, RDX
                if (userParamCount >= 1)
                    bytes.AddRange(new byte[] { 0x48, 0x89, 0xF2 });       // MOV RDX, RSI
                if (isStatic)
                {
                    // arg0 (RDI) → RSI, then dict (R10) → RDI
                    if (userParamCount >= 1)
                        bytes.AddRange(new byte[] { 0x48, 0x89, 0xFE });   // MOV RSI, RDI
                    bytes.AddRange(new byte[] { 0x4C, 0x89, 0xF7 });       // MOV RDI, R10
                }
                else
                {
                    // dict (R10) → RSI (this in RDI is unchanged)
                    bytes.AddRange(new byte[] { 0x4C, 0x89, 0xD6 });       // MOV RSI, R10
                }
                return bytes.ToArray();
            }
            // Windows x64: shift user args right by one (from RDX for instance,
            // from RCX for static), then load dict from R10 into RDX/RCX.
            // Shift right by 1, starting from the last arg to avoid overwriting.
            if (userParamCount >= 3)
                bytes.AddRange(new byte[] { 0x4C, 0x89, 0x4C, 0x24, 0x28 }); // MOV [RSP+0x28], R9
            if (userParamCount >= 2)
                bytes.AddRange(new byte[] { 0x4D, 0x89, 0xC1 });       // MOV R9, R8
            if (userParamCount >= 1)
                bytes.AddRange(new byte[] { 0x49, 0x89, 0xD0 });       // MOV R8, RDX
            if (isStatic)
            {
                // For static: shift RCX (arg0) to RDX, then set RCX = R10 (genericDict)
                if (userParamCount >= 1)
                    bytes.AddRange(new byte[] { 0x48, 0x89, 0xCA });   // MOV RDX, RCX
                bytes.AddRange(new byte[] { 0x4C, 0x89, 0xD1 });       // MOV RCX, R10
            }
            else
            {
                // For instance: set RDX = R10 (genericDict)
                bytes.AddRange(new byte[] { 0x4C, 0x89, 0xD2 });       // MOV RDX, R10
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
                // Safety guard: if the JIT code already starts with E9 (relative
                // jump) or 48 B8 (absolute jump), a previous hook's uninstall
                // failed to restore the original bytes. Capturing these as
                // "original" would create an infinite loop on uninstall (the
                // restored E9 would jump to a freed trampoline). Skip the patch
                // and rely on the indirect-target + slot patches for hooking.
                if (_secondaryJitOriginalBytes[0] == 0xE9 ||
                    (_secondaryJitOriginalBytes[0] == 0x48 && _secondaryJitOriginalBytes[1] == 0xB8))
                {
                    diag.PatchError += "; SecondaryJitPatch SKIPPED: residual hook patch detected (E9/48B8) at JIT code — previous uninstall may have failed";
                    _secondaryJitOriginalBytes = null;
                    Memory.FreeExec(trampoline, trampolineSize);
                    return;
                }
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
                // The fixup thunk pattern's first 5 bytes differ by platform ABI
                // (Windows: 49 89 D0 48 BA, Linux: 48 89 F2 48 BE); see
                // IsX64FixupThunkPrefix. The 48 B8 <jit_addr> at offset 13 and the
                // jit operand at offset 15 are identical on both ABIs. We only
                // require the prefix + 48 B8 to extract <jit_addr> at offset 15.
                byte[] fixupBytes = MemOps.ReadBytesSafe(target1Addr, 25);
                IntPtr innerCodeAddr = IntPtr.Zero;
                bool patternMatch = fixupBytes != null && fixupBytes.Length >= 23 &&
                    IsX64FixupThunkPrefix(fixupBytes[0], fixupBytes[1], fixupBytes[2], fixupBytes[3], fixupBytes[4]) &&
                    fixupBytes[13] == 0x48 && fixupBytes[14] == 0xB8;
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
                        IntPtr realJit = MethodEntryResolver.ResolveRealEntry(innerCodeAddr);
                        if (realJit != IntPtr.Zero && realJit != innerCodeAddr)
                        {
                            diag.CallOrigStatus = (diag.CallOrigStatus ?? "") + "; ResolvedInner->RealJit 0x" + realJit.ToInt64().ToString("X");
                            innerCodeAddr = realJit;
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
                // Safety guard: if the fixup thunk already starts with 48 B8
                // (MOV RAX, imm64 — our absolute jump pattern), a previous hook's
                // uninstall failed to restore the original fixup bytes. Capturing
                // these as "original" would create an infinite loop on uninstall.
                if (_target1OriginalBytes[0] == 0x48 && _target1OriginalBytes[1] == 0xB8)
                {
                    diag.PatchError += "; Target1Patch SKIPPED: residual hook patch detected (48B8) at fixup thunk — previous uninstall may have failed";
                    _target1OriginalBytes = null;
                    _target1Address = IntPtr.Zero;
                    return;
                }
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
                        // Only patch if it looks like JIT code (not already patched,
                        // and not a DATA structure). On .NET Framework 4.x, <jit_addr>
                        // may point to a DATA structure — patching it corrupts memory.
                        if (innerBytes != null && innerBytes.Length >= 12 &&
                            (innerBytes[0] != 0x48 || innerBytes[1] != 0xB8) &&
                            LooksLikeRealJitCode(innerCodeAddr))
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
                    }
                    catch (Exception ex)
                    {
                        diag.PatchError += "; InnerCodePatch error: " + ex.Message;
                    }
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
                        // Try .NET 6+ E9 precode pattern: 49 BA <dict> at offset 16
                        genericDict = TryExtractGenericDictFromE9Precode(_precodeAddr);
                    }
                    if (genericDict == IntPtr.Zero)
                    {
                        // Try .NET Framework 4.x fixup code pattern
                        genericDict = TryExtractGenericDictFromFixupCode(jitCodeAddr);
                    }
                    if (genericDict == IntPtr.Zero)
                    {
                        // Try following the original E9 jump to the fixup code
                        // (the precode is now patched, so use _originalBytes for the rel32)
                        genericDict = TryExtractGenericDictFromOriginalPrecode();
                    }
                    // If still not found, install the trampoline without R10 setup.
                    // Some JIT-compiled methods may not use the generic dictionary at
                    // all (type info inlined), so this is a best-effort fallback.
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

                // Build the arg-shift code (standard → generic calling convention).
                // delegate*/Marshal.GetDelegateForFunctionPointer passes args in
                // standard convention (RCX, RDX, R8, R9), but the original JIT code
                // for generic methods expects them in generic convention (dict in
                // RDX for instance, RCX for static; user args shifted right by 1).
                // R10 must be set to genericDict BEFORE the arg-shift code runs,
                // because the arg-shift code copies R10 into RDX (instance) or RCX (static).
                byte[] argShift = (_needsGenericAdapter && genericDict != IntPtr.Zero)
                    ? BuildReverseGenericAdapterBytes(_targetMethod.IsStatic, _targetMethod.GetParameters().Length)
                    : Array.Empty<byte>();

                // Build the trampoline:
                // [MOV R10, genericDict]?  (10 bytes, generic only)
                // [arg-shift code]?        (variable, generic only: standard→generic)
                // [copied prologue]        (copyLen bytes, RIP-relative relocated)
                // [MOV RAX, jit+copyLen]   (10 bytes)
                // [JMP RAX]                (2 bytes)
                int prefixLen = (_needsGenericAdapter && genericDict != IntPtr.Zero) ? 10 + argShift.Length : 0;
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

                if (_needsGenericAdapter && genericDict != IntPtr.Zero)
                {
                    // MOV R10, imm64: 49 BA <8 bytes>
                    trampBytes[0] = 0x49;
                    trampBytes[1] = 0xBA;
                    BitConverter.GetBytes(genericDict.ToInt64()).CopyTo(trampBytes, 2);
                    offset = 10;

                    // Arg-shift code: convert standard convention → generic convention.
                    // Must come AFTER MOV R10 (arg-shift reads R10 to set RDX/RCX).
                    Buffer.BlockCopy(argShift, 0, trampBytes, offset, argShift.Length);
                    offset += argShift.Length;
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

                // MOV RAX, jitCodeAddr + copyLen; JMP RAX (12-byte absolute jump)
                byte[] tailJump = Jumper.BuildAbsJumpX64(new IntPtr(jitCodeAddr.ToInt64() + copyLen));
                Buffer.BlockCopy(tailJump, 0, trampBytes, offset, tailJump.Length);

                MemOps.WriteBytes(tramp, trampBytes);

                // Register the trampoline as a valid CFG indirect-call target.
                // delegate* (calli) is an indirect call, and .NET 6+ coreclr is built
                // with CFG enabled — without this registration the calli to the
                // trampoline raises STATUS_ACCESS_VIOLATION (0xC0000005).
                Memory.RegisterValidCallTarget(tramp, trampSize);

                _callOrigTrampoline = tramp;
                diag.CallOrigTrampolineBytes = trampBytes;
                diag.CallOrigStatus = "CopyPrologueTramp at 0x" + tramp.ToInt64().ToString("X") +
                    " (jitCode=0x" + jitCodeAddr.ToInt64().ToString("X") +
                    ", copyLen=" + copyLen +
                    (_needsGenericAdapter ? ", genDict=0x" + genericDict.ToInt64().ToString("X") +
                        ", argShift=" + argShift.Length + "B" : "") + ")";
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
            // On .NET Framework 4.x, AccessViolationException is uncatchable by
            // default, so all pointer dereferences must be guarded by IsReadable.
            if (!Memory.IsReadable(_precodeAddr, 6)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)_precodeAddr;
                // If precode is E9, follow it to the fixup code
                if (p[0] == 0xE9)
                {
                    int rel32 = *(int*)(p + 1);
                    long fixupAddr = _precodeAddr.ToInt64() + 5 + rel32;
                    if (!Memory.IsReadable(new IntPtr(fixupAddr), 13)) return IntPtr.Zero;
                    byte* fp = (byte*)fixupAddr;
                    // Accept both Windows (49 89 D0 48 BA) and Linux (48 89 F2 48 BE) prefixes.
                    if (IsX64FixupThunkPrefix(fp[0], fp[1], fp[2], fp[3], fp[4]))
                    {
                        // Dictionary is the 8-byte operand at offset 5 (MOV RDX/RSI, imm64)
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
        /// Tries to extract the generic dictionary from a .NET 6+ E9 (DirectJump)
        /// precode. The precode layout is:
        ///   E9 rel32                ; JMP rel32 (to fixup/warmup code)
        ///   5F                      ; POP RDI (precode sentinel)
        ///   <8-byte target1 ptr>    ; at offset 6
        ///   49 BA <8-byte dict>     ; MOV R10, imm64 (generic dictionary) at offset 16
        /// The dictionary value is the 8-byte operand of MOV R10 (49 BA) at offset 18.
        /// On .NET 6+, the JIT prologue expects R10 to already contain the generic
        /// dictionary, which is set up by this MOV R10 instruction in the precode.
        /// </summary>
        private unsafe IntPtr TryExtractGenericDictFromE9Precode(IntPtr precodeAddr)
        {
            if (precodeAddr == IntPtr.Zero) return IntPtr.Zero;
            if (!Memory.IsReadable(precodeAddr, 26)) return IntPtr.Zero;
            try
            {
                byte* p = (byte*)precodeAddr;
                // Must be E9 precode
                if (p[0] != 0xE9) return IntPtr.Zero;
                // Check for 49 BA (MOV R10, imm64) at offset 16
                if (p[16] != 0x49 || p[17] != 0xBA) return IntPtr.Zero;
                long dict = *(long*)(p + 18);
                if (dict == 0) return IntPtr.Zero;
                return new IntPtr(dict);
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        /// <summary>
        /// Tries to extract the generic dictionary by following the ORIGINAL E9 jump
        /// (from saved _originalBytes) to the fixup code, then scanning for a
        /// MOV r64, imm64 instruction that loads the dictionary. This handles .NET
        /// 6+ precodes where the generic dictionary is set up in the fixup code
        /// rather than inline in the precode. The dict-load instruction differs by
        /// platform ABI:
        ///   Windows x64: 49 BA (MOV R10, imm64) — dict staged in R10
        ///   Linux x64:   48 BE (MOV RSI, imm64) — dict in RSI (System V)
        ///   (also 48 BA / MOV RDX for .NET Framework 4.x instance)
        /// </summary>
        private unsafe IntPtr TryExtractGenericDictFromOriginalPrecode()
        {
            if (_precodeAddr == IntPtr.Zero) return IntPtr.Zero;
            if (_originalBytes == null || _originalBytes.Length < 5) return IntPtr.Zero;
            if (_originalBytes[0] != 0xE9) return IntPtr.Zero;
            try
            {
                int rel32 = BitConverter.ToInt32(_originalBytes, 1);
                long fixupAddr = _precodeAddr.ToInt64() + 5 + rel32;
                if (!Memory.IsReadable(new IntPtr(fixupAddr), 64)) return IntPtr.Zero;
                byte* fp = (byte*)fixupAddr;
                // Scan up to 64 bytes for a dict-load MOV r64, imm64 pattern.
                long dict = ScanForGenericDictLoad(fp, 0, 54);
                if (dict != 0) return new IntPtr(dict);
                // Also try following any E9 rel32 in the fixup code (nested jump)
                for (int i = 0; i < 59; i++)
                {
                    if (fp[i] == 0xE9)
                    {
                        int innerRel = *(int*)(fp + i + 1);
                        long innerAddr = fixupAddr + i + 5 + innerRel;
                        if (Memory.IsReadable(new IntPtr(innerAddr), 24))
                        {
                            byte* ip = (byte*)innerAddr;
                            dict = ScanForGenericDictLoad(ip, 0, 14);
                            if (dict != 0) return new IntPtr(dict);
                        }
                    }
                }
            }
            catch
            {
            }
            return IntPtr.Zero;
        }

        /// <summary>
        /// Scans a code region for a MOV r64, imm64 instruction that loads the
        /// generic dictionary, returning the 8-byte operand (or 0 if not found).
        /// Recognized opcodes (all share the B8+rd imm64 form with a REX prefix):
        ///   49 BA  (MOV R10, imm64) — Windows / .NET 6+ precode staging register
        ///   48 BE  (MOV RSI, imm64) — Linux System V (dict in RSI)
        ///   48 BA  (MOV RDX, imm64) — .NET Framework 4.x instance (dict in RDX)
        ///   48 B9  (MOV RCX, imm64) — .NET Framework 4.x static (dict in RCX)
        /// </summary>
        private static unsafe long ScanForGenericDictLoad(byte* p, int start, int count)
        {
            for (int i = start; i < count; i++)
            {
                byte rex = p[i];
                byte op = p[i + 1];
                // REX.W (0x48) or REX.WB (0x49) or REX.WR (0x4C)
                bool isMovImm64 =
                    (rex == 0x49 && op == 0xBA) ||  // MOV R10, imm64 (Windows/.NET 6+)
                    (rex == 0x48 && op == 0xBE) ||  // MOV RSI, imm64 (Linux)
                    (rex == 0x48 && op == 0xBA) ||  // MOV RDX, imm64 (Win Fx instance)
                    (rex == 0x48 && op == 0xB9);    // MOV RCX, imm64 (Win Fx static)
                if (isMovImm64)
                {
                    long dict = *(long*)(p + i + 2);
                    if (dict != 0) return dict;
                }
            }
            return 0;
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

            // REX + push r64 / pop r64 (50-5F): 2 bytes total
            if (op >= 0x50 && op <= 0x5F) return idx + 1;

            // REX + MOV RAX..R15, imm64 (B8-BF): 2 + 8 = 10 bytes total
            if (op >= 0xB8 && op <= 0xBF) return idx + 9;

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
                                long adjustment = origAddr.ToInt64() - newAddr.ToInt64();
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
                return MemOps.ReadIntPtr(new IntPtr(dictAddr));
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

            // Path 0b (call-original trampoline) is DISABLED.
            // The trampoline is native code (VirtualAlloc) that sits between two
            // managed frames. When a GC occurs inside the original method (e.g.
            // ConvertAll allocates a List), the GC cannot walk through the native
            // trampoline frame — it has no GC info, no method table entry, and the
            // return address points to unmanaged code. This causes the GC to miss
            // object references or crash with AccessViolationException.
            // Instead, use Path 0 (RestoreAll + delegate Invoke + ReapplyAll)
            // which keeps all frames managed and GC-walkable.
            if (false && _callOrigTrampoline != IntPtr.Zero && CanUseTrampoline(methodInfo))
            {
                return InvokeViaTrampoline(methodInfo, instance, args);
            }

            // Path 0: for generic methods, use RestoreAll + invoke + ReapplyAll.
            // Prefer the delegate's Invoke method (via delegate*) over MethodInfo.Invoke,
            // because RuntimeMethodHandle.InvokeMethod (used by MethodInfo.Invoke) does not
            // set up the generic dictionary for E9/DirectJump precodes on .NET Framework 4.x,
            // causing AccessViolationException. The delegate's Invoke method is JIT-compiled
            // with full knowledge of the generic arguments and correctly sets up the generic
            // dictionary (R10 on CoreCLR, RDX on .NET Framework 4.x) before calling the precode.
            // delegate* (managed function pointer) keeps the thread in cooperative GC mode,
            // so object references are properly GC-tracked.
            //
            // MUST run on the SAME thread as the hook (not a clean thread).
            // delegate* (calli) with managed calling convention requires the caller's
            // stack to have proper GC-tracked frames for the object references passed
            // as arguments. Running on a new thread (InvokeOnCleanThread) breaks this —
            // the GC cannot find the object references during a GC triggered inside
            // ConvertAll (e.g. when allocating the result List), causing
            // AccessViolationException. After RestoreAll, ALL patches are removed,
            // so there is no re-entrancy risk (the hook cannot re-trigger).
            if (_needsGenericAdapter)
            {
                RestoreAll();
                try
                {
                    // MethodInfo.Invoke crashes with 0x80131506 for hooked generic
                    // methods on ALL frameworks:
                    // - .NET Framework 4.x: RuntimeMethodHandle.InvokeMethod does not
                    //   set up the generic dictionary for E9/DirectJump precodes.
                    // - .NET 6+: The CLR's internal type-checking code path
                    //   (RuntimeTypeHandle.IsInstanceOfType) crashes after the JIT
                    //   code has been patched and restored, even though the original
                    //   bytes are restored correctly.
                    //
                    // The delegate's Invoke method is JIT-compiled with full knowledge
                    // of the generic arguments and correctly sets up the generic
                    // dictionary (R10 on CoreCLR, RDX on .NET Framework 4.x) before
                    // calling the precode. delegate* (managed function pointer) keeps
                    // the thread in cooperative GC mode, so object references are
                    // properly GC-tracked. At the ABI level, all reference type
                    // parameters use the same calling convention (object pointer in
                    // RCX/RDX/R8/R9), so delegate*<object,...> is compatible with the
                    // delegate's Invoke method regardless of its concrete parameter
                    // types.
                    if (_delegateInvokeFptr != IntPtr.Zero && _originalDelegate != null
                        && CanUseTrampoline(methodInfo))
                    {
                        return InvokeViaDelegateFptr(methodInfo, instance, args);
                    }
                    // Fallback: MethodInfo.Invoke (may crash with 0x80131506)
                    if (methodInfo.IsStatic)
                        return methodInfo.Invoke(null, args);
                    return methodInfo.Invoke(instance, args);
                }
                finally
                {
                    ReapplyAll();
                }
            }

            // Path 1: cached delegate's Invoke via function pointer.
            // For generic methods, DynamicInvoke goes through
            // RuntimeMethodHandle.InvokeMethod which crashes (0x80131506).
            // Using delegate* to call the delegate's Invoke method bypasses
            // reflection entirely. The Invoke method is non-generic and sets
            // up the generic dictionary (R10) before calling the target.
            // MUST run on the SAME thread — see Path 0 comment for details.
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

            // Path 2: RestoreAll + MethodInfo.Invoke + ReapplyAll.
            // Must run on the same thread — see Path 0 comment for details.
            RestoreAll();
            try
            {
                if (methodInfo.IsStatic)
                {
                    return methodInfo.Invoke(null, args);
                }
                return methodInfo.Invoke(instance, args);
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
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex).Throw();
            }
            return result;
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
            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    flatArgs[slot++] = args[i];
                }
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
            System.Console.Error.WriteLine($"[MethodHook] Uninstall START: {_targetMethod.DeclaringType?.Name}.{_targetMethod.Name}");
            System.Console.Error.WriteLine($"[MethodHook] Uninstall: calling RestoreAll");
            RestoreAll();
            System.Console.Error.WriteLine($"[MethodHook] Uninstall: RestoreAll done");
            if (_nearTrampoline != IntPtr.Zero)
            {
                SafeTry("FreeExec nearTrampoline", () => Memory.FreeExec(_nearTrampoline, 12));
                _nearTrampoline = IntPtr.Zero;
            }
            if (_secondaryTrampoline != IntPtr.Zero)
            {
                SafeTry("FreeExec secondaryTrampoline", () => Memory.FreeExec(_secondaryTrampoline, 12));
                _secondaryTrampoline = IntPtr.Zero;
            }
            if (_callOrigTrampoline != IntPtr.Zero)
            {
                SafeTry("FreeExec callOrigTrampoline", () => Memory.FreeExec(_callOrigTrampoline, _callOrigTrampSize));
                _callOrigTrampoline = IntPtr.Zero;
            }
            if (_hookAdapterTrampoline != IntPtr.Zero)
            {
                SafeTry("FreeExec hookAdapterTrampoline", () => Memory.FreeExec(_hookAdapterTrampoline, 12));
                _hookAdapterTrampoline = IntPtr.Zero;
            }
            _isInstalled = false;
            System.Console.Error.WriteLine($"[MethodHook] Uninstall END: {_targetMethod.DeclaringType?.Name}.{_targetMethod.Name}");
        }

        private void SafeTry(string description, Action action)
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                if (DiagInfo != null)
                {
                    DiagInfo.PatchError += "; " + description + ": " + ex.Message;
                }
            }
        }

        private void RestoreAll()
        {
            if (_slotAddresses != null)
            {
                foreach (IntPtr slotAddress in _slotAddresses)
                {
                    // Restore each slot to ITS OWN original value. Generic-dictionary
                    // slots may have held the JIT code address (not the precode
                    // address), so a uniform _originalSlotValue would corrupt them.
                    IntPtr orig = (_slotOriginalValues != null && _slotOriginalValues.TryGetValue(slotAddress, out IntPtr v))
                        ? v : _originalSlotValue;
                    SafeTry("RestoreSlot " + slotAddress, () => SlotPatcher.ReplaceSlot(slotAddress, orig));
                }
            }
            RestoreCodePatch();
        }

        private void RestoreCodePatch()
        {
            switch (_patchType)
            {
                case 1:
                    if (_indirectTargetLoc == IntPtr.Zero)
                    {
                        break;
                    }
                    SafeTry("Restore indirectTargetLoc", () => MemOps.WriteIntPtrCell(_indirectTargetLoc, _originalIndirectTarget));
                    break;
                case 2:
                case 3:
                    if (_patchAddress != IntPtr.Zero && _originalBytes != null)
                    {
                        SafeTry("Restore patchAddress", () => Jumper.Restore(_patchAddress, _originalBytes));
                    }
                    break;
            }
            if (_hasSecondaryPatch && _secondaryJitAddress != IntPtr.Zero && _secondaryJitOriginalBytes != null)
            {
                SafeTry("Restore secondaryJit", () => Jumper.Restore(_secondaryJitAddress, _secondaryJitOriginalBytes));
            }
            if (_hasTarget1Patch && _target1Address != IntPtr.Zero && _target1OriginalBytes != null)
            {
                SafeTry("Restore target1", () => Jumper.Restore(_target1Address, _target1OriginalBytes));
            }
            if (_hasInnerCodePatch && _innerCodeAddress != IntPtr.Zero && _innerCodeOriginalBytes != null)
            {
                SafeTry("Restore innerCode", () => Jumper.Restore(_innerCodeAddress, _innerCodeOriginalBytes));
            }
            if (_hasTarget2Patch && _target2Loc != IntPtr.Zero)
            {
                SafeTry("Restore target2", () => MemOps.WriteIntPtrCell(_target2Loc, _target2OriginalValue));
            }
            if (_hasFixupJitAddrPatch && _fixupJitAddrLoc != IntPtr.Zero)
            {
                SafeTry("Restore fixupJitAddr", () => MemOps.WriteIntPtrCell(_fixupJitAddrLoc, _fixupJitAddrOriginal));
            }
        }

        private void ReapplyAll()
        {
            if (_slotAddresses != null)
            {
                foreach (IntPtr slotAddress in _slotAddresses)
                {
                    SafeTry("ReapplySlot " + slotAddress, () => SlotPatcher.ReplaceSlot(slotAddress, _newSlotValue));
                }
            }
            ReapplyCodePatch();
        }

        private void ReapplyCodePatch()
        {
            switch (_patchType)
            {
                case 1:
                    if (_indirectTargetLoc == IntPtr.Zero)
                    {
                        break;
                    }
                    SafeTry("Reapply indirectTargetLoc", () => MemOps.WriteIntPtrCell(_indirectTargetLoc, _newSlotValue));
                    break;
                case 2:
                    if (_patchAddress != IntPtr.Zero && _nearTrampoline != IntPtr.Zero)
                    {
                        SafeTry("Reapply patchAddress case2", () =>
                        {
                            byte[] array = Jumper.BuildRelJump(_patchAddress, _nearTrampoline);
                            MemOps.WriteBytesProtected(_patchAddress, array);
                        });
                    }
                    break;
                case 3:
                    if (_patchAddress != IntPtr.Zero)
                    {
                        SafeTry("Reapply patchAddress case3", () => Jumper.WriteJump(_patchAddress, _newSlotValue));
                    }
                    break;
            }
            if (_hasSecondaryPatch && _secondaryJitAddress != IntPtr.Zero)
            {
                SafeTry("Reapply secondaryJit", () =>
                {
                    IntPtr secondaryTarget = _secondaryTrampoline != IntPtr.Zero
                        ? _secondaryTrampoline
                        : _newSlotValue;
                    byte[] patch = Jumper.BuildRelJump(_secondaryJitAddress, secondaryTarget);
                    MemOps.WriteBytesProtected(_secondaryJitAddress, patch);
                });
            }
            if (_hasTarget1Patch && _target1Address != IntPtr.Zero)
            {
                SafeTry("Reapply target1", () =>
                {
                    byte[] patch = Jumper.BuildAbsJumpX64(_newSlotValue);
                    MemOps.WriteBytesProtected(_target1Address, patch);
                });
            }
            if (_hasInnerCodePatch && _innerCodeAddress != IntPtr.Zero)
            {
                SafeTry("Reapply innerCode", () =>
                {
                    byte[] patch = Jumper.BuildAbsJumpX64(_newSlotValue);
                    MemOps.WriteBytesProtected(_innerCodeAddress, patch);
                });
            }
            if (_hasTarget2Patch && _target2Loc != IntPtr.Zero)
            {
                SafeTry("Reapply target2", () => MemOps.WriteIntPtrCell(_target2Loc, _newSlotValue));
            }
            if (_hasFixupJitAddrPatch && _fixupJitAddrLoc != IntPtr.Zero)
            {
                SafeTry("Reapply fixupJitAddr", () => MemOps.WriteIntPtrCell(_fixupJitAddrLoc, _newSlotValue));
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

        // ReadBytesSafe moved to MemOps.ReadBytesSafe (unified low-level API).
    }
}
