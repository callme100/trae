using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace Crane.MethodHook
{
    public sealed partial class MethodHook : IDisposable
    {
        private readonly MethodBase _targetMethod;

        private readonly MethodBase _hookMethod;

        private List<IntPtr> _slotAddresses;

        private IntPtr _originalSlotValue;

        /// <summary>
        /// Per-slot original values saved BEFORE patching, parallel to
        /// <see cref="_slotAddresses"/>. SlotPatcher.FindSlots can find slots
        /// holding DIFFERENT original values (e.g. the first precode address AND
        /// the boxed→unboxed thunk address for value-type instance methods).
        /// Restoring all slots to a single shared value corrupts the slots that
        /// had a different original, creating a circular dispatch loop between
        /// the two precodes. This list preserves each slot's true original.
        /// </summary>
        private List<IntPtr> _originalSlotValues;

        private IntPtr _newSlotValue;

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

        /// <summary>
        /// Target method's JIT code address, resolved in Install() BEFORE slot
        /// replacement. Saved here so InstallSecondaryJitPatch can reuse it
        /// instead of calling ResolveRealEntry again (which would follow the
        /// now-modified MethodTable slot and resolve to the hook's address,
        /// creating an infinite loop — especially when tiered compilation is
        /// disabled, e.g. when a debugger is attached).
        /// </summary>
        private IntPtr _targetJitCode;

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

        /// <summary>
        /// True when the FF 25 precode's indirect target data cell has been
        /// patched independently of _patchType. On .NET 8+, the CLR may
        /// overwrite this data cell during tiered compilation promotion,
        /// so we ALSO patch the precode instruction itself (_patchType=2).
        /// This flag ensures the data cell is still restored/reapplied
        /// during CallOriginal even when _patchType != 1.
        /// </summary>
        private bool _hasIndirectPatch;

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

        /// <summary>
        /// Re-entrancy guard for CallOriginal. When CallOriginal is executing
        /// (between RestoreAll and ReapplyAll), the patches are temporarily
        /// removed. If the delegate's Invoke method dispatches through the
        /// MethodTable slot (which may still be patched if RestoreAll failed
        /// to restore it — observed on .NET 8+ for CoreLib methods), the hook
        /// is re-entered, causing infinite recursion. This flag detects such
        /// re-entrancy and throws instead of crashing with AccessViolationException.
        /// </summary>
        private bool _inCallOriginal;

        private bool _isInstalled;

        private bool _isDisposed;

        public bool IsEnabled => _isInstalled;

        public MethodBase SourceMethod => _targetMethod;
        public MethodBase TargetMethod => _hookMethod;

        public HookDiagInfo DiagInfo { get; private set; }

        /// <summary>
        /// True when the hook patch was applied to raw JIT code (no precode) and
        /// the target method's IL is small enough to be JIT-inlined. On the
        /// legacy .NET Framework 4.x JIT64, direct calls to such methods may be
        /// inlined into callers, bypassing the hook. When this is true, inspect
        /// <see cref="DiagInfo"/>.<see cref="HookDiagInfo.InliningRiskMessage"/>
        /// for the recommended workaround (invoke via a delegate).
        /// </summary>
        public bool InliningRisk => DiagInfo != null && DiagInfo.InliningRisk;

        public MethodHook(MethodBase targetMethod, MethodBase hookMethod)
        {
            _targetMethod = targetMethod ?? throw new ArgumentNullException("targetMethod");
            _hookMethod = hookMethod ?? throw new ArgumentNullException("hookMethod");
        }

        public void StartHook()
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
            // Resolve the hook method's entry point for use as the patch jump target.
            //
            // We try ResolveRealEntry first for ALL methods. If the result looks
            // like real JIT code (function prologue), we use it directly — this
            // avoids the fixup helper entirely and is the safest option.
            //
            // If ResolveRealEntry does NOT return JIT code (e.g., it returned a
            // fixup helper address because the precode wasn't backpatched), we
            // fall back to the precode address. The FixupPrecode's FF 25 only
            // sets R10 (MethodDesc) via MOV R10, [rip+disp] and does NOT touch
            // parameter registers (RCX, RDX, R8, R9). On .NET 8, the fixup
            // helper can identify the method from the precode's own data
            // structures, so the precode address is a safe fallback.
            //
            // For GENERIC methods, the adapter trampoline shifts registers
            // before jumping to the hook, so we need the JIT code address
            // (not the precode address). ResolveRealEntry follows the
            // precode → fixup table chain to find it.
            IntPtr intPtr;
            IntPtr resolved = MethodEntryResolver.ResolveRealEntry(functionPointer2);
            // Resolve the target method's JIT code address. When the hook method's
            // precode is NOT backpatched (e.g., when tiered compilation is disabled
            // — which happens when a debugger is attached), ResolveRealEntry may
            // follow the hook's precode → fixup helper chain and end up at the
            // TARGET method's JIT code address. Using that as the jump target
            // creates an infinite loop (target JIT code is E9-patched to jump
            // back to the same address). Detect and prevent this.
            IntPtr targetJitCode = MethodEntryResolver.ResolveRealEntry(functionPointer);
            // Save the target's JIT code address BEFORE slot replacement.
            // InstallSecondaryJitPatch reuses this instead of re-resolving,
            // because ResolveRealEntry called after slot replacement would
            // follow the modified MethodTable slot and resolve to the hook's
            // address — creating an infinite loop (debug mode / tiered-off).
            _targetJitCode = targetJitCode;
            if (_needsGenericAdapter)
            {
                intPtr = resolved;
                if (intPtr == IntPtr.Zero || intPtr == targetJitCode) intPtr = functionPointer2;
            }
            else if (resolved != IntPtr.Zero && resolved != functionPointer2
                     && resolved != targetJitCode
                     && LooksLikeRealJitCode(resolved))
            {
                // Resolved entry is real JIT code — use it directly to avoid
                // the fixup helper entirely.
                intPtr = resolved;
            }
            else
            {
                // Resolved entry is fixup helper, zero, or collides with the
                // target's JIT code — fall back to precode. The precode's FF 25
                // will route through the fixup helper, which backpatches the
                // precode and jumps to the hook's real JIT code on first call.
                intPtr = functionPointer2;
            }
            // Record hook precode diagnostics for troubleshooting.
            hookDiagInfo.HookPrecodeAddr = functionPointer2;
            hookDiagInfo.HookPrecodeBytes = MemOps.ReadBytesSafe(functionPointer2, 32);
            hookDiagInfo.HookResolvedEntry = intPtr;
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
            if (NeedsValueTypeAdapter())
            {
                // Value-type instance methods receive 'this' as a managed pointer
                // (byref) in RCX: RCX = &T. A static hook with signature Hook(T self)
                // expects the value by-value in RCX. Build an adapter that dereferences
                // the pointer (MOV RCX, [RCX]) before jumping to the hook, converting
                // byref → byval. Only for structs ≤ 8 bytes (single register).
                byte[] adapterBytes = BuildValueTypeAdapterBytes();
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
            _newSlotValue = intPtr;
            hookDiagInfo.JumpTargetAddr = intPtr;
            InstallSlotReplacement(functionPointer, intPtr, hookDiagInfo);
            // Set _isInstalled before InstallCodePatch so that if the hook is triggered
            // during patch installation (e.g., by String.Format or other BCL methods),
            // CallOriginal can correctly restore/invoke/reapply instead of throwing.
            _isInstalled = true;
            InstallCodePatch(functionPointer, intPtr, hookDiagInfo);
            // Correct _originalIndirectTarget if InstallSlotReplacement (called
            // BEFORE InstallCodePatch) already patched the indirect data cell.
            // SlotPatcher.FindSlots scans the MethodTable region (65536 bytes)
            // and may find the indirect cell (at precode+disp) within that range,
            // replacing it with the hook's jump target. When InstallCodePatch
            // subsequently reads the cell to capture _originalIndirectTarget, it
            // gets the hook's address instead of the true original. After
            // RestoreAll, the cell is "restored" to the hook's address, leaving
            // the hook active even after Uninstall — causing "Hook is not
            // installed" errors on subsequent CallOriginal calls.
            // Fix: if the captured original matches the hook's jump target, look
            // up the true original from the per-slot saved values.
            if (_indirectTargetLoc != IntPtr.Zero &&
                _slotAddresses != null && _originalSlotValues != null &&
                _originalIndirectTarget == _newSlotValue)
            {
                for (int i = 0; i < _slotAddresses.Count; i++)
                {
                    if (_slotAddresses[i] == _indirectTargetLoc && i < _originalSlotValues.Count)
                    {
                        _originalIndirectTarget = _originalSlotValues[i];
                        break;
                    }
                }
            }
            // Post-install verification: on .NET 8+, tiered promotion may
            // replace the precode DURING or shortly AFTER patch installation,
            // orphaning our patches. Detect this by re-checking
            // GetFunctionPointer() and the precode's first byte.
            if (Environment.Version.Major >= 8)
            {
                IntPtr postFp = _targetMethod.MethodHandle.GetFunctionPointer();
                if (postFp != IntPtr.Zero && postFp != functionPointer)
                {
                    hookDiagInfo.PatchError += "; WARNING: Precode replaced during install (0x"
                        + functionPointer.ToInt64().ToString("X") + " -> 0x"
                        + postFp.ToInt64().ToString("X")
                        + "). Patches may be orphaned. Consider re-installing the hook.";
                }
                else if (postFp == functionPointer)
                {
                    // Precode address unchanged — verify the E9 instruction
                    // patch is still in place.
                    byte[] verify = MemOps.ReadBytesSafe(functionPointer, 2);
                    if (verify != null && verify.Length >= 1 && verify[0] != 0xE9)
                    {
                        hookDiagInfo.PatchError += "; WARNING: Precode E9 patch lost after install"
                            + " (first byte=0x" + verify[0].ToString("X2")
                            + "). Tiered promotion may have overwritten the precode.";
                    }
                }
            }
            EvaluateInliningRisk(hookDiagInfo);
            DiagInfo = hookDiagInfo;
        }

        /// <summary>
        /// Detects whether the hook is at risk of being bypassed by JIT inlining.
        ///
        /// When the patch is applied to raw JIT code (PatchTarget == "JitCode",
        /// i.e. GetFunctionPointer returned the JIT code directly with no precode),
        /// the legacy .NET Framework 4.x JIT64 may inline the target method's body
        /// into its callers. An inlined call contains no CALL instruction, so the
        /// patch is never reached and the hook does not trigger for direct calls.
        /// This most commonly affects small static methods (e.g. DateTime.Compare).
        ///
        /// This is informational only — the hook still works for non-inlined call
        /// sites (delegate invocations, MethodInfo.Invoke, callers too large to
        /// inline). The recommended workaround is to invoke the target method
        /// through a delegate (Func&lt;...&gt;), which the JIT cannot inline.
        /// </summary>
        private void EvaluateInliningRisk(HookDiagInfo diag)
        {
            if (diag == null) return;
            string target = diag.PatchTarget ?? "";
            if (!target.StartsWith("JitCode", StringComparison.Ordinal))
            {
                // Precode / Slot patches funnel all calls through a single entry
                // point; inlining is not a concern there.
                return;
            }

            int ilSize = -1;
            try
            {
                MethodBody body = (_targetMethod as MethodInfo)?.GetMethodBody();
                if (body != null)
                {
                    byte[] il = body.GetILAsByteArray();
                    if (il != null) ilSize = il.Length;
                }
            }
            catch
            {
                // Some methods (e.g. intrinsics, P/Invoke) have no IL body.
            }

            // The legacy JIT64 inlines methods whose IL is small (typically <= ~64
            // bytes). Flag the risk when IL is small enough to be inlined. Even
            // when IL size is unknown, the JitCode patch target itself is a risk
            // signal on .NET Framework 4.x.
            bool frameworkIsNetFx = Environment.Version.Major < 6;
            bool smallIl = ilSize >= 0 && ilSize <= 64;
            if (smallIl || (frameworkIsNetFx && ilSize < 0))
            {
                diag.InliningRisk = true;
                diag.InliningRiskMessage = string.Format(
                    "Patch is on raw JIT code (no precode). IL size={0}. " +
                    "On .NET Framework 4.x the legacy JIT64 may inline this method " +
                    "into callers, bypassing the hook for direct calls. " +
                    "Workaround: invoke via a delegate (Func<...>) which the JIT " +
                    "cannot inline, or mark the caller with [MethodImpl(NoInlining)].",
                    ilSize < 0 ? "unknown" : ilSize.ToString());
            }
        }

        private void PrepareMethod(MethodBase method)
        {
            // For non-generic methods on constructed generic types (e.g. anonymous
            // type ToString, List<int>.Add), RuntimeHelpers.PrepareMethod without
            // instantiation throws ArgumentException ("The given generic
            // instantiation was invalid.") on .NET Framework 4.x. The method handle
            // is for the constructed type, but the API still requires the type's
            // generic arguments to be passed explicitly. Build the instantiation
            // from the declaring type's type arguments (and, for generic methods,
            // the method's own type arguments) and call the overloaded PrepareMethod.
            Type declaringType = method.DeclaringType;
            bool isOnConstructedGenericType = declaringType != null
                && declaringType.IsGenericType
                && !declaringType.IsGenericTypeDefinition;
            if (isOnConstructedGenericType)
            {
                try
                {
                    var handles = new List<RuntimeTypeHandle>();
                    foreach (Type t in declaringType.GetGenericArguments())
                        handles.Add(t.TypeHandle);
                    if (method.IsGenericMethod)
                    {
                        foreach (Type t in method.GetGenericArguments())
                            handles.Add(t.TypeHandle);
                    }
                    RuntimeHelpers.PrepareMethod(method.MethodHandle, handles.ToArray());
                    return;
                }
                catch
                {
                    // If instantiation fails, fall through to the non-instantiated
                    // call below (works on .NET 6+ which tolerates missing args).
                }
            }
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
            // Skip DynamicInvoke for value-type instance methods on .NET Framework 4.x.
            // These methods typically have E8 precodes whose fixup code is a CLR helper
            // (not the inline generic dictionary setup pattern), so we cannot extract
            // the JIT code address to patch it. DynamicInvoke backpatches direct call
            // sites to call JIT code directly, bypassing our precode patch entirely.
            // By skipping DynamicInvoke, call sites remain un-backpatched and go through
            // the precode (which we patch with E8→E9), triggering the hook.
            // PrepareMethod (called earlier) already JIT-compiles non-generic methods.
            if (Environment.Version.Major < 6
                && !mi.IsStatic
                && mi.DeclaringType != null
                && mi.DeclaringType.IsValueType)
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

                // On .NET 8+, force tiered compilation promotion by calling the
                // method many times. Tiered promotion can invalidate patches
                // applied to tier-0 JIT code — the CLR compiles new tier-1 code
                // at a different address and updates the precode's data cell,
                // orphaning our secondary JIT patch. Call sites that bypass the
                // precode (calling JIT code directly) then miss the hook entirely.
                // By forcing promotion BEFORE patching, we ensure ResolveRealEntry
                // returns the stable tier-1 JIT code address, and our patches are
                // applied to code that will not be promoted again.
                if (Environment.Version.Major >= 8 && !mi.IsGenericMethod)
                {
                    for (int i = 0; i < 50; i++)
                    {
                        try
                        {
                            if (_originalDelegate != null)
                                _originalDelegate.DynamicInvoke(invokeArgs);
                            else
                                mi.Invoke(instance, methodArgs);
                        }
                        catch
                        {
                            // Expected — dummy args may throw, but the call
                            // counter for tiered promotion increments regardless.
                        }
                    }
                    // Wait briefly for the background tier-1 JIT thread to
                    // complete compilation and update the precode's data cell.
                    System.Threading.Thread.Sleep(50);
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

                // For value-type instance methods, Delegate.CreateDelegate with
                // Func<T,...> fails because the CLR passes 'this' as a managed
                // pointer (byref), but Func<T,...> expects T byval. We use
                // Expression.Lambda to create a delegate that boxes/unboxes
                // automatically, providing a byval-compatible wrapper.
                bool isValueTypeInstance = !methodInfo.IsStatic
                    && methodInfo.DeclaringType != null
                    && methodInfo.DeclaringType.IsValueType;

                if (isValueTypeInstance)
                {
                    // Build an Expression that calls the method via a boxed parameter.
                    // The delegate accepts T byval (boxed in object for DynamicInvoke),
                    // and the expression unboxes to byref before calling the method.
                    ParameterExpression[] exprParams = new ParameterExpression[totalTypeArgs - (isVoid ? 0 : 1)];
                    int pi = 0;
                    ParameterExpression instanceParam = Expression.Parameter(methodInfo.DeclaringType, "instance");
                    exprParams[pi++] = instanceParam;
                    for (int i = 0; i < parameters.Length; i++)
                    {
                        exprParams[pi++] = Expression.Parameter(parameters[i].ParameterType, "p" + i);
                    }

                    // Call the method. For value-type instance methods, Expression.Call
                    // automatically handles the byref 'this' conversion.
                    Expression callExpr = Expression.Call(instanceParam, methodInfo, exprParams.Skip(1).Cast<Expression>());
                    if (isVoid)
                    {
                        Type actionType = Expression.GetActionType(exprParams.Select(p => p.Type).ToArray());
                        _originalDelegate = Expression.Lambda(actionType, callExpr, exprParams).Compile();
                    }
                    else
                    {
                        Type funcType = Expression.GetFuncType(exprParams.Select(p => p.Type).Append(returnType).ToArray());
                        _originalDelegate = Expression.Lambda(funcType, callExpr, exprParams).Compile();
                    }
                }
                else
                {
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
                }

                // Record the flat argument count (instance + declared params).
                _delegateFlatArgCount = parameters.Length + extraForInstance;

                // Capture the function pointer of the delegate's Invoke method.
                Type actualDelegateType = _originalDelegate.GetType();
                MethodInfo invokeMethod = actualDelegateType.GetMethod("Invoke");
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
            catch (Exception)
            {
                _originalDelegate = null;
                _delegateInvokeFptr = IntPtr.Zero;
                _delegateFlatArgCount = 0;
            }
        }

        public void StopHook()
        {
            if (!_isInstalled)
            {
                return;
            }
            // RestoreAll FIRST, before any diagnostic logging.
            RestoreAll();
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
            if (_hookAdapterTrampoline != IntPtr.Zero)
            {
                SafeTry("FreeExec hookAdapterTrampoline", () => Memory.FreeExec(_hookAdapterTrampoline, 12));
                _hookAdapterTrampoline = IntPtr.Zero;
            }
            _isInstalled = false;
        }

        private static string ByteHex(byte[] b)
        {
            if (b == null) return "null";
            var sb = new System.Text.StringBuilder(b.Length * 3);
            for (int i = 0; i < b.Length; i++) { if (i > 0) sb.Append(' '); sb.Append(b[i].ToString("X2")); }
            return sb.ToString();
        }
        private static IntPtr ReadIntPtrCellSafe(IntPtr addr)
        {
            if (addr == IntPtr.Zero) return IntPtr.Zero;
            try { return Marshal.ReadIntPtr(addr); } catch { return IntPtr.Zero; }
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
                // Use per-slot original values when available: SlotPatcher may find
                // slots with DIFFERENT originals (precode addr vs boxed→unboxed
                // thunk). Falling back to the shared _originalSlotValue would
                // corrupt the thunk-pointing slot and loop forever on the next call.
                int count = _slotAddresses.Count;
                for (int i = 0; i < count; i++)
                {
                    IntPtr slotAddress = _slotAddresses[i];
                    IntPtr originalValue = (_originalSlotValues != null && i < _originalSlotValues.Count)
                        ? _originalSlotValues[i]
                        : _originalSlotValue;
                    IntPtr captured = originalValue;
                    IntPtr capturedSlot = slotAddress;
                    SafeTry("RestoreSlot " + capturedSlot, () => SlotPatcher.ReplaceSlot(capturedSlot, captured));
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
            // Restore the indirect data cell independently when _hasIndirectPatch
            // is set (used with _patchType=2 E9 instruction patch on FF 25 precode).
            // This is NOT needed for _patchType=1 (case 1 already handles it).
            if (_hasIndirectPatch && _patchType != 1 && _indirectTargetLoc != IntPtr.Zero)
            {
                SafeTry("Restore indirectTargetLoc (hasIndirect)", () => MemOps.WriteIntPtrCell(_indirectTargetLoc, _originalIndirectTarget));
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
            // Reapply the indirect data cell independently when _hasIndirectPatch
            // is set (used with _patchType=2 E9 instruction patch on FF 25 precode).
            // This is NOT needed for _patchType=1 (case 1 already handles it).
            if (_hasIndirectPatch && _patchType != 1 && _indirectTargetLoc != IntPtr.Zero)
            {
                SafeTry("Reapply indirectTargetLoc (hasIndirect)", () => MemOps.WriteIntPtrCell(_indirectTargetLoc, _newSlotValue));
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
                StopHook();
                _isDisposed = true;
            }
        }

        // ReadBytesSafe moved to MemOps.ReadBytesSafe (unified low-level API).
    }
}
