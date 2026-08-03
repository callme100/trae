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
        /// <summary>
        /// Lock object protecting StartHook/StopHook/Dispose from concurrent
        /// execution on the same instance. Install/uninstall modify mutable
        /// patch state (_slotAddresses, _originalBytes, trampoline pointers)
        /// that must not be touched by two threads simultaneously.
        /// </summary>
        private readonly object _stateLock = new object();

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
        /// On .NET 8+, the precode's second FF 25 data cell points to the tier-1
        /// JIT code address. Call sites that have been backpatched by tiered
        /// compilation call this address DIRECTLY (not through the data cell),
        /// bypassing the Target2Patch data cell patch. We must also patch the JIT
        /// code at this address with a 12-byte absolute jump to the adapter.
        /// </summary>
        private bool _hasTarget2JitPatch;

        private IntPtr _target2JitAddress;

        private byte[] _target2JitOriginalBytes;

        /// <summary>
        /// The shared CLR FixupPrecode fixup helper address, read from the HOOK
        /// method's precode target2 data cell during StartHook. In CoreCLR, every
        /// FixupPrecode's second FF 25 target points to the SAME shared helper
        /// (FixupPrecode::Fixup). Patching this shared address with a method-
        /// specific absolute jump corrupts ALL precodes that dispatch through it.
        ///
        /// In .NET 8 Debug + tiered compilation ON (no debugger attached), the
        /// hook method's own precode may not be tier-1 backpatched yet, so it
        /// dispatches through this shared helper. If the helper is patched to
        /// redirect to the hook's adapter, the dispatch loops forever:
        ///   adapter → hook precode → shared helper (patched) → adapter → ...
        /// This field is used to guard InstallTarget2Patch against patching the
        /// shared helper.
        /// </summary>
        private IntPtr _sharedFixupHelperAddr;

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
        /// Generic dictionary address extracted from the target method's fixup
        /// thunk BEFORE EnsureJitCompiled backpatches the precode. On .NET 6, the
        /// E9 precode for a generic method is backpatched to point directly to JIT
        /// code, destroying the fixup thunk. Extracting the dictionary address
        /// after backpatching fails (ExtractGenericDictionaryFromFixup returns
        /// Zero), so the generic dictionary slot scan in InstallSlotReplacement is
        /// skipped — direct call sites that load the code pointer from the
        /// dictionary bypass the hook. This saved value is used as a fallback when
        /// the live extraction fails.
        /// </summary>
        private IntPtr _savedGenericDictionaryAddr;

        /// <summary>
        /// Re-entrancy guard for CallOriginal. When CallOriginal is executing
        /// (between RestoreAll and ReapplyAll), the patches are temporarily
        /// removed. If the delegate's Invoke method dispatches through the
        /// MethodTable slot (which may still be patched if RestoreAll failed
        /// to restore it — observed on .NET 8+ for CoreLib methods), the hook
        /// is re-entered, causing infinite recursion. This flag detects such
        /// re-entrancy and throws instead of crashing with AccessViolationException.
        ///
        /// Marked volatile so the re-entrancy check is visible across threads
        /// (e.g., when the hook is triggered on a GC/Finalizer thread while
        /// InvokeOriginal is running on the main thread).
        /// </summary>
        private volatile bool _inCallOriginal;

        /// <summary>
        /// Re-entrancy counter for CallOriginal. Counts how many times
        /// InvokeOriginal has been re-entered on the same hook instance.
        /// If this exceeds <see cref="HookConstants.MaxReentrancyCount"/>, the
        /// re-entrancy guard returns a default value instead of throwing,
        /// breaking potential infinite loops caused by tier-0 delegate Invoke
        /// retry stubs on .NET 8 Debug mode.
        /// </summary>
        private int _reentrancyCount;

        private bool _isInstalled;

        private volatile bool _isDisposed;

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
            lock (_stateLock)
            {
                if (_isInstalled)
                {
                    return;
                }
                if (_isDisposed)
                {
                    throw new ObjectDisposedException("MethodHook");
                }
                StartHookCore();
            }
        }

        /// <summary>
        /// Core hook installation logic. Caller must hold <see cref="_stateLock"/>.
        /// </summary>
        private void StartHookCore()
        {
            HookDiagInfo hookDiagInfo = new HookDiagInfo();
            hookDiagInfo.TargetMethod = _targetMethod.ToString();
            hookDiagInfo.HookMethod = _hookMethod.ToString();
            // Assign DiagInfo early so it is available for debugging even if
            // StartHook throws before reaching the final assignment at the end.
            DiagInfo = hookDiagInfo;
            // Set NoInlining on the target's MethodDesc to prevent the legacy
            // JIT64 (.NET Framework 4.x) from inlining the target into callers.
            // For value-type instance methods, this also calls PrepareMethod
            // first to establish a stable JIT entry point — without it,
            // NoInlining is silently ignored for constrained.callvirt.
            TrySetNoInlining(_targetMethod);
            PrepareMethod(_targetMethod);
            PrepareMethod(_hookMethod);
            // Create a delegate to the original method BEFORE any patching.
            // The delegate's Invoke method is JIT-compiled with the correct generic
            // dictionary setup (R10), bypassing RuntimeMethodHandle.InvokeMethod
            // which crashes (0x80131506) for hooked generic methods.
            CreateOriginalDelegate();
            // Disable tiered compilation for the target method BEFORE JIT
            // compilation. This prevents the CLR from promoting tier-0 JIT code
            // to tier-1 at a different address, which would orphan our patches.
            // This replaces the former approach of calling the method 50 times
            // to force tier-1 promotion.
            bool tieredDisabled = TryDisableTieredCompilation(_targetMethod);
            // For generic methods, extract the generic dictionary address from the
            // fixup thunk BEFORE EnsureJitCompiled backpatches the precode. On .NET 6,
            // the E9 precode is backpatched to point to JIT code, destroying the
            // fixup thunk — so ExtractGenericDictionaryFromFixup would return Zero
            // after backpatching. We save the address here and use it as a fallback
            // in InstallSlotReplacement when the live extraction fails.
            if (_targetMethod.IsGenericMethod)
            {
                try
                {
                    IntPtr preBackpatchFp = _targetMethod.MethodHandle.GetFunctionPointer();
                    _savedGenericDictionaryAddr = ExtractGenericDictionaryFromFixup(preBackpatchFp);
                }
                catch (Exception ex) {  }
            }
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
                // For generic methods, the adapter trampoline shifts registers
                // (generic dictionary in RDX/RCX) before jumping to the hook.
                //
                // On .NET 8+ Release (tiered compilation on), ResolveRealEntry
                // for the HOOK method's precode may resolve through shared CLR
                // fixup helpers and end up at the TARGET method's JIT code address
                // — not the hook's. Using that as the adapter jump target creates
                // an infinite loop: adapter → target JIT (E9-patched) → adapter → ...
                //
                // The existing `intPtr == targetJitCode` check only compares against
                // ResolveRealEntry(target precode), which may differ from the
                // MethodDesc-scanned JIT address. To be safe, always use the hook's
                // precode address (functionPointer2) for generic methods. The
                // FixupPrecode's FF 25 does not touch parameter registers
                // (RCX/RDX/R8/R9), so the adapter's register shuffle is preserved.
                intPtr = functionPointer2;
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
            // Read the shared fixup helper address from the hook method's precode
            // target2 data cell. In CoreCLR, every FixupPrecode's target2 points
            // to the SAME shared helper. Patching it corrupts all precodes that
            // dispatch through it (causing infinite loops in .NET 8 Debug + tiered
            // mode where the hook's own precode is not yet tier-1 backpatched).
            _sharedFixupHelperAddr = ReadFixupPrecodeTarget2(functionPointer2);
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
                intPtr = TryInstallAdapterTrampoline(intPtr, adapterBytes, hookDiagInfo);
            }
            if (NeedsValueTypeAdapter())
            {
                // Value-type instance methods receive 'this' as a managed pointer
                // (byref) in RCX: RCX = &T. A static hook with signature Hook(T self)
                // expects the value by-value in RCX. Build an adapter that dereferences
                // the pointer (MOV RCX, [RCX]) before jumping to the hook, converting
                // byref → byval. Only for structs ≤ 8 bytes (single register).
                byte[] adapterBytes = BuildValueTypeAdapterBytes();
                intPtr = TryInstallAdapterTrampoline(intPtr, adapterBytes, hookDiagInfo);
            }
            _newSlotValue = intPtr;
            hookDiagInfo.JumpTargetAddr = intPtr;
            InstallSlotReplacement(functionPointer, intPtr, hookDiagInfo);
            // Set _isInstalled before InstallCodePatch so that if the hook is triggered
            // during patch installation (e.g., by String.Format or other BCL methods),
            // CallOriginal can correctly restore/invoke/reapply instead of throwing.
            _isInstalled = true;
            try
            {
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
            }
            catch (Exception ex)
            {
                // InstallCodePatch failed after slot replacement was already applied.
                // Roll back ALL patches (slots + partial code patches + trampolines)
                // to avoid leaving the runtime in an inconsistent state where some
                // calls are redirected (via slots) but others are not.
                hookDiagInfo.PatchError += "; StartHook failed during InstallCodePatch: " + ex.Message;
                try { StopHook(); } catch { /* best-effort rollback */ }
                throw;
            }
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
        /// Clears the <c>IsEligibleForTieredCompilation</c> flag on the target
        /// method's MethodDesc so the CLR will not promote its JIT code from
        /// tier-0 to tier-1. This ensures patches applied to the current JIT
        /// code address remain stable — the CLR won't compile new code at a
        /// different address and orphan our secondary JIT patch.
        ///
        /// This is the preferred alternative to forcing tier-1 promotion by
        /// calling the method many times (which is slow and has side effects).
        /// By disabling tiered compilation for just this one method, the JIT
        /// code address we patch at install time remains valid for the lifetime
        /// of the hook.
        ///
        /// MethodDesc flag layout (RELEASE build, x64):
        ///   .NET 6/7: m_bFlags2 at offset 3, bit 0x20
        ///   .NET 8+ : m_wFlags3AndTokenRemainder at offset 0, bit 0x8000
        ///
        /// Returns true if the flag was found and cleared, false if the
        /// runtime version is unsupported or the flag could not be verified.
        /// </summary>
        private bool TryDisableTieredCompilation(MethodBase method)
        {
            // Tiered compilation only exists on .NET Core 3.0+ / .NET 5+.
            // .NET Framework 4.x has no tiered compilation — nothing to disable.
            if (Environment.Version.Major < 6)
                return false;

            IntPtr md = method.MethodHandle.Value;
            if (md == IntPtr.Zero) return false;
            // MethodDesc is only 8 bytes in RELEASE layout, but we read a few
            // extra bytes for the sanity-check verification below.
            if (!Memory.IsReadable(md, 8)) return false;

            try
            {
                if (Environment.Version.Major >= 8)
                {
                    // .NET 8+: flag is in m_wFlags3AndTokenRemainder at offset 0
                    // Sanity check: HasStableEntryPoint or HasPrecode should be set
                    // after RuntimeHelpers.PrepareMethod (called earlier in StartHook).
                    ushort flags = (ushort)Marshal.ReadInt16(md, 0);
                    if ((flags & HookConstants.Flag3StableMask) == 0)
                    {
                        // Neither HasStableEntryPoint nor HasPrecode is set —
                        // likely a DEBUG runtime (extra fields shift the offset)
                        // or an unexpected MethodDesc layout. Bail out safely.
                        return false;
                    }
                    if ((flags & HookConstants.Flag3IsEligibleForTieredCompilation) == 0)
                        return true; // Already not eligible — nothing to do.

                    ushort cleared = (ushort)(flags & ~HookConstants.Flag3IsEligibleForTieredCompilation);
                    Memory.ProtectReadWrite(md, 2);
                    Marshal.WriteInt16(md, 0, (short)cleared);
                    return true;
                }
                else
                {
                    // .NET 6/7: flag is in m_bFlags2 at offset 3
                    // Sanity check: HasStableEntryPoint or HasPrecode should be set.
                    byte flags = MemOps.ReadByte(md + 3);
                    if ((flags & HookConstants.Flag2StableMask) == 0)
                        return false;
                    if ((flags & HookConstants.Flag2IsEligibleForTieredCompilation) == 0)
                        return true; // Already not eligible.

                    byte clearedByte = (byte)(flags & ~HookConstants.Flag2IsEligibleForTieredCompilation);
                    Memory.ProtectReadWrite(md + 3, 1);
                    Marshal.WriteByte(md + 3, clearedByte);
                    return true;
                }
            }
            catch (Exception ex)
            {
                DiagInfo?.AppendPatchError("TryDisableTieredCompilation", ex);
                return false;
            }
        }

        /// <summary>
        /// Prepares a target method for hooking by setting the NoInlining flag
        /// on its MethodDesc. This prevents the JIT from inlining the method
        /// into callers, ensuring that direct calls go through the method's
        /// precode/JIT code entry point (which the hook patches).
        ///
        /// CRITICAL: This MUST be called BEFORE the caller method is JIT-compiled.
        /// On .NET Framework 4.x Release mode, the legacy JIT64 inlines small
        /// method calls (including constrained.callvirt on value-type instance
        /// methods such as DateTime.ToString / Int32.ToString) at caller
        /// compilation time. If the caller is already compiled (e.g., the hook
        /// is installed inside the caller), setting NoInlining afterwards has
        /// no effect — the inlined call sites bypass the hook permanently.
        ///
        /// Typical usage: call PrepareForHooking from Main (or another method
        /// that runs before the test/caller method is invoked) for each target
        /// method you intend to hook.
        ///
        /// Note: On .NET 6+ (CoreCLR), this is a no-op — RyuJIT does not inline
        /// the target methods, so the flag is not needed. On .NET Framework 4.x
        /// (x64), this sets the internal NoInlining flag (bit 0x2000) at
        /// MethodDesc offset 6 (m_wFlags). For value-type instance methods, it
        /// also calls RuntimeHelpers.PrepareMethod first to establish a stable
        /// JIT entry point — without this, NoInlining is silently ignored for
        /// constrained.callvirt by the legacy JIT64 inliner.
        ///
        /// Returns true if the flag was set (or was already set). Returns false
        /// if the runtime is unsupported or the MethodDesc could not be modified.
        /// </summary>
        public static bool PrepareForHooking(MethodBase method)
        {
            if (method == null) return false;
            return TrySetNoInlining(method);
        }

        /// <summary>
        /// Sets the NoInlining flag on the method's MethodDesc so the JIT does
        /// not inline it into callers. Must be called BEFORE the caller is
        /// JIT-compiled. On .NET 6+ this is a no-op (RyuJIT does not inline
        /// these methods). Only .NET Framework 4.x (x64) is supported.
        /// </summary>
        private static bool TrySetNoInlining(MethodBase method)
        {
            // NoInlining flag manipulation is only needed on .NET Framework 4.x,
            // where the legacy JIT64 inlines small method calls at caller
            // compilation time. On .NET 6+ (CoreCLR), RyuJIT does not inline
            // these methods, so PrepareForHooking is a no-op there.
            if (Environment.Version.Major >= 6)
                return false;

            IntPtr md = method.MethodHandle.Value;
            if (md == IntPtr.Zero) return false;
            if (!Memory.IsReadable(md, 8)) return false;

            try
            {
                // .NET Framework 4.x (CLR 4.0) x64 MethodDesc layout:
                //   offset 6: m_wFlags (2 bytes) — MethodImplAttributes + internal flags
                //
                // NoInlining corresponds to bit 0x2000 in m_wFlags (verified
                // empirically via probe methods marked with [MethodImpl(NoInlining)]).
                // The managed MethodImplAttributes.NoInlining (0x0008) is NOT the
                // bit the JIT64 inliner checks — writing 0x0008 corrupts internal
                // state and crashes (0xC0000005).
                //
                // For value-type instance methods (e.g. DateTime.ToString,
                // Int32.ToString), the legacy JIT64 inlines constrained.callvirt
                // calls. Setting NoInlining (0x2000) alone is NOT enough for these
                // methods — they also need a stable JIT entry point (HasStableEntryPoint
                // 0x0008 in m_wFlags, set by the CLR after PrepareMethod). Without
                // PrepareMethod, NoInlining is silently ignored for constrained.callvirt.
                // We call RuntimeHelpers.PrepareMethod first to force JIT
                // compilation and establish the stable entry point, THEN set
                // NoInlining. This combination successfully prevents
                // constrained.callvirt inlining on .NET Framework 4.x x64.
                ushort flags = (ushort)Marshal.ReadInt16(md, HookConstants.MethodDescFlagsOffset);

                // For value-type instance methods, force JIT compilation first.
                // BCL value-type methods (DateTime.ToString, Int32.ToString) lack
                // the HasStableEntryPoint flag until PrepareMethod is called.
                // Without it, NoInlining is ignored for constrained.callvirt.
                bool isValueTypeInstance = method.DeclaringType != null &&
                    method.DeclaringType.IsValueType && !method.IsStatic;
                if (isValueTypeInstance && (flags & HookConstants.HasStableEntryPointFlag) == 0)
                {
                    try
                    {
                        RuntimeHelpers.PrepareMethod(method.MethodHandle);
                    }
                    catch { }
                    flags = (ushort)Marshal.ReadInt16(md, HookConstants.MethodDescFlagsOffset);
                }

                if ((flags & HookConstants.NoInliningFlag) != 0)
                    return true; // Already set

                ushort newFlags = (ushort)(flags | HookConstants.NoInliningFlag);
                Memory.ProtectReadWrite(md + HookConstants.MethodDescFlagsOffset, 2);
                Marshal.WriteInt16(md, HookConstants.MethodDescFlagsOffset, (short)newFlags);
                return true;
            }
            catch
            {
                return false;
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

                // On .NET 8+, tiered compilation promotion is handled by
                // TryDisableTieredCompilation (called earlier in StartHook),
                // which clears the IsEligibleForTieredCompilation flag on the
                // MethodDesc. This prevents the CLR from promoting tier-0 JIT
                // code to tier-1 at a different address, so the single
                // DynamicInvoke above is sufficient — no need for 50 calls
                // or address-stabilization polling.
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
            catch (Exception ex)
            {
                _originalDelegate = null;
                _delegateInvokeFptr = IntPtr.Zero;
                _delegateFlatArgCount = 0;
                if (DiagInfo != null)
                {
                    DiagInfo.PatchError += "; CreateOriginalDelegate failed: " + ex.Message;
                }
            }
        }

        public void StopHook()
        {
            lock (_stateLock)
            {
                if (!_isInstalled)
                {
                    return;
                }
                StopHookCore();
            }
        }

        /// <summary>
        /// Core hook removal logic. Caller must hold <see cref="_stateLock"/>.
        /// </summary>
        private void StopHookCore()
        {
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

        /// <summary>
        /// Allocates an adapter trampoline near <paramref name="hookEntry"/> that
        /// executes <paramref name="adapterBytes"/> (register shuffle / dereference)
        /// then jumps to <paramref name="hookEntry"/>. On success, updates
        /// <see cref="_hookAdapterTrampoline"/> and diagnostic fields, and returns
        /// the trampoline address (subsequent patches jump to adapter → hook).
        /// On failure, returns <paramref name="hookEntry"/> unchanged.
        /// </summary>
        private IntPtr TryInstallAdapterTrampoline(IntPtr hookEntry, byte[] adapterBytes, HookDiagInfo diag)
        {
            if (adapterBytes == null || adapterBytes.Length == 0)
                return hookEntry;
            int trampSize = adapterBytes.Length + 12; // adapter + MOV RAX,imm64; JMP RAX
            IntPtr trampoline = Memory.AllocExecNear(hookEntry, trampSize);
            if (trampoline == IntPtr.Zero || trampoline == new IntPtr(-1))
                return hookEntry;
            MemOps.WriteBytes(trampoline, adapterBytes);
            byte[] jumpBytes = Jumper.BuildAbsJumpX64(hookEntry);
            MemOps.WriteBytes(trampoline + adapterBytes.Length, jumpBytes);
            _hookAdapterTrampoline = trampoline;
            diag.AdapterAddr = trampoline;
            diag.AdapterBytes = adapterBytes;
            return trampoline; // all patches now jump to adapter → hook
        }

        private void RestoreAll()
        {
            // Phase 1: Restore code patches FIRST (see RestoreCodePatch comment).
            RestoreCodePatch();
            // Phase 2: Restore slot data cells.
            // Slots are MethodTable entries (data cells) that may point to precode
            // or JIT code. They must be restored AFTER code patches so that calls
            // through restored slots reach unpatched code.
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
        }

        private void RestoreCodePatch()
        {
            // Phase 1: Restore ALL code patches FIRST.
            // Code patches (Jumper.Restore) write original bytes to executable code
            // addresses. They must be restored before any data cell that points to
            // them is restored. Otherwise, a call through the restored data cell
            // hits still-patched code → adapter → hook → InvokeOriginal re-entrancy.
            //
            // CRITICAL: No file I/O or string allocation is allowed in this method.
            // On .NET 8 Debug mode with tiered compilation disabled, any allocation
            // can trigger GC or JIT compilation that calls through still-patched
            // code paths (target1/innerCode/target2Jit), causing re-entrancy.
            if (_patchType == HookConstants.PatchTypeInstruction || _patchType == HookConstants.PatchTypeAbsolute)
            {
                RestoreCodeBytes("patchAddress", _patchAddress, _originalBytes);
            }
            RestoreCodeBytes("secondaryJit", _hasSecondaryPatch, _secondaryJitAddress, _secondaryJitOriginalBytes);
            RestoreCodeBytes("target1", _hasTarget1Patch, _target1Address, _target1OriginalBytes);
            RestoreCodeBytes("innerCode", _hasInnerCodePatch, _innerCodeAddress, _innerCodeOriginalBytes);
            RestoreCodeBytes("target2Jit", _hasTarget2JitPatch, _target2JitAddress, _target2JitOriginalBytes);

            // Phase 2: Restore ALL data cell patches.
            // Now that all code patches are restored, data cells can safely point
            // to their original code addresses without triggering re-entrancy.
            if (_patchType == HookConstants.PatchTypeIndirect)
            {
                RestoreDataCell("indirectTargetLoc", _indirectTargetLoc, _originalIndirectTarget);
            }
            if (_hasIndirectPatch && _patchType != HookConstants.PatchTypeIndirect)
            {
                RestoreDataCell("indirectTargetLoc(hasIndirect)", _indirectTargetLoc, _originalIndirectTarget);
            }
            RestoreDataCell("target2", _hasTarget2Patch, _target2Loc, _target2OriginalValue);
            RestoreDataCell("fixupJitAddr", _hasFixupJitAddrPatch, _fixupJitAddrLoc, _fixupJitAddrOriginal);
        }

        /// <summary>
        /// Restores original bytes at a code patch address. No-op if the patch
        /// was not installed or the address/bytes are invalid.
        /// </summary>
        private void RestoreCodeBytes(string name, bool hasPatch, IntPtr addr, byte[] original)
        {
            if (!hasPatch) return;
            RestoreCodeBytes(name, addr, original);
        }

        private void RestoreCodeBytes(string name, IntPtr addr, byte[] original)
        {
            if (addr == IntPtr.Zero || original == null) return;
            SafeTry("Restore " + name, () => Jumper.Restore(addr, original));
        }

        /// <summary>
        /// Restores an 8-byte data cell to its original pointer value.
        /// No-op if the patch was not installed or the address is invalid.
        /// </summary>
        private void RestoreDataCell(string name, bool hasPatch, IntPtr loc, IntPtr original)
        {
            if (!hasPatch) return;
            RestoreDataCell(name, loc, original);
        }

        private void RestoreDataCell(string name, IntPtr loc, IntPtr original)
        {
            if (loc == IntPtr.Zero) return;
            SafeTry("Restore " + name, () => MemOps.WriteIntPtrCell(loc, original));
        }

        private void ReapplyAll()
        {
            // Phase 1: Re-apply code patches FIRST (symmetric with RestoreAll).
            ReapplyCodePatch();
            // Phase 2: Re-apply slot data cells.
            if (_slotAddresses != null)
            {
                foreach (IntPtr slotAddress in _slotAddresses)
                {
                    SafeTry("ReapplySlot " + slotAddress, () => SlotPatcher.ReplaceSlot(slotAddress, _newSlotValue));
                }
            }
        }

        private void ReapplyCodePatch()
        {
            // Phase 1: Re-apply ALL code patches FIRST.
            // Symmetric with RestoreCodePatch: code patches are re-applied before
            // data cell patches. This ensures that when a data cell is patched to
            // point to the adapter, the code at the data cell's original target is
            // already patched too — closing the window where direct calls to JIT
            // code could bypass the hook.
            if (_patchType == HookConstants.PatchTypeInstruction)
            {
                if (_patchAddress != IntPtr.Zero && _nearTrampoline != IntPtr.Zero)
                {
                    SafeTry("Reapply patchAddress case2", () =>
                    {
                        byte[] array = Jumper.BuildRelJump(_patchAddress, _nearTrampoline);
                        MemOps.WriteBytesProtected(_patchAddress, array);
                    });
                }
            }
            else if (_patchType == HookConstants.PatchTypeAbsolute)
            {
                if (_patchAddress != IntPtr.Zero)
                {
                    SafeTry("Reapply patchAddress case3", () => Jumper.WriteJump(_patchAddress, _newSlotValue));
                }
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
            // target1, innerCode, and target2Jit all use a 12-byte absolute
            // jump to _newSlotValue. Use the shared helper to reduce duplication.
            ReapplyAbsJumpPatch("target1", _hasTarget1Patch, _target1Address);
            ReapplyAbsJumpPatch("innerCode", _hasInnerCodePatch, _innerCodeAddress);
            ReapplyAbsJumpPatch("target2Jit", _hasTarget2JitPatch, _target2JitAddress);

            // Phase 2: Re-apply ALL data cell patches.
            if (_patchType == HookConstants.PatchTypeIndirect)
            {
                ReapplyDataCell("indirectTargetLoc", _indirectTargetLoc);
            }
            if (_hasIndirectPatch && _patchType != HookConstants.PatchTypeIndirect)
            {
                ReapplyDataCell("indirectTargetLoc(hasIndirect)", _indirectTargetLoc);
            }
            ReapplyDataCell("target2", _hasTarget2Patch, _target2Loc);
            ReapplyDataCell("fixupJitAddr", _hasFixupJitAddrPatch, _fixupJitAddrLoc);
        }

        /// <summary>
        /// Re-applies a 12-byte absolute jump patch (MOV RAX, hook; JMP RAX)
        /// at the given code address. No-op if the patch was not installed or
        /// the address is invalid.
        /// </summary>
        private void ReapplyAbsJumpPatch(string name, bool hasPatch, IntPtr addr)
        {
            if (!hasPatch || addr == IntPtr.Zero) return;
            SafeTry("Reapply " + name, () =>
            {
                byte[] patch = Jumper.BuildAbsJumpX64(_newSlotValue);
                MemOps.WriteBytesProtected(addr, patch);
            });
        }

        /// <summary>
        /// Re-applies a data cell patch (overwrites the 8-byte cell with the
        /// hook's jump target). No-op if the patch was not installed or the
        /// address is invalid.
        /// </summary>
        private void ReapplyDataCell(string name, bool hasPatch, IntPtr loc)
        {
            if (!hasPatch || loc == IntPtr.Zero) return;
            SafeTry("Reapply " + name, () => MemOps.WriteIntPtrCell(loc, _newSlotValue));
        }

        private void ReapplyDataCell(string name, IntPtr loc)
        {
            if (loc == IntPtr.Zero) return;
            SafeTry("Reapply " + name, () => MemOps.WriteIntPtrCell(loc, _newSlotValue));
        }

        /// <summary>
        /// Releases all resources used by this hook. Safe to call multiple times.
        /// Restores original code and frees trampoline allocations.
        /// </summary>
        /// <remarks>
        /// This class does not have a finalizer because unhooking from a finalizer
        /// thread is unsafe (the CLR may have already cleaned up method handles).
        /// Users must call <see cref="Dispose"/> explicitly or use
        /// <see cref="MethodHookManager.RemoveAllHook"/> before application shutdown.
        /// </remarks>
        public void Dispose()
        {
            lock (_stateLock)
            {
                if (_isDisposed)
                {
                    return;
                }
                try
                {
                    StopHookCore();
                }
                catch (Exception ex)
                {
                    if (DiagInfo != null)
                    {
                        DiagInfo.PatchError += "; Dispose StopHook failed: " + ex.Message;
                    }
                }
                finally
                {
                    _isDisposed = true;
                    // Suppress finalization to avoid redundant GC overhead. Even
                    // though there's no finalizer, this is the standard pattern
                    // and signals to the GC that the object is cleaned up.
                    GC.SuppressFinalize(this);
                }
            }
        }

        // ReadBytesSafe moved to MemOps.ReadBytesSafe (unified low-level API).
    }
}
