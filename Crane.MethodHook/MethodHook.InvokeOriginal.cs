using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Crane.MethodHook
{
    public sealed partial class MethodHook
    {
        public object InvokeOriginal(object instance, params object[] args)
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException("MethodHook");
            }
            if (!_isInstalled)
            {
                throw new InvalidOperationException("Hook is not installed");
            }
            // Re-entrancy guard: if InvokeOriginal is already in progress on this
            // hook instance, the hook has been re-entered through a still-patched
            // code path (observed on .NET 8+ Debug mode when tiered compilation is
            // disabled and RestoreAll partially restores patches).
            //
            // MUST return null immediately — NEVER throw. On .NET 8 Debug mode,
            // the CLR's tier-0 dispatch stubs CATCH and RETRY exceptions in a tight
            // loop, causing an infinite hang. Returning null breaks the cycle.
            //
            // CRITICAL: No file I/O or string allocation in this guard. Any
            // allocation can trigger GC/JIT that calls through still-patched
            // code paths, causing cascading re-entrancy.
            if (_inCallOriginal)
            {
                _reentrancyCount++;
                if (_reentrancyCount > HookConstants.MaxReentrancyCount)
                {
                    // Hard stop: too many re-entries. Return null silently to
                    // break any remaining cycle without further allocation.
                    return null;
                }
                return null;
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

            _reentrancyCount = 0;
            _inCallOriginal = true;
            try
            {
                // Path 0: for generic methods, use RestoreAll + invoke + ReapplyAll.
                //
                // IMPORTANT: Use DynamicInvoke (RuntimeMethodHandle.InvokeMethod) instead of
                // the delegate's Invoke method via delegate*. The delegate's Invoke method is
                // never invoked during setup (CreateOriginalDelegate only captures its function
                // pointer via PrepareMethod). On .NET 8 Debug mode with tiered compilation,
                // the delegate's Invoke remains tier-0 compiled. Tier-0 code contains
                // exception handling stubs that CATCH and RETRY on failure.
                //
                // DynamicInvoke uses RuntimeMethodHandle.InvokeMethod (native), which does
                // NOT have tiered compilation stubs and will NOT retry.
                //
                // MUST run on the SAME thread as the hook (not a clean thread).
                //
                // CRITICAL: No file I/O between RestoreAll and the invoke call.
                // Any allocation in this window can trigger GC/JIT that calls
                // through still-patched code paths, causing re-entrancy.
                if (_needsGenericAdapter)
                {
                    RestoreAll();
                    try
                    {
                        if (_originalDelegate != null)
                        {
                            object[] dlgArgs;
                            if (methodInfo.IsStatic)
                            {
                                dlgArgs = args ?? Array.Empty<object>();
                            }
                            else
                            {
                                dlgArgs = new object[(args?.Length ?? 0) + 1];
                                dlgArgs[0] = instance;
                                if (args != null) Array.Copy(args, 0, dlgArgs, 1, args.Length);
                            }
                            var result = _originalDelegate.DynamicInvoke(dlgArgs);
                            return result;
                        }
                        // Fallback: MethodInfo.Invoke
                        if (methodInfo.IsStatic)
                            return methodInfo.Invoke(null, args);
                        return methodInfo.Invoke(instance, args);
                    }
                    finally
                    {
                        ReapplyAll();
                    }
                }

                // Path 1a: Call the original JIT code directly via delegate*.
                // This bypasses BOTH the precode AND the MethodTable slot, making
                // it immune to re-entrancy. After RestoreAll, the secondary JIT
                // patch at _targetJitCode is restored to original bytes, so the
                // call reaches the real method body.
                //
                // Two sub-paths:
                // (a) Reference-type params (or no params): use delegate*<object, ...>
                //     via InvokeViaFptr (CanUseTrampoline). The managed calling
                //     convention keeps the thread in cooperative GC mode for
                //     proper object-reference tracking.
                // (b) Static methods with all value-type params (<=8 bytes,
                //     non-float/double): use delegate*<IntPtr, ...> via
                //     InvokeViaJitFptrDirect (CanUseJitDirectValueArgs). Each
                //     value-type arg is unboxed to a raw IntPtr. No GC-tracked
                //     references are involved, so delegate*<IntPtr> is safe.
                //     This eliminates re-entrancy for methods like DateTime.Compare
                //     on .NET 8+ where DynamicInvoke/MethodInfo.Invoke may
                //     dispatch through a patched slot.
                // Non-primitive value-type returns (DateTime, TimeSpan, etc.) cannot
                // go through either delegate*<object,...,IntPtr> path:
                //  - Path 1a(a) calls delegate*<object,...,IntPtr> at raw JIT code and
                //    reinterprets RAX bits — unreliable for non-primitive value types.
                //  - Path 1 InvokeViaDelegateFptr uses the same delegate*<object,...,IntPtr>
                //    signature on the delegate's Invoke method, which throws
                //    ArgumentException "signature not compatible" for non-primitive
                //    value-type returns.
                // Both paths must fall through to DynamicInvoke (Path 1 fallback),
                // which correctly boxes/unboxes value-type returns.
                bool nonPrimitiveValueReturn = !isVoid && returnType.IsValueType
                    && returnType != typeof(float) && returnType != typeof(double)
                    && !returnType.IsEnum && !returnType.IsPrimitive;

                if (_targetJitCode != IntPtr.Zero)
                {
                    bool useRefPath = CanUseTrampoline(methodInfo);
                    bool useValuePath = !useRefPath && CanUseJitDirectValueArgs(methodInfo);
                    if (nonPrimitiveValueReturn && useRefPath && argCount > 0)
                    {
                        useRefPath = false;
                    }
                    if (useRefPath || useValuePath)
                    {
                        RestoreAll();
                        try
                        {
                            object[] jitArgs = new object[argCount];
                            int slot = 0;
                            if (!methodInfo.IsStatic)
                            {
                                jitArgs[slot++] = instance;
                            }
                            if (args != null)
                            {
                                for (int i = 0; i < args.Length; i++)
                                {
                                    jitArgs[slot++] = args[i];
                                }
                            }
                            if (useValuePath)
                            {
                                return InvokeViaJitFptrDirect(_targetJitCode, jitArgs, isVoid, returnType, methodInfo);
                            }
                            return InvokeViaFptr(_targetJitCode, jitArgs, isVoid, returnType);
                        }
                        finally
                        {
                            ReapplyAll();
                        }
                    }
                }
                // Path 1: cached delegate's Invoke via function pointer.
                // For generic methods, DynamicInvoke goes through
                // RuntimeMethodHandle.InvokeMethod which crashes (0x80131506).
                // Using delegate* to call the delegate's Invoke method bypasses
                // reflection entirely. The Invoke method is non-generic and sets
                // up the generic dictionary (R10) before calling the target.
                // MUST run on the SAME thread — see Path 0 comment for details.
                //
                // SKIP for value-type instance methods: on .NET 8+, the delegate's
                // Invoke method may dispatch through the MethodTable slot rather
                // than _methodPtrAux (the precode). If RestoreAll fails to restore
                // the slot (observed for CoreLib methods like DateTime.ToString()
                // when a debugger is attached and tiered compilation is disabled),
                // DynamicInvoke re-enters the hook → infinite recursion →
                // AccessViolationException. MethodInfo.Invoke (Path 2) uses
                // RuntimeMethodHandle.InvokeMethod which bypasses the slot.
                bool isValueTypeInstance = !methodInfo.IsStatic
                    && methodInfo.DeclaringType != null
                    && methodInfo.DeclaringType.IsValueType;
                if (_originalDelegate != null && !isValueTypeInstance)
                {
                    RestoreAll();
                    try
                    {
                        // delegate*<object, ...> passes all args as object references.
                        // This works for reference-type parameters. For value-type
                        // parameters, fall back to DynamicInvoke (which correctly
                        // boxes/unboxes). Value-type RETURNS are handled by
                        // InvokeViaFptr via delegate*<..., IntPtr>.
                        if (_delegateInvokeFptr != IntPtr.Zero && CanUseTrampoline(methodInfo)
                            && !nonPrimitiveValueReturn)
                        {
                            return InvokeViaDelegateFptr(methodInfo, instance, args);
                        }
                        // Fallback when delegate* cannot be used (value-type params
                        // that don't meet the JIT-direct criteria — e.g. float/double
                        // params, value types >8 bytes, or instance methods with
                        // value-type params). DynamicInvoke correctly boxes/unboxes
                        // value-type parameters. For static methods with value-type
                        // params that DO meet the criteria, Path 1a handles them
                        // without re-entrancy; this fallback is only reached for
                        // the remaining cases.
                        if (methodInfo.IsStatic)
                        {
                            return _originalDelegate.DynamicInvoke(args ?? Array.Empty<object>());
                        }
                        object[] invokeArgs = new object[(args?.Length ?? 0) + 1];
                        invokeArgs[0] = instance;
                        if (args != null)
                        {
                            Array.Copy(args, 0, invokeArgs, 1, args.Length);
                        }
                        return _originalDelegate.DynamicInvoke(invokeArgs);
                    }
                    finally
                    {
                        ReapplyAll();
                    }
                }

                // Path 2: RestoreAll + invoke + ReapplyAll.
                // For value-type instance methods, prefer the delegate's DynamicInvoke
                // over MethodInfo.Invoke. On .NET 8 with tiered compilation disabled
                // (e.g., debugger attached), MethodInfo.Invoke uses
                // RuntimeMethodHandle.InvokeMethod which may crash with AV for
                // CoreLib value-type methods. The delegate's Invoke method is
                // JIT-compiled with knowledge of the value type and correctly
                // handles byref unboxing.
                RestoreAll();
                try
                {
                    if (methodInfo.IsStatic)
                    {
                        return methodInfo.Invoke(null, args);
                    }
                    // Build args for delegate DynamicInvoke (instance first)
                    if (_originalDelegate != null)
                    {
                        object[] dlgArgs = new object[(args?.Length ?? 0) + 1];
                        dlgArgs[0] = instance;
                        if (args != null) Array.Copy(args, 0, dlgArgs, 1, args.Length);
                        return _originalDelegate.DynamicInvoke(dlgArgs);
                    }
                    return methodInfo.Invoke(instance, args);
                }
                finally
                {
                    ReapplyAll();
                }
            } // end outer try (_inCallOriginal)
            finally
            {
                _inCallOriginal = false;
            }
        }

        public T InvokeOriginal<T>(object instance, params object[] args)
        {
            var ret = InvokeOriginal(instance, args);
            if (ret == null)
            {
                return default(T);
            }
            else
            {
                return (T)Convert.ChangeType(ret, typeof(T));
            }
        }

        /// <summary>
        /// Checks whether all PARAMETERS are reference types (or IntPtr/UIntPtr),
        /// which is required for the delegate* trampoline path. The return type
        /// can be any type: reference returns use delegate*&lt;..., object&gt;,
        /// value-type returns use delegate*&lt;..., IntPtr&gt; (reading RAX) or
        /// delegate*&lt;..., double&gt; (reading XMM0 for float/double).
        ///
        /// Value-type instance methods are also excluded: the delegate* paths pass
        /// the instance as a boxed object reference in RCX, but the original method
        /// expects a managed pointer (byref) in RCX. MethodInfo.Invoke (Path 2)
        /// correctly handles value-type instances by unboxing and passing byref.
        /// </summary>
        private static bool CanUseTrampoline(MethodInfo methodInfo)
        {
            // Value-type instance methods: delegate* passes boxed object ref,
            // but original expects byref — fall back to MethodInfo.Invoke.
            if (!methodInfo.IsStatic && methodInfo.DeclaringType != null
                && methodInfo.DeclaringType.IsValueType)
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
        /// Calls the trampoline via delegate* (managed function pointer). The managed
        /// calling convention keeps the thread in cooperative GC mode, so object
        /// references passed as arguments and return values are properly GC-tracked.
        /// Requires .NET 5+ runtime; the containing methods are only JIT-compiled when
        /// actually called on .NET 5+, so they never fail to load on older runtimes.
        /// </summary>
        private static unsafe object InvokeViaFptr(IntPtr fptr, object[] args, bool isVoid, Type returnType)
        {
            // Categorize the return type:
            // - void: no return value
            // - refReturn: reference type (GC-tracked in RAX)
            // - floatReturn / doubleReturn: floating-point (returned in XMM0)
            // - valueReturn: other value types ≤ 8 bytes (returned in RAX, not GC-tracked)
            bool refReturn = !isVoid && !returnType.IsValueType;
            bool floatReturn = returnType == typeof(float);
            bool doubleReturn = returnType == typeof(double);
            bool valueReturn = !isVoid && returnType.IsValueType && !floatReturn && !doubleReturn;

            // Value types > 8 bytes use a hidden pointer parameter (RCX on x64),
            // which shifts all other arguments and breaks the delegate* ABI.
            // Use GetValueTypeSize instead of Marshal.SizeOf: Auto-layout value
            // types (e.g. DateTime, which is 8 bytes but [StructLayout(Auto)])
            // cause Marshal.SizeOf to throw ArgumentException, which previously
            // fell back to sz=16 and incorrectly rejected DateTime as > 8 bytes.
            if (valueReturn)
            {
                int sz = GetValueTypeSize(returnType);
                if (sz < 0 || sz > 8)
                {
                    throw new NotSupportedException(
                        "delegate* path does not support value-type returns > 8 bytes: " + returnType);
                }
            }

            object result;
            switch (args.Length)
            {
                case 0:
                    if (isVoid) { ((delegate*<void>)fptr)(); result = null; }
                    else if (refReturn) result = ((delegate*<object>)fptr)();
                    else if (floatReturn) result = ((delegate*<float>)fptr)();
                    else if (doubleReturn) result = ((delegate*<double>)fptr)();
                    else result = BoxValueResult(((delegate*<IntPtr>)fptr)(), returnType);
                    break;
                case 1:
                    if (isVoid) { ((delegate*<object, void>)fptr)(args[0]); result = null; }
                    else if (refReturn) result = ((delegate*<object, object>)fptr)(args[0]);
                    else if (floatReturn) result = ((delegate*<object, float>)fptr)(args[0]);
                    else if (doubleReturn) result = ((delegate*<object, double>)fptr)(args[0]);
                    else result = BoxValueResult(((delegate*<object, IntPtr>)fptr)(args[0]), returnType);
                    break;
                case 2:
                    if (isVoid) { ((delegate*<object, object, void>)fptr)(args[0], args[1]); result = null; }
                    else if (refReturn) result = ((delegate*<object, object, object>)fptr)(args[0], args[1]);
                    else if (floatReturn) result = ((delegate*<object, object, float>)fptr)(args[0], args[1]);
                    else if (doubleReturn) result = ((delegate*<object, object, double>)fptr)(args[0], args[1]);
                    else result = BoxValueResult(((delegate*<object, object, IntPtr>)fptr)(args[0], args[1]), returnType);
                    break;
                case 3:
                    if (isVoid) { ((delegate*<object, object, object, void>)fptr)(args[0], args[1], args[2]); result = null; }
                    else if (refReturn) result = ((delegate*<object, object, object, object>)fptr)(args[0], args[1], args[2]);
                    else if (floatReturn) result = ((delegate*<object, object, object, float>)fptr)(args[0], args[1], args[2]);
                    else if (doubleReturn) result = ((delegate*<object, object, object, double>)fptr)(args[0], args[1], args[2]);
                    else result = BoxValueResult(((delegate*<object, object, object, IntPtr>)fptr)(args[0], args[1], args[2]), returnType);
                    break;
                case 4:
                    if (isVoid) { ((delegate*<object, object, object, object, void>)fptr)(args[0], args[1], args[2], args[3]); result = null; }
                    else if (refReturn) result = ((delegate*<object, object, object, object, object>)fptr)(args[0], args[1], args[2], args[3]);
                    else if (floatReturn) result = ((delegate*<object, object, object, object, float>)fptr)(args[0], args[1], args[2], args[3]);
                    else if (doubleReturn) result = ((delegate*<object, object, object, object, double>)fptr)(args[0], args[1], args[2], args[3]);
                    else result = BoxValueResult(((delegate*<object, object, object, object, IntPtr>)fptr)(args[0], args[1], args[2], args[3]), returnType);
                    break;
                default:
                    throw new NotSupportedException("delegate* path supports at most 4 arguments");
            }
            return result;
        }

        /// <summary>
        /// Boxes a raw IntPtr return value (from delegate*&lt;..., IntPtr&gt;) into
        /// the correct value type. On x64, value-type returns ≤ 8 bytes are in RAX;
        /// reading as IntPtr gives the full 64-bit register, and we truncate/convert
        /// to the target type.
        /// </summary>
        private static object BoxValueResult(IntPtr rawResult, Type returnType)
        {
            long val = rawResult.ToInt64();
            if (returnType == typeof(int)) return (int)val;
            if (returnType == typeof(uint)) return (uint)val;
            if (returnType == typeof(long)) return val;
            if (returnType == typeof(ulong)) return (ulong)val;
            if (returnType == typeof(short)) return (short)val;
            if (returnType == typeof(ushort)) return (ushort)val;
            if (returnType == typeof(byte)) return (byte)val;
            if (returnType == typeof(sbyte)) return (sbyte)val;
            if (returnType == typeof(bool)) return val != 0;
            if (returnType == typeof(char)) return (char)val;
            if (returnType == typeof(IntPtr)) return rawResult;
            if (returnType == typeof(UIntPtr)) return (UIntPtr)val;
            if (returnType.IsEnum) return Enum.ToObject(returnType, val);
            // Non-primitive value types <= 8 bytes (DateTime, TimeSpan, etc.):
            // reinterpret the raw bits in RAX as the target type. These types
            // (often [StructLayout(Auto)]) cannot use Convert.ChangeType and
            // are not blittable for pinned-handle tricks. The generic helper
            // below is JIT-specialized per type and performs a raw reinterpret.
            if (returnType.IsValueType)
            {
                return ReinterpretValueBits(rawResult, returnType);
            }
            return Convert.ChangeType(val, returnType);
        }

        /// <summary>
        /// Reinterprets the raw 64-bit return value (RAX) as an arbitrary
        /// unmanaged value type &le; 8 bytes and boxes it. Used for non-primitive
        /// value types such as <see cref="DateTime"/> and <see cref="TimeSpan"/>
        /// whose raw bits are returned in RAX but which are not blittable and
        /// cannot be reconstructed via <see cref="Convert.ChangeType"/>.
        ///
        /// The generic specialization is invoked through a cached reflection
        /// delegate (one per type) so the reinterpret is a single unsafe pointer
        /// dereference with no per-call reflection cost.
        /// </summary>
        private static unsafe TReturn ReinterpretBits<TReturn>(long bits) where TReturn : unmanaged
        {
            // Copy to a local so we can take its address. Value types <= 8 bytes
            // with no reference fields (validated by the unmanaged constraint and
            // the caller's GetValueTypeSize <= 8 check) can be reinterpreted safely.
            long local = bits;
            return *(TReturn*)&local;
        }

        // Cache of compiled ReinterpretBits<T> invokers, keyed by return type.
        private static readonly System.Collections.Generic.Dictionary<Type, Func<long, object>> _reinterpretCache =
            new System.Collections.Generic.Dictionary<Type, Func<long, object>>();

        private static object ReinterpretValueBits(IntPtr rawResult, Type returnType)
        {
            Func<long, object> invoker;
            lock (_reinterpretCache)
            {
                if (!_reinterpretCache.TryGetValue(returnType, out invoker))
                {
                    MethodInfo mi = typeof(MethodHook).GetMethod(
                        "ReinterpretBits",
                        BindingFlags.NonPublic | BindingFlags.Static)
                        .MakeGenericMethod(returnType);
                    invoker = (Func<long, object>)mi.CreateDelegate(typeof(Func<long, object>));
                    _reinterpretCache[returnType] = invoker;
                }
            }
            return invoker(rawResult.ToInt64());
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

            return InvokeViaFptr(_delegateInvokeFptr, invokeArgs, isVoid, methodInfo.ReturnType);
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

        /// <summary>
        /// Checks whether a STATIC method has all value-type parameters (<=8 bytes,
        /// non-float/double) and a value-type or void return (<=8 bytes), making it
        /// eligible for the JIT-direct delegate* path with raw IntPtr arguments.
        ///
        /// This path bypasses BOTH the precode AND the MethodTable slot, eliminating
        /// re-entrancy for methods like DateTime.Compare on .NET 8+ where
        /// DynamicInvoke/MethodInfo.Invoke may dispatch through a patched slot.
        ///
        /// Restrictions:
        /// - Static only (instance methods have a reference-type 'this' needing GC
        ///   tracking, which delegate*<IntPtr> cannot provide).
        /// - No float/double params (they use XMM registers, not general-purpose
        ///   registers; delegate*<IntPtr> would place them in the wrong register).
        /// - No reference-type returns (cannot safely convert IntPtr back to a
        ///   GC-tracked object reference without Unsafe, which is unavailable on
        ///   netstandard2.0).
        /// - All value types must be <=8 bytes (single-register passing) and
        ///   blittable (for GCHandle.Pinned used during unboxing).
        /// - Nullable&lt;T&gt; is excluded due to special boxing semantics.
        /// </summary>
        private static bool CanUseJitDirectValueArgs(MethodInfo methodInfo)
        {
            // Only for static methods — instance methods have a reference-type
            // 'this' that needs GC tracking.
            if (!methodInfo.IsStatic) return false;

            // Check return type — no reference returns.
            Type returnType = methodInfo.ReturnType;
            if (returnType != typeof(void))
            {
                if (!returnType.IsValueType) return false;
                if (returnType.IsGenericType &&
                    returnType.GetGenericTypeDefinition() == typeof(Nullable<>)) return false;
                // Value-type returns >8 bytes use a hidden pointer parameter
                // which shifts all other arguments.
                int retSz = GetValueTypeSize(returnType);
                if (retSz < 0 || retSz > 8) return false;
            }

            // Check all params are value types <=8 bytes (non-float/double).
            foreach (ParameterInfo p in methodInfo.GetParameters())
            {
                Type t = p.ParameterType;
                if (!t.IsValueType) return false;
                if (t == typeof(float) || t == typeof(double)) return false;
                if (t.IsGenericType &&
                    t.GetGenericTypeDefinition() == typeof(Nullable<>)) return false;
                int sz = GetValueTypeSize(t);
                if (sz < 0 || sz > 8) return false;
            }

            return true;
        }

        /// <summary>
        /// Calls the target JIT code directly via delegate* with raw IntPtr
        /// arguments. Used for static methods where all parameters are value
        /// types <=8 bytes (non-float/double). Each boxed value-type arg is
        /// unboxed to a raw IntPtr and passed in the correct register via
        /// delegate*<IntPtr, ...>.
        ///
        /// This bypasses BOTH the precode AND the MethodTable slot, making it
        /// immune to the re-entrancy that affects DynamicInvoke/MethodInfo.Invoke
        /// on .NET 8+. After RestoreAll, the JIT code at _targetJitCode is
        /// restored to original bytes, so the call reaches the real method body.
        ///
        /// No GC-tracked references are involved (all args are raw values, return
        /// is void or value-type), so delegate*<IntPtr> is safe without GC
        /// reporting. The calling convention for IntPtr args matches the JIT
        /// code's expectation on both Windows x64 (RCX, RDX, R8, R9) and Unix
        /// System V AMD64 (RDI, RSI, RDX, RCX, R8, R9).
        /// </summary>
        private static unsafe object InvokeViaJitFptrDirect(
            IntPtr fptr, object[] args, bool isVoid, Type returnType,
            MethodInfo methodInfo)
        {
            // Categorize return type (no reference returns — excluded by
            // CanUseJitDirectValueArgs).
            bool floatReturn = returnType == typeof(float);
            bool doubleReturn = returnType == typeof(double);
            bool valueReturn = !isVoid && returnType.IsValueType
                && !floatReturn && !doubleReturn;

            // Convert all args from boxed objects to raw IntPtr values.
            // For static methods (the only kind reaching here), all args are
            // value-type params.
            int n = args.Length;
            IntPtr[] rawArgs = new IntPtr[n];
            ParameterInfo[] parameters = methodInfo.GetParameters();
            int paramOffset = methodInfo.IsStatic ? 0 : 1;
            for (int i = 0; i < n; i++)
            {
                if (i < paramOffset)
                {
                    // Instance arg — not reached for static methods.
                    rawArgs[i] = IntPtr.Zero;
                }
                else
                {
                    rawArgs[i] = UnboxValueToIntPtr(args[i],
                        parameters[i - paramOffset].ParameterType);
                }
            }

            object result;
            switch (n)
            {
                case 0:
                    if (isVoid) { ((delegate*<void>)fptr)(); result = null; }
                    else if (floatReturn) result = ((delegate*<float>)fptr)();
                    else if (doubleReturn) result = ((delegate*<double>)fptr)();
                    else result = BoxValueResult(((delegate*<IntPtr>)fptr)(), returnType);
                    break;
                case 1:
                    if (isVoid) { ((delegate*<IntPtr, void>)fptr)(rawArgs[0]); result = null; }
                    else if (floatReturn) result = ((delegate*<IntPtr, float>)fptr)(rawArgs[0]);
                    else if (doubleReturn) result = ((delegate*<IntPtr, double>)fptr)(rawArgs[0]);
                    else result = BoxValueResult(((delegate*<IntPtr, IntPtr>)fptr)(rawArgs[0]), returnType);
                    break;
                case 2:
                    if (isVoid) { ((delegate*<IntPtr, IntPtr, void>)fptr)(rawArgs[0], rawArgs[1]); result = null; }
                    else if (floatReturn) result = ((delegate*<IntPtr, IntPtr, float>)fptr)(rawArgs[0], rawArgs[1]);
                    else if (doubleReturn) result = ((delegate*<IntPtr, IntPtr, double>)fptr)(rawArgs[0], rawArgs[1]);
                    else result = BoxValueResult(((delegate*<IntPtr, IntPtr, IntPtr>)fptr)(rawArgs[0], rawArgs[1]), returnType);
                    break;
                case 3:
                    if (isVoid) { ((delegate*<IntPtr, IntPtr, IntPtr, void>)fptr)(rawArgs[0], rawArgs[1], rawArgs[2]); result = null; }
                    else if (floatReturn) result = ((delegate*<IntPtr, IntPtr, IntPtr, float>)fptr)(rawArgs[0], rawArgs[1], rawArgs[2]);
                    else if (doubleReturn) result = ((delegate*<IntPtr, IntPtr, IntPtr, double>)fptr)(rawArgs[0], rawArgs[1], rawArgs[2]);
                    else result = BoxValueResult(((delegate*<IntPtr, IntPtr, IntPtr, IntPtr>)fptr)(rawArgs[0], rawArgs[1], rawArgs[2]), returnType);
                    break;
                case 4:
                    if (isVoid) { ((delegate*<IntPtr, IntPtr, IntPtr, IntPtr, void>)fptr)(rawArgs[0], rawArgs[1], rawArgs[2], rawArgs[3]); result = null; }
                    else if (floatReturn) result = ((delegate*<IntPtr, IntPtr, IntPtr, IntPtr, float>)fptr)(rawArgs[0], rawArgs[1], rawArgs[2], rawArgs[3]);
                    else if (doubleReturn) result = ((delegate*<IntPtr, IntPtr, IntPtr, IntPtr, double>)fptr)(rawArgs[0], rawArgs[1], rawArgs[2], rawArgs[3]);
                    else result = BoxValueResult(((delegate*<IntPtr, IntPtr, IntPtr, IntPtr, IntPtr>)fptr)(rawArgs[0], rawArgs[1], rawArgs[2], rawArgs[3]), returnType);
                    break;
                default:
                    throw new NotSupportedException(
                        "JIT-direct path supports at most 4 arguments");
            }
            return result;
        }

        /// <summary>
        /// Unboxes a boxed value type (<=8 bytes, non-float) to a raw IntPtr.
        /// Uses GCHandle.Pinned to get a pointer to the value data, then reads
        /// the appropriate number of bytes (4 or 8) and zero-extends to 64 bits.
        ///
        /// For types <=4 bytes (int, uint, short, etc.), reads 4 bytes and
        /// zero-extends. For types 5-8 bytes (DateTime, long, etc.), reads the
        /// full 8 bytes. This matches the x64 calling convention where small
        /// values are zero-extended to 64 bits in the register.
        ///
        /// Non-blittable value types (Auto layout, e.g. <see cref="DateTime"/>)
        /// cannot be pinned via GCHandle.Pinned — GCHandle.Alloc throws
        /// ArgumentException. For these, fall back to a DynamicMethod that
        /// unboxes the value and reinterprets its raw bits as a long via cpblk.
        /// This is safe because CanUseJitDirectValueArgs already enforces
        /// size <=8 bytes (single-register passing).
        /// </summary>
        private static IntPtr UnboxValueToIntPtr(object boxed, Type type)
        {
            if (boxed == null) return IntPtr.Zero;

            int sz = GetValueTypeSize(type);
            if (sz < 0)
            {
                throw new NotSupportedException(
                    "JIT-direct path cannot determine size of value type: " + type.FullName);
            }

            GCHandle handle;
            bool pinned = false;
            try
            {
                handle = GCHandle.Alloc(boxed, GCHandleType.Pinned);
                pinned = true;
            }
            catch (ArgumentException)
            {
                // Non-blittable value type (Auto layout, e.g. DateTime).
                // Fall back to DynamicMethod-based bit reinterpretation.
                long bits = UnboxNonBlittableToLong(boxed, type);
                if (sz <= 4)
                {
                    return new IntPtr((long)(ulong)(uint)bits);
                }
                return new IntPtr(bits);
            }

            try
            {
                IntPtr dataPtr = handle.AddrOfPinnedObject();
                if (sz <= 4)
                {
                    // Zero-extend 4-byte value to 64 bits (int, uint, short, etc.)
                    return new IntPtr((long)(ulong)(uint)Marshal.ReadInt32(dataPtr));
                }
                // Read 8 bytes (DateTime, long, etc.)
                return Marshal.ReadIntPtr(dataPtr);
            }
            finally
            {
                if (pinned) handle.Free();
            }
        }

        /// <summary>
        /// Cached unboxers for non-blittable value types. Each entry maps a
        /// Type to a <see cref="MethodInfo"/> for the generic helper
        /// <see cref="ValueToBits{T}"/>; invoking it unboxes the value and
        /// reinterprets its raw bits as a long. Safe for value types <=8 bytes
        /// (enforced by CanUseJitDirectValueArgs).
        /// </summary>
        private static readonly System.Collections.Generic.Dictionary<Type, MethodInfo>
            _unboxToLongCache = new System.Collections.Generic.Dictionary<Type, MethodInfo>();

        /// <summary>
        /// Reinterprets the raw bits of an unmanaged value type as a long.
        /// Used to unbox non-blittable value types (e.g. DateTime, which is
        /// Auto-layout and cannot be pinned via GCHandle) into a raw IntPtr
        /// for the JIT-direct delegate* path.
        /// </summary>
        private static unsafe long ValueToBits<T>(T value) where T : unmanaged
        {
            T local = value;
            // CanUseJitDirectValueArgs enforces <=8 bytes; for <=4 bytes,
            // zero-extend to match x64 calling convention.
            if (sizeof(T) <= 4)
            {
                return (long)(ulong)(uint)(*(int*)&local);
            }
            return *(long*)&local;
        }

        private static long UnboxNonBlittableToLong(object boxed, Type type)
        {
            MethodInfo mi;
            lock (_unboxToLongCache)
            {
                if (!_unboxToLongCache.TryGetValue(type, out mi))
                {
                    // MakeGenericMethod throws ArgumentException if the type
                    // does not satisfy the `unmanaged` constraint (i.e. it
                    // contains reference-type fields). CanUseJitDirectValueArgs
                    // already filtered such types via GetValueTypeSize, but
                    // guard against it just in case.
                    MethodInfo template = typeof(MethodHook).GetMethod(
                        "ValueToBits",
                        BindingFlags.NonPublic | BindingFlags.Static);
                    mi = template.MakeGenericMethod(type);
                    _unboxToLongCache[type] = mi;
                }
            }
            // Invoke unboxes the object argument to T automatically.
            return (long)mi.Invoke(null, new object[] { boxed });
        }

        /// <summary>
        /// Computes the in-memory size of a value type, in bytes.
        ///
        /// Uses <see cref="Marshal.SizeOf(Type)"/> for blittable Sequential/Explicit
        /// layouts (the common case). For Auto-layout types such as
        /// <see cref="DateTime"/> (where Marshal.SizeOf throws
        /// <see cref="ArgumentException"/>), falls back to summing the sizes of all
        /// instance fields recursively.
        ///
        /// Returns -1 if the size cannot be determined — e.g. if the type (or any
        /// nested value-type field) contains a reference-type field, which would
        /// make it ineligible for the delegate*&lt;IntPtr&gt; JIT-direct path anyway.
        ///
        /// The field-sum is a conservative approximation that ignores inter-field
        /// padding. This is acceptable for the &lt;=8-byte register-passing check:
        /// single-field structs (DateTime, TimeSpan, DateTimeOffset — all 8 bytes)
        /// are computed exactly, and multi-field structs with padding that pushes
        /// the actual size above 8 bytes still have a field-sum &gt;= the size of
        /// their largest field, so 8+byte fields yield a sum &gt; 8 → rejected.
        /// </summary>
        private static int GetValueTypeSize(Type t)
        {
            // Reference types cannot be passed via delegate*<IntPtr>.
            if (!t.IsValueType) return -1;

            // Blittable Sequential/Explicit layouts — Marshal.SizeOf is exact.
            try { return Marshal.SizeOf(t); }
            catch { /* Auto layout or non-blittable — fall through */ }

            // Auto-layout value types (e.g. DateTime): sum instance field sizes.
            // Enums reach here too on some runtimes; use the underlying type.
            if (t.IsEnum)
            {
                return GetValueTypeSize(Enum.GetUnderlyingType(t));
            }

            int total = 0;
            foreach (FieldInfo f in t.GetFields(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            {
                int sub = GetValueTypeSize(f.FieldType);
                if (sub < 0) return -1; // contains a reference-type field
                total += sub;
            }
            return total;
        }
    }
}
