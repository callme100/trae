using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace DynamicHook
{
    public sealed partial class MethodHook
    {
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

            // Path 1a: Call the original JIT code directly via delegate*.
            // On .NET 8+, the delegate's Invoke method may dispatch through
            // the MethodTable slot rather than _methodPtrAux (the precode).
            // If RestoreAll fails to restore the slot (observed on .NET 8 for
            // CoreLib methods like string.Compare), the delegate's Invoke
            // re-enters the hook, causing an infinite loop.
            //
            // Calling _targetJitCode directly bypasses BOTH the precode and
            // the MethodTable slot. After RestoreAll, the secondary JIT patch
            // at _targetJitCode is restored to original bytes, so the call
            // reaches the real method body. delegate* (managed calling convention)
            // keeps the thread in cooperative GC mode for proper object-reference
            // tracking. Only works for reference-type parameters (CanUseTrampoline).
            if (_targetJitCode != IntPtr.Zero && CanUseTrampoline(methodInfo))
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
                    return InvokeViaFptr(_targetJitCode, jitArgs, isVoid, returnType);
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
                    // This works for reference-type parameters. For value-type
                    // parameters, fall back to DynamicInvoke (which correctly
                    // boxes/unboxes). Value-type RETURNS are handled by
                    // InvokeViaFptr via delegate*<..., IntPtr>.
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
        /// Checks whether all PARAMETERS are reference types (or IntPtr/UIntPtr),
        /// which is required for the delegate* trampoline path. The return type
        /// can be any type: reference returns use delegate*&lt;..., object&gt;,
        /// value-type returns use delegate*&lt;..., IntPtr&gt; (reading RAX) or
        /// delegate*&lt;..., double&gt; (reading XMM0 for float/double).
        /// </summary>
        private static bool CanUseTrampoline(MethodInfo methodInfo)
        {
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
            if (valueReturn)
            {
                int sz;
                try { sz = Marshal.SizeOf(returnType); }
                catch { sz = 16; }
                if (sz > 8)
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
            return Convert.ChangeType(val, returnType);
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
    }
}
