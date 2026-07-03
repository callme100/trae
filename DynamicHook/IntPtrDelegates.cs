using System;

namespace DynamicHook
{
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
}
