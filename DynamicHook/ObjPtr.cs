using System;

namespace DynamicHook
{
    /// <summary>
    /// Overlays a managed <c>object</c> reference with a raw <c>IntPtr</c> so that
    /// an object pointer obtained from native code (via a IntPtr-returning delegate)
    /// can be reinterpreted back into a tracked managed reference. Conversion is
    /// implemented with <c>TypedReference</c> (<c>__makeref</c>/<c>__refvalue</c>)
    /// because the CLR forbids explicit-layout structs that overlap an object field
    /// with a non-object field, and <c>Marshal.GetDelegateForFunctionPointer</c>
    /// rejects delegates whose return/parameter type is <c>object</c>.
    /// </summary>
    internal static class ObjPtr
    {
        public static unsafe IntPtr From(object obj)
        {
            if (obj == null)
            {
                return IntPtr.Zero;
            }
            // __makeref yields a TypedReference whose first field is the raw
            // managed object reference (pointer to the object header).
            TypedReference tr = __makeref(obj);
            return *(IntPtr*)&tr;
        }

        public static unsafe object To(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return null;
            }
            // Build a TypedReference whose value field points to the object, then
            // dereference it as object. The type handle in the TypedReference is
            // irrelevant when the compile-time type is 'object'.
            object dummy = null;
            TypedReference tr = __makeref(dummy);
            *(IntPtr*)&tr = ptr;
            return __refvalue(tr, object);
        }
    }
}
