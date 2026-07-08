using System;
using System.Collections.Generic;

namespace DynamicHook
{
    internal static class SlotPatcher
    {
        public static List<IntPtr> FindSlots(IntPtr methodDesc, IntPtr methodTable, IntPtr value)
        {
            return FindSlots(methodDesc, methodTable, value, 128);
        }

        public static List<IntPtr> FindSlots(IntPtr methodDesc, IntPtr methodTable, IntPtr value, int methodDescScanSize)
        {
            List<IntPtr> list = new List<IntPtr>();
            int size = IntPtr.Size;
            // Match a slot if it holds ANY address in the precode→JIT resolution
            // chain (the precode address itself, the first-level target, an
            // intermediate fixup thunk, or the fully-resolved JIT code entry).
            // On .NET 8, after tiered JIT or precode backpatching, a vtable slot
            // frequently holds the precode's first-level target — an intermediate
            // address that ResolveRealEntry skips over — so matching only the
            // endpoints (precode addr and fully-resolved JIT entry) would miss it.
            var candidates = new HashSet<long>();
            foreach (IntPtr c in MethodEntryResolver.ResolveChain(value))
                candidates.Add(c.ToInt64());
            if (methodDesc != IntPtr.Zero)
            {
                for (int i = 0; i < methodDescScanSize; i += size)
                {
                    if (!Memory.IsReadable(methodDesc + i, size))
                    {
                        break;
                    }
                    try
                    {
                        long num3 = MemOps.ReadIntPtr(methodDesc + i).ToInt64();
                        if (candidates.Contains(num3))
                        {
                            list.Add(methodDesc + i);
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }
            if (methodTable != IntPtr.Zero)
            {
                int consecutiveUnreadable = 0;
                for (int j = 0; j < 65536; j += size)
                {
                    if (!Memory.IsReadable(methodTable + j, size))
                    {
                        // Skip unreadable regions instead of breaking. The MethodTable
                        // may span non-contiguous pages (e.g. on x86 where the vtable
                        // extends past a page boundary). Allow up to 4096 bytes of
                        // consecutive unreadable memory before giving up.
                        consecutiveUnreadable += size;
                        if (consecutiveUnreadable >= 4096)
                            break;
                        continue;
                    }
                    consecutiveUnreadable = 0;
                    try
                    {
                        long num4 = MemOps.ReadIntPtr(methodTable + j).ToInt64();
                        if (candidates.Contains(num4))
                        {
                            list.Add(methodTable + j);
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }
            return list;
        }

        public static void ReplaceSlot(IntPtr slot, IntPtr newValue)
        {
            MemOps.WriteIntPtrCell(slot, newValue);
        }
    }
}
