using System;
using System.Collections.Generic;

namespace Crane.MethodHook
{
    internal static class SlotPatcher
    {
        public static List<IntPtr> FindSlots(IntPtr methodDesc, IntPtr methodTable, IntPtr value)
        {
            return FindSlots(methodDesc, methodTable, value, HookConstants.MethodDescScanSize);
        }

        public static List<IntPtr> FindSlots(IntPtr methodDesc, IntPtr methodTable, IntPtr value, int methodDescScanSize)
        {
            List<IntPtr> list = new List<IntPtr>();
            int size = IntPtr.Size;
            long num = value.ToInt64();
            long num2 = MethodEntryResolver.ResolveRealEntry(value).ToInt64();
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
                        if (num3 == num || num3 == num2)
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
                for (int j = 0; j < HookConstants.MethodTableScanSize; j += size)
                {
                    if (!Memory.IsReadable(methodTable + j, size))
                    {
                        // Skip unreadable regions instead of breaking. The MethodTable
                        // may span non-contiguous pages (e.g. on x86 where the vtable
                        // extends past a page boundary). Allow up to MaxConsecutiveUnreadable
                        // bytes of consecutive unreadable memory before giving up.
                        consecutiveUnreadable += size;
                        if (consecutiveUnreadable >= HookConstants.MaxConsecutiveUnreadable)
                            break;
                        continue;
                    }
                    consecutiveUnreadable = 0;
                    try
                    {
                        long num4 = MemOps.ReadIntPtr(methodTable + j).ToInt64();
                        if (num4 == num || num4 == num2)
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
