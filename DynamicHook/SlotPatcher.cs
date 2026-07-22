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
            long num = value.ToInt64();
            long num2 = MethodEntryResolver.ResolveRealEntry(value).ToInt64();
            if (methodDesc != IntPtr.Zero)
            {
                for (int i = 0; i < methodDescScanSize; i += size)
                {
                    long cellValue;
                    if (!TryReadIntPtrSafe(methodDesc + i, out cellValue))
                    {
                        break;
                    }
                    if (cellValue == num || cellValue == num2)
                    {
                        list.Add(methodDesc + i);
                    }
                }
            }
            if (methodTable != IntPtr.Zero)
            {
                int consecutiveUnreadable = 0;
                for (int j = 0; j < 65536; j += size)
                {
                    long cellValue;
                    if (!TryReadIntPtrSafe(methodTable + j, out cellValue))
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
                    if (cellValue == num || cellValue == num2)
                    {
                        list.Add(methodTable + j);
                    }
                }
            }
            return list;
        }

        /// <summary>
        /// Reads an IntPtr-sized value from memory safely. Uses Memory.IsReadable
        /// as the primary check (reliable on all platforms: VirtualQuery on Windows,
        /// /proc/self/maps on Linux, mincore on macOS). Falls back to try/catch
        /// around MemOps.ReadIntPtr for edge cases where IsReadable returns true
        /// but the read still fails (e.g. race condition with page unmapping).
        /// </summary>
        private static bool TryReadIntPtrSafe(IntPtr addr, out long value)
        {
            value = 0;
            if (!Memory.IsReadable(addr, IntPtr.Size))
            {
                return false;
            }
            try
            {
                value = MemOps.ReadIntPtr(addr).ToInt64();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static void ReplaceSlot(IntPtr slot, IntPtr newValue)
        {
            MemOps.WriteIntPtrCell(slot, newValue);
        }
    }
}
