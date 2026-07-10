using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using DynamicHook;

class Program
{
    public static int HookEntryCount = 0;
    public static int CallOriginalCount = 0;
    public static MethodHook ActiveHook;
    public static IntPtr PrecodeAddr;
    public static IntPtr JitCodeAddr;

    public static int NewStringCompare(string a, string b)
    {
        HookEntryCount++;
        if (HookEntryCount > 10)
        {
            Console.WriteLine("LOOP DETECTED — HookEntryCount=" + HookEntryCount);
            return 0;
        }
        if (HookEntryCount == 2)
        {
            Console.WriteLine("  [hook#2] STACK TRACE for re-entry:");
            Console.WriteLine(Environment.StackTrace);
            // Check slot values during re-entry (after RestoreAll, before ReapplyAll)
            var slotAddressesField = typeof(MethodHook).GetField("_slotAddresses",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var newSlotField = typeof(MethodHook).GetField("_newSlotValue",
                BindingFlags.NonPublic | BindingFlags.Instance);
            if (slotAddressesField != null)
            {
                var slots = slotAddressesField.GetValue(ActiveHook) as System.Collections.Generic.List<IntPtr>;
                IntPtr newSlot = newSlotField != null ? (IntPtr)newSlotField.GetValue(ActiveHook) : IntPtr.Zero;
                if (slots != null)
                {
                    foreach (var sa in slots)
                    {
                        long val = Marshal.ReadInt64(sa);
                        Console.WriteLine("  [hook#2] slot@0x" + sa.ToString("X16") + " = 0x" + val.ToString("X16")
                            + (val == newSlot.ToInt64() ? " (HOOK!)" : ""));
                    }
                }
            }
        }
        int result = (int)ActiveHook.CallOriginal(null, a, b);
        CallOriginalCount++;
        if (HookEntryCount == 1)
        {
            Console.WriteLine("  [hook#1] AFTER CallOriginal (should be re-patched):");
            Console.WriteLine("    precode bytes: " + FormatBytes(ReadBytes(PrecodeAddr, 6)));
            if (JitCodeAddr != IntPtr.Zero)
                Console.WriteLine("    jitCode bytes: " + FormatBytes(ReadBytes(JitCodeAddr, 6)));
        }
        return result;
    }

    static void Main(string[] args)
    {
        Console.WriteLine("=== .NET 8 string.Compare CallOriginal Loop Test ===");
        Console.WriteLine("CLR: " + RuntimeInformation.FrameworkDescription);
        Console.WriteLine();

        MethodInfo target = typeof(string).GetMethod("Compare",
            BindingFlags.Public | BindingFlags.Static, null,
            new[] { typeof(string), typeof(string) }, null);
        MethodInfo hook = typeof(Program).GetMethod("NewStringCompare",
            BindingFlags.Public | BindingFlags.Static);

        using (ActiveHook = new MethodHook(target, hook))
        {
            ActiveHook.Install();
            PrecodeAddr = ActiveHook.DiagInfo.PrecodeAddr;
            JitCodeAddr = ActiveHook.DiagInfo.JitCodeAddr;

            Console.WriteLine("patchType = " + ActiveHook.DiagInfo.PatchType);
            Console.WriteLine("precodeAddr = 0x" + PrecodeAddr.ToString("X16"));
            Console.WriteLine("jitCodeAddr = 0x" + JitCodeAddr.ToString("X16"));
            Console.WriteLine("patchError = " + (ActiveHook.DiagInfo.PatchError ?? "-"));
            Console.WriteLine();

            // Dump delegate internals
            DumpDelegateInternals(ActiveHook);

            // Dump slot info
            var slotAddressesField = typeof(MethodHook).GetField("_slotAddresses",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var origSlotField = typeof(MethodHook).GetField("_originalSlotValue",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var newSlotField = typeof(MethodHook).GetField("_newSlotValue",
                BindingFlags.NonPublic | BindingFlags.Instance);
            if (slotAddressesField != null)
            {
                var slots = slotAddressesField.GetValue(ActiveHook) as System.Collections.Generic.List<IntPtr>;
                IntPtr origSlot = origSlotField != null ? (IntPtr)origSlotField.GetValue(ActiveHook) : IntPtr.Zero;
                IntPtr newSlot = newSlotField != null ? (IntPtr)newSlotField.GetValue(ActiveHook) : IntPtr.Zero;
                Console.WriteLine("slotCount=" + (slots?.Count ?? 0));
                Console.WriteLine("_originalSlotValue=0x" + origSlot.ToString("X16"));
                Console.WriteLine("_newSlotValue=0x" + newSlot.ToString("X16"));
                if (slots != null)
                {
                    foreach (var sa in slots)
                    {
                        long val = Marshal.ReadInt64(sa);
                        Console.WriteLine("  slot@0x" + sa.ToString("X16") + " = 0x" + val.ToString("X16")
                            + (val == newSlot.ToInt64() ? " (HOOK!)" : val == origSlot.ToInt64() ? " (orig)" : " (?)"));
                    }
                }
            }
            Console.WriteLine();

            HookEntryCount = 0;
            CallOriginalCount = 0;

            Console.WriteLine("=== Calling string.Compare('hello', 'world') ===");
            try
            {
                int r = string.Compare("hello", "world");
                Console.WriteLine("  Result=" + r + " HookEntries=" + HookEntryCount + " CallOriginal=" + CallOriginalCount);
            }
            catch (Exception ex) { Console.WriteLine("  EX: " + ex); }
        }
        Console.WriteLine("Done.");
    }

    static void DumpDelegateInternals(MethodHook hk)
    {
        // Use reflection to get the delegate's internal _methodPtr and _methodPtrAux
        var delegateField = typeof(MethodHook).GetField("_originalDelegate",
            BindingFlags.NonPublic | BindingFlags.Instance);
        if (delegateField == null) { Console.WriteLine("_originalDelegate field not found"); return; }
        Delegate del = delegateField.GetValue(hk) as Delegate;
        if (del == null) { Console.WriteLine("_originalDelegate is null"); return; }

        Console.WriteLine("delegate type: " + del.GetType().FullName);

        var methodPtrField = typeof(Delegate).GetField("_methodPtr",
            BindingFlags.NonPublic | BindingFlags.Instance);
        var methodPtrAuxField = typeof(Delegate).GetField("_methodPtrAux",
            BindingFlags.NonPublic | BindingFlags.Instance);

        if (methodPtrField != null)
        {
            IntPtr mp = (IntPtr)methodPtrField.GetValue(del);
            Console.WriteLine("_methodPtr = 0x" + mp.ToString("X16"));
            if (mp != IntPtr.Zero)
                Console.WriteLine("  _methodPtr bytes: " + FormatBytes(ReadBytes(mp, 8)));
        }
        if (methodPtrAuxField != null)
        {
            IntPtr mpa = (IntPtr)methodPtrAuxField.GetValue(del);
            Console.WriteLine("_methodPtrAux = 0x" + mpa.ToString("X16"));
            if (mpa != IntPtr.Zero)
                Console.WriteLine("  _methodPtrAux bytes: " + FormatBytes(ReadBytes(mpa, 8)));
        }

        // Also dump _delegateInvokeFptr
        var fptrField = typeof(MethodHook).GetField("_delegateInvokeFptr",
            BindingFlags.NonPublic | BindingFlags.Instance);
        if (fptrField != null)
        {
            IntPtr fptr = (IntPtr)fptrField.GetValue(hk);
            Console.WriteLine("_delegateInvokeFptr = 0x" + fptr.ToString("X16"));
        }
        Console.WriteLine();
    }

    static byte[] ReadBytes(IntPtr addr, int count)
    {
        byte[] bytes = new byte[count];
        Marshal.Copy(addr, bytes, 0, count);
        return bytes;
    }

    static string FormatBytes(byte[] bytes)
    {
        return "[" + string.Join(" ", Array.ConvertAll(bytes, b => b.ToString("X2"))) + "]";
    }
}
