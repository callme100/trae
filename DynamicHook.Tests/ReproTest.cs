using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using DynamicHook;

namespace DynamicHook.Tests
{
    /// <summary>
    /// Reproduces the user's scenario: hook method with return type `object`
    /// instead of `int` for DateTime.Compare.
    /// </summary>
    internal static class ReproTest
    {
        // The user's hook method — returns object instead of int.
        public static object NewCompare(DateTime str1, DateTime str2)
        {
            Console.WriteLine("  [HOOK ENTERED] str1=" + str1 + " str2=" + str2);
            return 999;
        }

        // Simplified: no Console.WriteLine, just a static counter.
        public static int HookEntryCount = 0;
        public static DateTime LastD1;
        public static DateTime LastD2;

        public static object NewCompareSimple(DateTime str1, DateTime str2)
        {
            HookEntryCount++;
            LastD1 = str1;
            LastD2 = str2;
            return 999;
        }

        // Correct signature: returns int.
        public static int CorrectCompare(DateTime d1, DateTime d2)
        {
            HookEntryCount++;
            LastD1 = d1;
            LastD2 = d2;
            return -1;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int DirectCall(DateTime a, DateTime b)
        {
            return DateTime.Compare(a, b);
        }

        public static void Run()
        {
            Console.WriteLine("=== Repro: user's scenario (object return) on .NET 8 ===");
            Console.WriteLine("CLR: " + System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
            Console.WriteLine();

            MethodInfo target = typeof(DateTime).GetMethod(
                "Compare",
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(DateTime), typeof(DateTime) },
                null);

            DateTime a = new DateTime(2024, 1, 1);
            DateTime b = new DateTime(2025, 1, 1);

            // Warm up
            int baseline = DateTime.Compare(a, b);
            Console.WriteLine("Baseline: DateTime.Compare(a, b) = " + baseline);

            // --- Test 1: simplified object return hook (no Console.WriteLine) ---
            Console.WriteLine("\n--- Test 1: simplified `object` return hook (direct call) ---");
            MethodInfo hookObj = typeof(ReproTest).GetMethod(
                "NewCompareSimple",
                BindingFlags.Public | BindingFlags.Static);
            Console.WriteLine("Hook return type: " + hookObj.ReturnType);
            Console.WriteLine("Target return type: " + target.ReturnType);

            try
            {
                using (var hk = new MethodHook(target, hookObj))
                {
                    hk.Install();
                    Console.WriteLine("Install OK.");
                    Console.WriteLine("  patchType: " + hk.DiagInfo.PatchType);
                    Console.WriteLine("  patchTarget: " + hk.DiagInfo.PatchTarget);
                    Console.WriteLine("  hookPrecode: 0x" + hk.DiagInfo.HookPrecodeAddr.ToInt64().ToString("X"));
                    Console.WriteLine("  hookResolved: 0x" + hk.DiagInfo.HookResolvedEntry.ToInt64().ToString("X"));
                    string hpb = hk.DiagInfo.HookPrecodeBytes != null
                        ? string.Join(" ", System.Linq.Enumerable.Select(hk.DiagInfo.HookPrecodeBytes, x => x.ToString("X2")))
                        : "-";
                    Console.WriteLine("  hookPrecodeBytes: [" + hpb + "]");
                    Console.WriteLine("  patchError: " + (hk.DiagInfo.PatchError ?? "-"));

                    HookEntryCount = 0;
                    Console.WriteLine("Calling DirectCall(a, b)...");
                    int result = DirectCall(a, b);
                    Console.WriteLine("Result: " + result + " HookEntryCount: " + HookEntryCount);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: " + ex.GetType().Name + ": " + ex.Message);
            }

            // --- Test 2: correct int return hook ---
            Console.WriteLine("\n--- Test 2: correct `int` return hook (direct call) ---");
            MethodInfo hookInt = typeof(ReproTest).GetMethod(
                "CorrectCompare",
                BindingFlags.Public | BindingFlags.Static);

            try
            {
                using (var hk = new MethodHook(target, hookInt))
                {
                    hk.Install();
                    Console.WriteLine("Install OK.");
                    Console.WriteLine("  patchType: " + hk.DiagInfo.PatchType);
                    Console.WriteLine("  hookPrecode: 0x" + hk.DiagInfo.HookPrecodeAddr.ToInt64().ToString("X"));
                    Console.WriteLine("  hookResolved: 0x" + hk.DiagInfo.HookResolvedEntry.ToInt64().ToString("X"));

                    HookEntryCount = 0;
                    Console.WriteLine("Calling DirectCall(a, b)...");
                    int result = DirectCall(a, b);
                    Console.WriteLine("Result: " + result + " HookEntryCount: " + HookEntryCount);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: " + ex.GetType().Name + ": " + ex.Message);
            }

            // --- Test 3: object return hook via delegate ---
            Console.WriteLine("\n--- Test 3: `object` return hook via delegate ---");
            Func<DateTime, DateTime, int> cmpDel = DateTime.Compare;
            try
            {
                using (var hk = new MethodHook(target, hookObj))
                {
                    hk.Install();
                    Console.WriteLine("Install OK. patchType: " + hk.DiagInfo.PatchType);

                    HookEntryCount = 0;
                    Console.WriteLine("Calling via delegate...");
                    int result = cmpDel(a, b);
                    Console.WriteLine("Result: " + result + " HookEntryCount: " + HookEntryCount);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: " + ex.GetType().Name + ": " + ex.Message);
            }

            Console.WriteLine("\n=== Done ===");
        }
    }
}
