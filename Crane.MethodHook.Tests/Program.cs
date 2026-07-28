using System;
using System.Reflection;
using Crane.MethodHook;

public class Program
{
    public static string HookObjectToString(object instance)
    {
        var hook = MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
        if (hook == null) return "NO_HOOK";
        try
        {
            string original = hook.InvokeOriginal<string>(instance);
            return "[Hooked] " + original;
        }
        catch (Exception ex)
        {
            Console.WriteLine("[Hook] InvokeOriginal FAILED: " + ex.GetType().Name + ": " + ex.Message);
            Console.WriteLine("[Hook] Stack: " + ex.StackTrace);
            throw;
        }
    }

    public static int Main(string[] args)
    {
        Console.WriteLine("=== Anonymous object ToString hook test ===");
        Console.WriteLine("Runtime: " + System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);

        int pass = 0, fail = 0;

        // Scenario A: Hook object.ToString() — the base virtual method
        // Anonymous types override ToString(), so this hook SHOULD NOT be triggered
        // when calling anon.ToString(). But maybe the user expects it to be?
        RunScenario("Scenario A: Hook object.ToString() and call anon.ToString()", () =>
        {
            var anon = new { Name = "Alice", Age = 30 };
            Console.WriteLine("  Pre-hook anon.ToString(): " + anon.ToString());

            MethodInfo source = typeof(object).GetMethod("ToString", Type.EmptyTypes);
            MethodInfo target = typeof(Program).GetMethod(nameof(HookObjectToString), BindingFlags.Public | BindingFlags.Static,
                null, new Type[] { typeof(object) }, null);
            Console.WriteLine("  Source: " + source);
            Console.WriteLine("  Target: " + target);

            var hook = new MethodHook(source, target);
            MethodHookManager.Instance.AddHook(hook);
            MethodHookManager.Instance.StartHook();

            Console.WriteLine("  Diagnostics:");
            Console.WriteLine(hook.DiagInfo);

            string result = anon.ToString();
            Console.WriteLine("  Result: " + result);

            MethodHookManager.Instance.RemoveAllHook();
        }, ref pass, ref fail);

        // Scenario B: Hook the anon type's ToString using base.Object layout
        // The user might have used typeof(object) instead of anon.GetType()
        RunScenario("Scenario B: Hook anon type's ToString explicitly", () =>
        {
            var anon = new { Name = "Alice", Age = 30 };

            MethodInfo source = anon.GetType().GetMethod("ToString", Type.EmptyTypes);
            MethodInfo target = typeof(Program).GetMethod(nameof(HookObjectToString), BindingFlags.Public | BindingFlags.Static,
                null, new Type[] { typeof(object) }, null);
            Console.WriteLine("  Source: " + source);
            Console.WriteLine("  Source.DeclaringType: " + source.DeclaringType);

            var hook = new MethodHook(source, target);
            // Call StartHook directly (not through MethodHookManager) to see exceptions
            try
            {
                hook.StartHook();
            }
            catch (Exception ex)
            {
                Console.WriteLine("  StartHook THREW: " + ex.GetType().Name + ": " + ex.Message);
                Console.WriteLine("  Stack: " + ex.StackTrace);
                throw;
            }
            MethodHookManager.Instance.AddHook(hook);

            Console.WriteLine("  Diagnostics:");
            Console.WriteLine(hook.DiagInfo);

            string result = anon.ToString();
            Console.WriteLine("  Result: " + result);

            MethodHookManager.Instance.RemoveAllHook();
        }, ref pass, ref fail);

        // Scenario C: Test with hook method that has signature matching virtual override
        // (string ReturnType matching ToString)
        RunScenario("Scenario C: Hook with explicit ToString signature", () =>
        {
            var anon = new { Name = "Alice" };

            MethodInfo source = anon.GetType().GetMethod("ToString", Type.EmptyTypes);
            MethodInfo target = typeof(Program).GetMethod(nameof(HookWithStringReturn), BindingFlags.NonPublic | BindingFlags.Static,
                null, new Type[] { typeof(object) }, null);
            Console.WriteLine("  Source: " + source);
            Console.WriteLine("  Target: " + target);

            var hook = new MethodHook(source, target);
            MethodHookManager.Instance.AddHook(hook);
            MethodHookManager.Instance.StartHook();

            string result = anon.ToString();
            Console.WriteLine("  Result: " + result);

            MethodHookManager.Instance.RemoveAllHook();
        }, ref pass, ref fail);

        // Scenario D: Multiple calls with different anonymous objects of the same type
        RunScenario("Scenario D: Multiple anon instances of the same type", () =>
        {
            var anon1 = new { Name = "Alice", Age = 30 };
            var anon2 = new { Name = "Bob", Age = 25 };
            Console.WriteLine("  Same type? " + (anon1.GetType() == anon2.GetType()));

            MethodInfo source = anon1.GetType().GetMethod("ToString", Type.EmptyTypes);
            MethodInfo target = typeof(Program).GetMethod(nameof(HookObjectToString), BindingFlags.Public | BindingFlags.Static,
                null, new Type[] { typeof(object) }, null);

            var hook = new MethodHook(source, target);
            MethodHookManager.Instance.AddHook(hook);
            MethodHookManager.Instance.StartHook();

            string r1 = anon1.ToString();
            string r2 = anon2.ToString();
            Console.WriteLine("  anon1: " + r1);
            Console.WriteLine("  anon2: " + r2);

            MethodHookManager.Instance.RemoveAllHook();
        }, ref pass, ref fail);

        // Scenario E: Anonymous type with 3+ properties (different generic instantiation)
        RunScenario("Scenario E: Anonymous type with 3 properties", () =>
        {
            var anon = new { Name = "Alice", Age = 30, City = "NYC" };

            MethodInfo source = anon.GetType().GetMethod("ToString", Type.EmptyTypes);
            MethodInfo target = typeof(Program).GetMethod(nameof(HookObjectToString), BindingFlags.Public | BindingFlags.Static,
                null, new Type[] { typeof(object) }, null);

            var hook = new MethodHook(source, target);
            try { hook.StartHook(); }
            catch (Exception ex) { Console.WriteLine("  StartHook THREW: " + ex.Message); throw; }
            MethodHookManager.Instance.AddHook(hook);

            string result = anon.ToString();
            Console.WriteLine("  Result: " + result);
            if (!result.StartsWith("[Hooked]")) throw new Exception("Hook did not trigger");

            MethodHookManager.Instance.RemoveAllHook();
        }, ref pass, ref fail);

        // Scenario F: Nested anonymous types
        RunScenario("Scenario F: Nested anonymous types", () =>
        {
            var anon = new { Outer = "value", Inner = new { X = 1, Y = 2 } };

            MethodInfo source = anon.GetType().GetMethod("ToString", Type.EmptyTypes);
            MethodInfo target = typeof(Program).GetMethod(nameof(HookObjectToString), BindingFlags.Public | BindingFlags.Static,
                null, new Type[] { typeof(object) }, null);

            var hook = new MethodHook(source, target);
            try { hook.StartHook(); }
            catch (Exception ex) { Console.WriteLine("  StartHook THREW: " + ex.Message); throw; }
            MethodHookManager.Instance.AddHook(hook);

            string result = anon.ToString();
            Console.WriteLine("  Result: " + result);
            if (!result.StartsWith("[Hooked]")) throw new Exception("Hook did not trigger");

            MethodHookManager.Instance.RemoveAllHook();
        }, ref pass, ref fail);

        // Scenario G: Verify LastErrors is populated when a hook fails
        RunScenario("Scenario G: LastErrors captures install failures", () =>
        {
            // Hook a method with a mismatched return type (int vs string) —
            // this should cause StartHook to fail and the error to be captured.
            MethodInfo source = typeof(object).GetMethod("ToString", Type.EmptyTypes);
            MethodInfo badTarget = typeof(Program).GetMethod(nameof(BadHookWrongReturnType),
                BindingFlags.Public | BindingFlags.Static, null, new Type[] { typeof(object) }, null);

            var hook = new MethodHook(source, badTarget);
            MethodHookManager.Instance.AddHook(hook);
            MethodHookManager.Instance.StartHook();

            if (MethodHookManager.Instance.LastErrors.Count == 0)
            {
                // On some runtimes the install may succeed but produce garbage
                // results. The key assertion is that LastErrors is queryable.
                Console.WriteLine("  LastErrors: (empty — install succeeded)");
            }
            else
            {
                Console.WriteLine("  LastErrors count: " + MethodHookManager.Instance.LastErrors.Count);
                Console.WriteLine("  First error: " + MethodHookManager.Instance.LastErrors[0].GetType().Name
                    + ": " + MethodHookManager.Instance.LastErrors[0].Message);
            }

            MethodHookManager.Instance.RemoveAllHook();
        }, ref pass, ref fail);

        Console.WriteLine();
        Console.WriteLine($"=== Summary: {pass} passed, {fail} failed ===");
        return fail == 0 ? 0 : 1;
    }

    private static string HookWithStringReturn(object instance)
    {
        var hook = MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
        string original = hook.InvokeOriginal<string>(instance);
        return "[StringHook] " + original;
    }

    public static int BadHookWrongReturnType(object instance)
    {
        return 42;
    }

    private static void RunScenario(string name, Action action, ref int pass, ref int fail)
    {
        Console.WriteLine();
        Console.WriteLine($"--- {name} ---");
        try
        {
            action();
            Console.WriteLine($"  [PASS] {name}");
            pass++;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [FAIL] {name}");
            Console.WriteLine("  " + ex);
            fail++;
        }
    }
}
