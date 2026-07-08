using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace DynamicHook.ReproConsole
{
    class Program
    {
        static int testNum = 0;

        static void Main(string[] args)
        {
            Console.WriteLine($"Runtime: {Environment.Version}");
            Console.WriteLine($"64-bit: {Environment.Is64BitProcess}");
            Console.WriteLine();

            // Test 0: Cold-start hook (NO pre-warm, ConvertAll never called before)
            TestColdStartHook();

            // Test 1: List<int>.ConvertAll<string> with pre-warm
            TestListConvertAll(preWarm: true);

            // Test 2: List<int>.ConvertAll<string> WITHOUT pre-warm
            TestListConvertAll(preWarm: false);

            // Test 3: Lambda syntax (no explicit Converter wrapper)
            TestListConvertAllLambda();

            // Test 4: Array.ConvertAll<int, string> (static generic method)
            TestArrayConvertAll();

            // Test 5: List<string>.ConvertAll<int> (different generic args)
            TestListStringConvertAllInt();

            // Test 6: Hook with CallOriginal
            TestWithCallOriginal();

            Console.WriteLine("\nAll tests done. Press any key to exit...");
            if (!Console.IsInputRedirected) Console.ReadKey();
        }

        // ===== Hook methods =====

        // Hook for List<int>.ConvertAll<string> (instance, 2 args: this + converter)
        public static object NewConvertAll(object list, object function)
        {
            Console.WriteLine($"  [HOOK #{testNum}] NewConvertAll invoked!");
            return new List<string> { "a", "b" };
        }

        // Hook for Array.ConvertAll<int, string> (static, 2 args: array + converter)
        public static object NewArrayConvertAll(object array, object function)
        {
            Console.WriteLine($"  [HOOK #{testNum}] NewArrayConvertAll invoked!");
            return new[] { "x", "y" };
        }

        // Hook that calls CallOriginal
        public static List<string> HookWithCallOriginal(List<int> self, Converter<int, string> converter)
        {
            Console.WriteLine($"  [HOOK #{testNum}] HookWithCallOriginal invoked, calling CallOriginal...");
            var result = TestState.ActiveHook?.CallOriginal(self, converter);
            Console.WriteLine($"  [HOOK #{testNum}] CallOriginal returned: {result}");
            return (List<string>)result;
        }

        // ===== Tests =====

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        static void TestColdStartHook()
        {
            testNum++;
            Console.WriteLine($"=== Test {testNum}: Cold-start hook (NO pre-warm) ===");
            try
            {
                var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .First(m => m.Name == "ConvertAll" && m.IsGenericMethod);
                var target = openMethod.MakeGenericMethod(typeof(string));
                var hook = typeof(Program).GetMethod("NewConvertAll",
                    BindingFlags.Static | BindingFlags.Public, null,
                    new[] { typeof(object), typeof(object) }, null);

                using (var h = new MethodHook(target, hook))
                {
                    h.Install();
                    Console.WriteLine($"  Patch: {h.DiagInfo.PatchType} | {h.DiagInfo.PatchError}");
                    Console.WriteLine($"  Precode bytes: {BitConverter.ToString(h.DiagInfo.PrecodeBytes ?? Array.Empty<byte>())}");
                    Console.WriteLine($"  JitCodeAddr: 0x{h.DiagInfo.JitCodeAddr.ToInt64():X}");
                    Console.WriteLine($"  JitCodeOrig: {BitConverter.ToString(h.DiagInfo.JitCodeOriginalBytes ?? Array.Empty<byte>())}");
                    Console.WriteLine($"  JitCodePatched: {BitConverter.ToString(h.DiagInfo.JitCodePatchedBytes ?? Array.Empty<byte>())}");
                    Console.WriteLine($"  Adapter: 0x{h.DiagInfo.AdapterAddr.ToInt64():X} Bytes: {BitConverter.ToString(h.DiagInfo.AdapterBytes ?? Array.Empty<byte>())}");
                    Console.WriteLine($"  JumpTarget: 0x{h.DiagInfo.JumpTargetAddr.ToInt64():X}");
                    var list = new List<int> { 1, 2, 3 };
                    var result = list.ConvertAll(new Converter<int, string>(x => x.ToString()));
                    Console.WriteLine($"  Result: [{string.Join(",", result)}]");
                }
            }
            catch (Exception ex) { Console.WriteLine($"  FAILED: {ex.GetType().Name}: {ex.Message}"); }
            Console.WriteLine();
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        static void TestListConvertAll(bool preWarm)
        {
            testNum++;
            Console.WriteLine($"=== Test {testNum}: List<int>.ConvertAll<string>, preWarm={preWarm} ===");
            try
            {
                if (preWarm)
                {
                    var w = new List<int> { 0 }.ConvertAll(x => $"w{x}");
                    Console.WriteLine($"  Warmup: [{string.Join(",", w)}]");
                }

                var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .First(m => m.Name == "ConvertAll" && m.IsGenericMethod);
                var target = openMethod.MakeGenericMethod(typeof(string));
                var hook = typeof(Program).GetMethod("NewConvertAll",
                    BindingFlags.Static | BindingFlags.Public, null,
                    new[] { typeof(object), typeof(object) }, null);

                using (var h = new MethodHook(target, hook))
                {
                    h.Install();
                    Console.WriteLine($"  Patch: {h.DiagInfo.PatchType} | {h.DiagInfo.PatchError}");
                    var list = new List<int> { 1, 2, 3 };
                    var result = list.ConvertAll(new Converter<int, string>(x => x.ToString()));
                    Console.WriteLine($"  Result: [{string.Join(",", result)}]");
                }
                var r2 = new List<int> { 10 }.ConvertAll(x => x.ToString());
                Console.WriteLine($"  After uninstall: [{string.Join(",", r2)}]");
            }
            catch (Exception ex) { Console.WriteLine($"  FAILED: {ex.GetType().Name}: {ex.Message}"); }
            Console.WriteLine();
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        static void TestListConvertAllLambda()
        {
            testNum++;
            Console.WriteLine($"=== Test {testNum}: Lambda syntax (no explicit Converter) ===");
            try
            {
                var w = new List<int> { 0 }.ConvertAll(x => $"w{x}");

                var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .First(m => m.Name == "ConvertAll" && m.IsGenericMethod);
                var target = openMethod.MakeGenericMethod(typeof(string));
                var hook = typeof(Program).GetMethod("NewConvertAll",
                    BindingFlags.Static | BindingFlags.Public, null,
                    new[] { typeof(object), typeof(object) }, null);

                using (var h = new MethodHook(target, hook))
                {
                    h.Install();
                    Console.WriteLine($"  Patch: {h.DiagInfo.PatchType}");
                    // Lambda syntax - compiler creates Converter internally
                    var list = new List<int> { 1, 2, 3 };
                    var result = list.ConvertAll(x => x.ToString());
                    Console.WriteLine($"  Result: [{string.Join(",", result)}]");
                }
            }
            catch (Exception ex) { Console.WriteLine($"  FAILED: {ex.GetType().Name}: {ex.Message}"); }
            Console.WriteLine();
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        static void TestArrayConvertAll()
        {
            testNum++;
            Console.WriteLine($"=== Test {testNum}: Array.ConvertAll<int,string> (static generic) ===");
            try
            {
                // Pre-warm
                var w = Array.ConvertAll(new[] { 0 }, x => $"w{x}");

                var openMethod = typeof(Array).GetMethods(BindingFlags.Public | BindingFlags.Static)
                    .First(m => m.Name == "ConvertAll" && m.IsGenericMethod);
                var target = openMethod.MakeGenericMethod(typeof(int), typeof(string));
                var hook = typeof(Program).GetMethod("NewArrayConvertAll",
                    BindingFlags.Static | BindingFlags.Public, null,
                    new[] { typeof(object), typeof(object) }, null);

                Console.WriteLine($"  Target: {target}");
                Console.WriteLine($"  Hook:   {hook}");

                using (var h = new MethodHook(target, hook))
                {
                    h.Install();
                    Console.WriteLine($"  Patch: {h.DiagInfo.PatchType} | {h.DiagInfo.PatchError}");
                    var arr = new[] { 1, 2, 3 };
                    var result = Array.ConvertAll(arr, new Converter<int, string>(x => x.ToString()));
                    Console.WriteLine($"  Result: [{string.Join(",", result)}]");
                }
                var r2 = Array.ConvertAll(new[] { 10 }, x => x.ToString());
                Console.WriteLine($"  After uninstall: [{string.Join(",", r2)}]");
            }
            catch (Exception ex) { Console.WriteLine($"  FAILED: {ex.GetType().Name}: {ex.Message}"); }
            Console.WriteLine();
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        static void TestListStringConvertAllInt()
        {
            testNum++;
            Console.WriteLine($"=== Test {testNum}: List<string>.ConvertAll<int> (different generic args) ===");
            try
            {
                var w = new List<string> { "0" }.ConvertAll(x => int.Parse(x));

                var openMethod = typeof(List<string>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .First(m => m.Name == "ConvertAll" && m.IsGenericMethod);
                var target = openMethod.MakeGenericMethod(typeof(int));
                Console.WriteLine($"  Target: {target}");

                // Hook with matching signature
                var hookMethod = typeof(Program).GetMethod("HookListStringConvertAllInt",
                    BindingFlags.Static | BindingFlags.Public, null,
                    new[] { typeof(List<string>), typeof(Converter<string, int>) }, null);

                using (var h = new MethodHook(target, hookMethod))
                {
                    h.Install();
                    Console.WriteLine($"  Patch: {h.DiagInfo.PatchType} | {h.DiagInfo.PatchError}");
                    var list = new List<string> { "1", "2", "3" };
                    var result = list.ConvertAll(new Converter<string, int>(x => int.Parse(x)));
                    Console.WriteLine($"  Result: [{string.Join(",", result)}]");
                }
            }
            catch (Exception ex) { Console.WriteLine($"  FAILED: {ex.GetType().Name}: {ex.Message}"); }
            Console.WriteLine();
        }

        public static List<int> HookListStringConvertAllInt(List<string> self, Converter<string, int> converter)
        {
            Console.WriteLine($"  [HOOK #{testNum}] HookListStringConvertAllInt invoked!");
            return new List<int> { 99, 88 };
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        static void TestWithCallOriginal()
        {
            testNum++;
            Console.WriteLine($"=== Test {testNum}: Hook with CallOriginal ===");
            try
            {
                var w = new List<int> { 0 }.ConvertAll(x => $"w{x}");

                var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .First(m => m.Name == "ConvertAll" && m.IsGenericMethod);
                var target = openMethod.MakeGenericMethod(typeof(string));
                var hook = typeof(Program).GetMethod("HookWithCallOriginal",
                    BindingFlags.Static | BindingFlags.Public, null,
                    new[] { typeof(List<int>), typeof(Converter<int, string>) }, null);

                using (var h = new MethodHook(target, hook))
                {
                    h.Install();
                    TestState.ActiveHook = h;
                    Console.WriteLine($"  Patch: {h.DiagInfo.PatchType} | {h.DiagInfo.PatchError}");
                    Console.WriteLine($"  --- Full DiagInfo ---");
                    Console.WriteLine(h.DiagInfo.ToString());
                    var list = new List<int> { 1, 2, 3 };
                    var result = list.ConvertAll(new Converter<int, string>(x => $"v{x}"));
                    Console.WriteLine($"  Result: [{string.Join(",", result)}]");
                    TestState.ActiveHook = null;
                }
            }
            catch (Exception ex) { Console.WriteLine($"  FAILED: {ex.GetType().Name}: {ex.Message}"); }
            Console.WriteLine();
        }
    }

    static class TestState
    {
        public static MethodHook ActiveHook;
    }
}
