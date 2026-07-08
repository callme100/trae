using System;
using System.Reflection;
using DynamicHook;

namespace DynamicHook.ReproConsole
{
    /// <summary>
    /// 独立控制台程序：验证 String.Compare(string,string) 静态方法 hook。
    /// 脱离 xUnit testhost，避免测试框架内部对 String.Compare 的高频调用
    /// 干扰 hook 安装/卸载过程。
    /// </summary>
    internal static class Program
    {
        [ThreadStatic]
        private static bool _armHook;

        [ThreadStatic]
        private static MethodHook _currentHook;

        private static int Main(string[] args)
        {
            Console.WriteLine($"Runtime: {Environment.Version}  Arch: {System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}");
            Console.WriteLine($"Args: {string.Join(",", args)}");

            string mode = args.Length > 0 ? args[0] : "replace";
            int rc = 0;
            switch (mode)
            {
                case "replace": rc = Run_Replace(); break;
                case "negate":  rc = Run_Negate();  break;
                case "reinstall": rc = Run_Reinstall(); break;
                default:
                    Console.Error.WriteLine($"Unknown mode: {mode}");
                    return 2;
            }
            Console.WriteLine($"RESULT={(rc == 0 ? "PASS" : "FAIL")}");
            return rc;
        }

        private static MethodInfo GetTarget()
        {
            return typeof(string).GetMethod("Compare",
                BindingFlags.Public | BindingFlags.Static,
                null, new[] { typeof(string), typeof(string) }, null);
        }

        // ---- Replace 模式 ----
        public static int Hook_Compare_Replace(string a, string b)
        {
            if (_armHook) return 42;
            // 测试：_armHook=false 时直接返回 0，不调用任何可能递归的代码
            return 0;
        }

        private static int Run_Replace()
        {
            var target = GetTarget();
            var hook = typeof(Program).GetMethod(nameof(Hook_Compare_Replace),
                BindingFlags.Public | BindingFlags.Static,
                null, new[] { typeof(string), typeof(string) }, null);

            // 预热
            int pre = string.Compare("abc", "abd");
            Console.WriteLine($"Pre-hook: Compare(\"abc\",\"abd\")={pre} (expect <0)");
            if (pre >= 0) { Console.WriteLine("FAIL: pre-hook"); return 1; }

            using (var mh = new MethodHook(target, hook))
            {
                _currentHook = mh;
                Console.WriteLine("Installing hook...");
                mh.Install();
                Console.WriteLine("Hook installed. DiagInfo:");
                Console.WriteLine(mh.DiagInfo.ToString());

                _armHook = true;
                int r1 = string.Compare("abc", "abd");
                int r2 = string.Compare("zzz", "aaa");
                int r3 = string.Compare("same", "same");
                _armHook = false;
                Console.WriteLine($"Hooked: r1={r1} r2={r2} r3={r3} (expect 42,42,42)");

                if (r1 != 42 || r2 != 42 || r3 != 42) { Console.WriteLine("FAIL: hooked values"); return 1; }
                _currentHook = null;
            }

            int p1 = string.Compare("abc", "abd");
            int p2 = string.Compare("zzz", "aaa");
            int p3 = string.Compare("same", "same");
            Console.WriteLine($"Post-uninstall: p1={p1} p2={p2} p3={p3} (expect <0, >0, 0)");
            if (p1 >= 0 || p2 <= 0 || p3 != 0) { Console.WriteLine("FAIL: post-uninstall"); return 1; }
            Console.WriteLine("PASS: replace mode");
            return 0;
        }

        // ---- Negate 模式 ----
        public static int Hook_Compare_Negate(string a, string b)
        {
            if (!_armHook) return ManualCompareOrdinal(a, b);
            int orig = (int)_currentHook.CallOriginal(null, a, b);
            return -orig;
        }

        private static int Run_Negate()
        {
            var target = GetTarget();
            var hook = typeof(Program).GetMethod(nameof(Hook_Compare_Negate),
                BindingFlags.Public | BindingFlags.Static,
                null, new[] { typeof(string), typeof(string) }, null);

            using (var mh = new MethodHook(target, hook))
            {
                _currentHook = mh;
                Console.WriteLine("Installing negate hook...");
                mh.Install();
                Console.WriteLine(mh.DiagInfo.ToString());

                _armHook = true;
                int r1 = string.Compare("abc", "abd"); // <0 -> >0
                int r2 = string.Compare("zzz", "aaa"); // >0 -> <0
                int r3 = string.Compare("same", "same"); // 0 -> 0
                _armHook = false;
                Console.WriteLine($"Negated: r1={r1} r2={r2} r3={r3} (expect >0, <0, 0)");
                if (r1 <= 0 || r2 >= 0 || r3 != 0) { Console.WriteLine("FAIL: negated values"); return 1; }
                _currentHook = null;
            }

            int p1 = string.Compare("abc", "abd");
            int p2 = string.Compare("zzz", "aaa");
            Console.WriteLine($"Post-uninstall: p1={p1} p2={p2} (expect <0, >0)");
            if (p1 >= 0 || p2 <= 0) { Console.WriteLine("FAIL: post-uninstall"); return 1; }
            Console.WriteLine("PASS: negate mode");
            return 0;
        }

        // ---- Reinstall 模式 ----
        private static int Run_Reinstall()
        {
            var target = GetTarget();
            var hook = typeof(Program).GetMethod(nameof(Hook_Compare_Replace),
                BindingFlags.Public | BindingFlags.Static,
                null, new[] { typeof(string), typeof(string) }, null);

            for (int i = 0; i < 3; i++)
            {
                using (var mh = new MethodHook(target, hook))
                {
                    _currentHook = mh;
                    mh.Install();
                    _armHook = true;
                    int r = string.Compare("a", "b");
                    _armHook = false;
                    Console.WriteLine($"Iter {i+1}: hooked={r} (expect 42)");
                    if (r != 42) { Console.WriteLine("FAIL: reinstall hooked"); return 1; }
                    _currentHook = null;
                }
                int p = string.Compare("a", "b");
                Console.WriteLine($"Iter {i+1}: post={p} (expect <0)");
                if (p >= 0) { Console.WriteLine("FAIL: reinstall post"); return 1; }
            }
            Console.WriteLine("PASS: reinstall mode");
            return 0;
        }

        private static int ManualCompareOrdinal(string a, string b)
        {
            if (a == null) return b == null ? 0 : -1;
            if (b == null) return 1;
            int la = a.Length;
            int lb = b.Length;
            int n = la < lb ? la : lb;
            for (int i = 0; i < n; i++)
            {
                int ca = a[i];
                int cb = b[i];
                if (ca != cb) return ca - cb;
            }
            return la - lb;
        }
    }
}
