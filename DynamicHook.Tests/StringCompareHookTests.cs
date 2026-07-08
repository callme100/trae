using System;
using System.Reflection;
using Xunit;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    /// <summary>
    /// 针对 <see cref="string.Compare(string, string)"/> 静态方法的 hook 测试。
    ///
    /// 该方法是 BCL 内静态方法，签名固定为 (string, string) -> int，
    /// 不涉及泛型字典/实例 this 指针，是验证静态方法 hook 的最小用例。
    ///
    /// 重要：<see cref="string.Compare(string, string)"/> 被测试框架（xUnit）、
    /// 运行时、GC 等大量内部代码调用。直接全局替换其返回值会导致测试进程崩溃/死循环。
    /// 因此 hook 方法使用 <see cref="_armHook"/> 重入保护标志：仅在测试主动设置的
    /// "生效窗口"内返回替换值，其余调用通过 <see cref="MethodHook.CallOriginal"/>
    /// 透传原始行为，避免干扰框架内部逻辑。
    /// </summary>
    public class StringCompareHookTests
    {
        private readonly ITestOutputHelper _output;

        public StringCompareHookTests(ITestOutputHelper output)
        {
            _output = output;
        }

        private static MethodInfo GetTargetMethod()
        {
            return typeof(string).GetMethod(
                "Compare",
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(string), typeof(string) },
                null);
        }

        /// <summary>
        /// 重入保护标志。仅当测试代码在调用 String.Compare 前将其设为 true，
        /// hook 才返回替换值；调用后立即设回 false。这样测试框架/运行时内部的
        /// String.Compare 调用（发生在标志为 false 时）会透传原始行为。
        /// </summary>
        [ThreadStatic]
        private static bool _armHook;

        /// <summary>当前 hook 实例，供 hook 方法内调用 CallOriginal 使用。</summary>
        [ThreadStatic]
        private static MethodHook _currentHook;

        /// <summary>hook 替换实现：仅在生效窗口内返回 42，否则透传原始结果。</summary>
        public static int Hook_StringCompare(string a, string b)
        {
            if (_armHook)
            {
                return 42;
            }
            // 非测试主动调用：透传原始行为，避免干扰框架内部逻辑。
            return (int)_currentHook.CallOriginal(null, a, b);
        }

        /// <summary>hook 反转实现：仅在生效窗口内反转符号，否则透传原始结果。</summary>
        public static int Hook_StringCompare_Negate(string a, string b)
        {
            int orig = (int)_currentHook.CallOriginal(null, a, b);
            if (_armHook)
            {
                return -orig;
            }
            return orig;
        }

        /// <summary>
        /// 基本 hook：安装后 String.Compare 在生效窗口内返回固定值 42，
        /// 卸载后恢复原始比较语义。
        /// </summary>
        [Fact]
        public void Hook_StringCompare_Static_ReplaceReturn()
        {
            TestEnvironment.Dump(_output);

            MethodInfo target = GetTargetMethod();
            MethodInfo hook = typeof(StringCompareHookTests).GetMethod(
                nameof(Hook_StringCompare),
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(string), typeof(string) },
                null);
            Assert.NotNull(target);
            Assert.NotNull(hook);

            // 预热：确保 JIT 编译
            int pre = string.Compare("abc", "abd");
            _output.WriteLine($"Pre-hook: Compare(\"abc\",\"abd\") = {pre}");
            Assert.True(pre < 0);

            using (var mh = new MethodHook(target, hook))
            {
                _currentHook = mh;
                mh.Install();
                _output.WriteLine("=== DiagInfo ===");
                _output.WriteLine(mh.DiagInfo.ToString());

                // 生效窗口：仅在这几次调用期间 _armHook=true
                _armHook = true;
                int r1 = string.Compare("abc", "abd");
                int r2 = string.Compare("zzz", "aaa");
                int r3 = string.Compare("same", "same");
                _armHook = false;

                _output.WriteLine($"Hooked: Compare(\"abc\",\"abd\")={r1}, Compare(\"zzz\",\"aaa\")={r2}, Compare(\"same\",\"same\")={r3}");

                Assert.Equal(42, r1);
                Assert.Equal(42, r2);
                Assert.Equal(42, r3);
                _currentHook = null;
            }

            // 卸载后恢复
            int post1 = string.Compare("abc", "abd");
            int post2 = string.Compare("zzz", "aaa");
            int post3 = string.Compare("same", "same");
            _output.WriteLine($"Post-uninstall: {post1}, {post2}, {post3}");
            Assert.True(post1 < 0);
            Assert.True(post2 > 0);
            Assert.Equal(0, post3);
        }

        /// <summary>
        /// hook 中调用原始方法并修改返回值：反转比较结果符号。
        /// 验证 CallOriginal 路径在静态方法上工作正常。
        /// </summary>
        [Fact]
        public void Hook_StringCompare_Static_CallOriginal_Negate()
        {
            TestEnvironment.Dump(_output);

            MethodInfo target = GetTargetMethod();
            MethodInfo hook = typeof(StringCompareHookTests).GetMethod(
                nameof(Hook_StringCompare_Negate),
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(string), typeof(string) },
                null);
            Assert.NotNull(hook);

            using (var mh = new MethodHook(target, hook))
            {
                _currentHook = mh;
                mh.Install();
                _output.WriteLine(mh.DiagInfo.ToString());

                _armHook = true;
                int r1 = string.Compare("abc", "abd"); // 原本 <0 → 反转 >0
                int r2 = string.Compare("zzz", "aaa"); // 原本 >0 → 反转 <0
                int r3 = string.Compare("same", "same"); // 原本 0 → 仍 0
                _armHook = false;

                _output.WriteLine($"Negated: {r1}, {r2}, {r3}");

                Assert.True(r1 > 0);
                Assert.True(r2 < 0);
                Assert.Equal(0, r3);
                _currentHook = null;
            }

            // 卸载后恢复
            Assert.True(string.Compare("abc", "abd") < 0);
            Assert.True(string.Compare("zzz", "aaa") > 0);
            Assert.Equal(0, string.Compare("same", "same"));
        }

        /// <summary>
        /// 重复安装/卸载多次，验证状态正确恢复，无残留补丁导致无限循环。
        /// </summary>
        [Theory]
        [InlineData(3)]
        public void Hook_StringCompare_Static_Reinstall(int times)
        {
            TestEnvironment.Dump(_output);

            MethodInfo target = GetTargetMethod();
            MethodInfo hook = typeof(StringCompareHookTests).GetMethod(
                nameof(Hook_StringCompare),
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(string), typeof(string) },
                null);

            for (int i = 0; i < times; i++)
            {
                using (var mh = new MethodHook(target, hook))
                {
                    _currentHook = mh;
                    mh.Install();
                    _armHook = true;
                    int r = string.Compare("a", "b");
                    _armHook = false;
                    Assert.Equal(42, r);
                    _currentHook = null;
                }
                // 卸载后立即验证恢复
                Assert.True(string.Compare("a", "b") < 0);
                _output.WriteLine($"Iteration {i+1}/{times}: OK");
            }
        }
    }
}
