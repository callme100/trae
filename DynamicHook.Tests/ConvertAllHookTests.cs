using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Xunit;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    /// <summary>
    /// 针对 <see cref="List{T}.ConvertAll{TOutput}"/> 泛型实例方法的 hook 测试。
    /// 该方法是 BCL 内泛型实例方法，签名 (List&lt;int&gt;, Converter&lt;int,string&gt;) -> List&lt;string&gt;，
    /// 涉及泛型字典寄存器（x64 Windows: RDX, Linux System V: RSI），是验证泛型方法 hook
    /// 跨平台 ABI 适配（adapter trampoline）的核心用例。
    /// </summary>
    public class ConvertAllHookTests
    {
        private readonly ITestOutputHelper _output;

        public ConvertAllHookTests(ITestOutputHelper output)
        {
            _output = output;
        }

        private static MethodInfo GetTargetMethod()
        {
            // ConvertAll<TOutput> 是开放泛型方法，需先获取方法定义再实例化为 ConvertAll<string>
            MethodInfo open = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(m => m.Name == "ConvertAll" && m.IsGenericMethod);
            Assert.NotNull(open);
            return open.MakeGenericMethod(typeof(string));
        }

        private static MethodInfo GetHookMethod_Replace()
        {
            return typeof(ConvertAllHookTests).GetMethod(
                nameof(Hook_ConvertAll_Replace),
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(List<int>), typeof(Converter<int, string>) },
                null);
        }

        /// <summary>hook 替换实现：忽略原转换，固定返回单元素列表。</summary>
        public static List<string> Hook_ConvertAll_Replace(List<int> self, Converter<int, string> converter)
        {
            var result = new List<string>();
            result.Add("HOOKED_CONVERTALL");
            return result;
        }

        /// <summary>
        /// 基本 hook（仅替换返回值）。
        ///
        /// 注意：在 .NET 6+ 上，对泛型方法的直接调用（direct call）会被 backpatch
        /// 为直接调用 JIT 代码，绕过 precode。这会导致 hook（patch 在 precode/JIT 入口）
        /// 不生效。因此该用例在 .NET 6+ 上仅验证委托调用（delegate.Invoke）路径，
        /// 直接调用路径仅在 .NET Framework 4.x 上验证。
        /// </summary>
        [Fact]
        public void Hook_ConvertAll_Generic_ReplaceReturn()
        {
            TestEnvironment.Dump(_output);

            MethodInfo target = GetTargetMethod();
            MethodInfo hook = GetHookMethod_Replace();

            // 预热：确保 JIT 编译并填充泛型字典
            var warmup = new List<int> { 0 };
            var wr = warmup.ConvertAll(x => x.ToString());
            _output.WriteLine($"Pre-hook warmup: [{string.Join(",", wr)}]");

            using (var mh = new MethodHook(target, hook))
            {
                mh.Install();
                _output.WriteLine("=== DiagInfo ===");
                _output.WriteLine(mh.DiagInfo.ToString());

                var list = new List<int> { 1, 2, 3 };

                // 委托调用路径（所有运行时都支持，绕过 direct-call backpatch）
                var delType = typeof(Func<List<int>, Converter<int, string>, List<string>>);
                var del = (Func<List<int>, Converter<int, string>, List<string>>)
                    target.CreateDelegate(delType);
                var resultDel = del(list, new Converter<int, string>(x => x.ToString()));
                _output.WriteLine($"Delegate call result: [{string.Join(",", resultDel)}]");
                Assert.Single(resultDel);
                Assert.Equal("HOOKED_CONVERTALL", resultDel[0]);

                // 直接调用路径：.NET 6+ 会 backpatch 绕过 precode，hook 可能不生效。
                // 仅在 .NET Framework 4.x 上断言直接调用也被 hook。
                if (TestEnvironment.IsNetFramework)
                {
                    var resultDirect = list.ConvertAll(new Converter<int, string>(x => x.ToString()));
                    _output.WriteLine($"Direct call result (.NET FX only): [{string.Join(",", resultDirect)}]");
                    Assert.Single(resultDirect);
                    Assert.Equal("HOOKED_CONVERTALL", resultDirect[0]);
                }
                else
                {
                    _output.WriteLine("Direct call not asserted on .NET 6+ (backpatch bypasses precode).");
                }
            }

            // 卸载后恢复
            var after = new List<int> { 10, 20 };
            var resultAfter = after.ConvertAll(x => x.ToString());
            _output.WriteLine($"Post-uninstall: [{string.Join(",", resultAfter)}]");
            Assert.Equal(2, resultAfter.Count);
            Assert.Equal("10", resultAfter[0]);
            Assert.Equal("20", resultAfter[1]);
        }

        /// <summary>
        /// hook 中调用原始方法并包装结果，验证泛型方法的 CallOriginal 路径
        /// （包括适配器 trampoline 的反向变换）跨平台工作正常。
        /// </summary>
        [Fact]
        public void Hook_ConvertAll_Generic_CallOriginal_Wrap()
        {
            TestEnvironment.Dump(_output);

            MethodInfo target = GetTargetMethod();
            MethodInfo hook = typeof(ConvertAllHookTests).GetMethod(
                nameof(Hook_ConvertAll_Wrap),
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(List<int>), typeof(Converter<int, string>) },
                null);
            Assert.NotNull(hook);

            using (var mh = new MethodHook(target, hook))
            {
                _currentHook = mh;
                mh.Install();
                _output.WriteLine(mh.DiagInfo.ToString());

                var list = new List<int> { 1, 2, 3 };
                var delType = typeof(Func<List<int>, Converter<int, string>, List<string>>);
                var del = (Func<List<int>, Converter<int, string>, List<string>>)
                    target.CreateDelegate(delType);
                var result = del(list, new Converter<int, string>(x => $"item{x}"));
                _output.WriteLine($"Wrapped result: [{string.Join(",", result)}]");

                // 原始返回 ["item1","item2","item3"]，包装后加前缀元素
                Assert.Equal(4, result.Count);
                Assert.Equal("WRAPPED", result[0]);
                Assert.Equal("item1", result[1]);
                Assert.Equal("item2", result[2]);
                Assert.Equal("item3", result[3]);
                _currentHook = null;
            }

            // 卸载后恢复
            var after = new List<int> { 5 };
            var resultAfter = after.ConvertAll(x => x.ToString());
            Assert.Single(resultAfter);
            Assert.Equal("5", resultAfter[0]);
        }

        public static List<string> Hook_ConvertAll_Wrap(List<int> self, Converter<int, string> converter)
        {
            var orig = (List<string>)_currentHook.CallOriginal(self, converter);
            var result = new List<string> { "WRAPPED" };
            result.AddRange(orig);
            return result;
        }

        [ThreadStatic]
        internal static MethodHook _currentHook;

        /// <summary>
        /// 重复安装/卸载多次，验证泛型方法 hook 的槽位/字典状态正确恢复。
        /// </summary>
        [Theory]
        [InlineData(3)]
        public void Hook_ConvertAll_Generic_Reinstall(int times)
        {
            TestEnvironment.Dump(_output);

            MethodInfo target = GetTargetMethod();
            MethodInfo hook = GetHookMethod_Replace();

            for (int i = 0; i < times; i++)
            {
                using (var mh = new MethodHook(target, hook))
                {
                    mh.Install();

                    var list = new List<int> { 1, 2 };
                    var delType = typeof(Func<List<int>, Converter<int, string>, List<string>>);
                    var del = (Func<List<int>, Converter<int, string>, List<string>>)
                        target.CreateDelegate(delType);
                    var result = del(list, new Converter<int, string>(x => x.ToString()));
                    Assert.Single(result);
                    Assert.Equal("HOOKED_CONVERTALL", result[0]);
                }
                // 卸载后恢复
                var after = new List<int> { 7, 8 };
                var ra = after.ConvertAll(x => x.ToString());
                Assert.Equal(2, ra.Count);
                Assert.Equal("7", ra[0]);
                Assert.Equal("8", ra[1]);
                _output.WriteLine($"Iteration {i+1}/{times}: OK");
            }
        }
    }
}
