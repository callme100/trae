using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    /// <summary>
    /// 最小化hook测试 - 不使用CallOriginal，只验证基本hook是否工作
    /// </summary>
    public class MinimalHookTests
    {
        private readonly ITestOutputHelper _output;

        public MinimalHookTests(ITestOutputHelper output)
        {
            _output = output;
        }

        private MethodInfo GetMethod(Type type, string name, params Type[] paramTypes)
        {
            return type.GetMethod(name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static, null, paramTypes ?? Type.EmptyTypes, null);
        }

        // ===== 最简单的静态方法hook =====
        // Hook不调用CallOriginal，只返回固定值
        public static string SimpleHook_Static(int x, string y)
        {
            return $"HOOKED:{x}-{y}";
        }

        [Fact]
        public void Minimal_StaticMethod_Hook_NoCallOriginal()
        {
            var targetMethod = GetMethod(typeof(StaticTarget), "StaticTargetMethod",
                new[] { typeof(int), typeof(string) });
            var hookMethod = GetMethod(typeof(MinimalHookTests), "SimpleHook_Static",
                new[] { typeof(int), typeof(string) });

            Assert.NotNull(targetMethod);
            Assert.NotNull(hookMethod);

            using (var hook = new MethodHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine("=== DiagInfo ===");
                _output.WriteLine(hook.DiagInfo.ToString());

                // 先调用一次看是否crash
                var result = StaticTarget.StaticTargetMethod(42, "test");
                _output.WriteLine($"Result: {result}");
                Assert.Equal("HOOKED:42-test", result);
            }

            // 卸载后
            var r2 = StaticTarget.StaticTargetMethod(100, "after");
            _output.WriteLine($"After uninstall: {r2}");
            Assert.Equal("ORIGINAL:100-after", r2);
        }

        // ===== 实例方法hook - 简单返回 =====
        public static string SimpleHook_ReadToEnd(StreamReader self)
        {
            return "HOOKED_READTOEND";
        }

        [Fact]
        public void Minimal_ReadToEnd_Hook_NoCallOriginal()
        {
            var targetMethod = GetMethod(typeof(StreamReader), "ReadToEnd", Type.EmptyTypes);
            var hookMethod = GetMethod(typeof(MinimalHookTests), "SimpleHook_ReadToEnd",
                new[] { typeof(StreamReader) });

            using (var hook = new MethodHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine(hook.DiagInfo.ToString());

                using (var sr = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("Hello"))))
                {
                    var result = sr.ReadToEnd();
                    _output.WriteLine($"Result: {result}");
                    Assert.Equal("HOOKED_READTOEND", result);
                }
            }

            // 卸载后
            using (var sr = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("World"))))
            {
                var result = sr.ReadToEnd();
                _output.WriteLine($"After uninstall: {result}");
                Assert.Equal("World", result);
            }
        }

        // ===== 泛型方法hook - 简单返回 =====
        public static List<string> SimpleHook_ConvertAll(List<int> self, Converter<int, string> converter)
        {
            var result = new List<string>();
            result.Add("HOOKED_CONVERTALL");
            return result;
        }

        [Fact]
        public void Minimal_ConvertAll_Hook_NoCallOriginal()
        {
            // ConvertAll<TOutput> 是开放泛型方法，需要先获取方法定义再实例化
            var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(m => m.Name == "ConvertAll" && m.IsGenericMethod);
            Assert.NotNull(openMethod);
            var genericTarget = openMethod.MakeGenericMethod(typeof(string));
            var hookMethod = GetMethod(typeof(MinimalHookTests), "SimpleHook_ConvertAll",
                new[] { typeof(List<int>), typeof(Converter<int, string>) });

            // 先调用一次以确保方法被JIT编译，泛型字典被填充
            var list0 = new List<int> { 0 };
            var r0 = list0.ConvertAll(x => x.ToString());
            _output.WriteLine($"Pre-call result: [{string.Join(",", r0)}]");

            using (var hook = new MethodHook(genericTarget, hookMethod))
            {
                hook.Install();
                _output.WriteLine(hook.DiagInfo.ToString());

                // Test 1: direct call after hook install
                var list = new List<int> { 1, 2, 3 };
                var result = list.ConvertAll(new Converter<int, string>(x => x.ToString()));
                _output.WriteLine($"Direct call result count: {result.Count}");
                _output.WriteLine($"Direct call result: [{string.Join(",", result)}]");

                Assert.Single(result);
                Assert.Equal("HOOKED_CONVERTALL", result[0]);

                // Test 2: delegate call after hook install
                var delType = typeof(Func<List<int>, Converter<int, string>, List<string>>);
                var del = (Func<List<int>, Converter<int, string>, List<string>>)
                    genericTarget.CreateDelegate(delType);
                var list2 = new List<int> { 4, 5, 6 };
                var result2 = del(list2, new Converter<int, string>(x => x.ToString()));
                _output.WriteLine($"Delegate call result count: {result2.Count}");
                _output.WriteLine($"Delegate call result: [{string.Join(",", result2)}]");

                Assert.Single(result2);
                Assert.Equal("HOOKED_CONVERTALL", result2[0]);
            }

            // 卸载后
            var list3 = new List<int> { 10, 20 };
            var result3 = list3.ConvertAll(x => x.ToString());
            _output.WriteLine($"After uninstall: [{string.Join(",", result3)}]");
            Assert.Equal(2, result3.Count);
        }

        // ===== 诊断测试：验证 MethodInfo.Invoke 对泛型方法是否工作 =====
        [Fact]
        public void Diag_Invoke_GenericMethod_NoHook()
        {
            var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(m => m.Name == "ConvertAll" && m.IsGenericMethod);
            Assert.NotNull(openMethod);
            var genericMethod = openMethod.MakeGenericMethod(typeof(string));

            var list = new List<int> { 1, 2, 3 };
            var converter = new Converter<int, string>(x => $"item{x}");

            // 1. 直接调用
            var directResult = list.ConvertAll(converter);
            _output.WriteLine($"Direct call: [{string.Join(",", directResult)}]");
            Assert.Equal(3, directResult.Count);

            // 2. MethodInfo.Invoke 调用（无 hook）
            var invokeResult = (List<string>)genericMethod.Invoke(list, new object[] { converter });
            _output.WriteLine($"Invoke call: [{string.Join(",", invokeResult)}]");
            Assert.Equal(3, invokeResult.Count);

            // 3. Delegate.CreateDelegate + DynamicInvoke（无 hook）
            var delegateType = typeof(Func<,,>).MakeGenericType(typeof(List<int>), typeof(Converter<int, string>), typeof(List<string>));
            var del = Delegate.CreateDelegate(delegateType, genericMethod, throwOnBindFailure: false);
            Assert.NotNull(del);
            var dynResult = del.DynamicInvoke(list, converter);
            _output.WriteLine($"DynamicInvoke call: {dynResult}");
            Assert.NotNull(dynResult);

            _output.WriteLine("All invoke methods work without hook.");
        }
    }
}
