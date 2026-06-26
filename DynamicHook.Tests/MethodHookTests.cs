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
    public class MethodHookTests
    {
        private readonly ITestOutputHelper _output;

        public MethodHookTests(ITestOutputHelper output)
        {
            _output = output;
        }

        private MethodInfo GetMethod(Type type, string name, params Type[] paramTypes)
        {
            return type.GetMethod(name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static, null, paramTypes ?? Type.EmptyTypes, null);
        }

        private MethodHook CreateHook(MethodBase target, MethodBase hook)
        {
            var h = new MethodHook(target, hook);
            TestState.ActiveHook = h;
            return h;
        }

        // ============================================================
        // StreamReader.ReadToEnd() - 实例方法测试
        // ============================================================

        [Fact]
        public void Hook_StreamReader_ReadToEnd_Basic()
        {
            TestState.Reset();

            var targetMethod = GetMethod(typeof(StreamReader), "ReadToEnd", Type.EmptyTypes);
            var hookMethod = GetMethod(typeof(HookContainer), "HookReadToEnd", new[] { typeof(StreamReader) });

            Assert.NotNull(targetMethod);
            Assert.NotNull(hookMethod);

            using (var hook = CreateHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine("=== DiagInfo ===");
                _output.WriteLine(hook.DiagInfo.ToString());

                // 调用ReadToEnd，应该被hook拦截
                using (var sr = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("Hello World"))))
                {
                    var result = sr.ReadToEnd();
                    _output.WriteLine($"Result: {result}");

                    Assert.Equal("ReadToEnd", TestState.LastHookCall);
                    Assert.Equal(1, TestState.HookCallCount);
                    Assert.NotNull(TestState.LastInstance);
                    Assert.Same(sr, TestState.LastInstance);
                    // CallOriginal should return actual content
                    Assert.Equal("Hello World", result);
                }
            }

            // 卸载后应恢复正常
            TestState.Reset();
            using (var sr = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("AfterUnhook"))))
            {
                var result = sr.ReadToEnd();
                Assert.Equal("AfterUnhook", result);
                Assert.Equal(0, TestState.HookCallCount);
            }
        }

        [Fact]
        public void Hook_StreamReader_ReadToEnd_CallOriginal()
        {
            TestState.Reset();

            var targetMethod = GetMethod(typeof(StreamReader), "ReadToEnd", Type.EmptyTypes);
            var hookMethod = GetMethod(typeof(HookContainer), "HookReadToEnd", new[] { typeof(StreamReader) });

            using (var hook = CreateHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine(hook.DiagInfo.ToString());

                using (var sr = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("ORIGINAL_CONTENT"))))
                {
                    var result = sr.ReadToEnd();
                    _output.WriteLine($"Hooked result: {result}");
                    Assert.Equal("ORIGINAL_CONTENT", result);
                }
            }
        }

        // ============================================================
        // List<int>.ConvertAll<string>() - 泛型方法测试
        // ============================================================

        [Fact]
        public void Hook_List_ConvertAll_GenericMethod()
        {
            TestState.Reset();

            // List<int>.ConvertAll<string>(Converter<int,string>)
            // ConvertAll<TOutput>是开放泛型方法，需要先获取方法定义再实例化
            var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(m => m.Name == "ConvertAll" && m.IsGenericMethod);
            Assert.NotNull(openMethod);
            var genericTarget = openMethod.MakeGenericMethod(typeof(string));

            var hookMethod = GetMethod(typeof(HookContainer), "HookConvertAll",
                new[] { typeof(List<int>), typeof(Converter<int, string>) });

            Assert.NotNull(genericTarget);
            Assert.NotNull(hookMethod);

            using (var hook = CreateHook(genericTarget, hookMethod))
            {
                hook.Install();
                _output.WriteLine("=== DiagInfo ===");
                _output.WriteLine(hook.DiagInfo.ToString());

                var list = new List<int> { 1, 2, 3 };
                var result = list.ConvertAll(x => $"item{x}");

                _output.WriteLine($"Result: [{string.Join(",", result)}]");

                Assert.Equal("ConvertAll", TestState.LastHookCall);
                Assert.Equal(1, TestState.HookCallCount);
                Assert.Same(list, TestState.LastInstance);
                Assert.NotNull(TestState.LastConverter);

                // CallOriginal should return the actual conversion result
                Assert.Equal(3, result.Count);
                Assert.Equal("item1", result[0]);
                Assert.Equal("item2", result[1]);
                Assert.Equal("item3", result[2]);
            }

            // 卸载后正常
            TestState.Reset();
            var list2 = new List<int> { 10, 20 };
            var result2 = list2.ConvertAll(x => $"v{x}");
            Assert.Equal(2, result2.Count);
            Assert.Equal("v10", result2[0]);
            Assert.Equal("v20", result2[1]);
            Assert.Equal(0, TestState.HookCallCount);
        }

        // ============================================================
        // 静态方法hook测试
        // ============================================================

        [Fact]
        public void Hook_StaticMethod()
        {
            TestState.Reset();

            var targetMethod = GetMethod(typeof(StaticTarget), "StaticTargetMethod",
                new[] { typeof(int), typeof(string) });
            var hookMethod = GetMethod(typeof(HookContainer), "HookStaticMethod",
                new[] { typeof(int), typeof(string) });

            Assert.NotNull(targetMethod);
            Assert.NotNull(hookMethod);

            using (var hook = CreateHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine(hook.DiagInfo.ToString());

                var result = StaticTarget.StaticTargetMethod(42, "test");
                _output.WriteLine($"Result: {result}");

                Assert.Equal("StaticMethod", TestState.LastHookCall);
                Assert.Equal(42, TestState.LastIntArg);
                Assert.Equal("test", TestState.LastStringArg);
                Assert.Equal("ORIGINAL:42-test", result);
            }

            // 卸载后
            TestState.Reset();
            var r2 = StaticTarget.StaticTargetMethod(100, "after");
            Assert.Equal("ORIGINAL:100-after", r2);
            Assert.Equal(0, TestState.HookCallCount);
        }

        // ============================================================
        // 虚方法hook测试
        // ============================================================

        [Fact]
        public void Hook_VirtualMethod()
        {
            TestState.Reset();

            var targetMethod = GetMethod(typeof(VirtualTarget), "VirtualTargetMethod",
                new[] { typeof(string) });
            var hookMethod = GetMethod(typeof(HookContainer), "HookVirtualMethod",
                new[] { typeof(VirtualTarget), typeof(string) });

            Assert.NotNull(targetMethod);
            Assert.NotNull(hookMethod);

            using (var hook = CreateHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine(hook.DiagInfo.ToString());

                var obj = new VirtualTarget();
                var result = obj.VirtualTargetMethod("hello");
                _output.WriteLine($"Result: {result}");

                Assert.Equal("VirtualMethod", TestState.LastHookCall);
                Assert.Same(obj, TestState.LastInstance);
                Assert.Equal("hello", TestState.LastStringArg);
                Assert.Equal("ORIGINAL:hello", result);
            }

            // 卸载后
            TestState.Reset();
            var obj2 = new VirtualTarget();
            Assert.Equal("ORIGINAL:foo", obj2.VirtualTargetMethod("foo"));
            Assert.Equal(0, TestState.HookCallCount);
        }

        [Fact]
        public void Hook_VirtualMethod_DerivedClass()
        {
            TestState.Reset();

            var targetMethod = GetMethod(typeof(VirtualTarget), "VirtualTargetMethod",
                new[] { typeof(string) });
            var hookMethod = GetMethod(typeof(HookContainer), "HookVirtualMethod",
                new[] { typeof(VirtualTarget), typeof(string) });

            using (var hook = CreateHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine(hook.DiagInfo.ToString());

                var derived = new VirtualDerived();
                // 派生类override是独立的方法，hook只patch基类方法的precode和vtable slot。
                // 派生类的override有自己的MethodDesc/precode，不会被基类hook影响。
                // 因此派生类调用override方法直接返回"DERIVED:derived"，不经过hook。
                var result = derived.VirtualTargetMethod("derived");
                _output.WriteLine($"Derived result: {result}");

                // 派生类override不被拦截
                Assert.Null(TestState.LastHookCall);
                Assert.Equal("DERIVED:derived", result);
            }
        }

        // ============================================================
        // 多次Install/Uninstall测试
        // ============================================================

        [Fact]
        public void Hook_Reinstall()
        {
            TestState.Reset();

            var targetMethod = GetMethod(typeof(StaticTarget), "StaticTargetMethod",
                new[] { typeof(int), typeof(string) });
            var hookMethod = GetMethod(typeof(HookContainer), "HookStaticMethod",
                new[] { typeof(int), typeof(string) });

            // 第一次安装
            using (var hook = CreateHook(targetMethod, hookMethod))
            {
                hook.Install();
                var r1 = StaticTarget.StaticTargetMethod(1, "a");
                Assert.Equal(1, TestState.HookCallCount);
                Assert.Equal("ORIGINAL:1-a", r1);
            }

            // 卸载后
            TestState.Reset();
            var r2 = StaticTarget.StaticTargetMethod(2, "b");
            Assert.Equal("ORIGINAL:2-b", r2);
            Assert.Equal(0, TestState.HookCallCount);

            // 重新安装
            TestState.Reset();
            using (var hook = CreateHook(targetMethod, hookMethod))
            {
                hook.Install();
                var r3 = StaticTarget.StaticTargetMethod(3, "c");
                Assert.Equal(1, TestState.HookCallCount);
                Assert.Equal("ORIGINAL:3-c", r3);
            }
        }

        // ============================================================
        // 诊断信息输出测试
        // ============================================================

        [Fact]
        public void Hook_DiagnosticInfo_ReadToEnd()
        {
            TestState.Reset();

            var targetMethod = GetMethod(typeof(StreamReader), "ReadToEnd", Type.EmptyTypes);
            var hookMethod = GetMethod(typeof(HookContainer), "HookReadToEnd", new[] { typeof(StreamReader) });

            using (var hook = CreateHook(targetMethod, hookMethod))
            {
                hook.Install();

                var diag = hook.DiagInfo;
                _output.WriteLine("=== StreamReader.ReadToEnd() Diagnostic ===");
                _output.WriteLine(diag.ToString());

                Assert.NotNull(diag);
                Assert.NotEqual(IntPtr.Zero, diag.PrecodeAddr);
            }

            _output.WriteLine("Test completed.");
        }

        [Fact]
        public void Hook_DiagnosticInfo_ConvertAll()
        {
            TestState.Reset();

            var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(m => m.Name == "ConvertAll" && m.IsGenericMethod);
            Assert.NotNull(openMethod);
            var genericTarget = openMethod.MakeGenericMethod(typeof(string));
            var hookMethod = GetMethod(typeof(HookContainer), "HookConvertAll",
                new[] { typeof(List<int>), typeof(Converter<int, string>) });

            using (var hook = CreateHook(genericTarget, hookMethod))
            {
                hook.Install();

                var diag = hook.DiagInfo;
                _output.WriteLine("=== List<int>.ConvertAll<string>() Diagnostic ===");
                _output.WriteLine(diag.ToString());

                Assert.NotNull(diag);
                Assert.NotEqual(IntPtr.Zero, diag.PrecodeAddr);
                Assert.True(diag.NeedsGenericAdapter);
            }

            _output.WriteLine("Test completed.");
        }
    }
}
