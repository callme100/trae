using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using DynamicHook;
using Xunit;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    /// <summary>
    /// 用户自定义类的hook测试 - 排除BCL方法特殊性问题
    /// </summary>
    public class UserClassHookTests
    {
        private readonly ITestOutputHelper _output;

        public UserClassHookTests(ITestOutputHelper output)
        {
            _output = output;
        }

        private MethodInfo GetMethod(Type type, string name, params Type[] paramTypes)
        {
            return type.GetMethod(name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static, null, paramTypes ?? Type.EmptyTypes, null);
        }

        // ===== 用户自定义实例方法hook =====
        public class UserClass
        {
            public string InstanceMethod(string arg)
            {
                return "ORIGINAL:" + arg;
            }
        }

        public static string Hook_InstanceMethod(UserClass self, string arg)
        {
            return "HOOKED:" + arg;
        }

        [Fact]
        public void Hook_UserClass_InstanceMethod()
        {
            var targetMethod = GetMethod(typeof(UserClass), "InstanceMethod", new[] { typeof(string) });
            var hookMethod = GetMethod(typeof(UserClassHookTests), "Hook_InstanceMethod",
                new[] { typeof(UserClass), typeof(string) });

            using (var hook = new MethodHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine(hook.DiagInfo.ToString());

                var obj = new UserClass();
                var result = obj.InstanceMethod("test");
                _output.WriteLine($"Result: {result}");
                Assert.Equal("HOOKED:test", result);
            }

            // 卸载后
            var obj2 = new UserClass();
            Assert.Equal("ORIGINAL:foo", obj2.InstanceMethod("foo"));
        }

        // ===== 用户自定义虚方法hook =====
        public class UserVirtualClass
        {
            public virtual string VirtualMethod(string arg)
            {
                return "VORIGINAL:" + arg;
            }
        }

        public static string Hook_VirtualMethod(UserVirtualClass self, string arg)
        {
            return "VHOOKED:" + arg;
        }

        [Fact]
        public void Hook_UserClass_VirtualMethod()
        {
            var targetMethod = GetMethod(typeof(UserVirtualClass), "VirtualMethod", new[] { typeof(string) });
            var hookMethod = GetMethod(typeof(UserClassHookTests), "Hook_VirtualMethod",
                new[] { typeof(UserVirtualClass), typeof(string) });

            using (var hook = new MethodHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine(hook.DiagInfo.ToString());

                var obj = new UserVirtualClass();
                var result = obj.VirtualMethod("test");
                _output.WriteLine($"Result: {result}");
                Assert.Equal("VHOOKED:test", result);
            }

            // 卸载后
            var obj2 = new UserVirtualClass();
            Assert.Equal("VORIGINAL:foo", obj2.VirtualMethod("foo"));
        }

        // ===== 用户自定义无参实例方法hook (类似ReadToEnd) =====
        public class UserNoParamClass
        {
            private int _counter;
            public UserNoParamClass() { _counter = 0; }
            public string NoParamMethod()
            {
                _counter++;
                return "NORIGINAL:" + _counter;
            }
        }

        public static string Hook_NoParamMethod(UserNoParamClass self)
        {
            return "NHOOKED";
        }

        [Fact]
        public void Hook_UserClass_NoParamMethod()
        {
            var targetMethod = GetMethod(typeof(UserNoParamClass), "NoParamMethod", Type.EmptyTypes);
            var hookMethod = GetMethod(typeof(UserClassHookTests), "Hook_NoParamMethod",
                new[] { typeof(UserNoParamClass) });

            using (var hook = new MethodHook(targetMethod, hookMethod))
            {
                hook.Install();
                _output.WriteLine(hook.DiagInfo.ToString());

                var obj = new UserNoParamClass();
                var result = obj.NoParamMethod();
                _output.WriteLine($"Result: {result}");
                Assert.Equal("NHOOKED", result);
            }

            // 卸载后
            var obj2 = new UserNoParamClass();
            Assert.Equal("NORIGINAL:1", obj2.NoParamMethod());
        }
    }
}
