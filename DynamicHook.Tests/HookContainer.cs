using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;

namespace DynamicHook.Tests
{
    /// <summary>
    /// Hook方法容器 - 所有hook方法必须是static，且参数与目标方法一致
    /// （实例方法第一个参数为this，泛型方法参数已由适配器移除泛型字典）。
    /// </summary>
    public static class HookContainer
    {
        // ===== StreamReader.ReadToEnd() hook =====
        // 原方法: public virtual string ReadToEnd()  - 实例方法，无参，返回string
        // Hook签名: static string(StreamReader self)
        public static string HookReadToEnd(StreamReader self)
        {
            TestState.LastHookCall = "ReadToEnd";
            TestState.LastInstance = self;
            TestState.HookCallCount++;

            // 调用原始方法
            if (TestState.ActiveHook != null)
            {
                return (string)TestState.ActiveHook.CallOriginal(self);
            }
            return "HOOKED_DEFAULT";
        }

        // ===== List<int>.ConvertAll<string>() hook =====
        // 原方法: public List<TOutput> ConvertAll<TOutput>(Converter<int, TOutput> converter)
        //         实例泛型方法
        // Hook签名: static List<string>(List<int> self, Converter<int,string> converter)
        // 注意：泛型字典参数已被适配器移除
        public static List<string> HookConvertAll(List<int> self, Converter<int, string> converter)
        {
            TestState.LastHookCall = "ConvertAll";
            TestState.LastInstance = self;
            TestState.LastConverter = converter;
            TestState.HookCallCount++;

            if (TestState.ActiveHook != null)
            {
                return (List<string>)TestState.ActiveHook.CallOriginal(self, converter);
            }
            return new List<string> { "HOOKED" };
        }

        // ===== 静态方法hook测试 =====
        // 目标: static string StaticTargetMethod(int x, string y)
        public static string HookStaticMethod(int x, string y)
        {
            TestState.LastHookCall = "StaticMethod";
            TestState.LastIntArg = x;
            TestState.LastStringArg = y;
            TestState.HookCallCount++;

            if (TestState.ActiveHook != null)
            {
                // 静态方法没有this，第一个参数为null
                return (string)TestState.ActiveHook.CallOriginal(null, x, y);
            }
            return "HOOKED_STATIC";
        }

        // ===== 虚方法hook测试 =====
        // 目标: virtual string VirtualTargetMethod(string arg)
        public static string HookVirtualMethod(VirtualTarget self, string arg)
        {
            TestState.LastHookCall = "VirtualMethod";
            TestState.LastInstance = self;
            TestState.LastStringArg = arg;
            TestState.HookCallCount++;

            if (TestState.ActiveHook != null)
            {
                return (string)TestState.ActiveHook.CallOriginal(self, arg);
            }
            return "HOOKED_VIRTUAL";
        }
    }

    /// <summary>
    /// 测试状态共享存储（简化测试中hook方法与测试代码之间的通信）。
    /// </summary>
    public static class TestState
    {
        public static MethodHook ActiveHook;
        public static string LastHookCall;
        public static object LastInstance;
        public static object LastConverter;
        public static int LastIntArg;
        public static string LastStringArg;
        public static int HookCallCount;

        public static void Reset()
        {
            ActiveHook = null;
            LastHookCall = null;
            LastInstance = null;
            LastConverter = null;
            LastIntArg = 0;
            LastStringArg = null;
            HookCallCount = 0;
        }
    }

    /// <summary>
    /// 用于虚方法hook测试的目标类。
    /// </summary>
    public class VirtualTarget
    {
        public virtual string VirtualTargetMethod(string arg)
        {
            return "ORIGINAL:" + arg;
        }
    }

    /// <summary>
    /// VirtualTarget的派生类，用于测试虚方法override patching。
    /// </summary>
    public class VirtualDerived : VirtualTarget
    {
        public override string VirtualTargetMethod(string arg)
        {
            return "DERIVED:" + arg;
        }
    }

    /// <summary>
    /// 用于静态方法hook测试的目标类。
    /// </summary>
    public static class StaticTarget
    {
        public static string StaticTargetMethod(int x, string y)
        {
            return $"ORIGINAL:{x}-{y}";
        }
    }
}
