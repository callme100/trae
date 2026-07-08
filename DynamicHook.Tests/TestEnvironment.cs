using System;
using System.Runtime.InteropServices;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    /// <summary>
    /// 测试环境信息辅助类：统一报告运行平台、CPU 架构、.NET 运行时版本，
    /// 供测试输出与断言判断使用。所有测试在执行前都会先打印一次环境摘要。
    /// </summary>
    internal static class TestEnvironment
    {
        public static string OS => RuntimeInformation.OSDescription;

        public static string PlatformName
        {
            get
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return "Windows";
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return "Linux";
                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return "macOS";
#if !NET472
                if (RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD)) return "FreeBSD";
#endif
                return "Unknown";
            }
        }

        public static string ArchName => RuntimeInformation.ProcessArchitecture.ToString();

        public static bool Is64Bit => IntPtr.Size == 8;

        /// <summary>
        /// .NET 运行时版本（.NET Framework 4.x 报告 4.x，.NET Core/5+ 报告对应主版本）。
        /// </summary>
        public static string RuntimeVersion
        {
            get
            {
#if NET472
                return $".NET Framework {Environment.Version}";
#else
                return $".NET {Environment.Version}";
#endif
            }
        }

        public static int RuntimeMajorVersion => Environment.Version.Major;

        public static bool IsNetFramework => RuntimeMajorVersion <= 4;

        public static bool IsNetCoreOrLater => RuntimeMajorVersion >= 5;

        /// <summary>
        /// 当前 TFM 标识（编译期常量），用于跳过特定框架不支持的场景。
        /// </summary>
        public static string TargetFrameworkMoniker
        {
            get
            {
#if NET472
                return "net472";
#elif NET6_0
                return "net6.0";
#elif NET8_0
                return "net8.0";
#elif NET10_0
                return "net10.0";
#else
                return "unknown";
#endif
            }
        }

        /// <summary>
        /// 打印完整环境摘要到测试输出，便于诊断跨平台问题。
        /// </summary>
        public static void Dump(ITestOutputHelper output)
        {
            output.WriteLine("========== Test Environment ==========");
            output.WriteLine($"  OS:          {PlatformName} ({OS})");
            output.WriteLine($"  Architecture:{ArchName} ({(Is64Bit ? "64-bit" : "32-bit")})");
            output.WriteLine($"  Runtime:     {RuntimeVersion}");
            output.WriteLine($"  TFM:         {TargetFrameworkMoniker}");
            output.WriteLine($"  MajorVer:    {RuntimeMajorVersion}");
            output.WriteLine($"  IsNetFx:     {IsNetFramework}");
            output.WriteLine($"  IsNetCore+:  {IsNetCoreOrLater}");
            output.WriteLine("======================================");
        }

        /// <summary>
        /// 判断当前架构是否被 DynamicHook 原生支持（x64/x86/ARM64/ARM32）。
        /// </summary>
        public static bool IsSupportedArchitecture
        {
            get
            {
                switch (RuntimeInformation.ProcessArchitecture)
                {
                    case Architecture.X64:
                    case Architecture.X86:
                    case Architecture.Arm64:
                    case Architecture.Arm:
                        return true;
                    default:
                        return false;
                }
            }
        }
    }
}
