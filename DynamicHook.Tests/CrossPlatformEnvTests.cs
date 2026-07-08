using System;
using System.Runtime.InteropServices;
using Xunit;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    /// <summary>
    /// 跨平台/架构/运行时环境验证测试。
    /// 这组测试本身不执行 hook，仅断言当前环境被 DynamicHook 支持，
    /// 并在输出中记录完整的平台矩阵信息，便于在 CI 中追踪每个组合。
    /// </summary>
    public class CrossPlatformEnvTests
    {
        private readonly ITestOutputHelper _output;

        public CrossPlatformEnvTests(ITestOutputHelper output)
        {
            _output = output;
        }

        /// <summary>
        /// 验证当前 CPU 架构被 DynamicHook 原生支持。
        /// DynamicHook 内置 x86/x64/ARM32/ARM64 的跳转指令生成。
        /// </summary>
        [Fact]
        public void Env_Architecture_IsSupported()
        {
            TestEnvironment.Dump(_output);
            Assert.True(TestEnvironment.IsSupportedArchitecture,
                $"不支持的 CPU 架构: {TestEnvironment.ArchName}. DynamicHook 支持 x86/x64/ARM32/ARM64.");
            _output.WriteLine($"架构支持检查通过: {TestEnvironment.ArchName}");
        }

        /// <summary>
        /// 验证当前运行时是 .NET Framework 4.x 或 .NET Core/5+，
        /// 并记录具体的运行时版本，便于跨版本对比。
        /// </summary>
        [Fact]
        public void Env_Runtime_Version_Recorded()
        {
            TestEnvironment.Dump(_output);
            Assert.True(TestEnvironment.IsNetFramework || TestEnvironment.IsNetCoreOrLater,
                $"未知的运行时版本: {TestEnvironment.RuntimeVersion}");
            _output.WriteLine($"运行时版本: {TestEnvironment.RuntimeVersion} (Major={TestEnvironment.RuntimeMajorVersion})");
            _output.WriteLine($"TFM: {TestEnvironment.TargetFrameworkMoniker}");
        }

        /// <summary>
        /// 验证当前操作系统是 Windows/Linux/macOS 之一（DynamicHook 的内存保护 API
        /// 通过平台分支处理），并记录具体 OS 描述。
        /// </summary>
        [Fact]
        public void Env_OS_IsKnownPlatform()
        {
            TestEnvironment.Dump(_output);
            Assert.True(
                TestEnvironment.PlatformName == "Windows" ||
                TestEnvironment.PlatformName == "Linux" ||
                TestEnvironment.PlatformName == "macOS",
                $"未知/不支持的 OS: {TestEnvironment.PlatformName}");
            _output.WriteLine($"OS 平台检查通过: {TestEnvironment.PlatformName}");
        }

        /// <summary>
        /// 验证 IntPtr.Size 与报告的架构一致（64 位架构应 8 字节，32 位应 4 字节），
        /// 用于发现任何架构检测/位宽不匹配的异常。
        /// </summary>
        [Fact]
        public void Env_PtrSize_MatchesArchitecture()
        {
            TestEnvironment.Dump(_output);
            bool archIs64 = TestEnvironment.ArchName == "X64" || TestEnvironment.ArchName == "Arm64";
            Assert.Equal(archIs64, TestEnvironment.Is64Bit);
            _output.WriteLine($"IntPtr.Size={IntPtr.Size}, 架构 64 位={archIs64}");
        }
    }
}
