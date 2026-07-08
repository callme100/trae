using System;
using System.Diagnostics;
using System.IO;
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
    /// 重要：<see cref="string.Compare(string, string)"/> 被 xUnit testhost、运行时、
    /// GC 等大量内部代码高频调用。在 testhost 进程内直接 hook 它会触发无限递归
    /// （hook 安装/卸载过程中的内部 String.Compare 调用会重新进入 hook）。
    /// 因此本测试类通过启动独立的 <c>ReproConsole</c> 子进程来验证 String.Compare
    /// hook，子进程脱离 testhost，仅包含最小化的测试逻辑，可安全 hook。
    /// </summary>
    public class StringCompareHookTests
    {
        private readonly ITestOutputHelper _output;

        public StringCompareHookTests(ITestOutputHelper output)
        {
            _output = output;
        }

        /// <summary>
        /// 定位 ReproConsole 子进程的可执行程序集路径。
        /// 测试 csproj 中的 BuildAndCopyReproConsole 目标会将 ReproConsole(net8.0)
        /// 的构建产物整体复制到测试输出目录的 ReproConsole\ 子目录下，
        /// 因此这里直接在 AppContext.BaseDirectory 下查找。
        /// </summary>
        private string ResolveReproConsoleDll()
        {
            string testDir = AppContext.BaseDirectory;
            return Path.GetFullPath(Path.Combine(testDir, "ReproConsole", "ReproConsole.dll"));
        }

        /// <summary>
        /// 运行 ReproConsole 子进程并返回 (exitCode, stdout)。
        /// 超时 30s 防止 hook 死循环导致测试挂起。
        /// </summary>
        private (int ExitCode, string Output) RunReproConsole(string mode)
        {
            string dll = ResolveReproConsoleDll();
            if (!File.Exists(dll))
            {
                _output.WriteLine($"ReproConsole not found at {dll} — skipping (likely net472 or not built).");
                return (-1, "");
            }
            _output.WriteLine($"Running: dotnet {dll} {mode}");

            var psi = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"\"{dll}\" {mode}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using (var proc = Process.Start(psi))
            {
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                bool exited = proc.WaitForExit(30000);
                if (!exited)
                {
                    try { proc.Kill(); } catch { }
                    _output.WriteLine("TIMEOUT (process killed)");
                    _output.WriteLine("=== STDOUT ===");
                    _output.WriteLine(stdout);
                    _output.WriteLine("=== STDERR ===");
                    _output.WriteLine(stderr);
                    return (124, stdout);
                }
                _output.WriteLine($"ExitCode: {proc.ExitCode}");
                _output.WriteLine("=== STDOUT ===");
                _output.WriteLine(stdout);
                if (!string.IsNullOrEmpty(stderr))
                {
                    _output.WriteLine("=== STDERR ===");
                    _output.WriteLine(stderr);
                }
                return (proc.ExitCode, stdout);
            }
        }

        /// <summary>
        /// replace 模式：安装 hook 后 String.Compare 返回固定值 42，卸载后恢复。
        /// </summary>
        [Fact]
        public void Hook_StringCompare_Static_ReplaceReturn()
        {
            TestEnvironment.Dump(_output);

            // net472 无对应 ReproConsole 构建（ReproConsole 仅 net8.0），跳过。
            if (TestEnvironment.IsNetFramework)
            {
                _output.WriteLine("Skipped: ReproConsole not available on net472 (Linux 无 .NET Framework 运行时).");
                return;
            }

            var (ec, output) = RunReproConsole("replace");
            Assert.Equal(0, ec);
            Assert.Contains("PASS: replace mode", output);
        }

        /// <summary>
        /// negate 模式：hook 中调用 CallOriginal 并反转返回值符号。
        /// 验证 CallOriginal 路径在静态方法上工作正常。
        /// </summary>
        [Fact]
        public void Hook_StringCompare_Static_CallOriginal_Negate()
        {
            TestEnvironment.Dump(_output);

            if (TestEnvironment.IsNetFramework)
            {
                _output.WriteLine("Skipped: ReproConsole not available on net472.");
                return;
            }

            var (ec, output) = RunReproConsole("negate");
            Assert.Equal(0, ec);
            Assert.Contains("PASS: negate mode", output);
        }

        /// <summary>
        /// reinstall 模式：重复安装/卸载多次，验证状态正确恢复。
        /// </summary>
        [Theory]
        [InlineData("reinstall")]
        public void Hook_StringCompare_Static_Reinstall(string mode)
        {
            TestEnvironment.Dump(_output);

            if (TestEnvironment.IsNetFramework)
            {
                _output.WriteLine("Skipped: ReproConsole not available on net472.");
                return;
            }

            var (ec, output) = RunReproConsole(mode);
            Assert.Equal(0, ec);
            Assert.Contains("PASS: reinstall mode", output);
        }
    }
}
