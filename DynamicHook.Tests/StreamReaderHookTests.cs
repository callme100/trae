using System;
using System.IO;
using System.Reflection;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    /// <summary>
    /// 针对 <see cref="StreamReader.ReadToEnd"/> 实例方法的 hook 测试。
    /// 该方法是 BCL 内实例方法，签名 () -> string，this 指针通过 RCX 传递，
    /// 不涉及泛型字典，是验证实例方法 hook 的最小用例。
    /// </summary>
    public class StreamReaderHookTests
    {
        private readonly ITestOutputHelper _output;

        public StreamReaderHookTests(ITestOutputHelper output)
        {
            _output = output;
        }

        private static MethodInfo GetTargetMethod()
        {
            return typeof(StreamReader).GetMethod(
                "ReadToEnd",
                BindingFlags.Public | BindingFlags.Instance,
                null,
                Type.EmptyTypes,
                null);
        }

        private static MethodInfo GetHookMethod_Replace()
        {
            return typeof(StreamReaderHookTests).GetMethod(
                nameof(Hook_ReadToEnd_Replace),
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(StreamReader) },
                null);
        }

        /// <summary>hook 替换实现：忽略原内容，固定返回标记字符串。</summary>
        public static string Hook_ReadToEnd_Replace(StreamReader self)
        {
            return "HOOKED_READTOEND";
        }

        private static StreamReader MakeReader(string content)
        {
            return new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(content)));
        }

        /// <summary>
        /// 基本 hook：安装后 ReadToEnd 返回固定值，卸载后恢复原始读取。
        /// </summary>
        [Fact]
        public void Hook_ReadToEnd_Instance_ReplaceReturn()
        {
            TestEnvironment.Dump(_output);

            MethodInfo target = GetTargetMethod();
            MethodInfo hook = GetHookMethod_Replace();
            Assert.NotNull(target);
            Assert.NotNull(hook);

            // 预热
            using (var sr0 = MakeReader("warmup"))
            {
                string pre = sr0.ReadToEnd();
                _output.WriteLine($"Pre-hook: ReadToEnd = \"{pre}\"");
                Assert.Equal("warmup", pre);
            }

            using (var mh = new MethodHook(target, hook))
            {
                mh.Install();
                _output.WriteLine("=== DiagInfo ===");
                _output.WriteLine(mh.DiagInfo.ToString());

                using (var sr1 = MakeReader("Hello"))
                using (var sr2 = MakeReader("World"))
                {
                    string r1 = sr1.ReadToEnd();
                    string r2 = sr2.ReadToEnd();
                    _output.WriteLine($"Hooked: \"{r1}\", \"{r2}\"");

                    Assert.Equal("HOOKED_READTOEND", r1);
                    Assert.Equal("HOOKED_READTOEND", r2);
                }
            }

            // 卸载后恢复
            using (var sr = MakeReader("AfterUninstall"))
            {
                string post = sr.ReadToEnd();
                _output.WriteLine($"Post-uninstall: \"{post}\"");
                Assert.Equal("AfterUninstall", post);
            }
        }

        /// <summary>
        /// hook 中调用原始方法并在结果前加前缀，验证 CallOriginal 在实例方法上工作正常。
        /// </summary>
        [Fact]
        public void Hook_ReadToEnd_Instance_CallOriginal_Prefix()
        {
            TestEnvironment.Dump(_output);

            MethodInfo target = GetTargetMethod();
            MethodInfo hook = typeof(StreamReaderHookTests).GetMethod(
                nameof(Hook_ReadToEnd_Prefix),
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(StreamReader) },
                null);
            Assert.NotNull(hook);

            using (var mh = new MethodHook(target, hook))
            {
                _currentHook = mh;
                mh.Install();
                _output.WriteLine(mh.DiagInfo.ToString());

                using (var sr = MakeReader("Body"))
                {
                    string r = sr.ReadToEnd();
                    _output.WriteLine($"Prefixed: \"{r}\"");
                    Assert.Equal("PREFIX:Body", r);
                }
                _currentHook = null;
            }

            // 卸载后恢复
            using (var sr = MakeReader("Plain"))
            {
                Assert.Equal("Plain", sr.ReadToEnd());
            }
        }

        public static string Hook_ReadToEnd_Prefix(StreamReader self)
        {
            string orig = (string)_currentHook.CallOriginal(self);
            return "PREFIX:" + orig;
        }

        [ThreadStatic]
        internal static MethodHook _currentHook;

        /// <summary>
        /// 重复安装/卸载多次，验证状态正确恢复。
        /// </summary>
        [Theory]
        [InlineData(3)]
        public void Hook_ReadToEnd_Instance_Reinstall(int times)
        {
            TestEnvironment.Dump(_output);

            MethodInfo target = GetTargetMethod();
            MethodInfo hook = GetHookMethod_Replace();

            for (int i = 0; i < times; i++)
            {
                using (var mh = new MethodHook(target, hook))
                {
                    mh.Install();
                    using (var sr = MakeReader("x"))
                    {
                        Assert.Equal("HOOKED_READTOEND", sr.ReadToEnd());
                    }
                }
                // 卸载后恢复
                using (var sr = MakeReader("y"))
                {
                    Assert.Equal("y", sr.ReadToEnd());
                }
                _output.WriteLine($"Iteration {i+1}/{times}: OK");
            }
        }
    }
}
