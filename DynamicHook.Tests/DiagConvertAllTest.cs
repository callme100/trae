using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    public class DiagConvertAllTest
    {
        private readonly ITestOutputHelper _output;

        public DiagConvertAllTest(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void Diag_ConvertAll_Trampoline_Bytes()
        {
            // Pre-warm
            var warmupList = new List<int> { 0 };
            var warmupResult = warmupList.ConvertAll(x => $"warm{x}");
            Assert.Single(warmupResult);

            var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .First(m => m.Name == "ConvertAll" && m.IsGenericMethod);
            var genericTarget = openMethod.MakeGenericMethod(typeof(string));

            var hookMethod = typeof(DiagConvertAllTest).GetMethod("HookConvertAll",
                BindingFlags.Static | BindingFlags.NonPublic,
                null, new[] { typeof(List<int>), typeof(Converter<int, string>) }, null);

            var hook = new MethodHook(genericTarget, hookMethod);
            hook.Install();
            _output.WriteLine("=== DiagInfo ===");
            _output.WriteLine(hook.DiagInfo.ToString());

            // Try to read the JIT code bytes and trampoline bytes using unsafe code
            unsafe
            {
                var sb = new StringBuilder();
                // Read the precode address from the hook
                // We need to use reflection to get internal fields
                var hookType = typeof(MethodHook);
                var flags = BindingFlags.NonPublic | BindingFlags.Instance;

                var precodeField = hookType.GetField("_precodeAddr", flags);
                var innerCodeField = hookType.GetField("_innerCodeAddress", flags);
                var innerOrigField = hookType.GetField("_innerCodeOriginalBytesFull", flags);
                var trampField = hookType.GetField("_callOrigTrampoline", flags);
                var trampSizeField = hookType.GetField("_callOrigTrampSize", flags);
                var needsGenericField = hookType.GetField("_needsGenericAdapter", flags);
                var hasInnerField = hookType.GetField("_hasInnerCodePatch", flags);

                if (precodeField != null)
                {
                    IntPtr precodeAddr = (IntPtr)precodeField.GetValue(hook);
                    _output.WriteLine($"_precodeAddr = 0x{precodeAddr.ToInt64():X}");
                    if (precodeAddr != IntPtr.Zero)
                    {
                        byte* p = (byte*)precodeAddr;
                        sb.Append("_precodeAddr bytes (32): ");
                        for (int i = 0; i < 32; i++) sb.Append($"{p[i]:X2} ");
                        _output.WriteLine(sb.ToString()); sb.Clear();
                    }
                }

                if (innerCodeField != null)
                {
                    IntPtr innerAddr = (IntPtr)innerCodeField.GetValue(hook);
                    _output.WriteLine($"_innerCodeAddress = 0x{innerAddr.ToInt64():X}");
                    if (innerAddr != IntPtr.Zero)
                    {
                        byte* p = (byte*)innerAddr;
                        sb.Append("_innerCodeAddress bytes (32, current/patched): ");
                        for (int i = 0; i < 32; i++) sb.Append($"{p[i]:X2} ");
                        _output.WriteLine(sb.ToString()); sb.Clear();
                    }
                }

                if (innerOrigField != null)
                {
                    byte[] origBytes = (byte[])innerOrigField.GetValue(hook);
                    if (origBytes != null)
                    {
                        sb.Append("_innerCodeOriginalBytesFull (" + origBytes.Length + " bytes): ");
                        foreach (var b in origBytes) sb.Append($"{b:X2} ");
                        _output.WriteLine(sb.ToString()); sb.Clear();
                    }
                }

                if (trampField != null && trampSizeField != null)
                {
                    IntPtr trampAddr = (IntPtr)trampField.GetValue(hook);
                    int trampSize = (int)trampSizeField.GetValue(hook);
                    _output.WriteLine($"_callOrigTrampoline = 0x{trampAddr.ToInt64():X}, size={trampSize}");
                    if (trampAddr != IntPtr.Zero)
                    {
                        byte* p = (byte*)trampAddr;
                        sb.Append("Trampoline bytes (" + trampSize + "): ");
                        for (int i = 0; i < trampSize; i++) sb.Append($"{p[i]:X2} ");
                        _output.WriteLine(sb.ToString()); sb.Clear();

                        // Also dump with annotations
                        _output.WriteLine("Trampoline layout:");
                        int off = 0;
                        bool needsGeneric = needsGenericField != null && (bool)needsGenericField.GetValue(hook);
                        if (needsGeneric)
                        {
                            _output.WriteLine($"  [0..9]  MOV R10, imm64: {p[0]:X2} {p[1]:X2} {BitConverter.ToInt64(new byte[]{p[2],p[3],p[4],p[5],p[6],p[7],p[8],p[9]}, 0):X16}");
                            off = 10;
                        }
                        // Determine copyLen: trampSize - prefixLen - 12
                        int prefixLen = needsGeneric ? 10 : 0;
                        int copyLen = trampSize - prefixLen - 12;
                        _output.WriteLine($"  [{off}..{off + copyLen - 1}]  Copied prologue ({copyLen} bytes)");
                        sb.Append("    ");
                        for (int i = 0; i < copyLen; i++) sb.Append($"{p[off + i]:X2} ");
                        _output.WriteLine(sb.ToString()); sb.Clear();
                        off += copyLen;
                        _output.WriteLine($"  [{off}..{off + 11}]  MOV RAX, imm64; JMP RAX: {p[off]:X2} {p[off + 1]:X2} {BitConverter.ToInt64(new byte[]{p[off + 2],p[off + 3],p[off + 4],p[off + 5],p[off + 6],p[off + 7],p[off + 8],p[off + 9]}, 0):X16} {p[off + 10]:X2} {p[off + 11]:X2}");
                    }
                }
            }

            // Now try calling and catch exception
            try
            {
                var list = new List<int> { 1, 2, 3 };
                var result = list.ConvertAll(new Converter<int, string>(x => x.ToString()));
                _output.WriteLine($"Result: [{string.Join(",", result)}]");
            }
            catch (Exception ex)
            {
                _output.WriteLine($"EXCEPTION: {ex.GetType().Name}: {ex.Message}");
                _output.WriteLine($"Stack: {ex.StackTrace}");
            }

            hook.Uninstall();
        }

        private static List<string> HookConvertAll(List<int> self, Converter<int, string> converter)
        {
            // Don't call CallOriginal - just return a dummy to see if hook triggers
            return new List<string> { "HOOKED" };
        }
    }
}
