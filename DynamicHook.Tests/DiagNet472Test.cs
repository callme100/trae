using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using Xunit;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    public class DiagNet472Test
    {
        private readonly ITestOutputHelper _output;
        private static readonly string _logFile = Path.Combine(Path.GetTempPath(), "DiagNet472Test.log");

        public DiagNet472Test(ITestOutputHelper output)
        {
            _output = output;
            File.WriteAllText(_logFile, $"=== DiagNet472Test started {DateTime.Now:O} pid={System.Diagnostics.Process.GetCurrentProcess().Id} ===\r\n");
        }

        private void Log(string msg)
        {
            _output.WriteLine(msg);
            File.AppendAllText(_logFile, msg + "\r\n");
        }

        [Fact]
        public void Diag_Net472_DirectCall_Path()
        {
            try
            {
                // Pre-warm to force JIT compilation
                var warmupList = new List<int> { 0 };
                var warmupResult = warmupList.ConvertAll(x => $"warm{x}");

                var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .First(m => m.Name == "ConvertAll" && m.IsGenericMethod);
                var genericTarget = openMethod.MakeGenericMethod(typeof(string));

                // Get the function pointer BEFORE hooking
                RuntimeMethodHandle handle = genericTarget.MethodHandle;
                IntPtr preHookPtr = handle.GetFunctionPointer();
                Log($"Pre-hook function pointer: 0x{preHookPtr.ToInt64():X}");

                // Read bytes at the function pointer
                unsafe
                {
                    byte* p = (byte*)preHookPtr;
                    var sb = new System.Text.StringBuilder();
                    for (int i = 0; i < 32; i++) sb.Append($"{p[i]:X2} ");
                    Log($"Pre-hook bytes at func ptr: {sb}");
                }

                // Now resolve through the precode to find the JIT code
                IntPtr resolvedPtr = MethodEntryResolver.ResolveRealEntry(preHookPtr);
                Log($"Resolved real entry: 0x{resolvedPtr.ToInt64():X}");

                // Read bytes at resolved entry
                unsafe
                {
                    byte* p = (byte*)resolvedPtr;
                    var sb = new System.Text.StringBuilder();
                    for (int i = 0; i < 32; i++) sb.Append($"{p[i]:X2} ");
                    Log($"Bytes at resolved entry: {sb}");
                }

                // Install hook
                var hookMethod = typeof(DiagNet472Test).GetMethod("SimpleHook_ConvertAll",
                    BindingFlags.Static | BindingFlags.NonPublic,
                    null, new[] { typeof(List<int>), typeof(Converter<int, string>) }, null);

                Log("About to create MethodHook...");
                var hook = new MethodHook(genericTarget, hookMethod);
                Log("About to call hook.Install()...");
                hook.Install();
                Log("hook.Install() returned.");
                Log("=== DiagInfo ===");
                Log(hook.DiagInfo.ToString());

                // Read function pointer AFTER hooking
                IntPtr postHookPtr = handle.GetFunctionPointer();
                Log($"Post-hook function pointer: 0x{postHookPtr.ToInt64():X}");

                // Read bytes at the function pointer after hooking
                unsafe
                {
                    byte* p = (byte*)postHookPtr;
                    var sb = new System.Text.StringBuilder();
                    for (int i = 0; i < 32; i++) sb.Append($"{p[i]:X2} ");
                    Log($"Post-hook bytes at func ptr: {sb}");
                }

                // Read bytes at resolved entry after hooking
                IntPtr postResolvedPtr = MethodEntryResolver.ResolveRealEntry(postHookPtr);
                Log($"Post-hook resolved entry: 0x{postResolvedPtr.ToInt64():X}");
                unsafe
                {
                    byte* p = (byte*)postResolvedPtr;
                    var sb = new System.Text.StringBuilder();
                    for (int i = 0; i < 32; i++) sb.Append($"{p[i]:X2} ");
                    Log($"Post-hook bytes at resolved entry: {sb}");
                }

                // Check if function pointer changed
                Log($"Function pointer changed: {preHookPtr != postHookPtr}");

                // Try direct call
                Log("About to try direct call...");
                var list = new List<int> { 1, 2, 3 };
                var result = list.ConvertAll(new Converter<int, string>(x => x.ToString()));
                Log($"Direct call result: [{string.Join(",", result)}]");

                // Try delegate call
                Log("About to try delegate call...");
                var delType = typeof(Func<List<int>, Converter<int, string>, List<string>>);
                var del = (Func<List<int>, Converter<int, string>, List<string>>)
                    genericTarget.CreateDelegate(delType);
                var result2 = del(list, new Converter<int, string>(x => x.ToString()));
                Log($"Delegate call result: [{string.Join(",", result2)}]");

                Log("About to call hook.Uninstall()...");
                hook.Uninstall();
                Log("hook.Uninstall() returned.");
            }
            catch (Exception ex)
            {
                Log($"EXCEPTION: {ex.GetType().FullName}: {ex.Message}");
                Log($"Stack: {ex.StackTrace}");
                throw;
            }
            finally
            {
                Log($"=== Test ended {DateTime.Now:O} ===");
            }
        }

        private static List<string> SimpleHook_ConvertAll(List<int> self, Converter<int, string> converter)
        {
            File.AppendAllText(_logFile, $"[HOOK] SimpleHook_ConvertAll invoked! self.Count={self.Count}\r\n");
            return new List<string> { "HOOKED" };
        }
    }
}
