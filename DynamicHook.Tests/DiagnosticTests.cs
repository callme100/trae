using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using DynamicHook;
using Xunit;
using Xunit.Abstractions;

namespace DynamicHook.Tests
{
    /// <summary>
    /// 诊断测试 - 只输出信息，不做实际hook，用于分析precode格式
    /// </summary>
    public class DiagnosticTests
    {
        private readonly ITestOutputHelper _output;

        public DiagnosticTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void Diagnose_StaticMethod_Precode()
        {
            var method = typeof(StaticTarget).GetMethod("StaticTargetMethod",
                BindingFlags.Public | BindingFlags.Static);

            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            IntPtr precode = method.MethodHandle.GetFunctionPointer();
            _output.WriteLine($"Static method precode addr: 0x{precode.ToInt64():X16}");

            byte[] bytes = ReadBytes(precode, 32);
            _output.WriteLine($"Bytes: {FormatBytes(bytes)}");
            _output.WriteLine($"IsJump: {MethodEntryResolver.IsJump(precode)}");

            IntPtr resolved = MethodEntryResolver.ResolveRealEntry(precode);
            _output.WriteLine($"Resolved entry: 0x{resolved.ToInt64():X16}");

            if (resolved != precode)
            {
                byte[] resolvedBytes = ReadBytes(resolved, 32);
                _output.WriteLine($"Resolved bytes: {FormatBytes(resolvedBytes)}");
                _output.WriteLine($"Resolved IsJump: {MethodEntryResolver.IsJump(resolved)}");
            }

            // MethodDesc info
            IntPtr methodDesc = method.MethodHandle.Value;
            _output.WriteLine($"MethodDesc: 0x{methodDesc.ToInt64():X16}");

            // MethodTable info
            IntPtr methodTable = typeof(StaticTarget).TypeHandle.Value;
            _output.WriteLine($"MethodTable: 0x{methodTable.ToInt64():X16}");

            // Scan for precode pointer in MethodDesc (first 128 bytes)
            _output.WriteLine("\n--- Scanning MethodDesc for precode pointer ---");
            for (int i = 0; i < 128; i += IntPtr.Size)
            {
                try
                {
                    long val = IntPtr.Size == 8 ? Marshal.ReadInt64(methodDesc + i) : Marshal.ReadInt32(methodDesc + i);
                    if (val == precode.ToInt64())
                        _output.WriteLine($"  Found precode at MethodDesc+0x{i:X2}");
                }
                catch { break; }
            }

            // Scan MethodTable for precode pointer (first 1024 bytes)
            _output.WriteLine("\n--- Scanning MethodTable for precode pointer ---");
            int mtHits = 0;
            for (int i = 0; i < 4096; i += IntPtr.Size)
            {
                try
                {
                    long val = IntPtr.Size == 8 ? Marshal.ReadInt64(methodTable + i) : Marshal.ReadInt32(methodTable + i);
                    if (val == precode.ToInt64())
                    {
                        _output.WriteLine($"  Found precode at MethodTable+0x{i:X2}");
                        mtHits++;
                        if (mtHits > 10) break;
                    }
                }
                catch { break; }
            }
            _output.WriteLine($"Total MT hits: {mtHits}");

            // Also try calling the method to see what happens
            _output.WriteLine("\n--- Calling StaticTargetMethod(1, \"a\") ---");
            string result = StaticTarget.StaticTargetMethod(1, "a");
            _output.WriteLine($"Result: {result}");

            // After call, precode might change (JIT backpatching)
            byte[] bytesAfter = ReadBytes(precode, 32);
            _output.WriteLine($"Bytes after call: {FormatBytes(bytesAfter)}");
            _output.WriteLine($"IsJump after: {MethodEntryResolver.IsJump(precode)}");
        }

        [Fact]
        public void Diagnose_ReadToEnd_Precode()
        {
            var method = typeof(StreamReader).GetMethod("ReadToEnd", Type.EmptyTypes);
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            // Call it once first to ensure JIT
            using (var sr = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("test"))))
            {
                sr.ReadToEnd();
            }

            IntPtr precode = method.MethodHandle.GetFunctionPointer();
            _output.WriteLine($"ReadToEnd precode addr: 0x{precode.ToInt64():X16}");

            byte[] bytes = ReadBytes(precode, 32);
            _output.WriteLine($"Bytes: {FormatBytes(bytes)}");

            IntPtr resolved = MethodEntryResolver.ResolveRealEntry(precode);
            _output.WriteLine($"Resolved: 0x{resolved.ToInt64():X16}");
            if (resolved != precode)
            {
                _output.WriteLine($"Resolved bytes: {FormatBytes(ReadBytes(resolved, 32))}");
            }

            IntPtr methodDesc = method.MethodHandle.Value;
            IntPtr methodTable = typeof(StreamReader).TypeHandle.Value;
            _output.WriteLine($"MethodDesc: 0x{methodDesc.ToInt64():X16}");
            _output.WriteLine($"MethodTable: 0x{methodTable.ToInt64():X16}");

            int mtHits = 0;
            for (int i = 0; i < 8192; i += IntPtr.Size)
            {
                try
                {
                    long val = IntPtr.Size == 8 ? Marshal.ReadInt64(methodTable + i) : Marshal.ReadInt32(methodTable + i);
                    if (val == precode.ToInt64())
                    {
                        _output.WriteLine($"  Found at MT+0x{i:X2}");
                        mtHits++;
                        if (mtHits > 10) break;
                    }
                }
                catch { break; }
            }
            _output.WriteLine($"Total MT hits: {mtHits}");
        }

        [Fact]
        public void Diagnose_ConvertAll_Precode()
        {
            var openMethod = typeof(List<int>).GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(m => m.Name == "ConvertAll" && m.IsGenericMethod);
            Assert.NotNull(openMethod);
            var genericMethod = openMethod.MakeGenericMethod(typeof(string));

            // Call once to JIT
            var list = new List<int> { 1 };
            list.ConvertAll(x => x.ToString());

            RuntimeHelpers.PrepareMethod(genericMethod.MethodHandle);

            IntPtr precode = genericMethod.MethodHandle.GetFunctionPointer();
            _output.WriteLine($"ConvertAll<string> precode addr: 0x{precode.ToInt64():X16}");

            byte[] bytes = ReadBytes(precode, 64);
            _output.WriteLine($"Bytes: {FormatBytes(bytes)}");

            IntPtr resolved = MethodEntryResolver.ResolveRealEntry(precode);
            _output.WriteLine($"Resolved: 0x{resolved.ToInt64():X16}");
            if (resolved != precode)
            {
                _output.WriteLine($"Resolved bytes: {FormatBytes(ReadBytes(resolved, 64))}");
            }

            _output.WriteLine($"IsGenericMethod: {genericMethod.IsGenericMethod}");
            _output.WriteLine($"MethodDesc: 0x{genericMethod.MethodHandle.Value.ToInt64():X16}");
        }

        private byte[] ReadBytes(IntPtr addr, int count)
        {
            try
            {
                var bytes = new byte[count];
                Marshal.Copy(addr, bytes, 0, count);
                return bytes;
            }
            catch { return null; }
        }

        private string FormatBytes(byte[] bytes)
        {
            if (bytes == null) return "<null>";
            var sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                if (i > 0) sb.Append(" ");
                sb.Append($"{bytes[i]:X2}");
            }
            return sb.ToString();
        }
    }
}
