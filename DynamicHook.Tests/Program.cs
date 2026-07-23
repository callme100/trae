using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace DynamicHook.Tests
{
    /// <summary>
    /// Result of a single hook test case.
    /// </summary>
    internal sealed class TestResult
    {
        public string Name;
        public bool Passed;
        public string Expected;
        public string Detail;

        public void MarkPass(string detail)
        {
            Passed = true;
            Detail = detail;
        }

        public void MarkFail(string detail)
        {
            Passed = false;
            Detail = detail;
        }
    }

    internal static class Program
    {
        internal static readonly bool DiagEnabled =
            Environment.GetEnvironmentVariable("DTHOOK_DIAG") != null;

        // Per-case wall-clock timeout. A hooked method that hangs (e.g. an
        // infinite re-entrancy in CallOriginal) will be killed and reported as
        // FAIL("HANG") rather than blocking the whole run.
        private const int CaseTimeoutMs = 30000;

        private static int _passed;
        private static int _failed;

        internal static void Trace(string msg)
        {
            if (DiagEnabled)
            {
                Console.Error.WriteLine("[trace] " + msg);
                Console.Error.Flush();
            }
        }

        private static string FrameworkLabel()
        {
#if NET10_0
            return "net10.0";
#elif NET8_0
            return "net8.0";
#elif NET6_0
            return "net6.0";
#elif NET472
            return "net472";
#else
            return "unknown";
#endif
        }

        private static string ArchLabel()
        {
            try
            {
                switch (RuntimeInformation.ProcessArchitecture)
                {
                    case Architecture.X86: return "x86";
                    case Architecture.X64: return "x64";
                    case Architecture.Arm: return "arm32";
                    case Architecture.Arm64: return "arm64";
                    default: return "unknown";
                }
            }
            catch
            {
                return IntPtr.Size == 8 ? "x64?" : "x86?";
            }
        }

        private static string OsLabel()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return "Windows";
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return "Linux";
                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return "OSX";
            }
            catch { }
            return "unknown";
        }

        private static void PrintHeader()
        {
            Console.WriteLine("============================================================");
            Console.WriteLine(" DynamicHook cross-platform test runner");
            Console.WriteLine("============================================================");
            Console.WriteLine(" OS          : " + OsLabel());
            Console.WriteLine(" Architecture: " + ArchLabel());
            Console.WriteLine(" Framework   : " + FrameworkLabel());
            Console.WriteLine(" CLR         : " + RuntimeInformation.FrameworkDescription);
            Console.WriteLine(" IntPtr.Size : " + IntPtr.Size);
            Console.WriteLine("------------------------------------------------------------");
        }

        // Name -> test case factory. Names are used for --case selection.
        private static readonly Dictionary<string, Func<TestResult>> Cases =
            new Dictionary<string, Func<TestResult>>
            {
                { "DateTimeCompare",   HookTests.Test_DateTimeCompare },
                { "DateTimeCompareDirect", HookTests.Test_DateTimeCompareDirect },
                { "DateTimeCompareDiag", HookTests.Test_DateTimeCompareDiag },
                { "DateTimeCompareParams", HookTests.Test_DateTimeCompareParams },
                { "DateTimeCompareCallPatterns", HookTests.Test_DateTimeCompareCallPatterns },
                { "DateTimeCompareTieredStress", HookTests.Test_DateTimeCompareTieredStress },
                { "StreamReaderReadToEnd", HookTests.Test_StreamReaderReadToEnd },
                { "ListConvertAll",    HookTests.Test_ListConvertAll },
                { "ListConvertAllTieredStress", HookTests.Test_ListConvertAllTieredStress },
                { "DateTimeToString",  HookTests.Test_DateTimeToString },
                { "DateTimeParseExact", HookTests.Test_DateTimeParseExact },
                { "DateTimeGreaterThan", HookTests.Test_DateTimeGreaterThan },
            };

        /// <summary>
        /// Runs a single named test case in-process and writes a single-line
        /// machine-readable verdict to stdout: "PASS|FAIL\t&lt;name&gt;\t&lt;detail&gt;".
        /// Human-readable output is written to stderr.
        /// </summary>
        private static int RunSingleCase(string name)
        {
            Func<TestResult> test;
            if (!Cases.TryGetValue(name, out test))
            {
                Console.WriteLine("FAIL\t" + name + "\tUnknown case");
                return 1;
            }

            TestResult result = null;
            try
            {
                result = test();
            }
            catch (Exception ex)
            {
                result = new TestResult
                {
                    Name = name,
                    Passed = false,
                    Detail = "Unhandled exception: " + ex.GetType().Name + ": " + ex.Message
                             + (ex.StackTrace != null ? " | " + ex.StackTrace : "")
                };
            }

            string verdict = result.Passed ? "PASS" : "FAIL";
            // Escape newlines in detail for the single-line verdict.
            string detail = (result.Detail ?? "").Replace("\n", " ").Replace("\r", "");
            Console.WriteLine(verdict + "\t" + name + "\t" + detail);
            return result.Passed ? 0 : 1;
        }

        private static string CurrentExePath()
        {
            // On framework-dependent builds the host is dotnet.exe; the actual
            // assembly path (the .dll to re-launch) is the executing assembly
            // location, which works on all target frameworks.
            return Assembly.GetExecutingAssembly().Location;
        }

        /// <summary>
        /// Quotes an argument for the process argument string. When
        /// <see cref="ProcessStartInfo.UseShellExecute"/> is false, .NET's own
        /// argument parser handles the splitting — it respects double quotes for
        /// grouping on BOTH Windows and Unix, but does NOT handle single quotes
        /// on Unix (they become literal characters). So we always use double
        /// quotes.
        /// </summary>
        private static string QuoteArg(string arg)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return "\"" + arg.Replace("\"", "\"\"") + "\"";
            // Unix with UseShellExecute=false: .NET parses Arguments using
            // double-quote grouping. Backslash-escape embedded double quotes.
            return "\"" + arg.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        }

        /// <summary>
        /// Orchestrates running every case in its own child process (isolated, so
        /// a hang or corruption in one case cannot affect the others). Each child
        /// is killed if it exceeds <see cref="CaseTimeoutMs"/>.
        /// </summary>
        private static int RunAllCases()
        {
            string exe = CurrentExePath();
            string runner;
            string runnerArg;
            if (exe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                runner = "dotnet";
                runnerArg = exe;
            }
            else
            {
                runner = exe;
                runnerArg = null;
            }

            foreach (var kv in Cases)
            {
                string name = kv.Key;
                // Build a single Arguments string (works on net472 + modern .NET).
                var argsBuilder = new System.Text.StringBuilder();
                if (runnerArg != null) argsBuilder.Append(QuoteArg(runnerArg)).Append(' ');
                argsBuilder.Append(QuoteArg("--case")).Append(' ').Append(QuoteArg(name));

                var psi = new ProcessStartInfo
                {
                    FileName = runner,
                    Arguments = argsBuilder.ToString(),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = DiagEnabled,
                    CreateNoWindow = true,
                };
                if (DiagEnabled) psi.EnvironmentVariables["DTHOOK_DIAG"] = "1";

                string verdictLine = null;
                var stderrBuf = new System.Text.StringBuilder();
                bool timedOut = false;
                using (var proc = new Process { StartInfo = psi })
                {
                    proc.OutputDataReceived += (s, e) =>
                    {
                        if (e.Data != null && verdictLine == null && e.Data.Length > 0
                            && (e.Data.StartsWith("PASS\t") || e.Data.StartsWith("FAIL\t")))
                        {
                            verdictLine = e.Data;
                        }
                    };
                    if (DiagEnabled)
                    {
                        proc.ErrorDataReceived += (s, e) =>
                        {
                            if (e.Data != null) stderrBuf.AppendLine(e.Data);
                        };
                    }
                    try
                    {
                        proc.Start();
                        proc.BeginOutputReadLine();
                        if (DiagEnabled) proc.BeginErrorReadLine();
                    }
                    catch (Exception ex)
                    {
                        ReportCase(name, false, "Could not start child: " + ex.Message, "");
                        continue;
                    }

                    if (!proc.WaitForExit(CaseTimeoutMs))
                    {
                        timedOut = true;
                        try { proc.Kill(); } catch { }
                        try { proc.WaitForExit(2000); } catch { }
                    }
                    else
                    {
                        // The timed overload can return before asynchronous output
                        // events have been fully delivered. Wait once more (no
                        // timeout) so the verdict line is guaranteed to be read.
                        try { proc.WaitForExit(); } catch { }
                    }
                }
                string stderrText = stderrBuf.ToString();

                if (timedOut)
                {
                    ReportCase(name, false, "HANG (no verdict within " + CaseTimeoutMs + "ms)", stderrText);
                    continue;
                }

                if (verdictLine == null)
                {
                    ReportCase(name, false, "No verdict line produced (crash?)", stderrText);
                    continue;
                }

                // verdictLine = "PASS|FAIL\t<name>\t<detail>"
                string[] parts = verdictLine.Split('\t');
                bool passed = parts.Length > 0 && parts[0] == "PASS";
                string detail = parts.Length > 2 ? parts[2] : "";
                ReportCase(name, passed, detail, stderrText);
            }

            Console.WriteLine("------------------------------------------------------------");
            Console.WriteLine(string.Format(" Total: {0}  Passed: {1}  Failed: {2}",
                _passed + _failed, _passed, _failed));
            Console.WriteLine("============================================================");
            return _failed == 0 ? 0 : 1;
        }

        private static void ReportCase(string name, bool passed, string detail, string stderr)
        {
            string status = passed ? "PASS" : "FAIL";
            if (passed) _passed++; else _failed++;
            Console.WriteLine(string.Format(" [{0}] {1}", status, name));
            Console.WriteLine("        detail : " + detail);
            if (DiagEnabled && !string.IsNullOrEmpty(stderr))
            {
                Console.WriteLine("        stderr : " + stderr.Replace("\n", "\n                "));
            }
            Console.WriteLine();
        }

        private static int Main(string[] args)
        {
            // --case <name> : run a single case in-process (used by the orchestrator).
            if (args != null && args.Length >= 2 && args[0] == "--case")
            {
                return RunSingleCase(args[1]);
            }

            // --repro : run the user scenario reproduction test.
            if (args != null && args.Length >= 1 && args[0] == "--repro")
            {
                ReproTest.Run();
                return 0;
            }

            PrintHeader();
            return RunAllCases();
        }
    }
}
