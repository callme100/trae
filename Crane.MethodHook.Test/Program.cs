using System.Reflection;
using System.Text;

namespace Crane.MethodHook.Test
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("========================================");
            Console.WriteLine("  Crane.MethodHook 功能测试");
            Console.WriteLine("========================================");
            Console.WriteLine();

            try
            {
                InstallHook();
            }
            catch
            {
                throw;
            }

            // Print any hook installation errors for debugging
            var errors = MethodHookManager.Instance.LastErrors;
            if (errors != null && errors.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[安装阶段] {errors.Count} 个 hook 安装错误:");
                foreach (var ex in errors)
                {
                    Console.WriteLine($"  - {ex.Message}");
                }
                Console.ResetColor();
            }

            Console.WriteLine("[安装阶段] Hook 安装完成，开始执行测试...");
            Console.WriteLine();

            TestAll();

            // Stop all hooks before rendering the table to prevent Spectre.Console
            // internals (which call List.Add etc.) from triggering hooks.
            MethodHookManager.Instance.StopHook();

            PrintTestResults();

            Console.WriteLine();
            Console.WriteLine("按任意键退出...");
            try { Console.ReadKey(); } catch { }
        }

        private static List<string> _list = new();
        private static readonly List<TestResult> _testResults = new();
        private static readonly HashSet<string> _recordedTests = new(); // 防止重复记录同一测试项
        [ThreadStatic]
        private static bool _isRecording; // 防止 List.Add hook 导致的递归重入

        private static void InstallHook()
        {
            var allBindings = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;

            //DateTime.ToString
            var sourceMethod = typeof(DateTime).GetMethod("ToString", allBindings, null, new Type[0], null);
            var targetMethod = typeof(Program).GetMethod(nameof(HookDateTimeToString), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            //Int32.ToString
            sourceMethod = typeof(int).GetMethod("ToString", allBindings, null, new Type[0], null);
            targetMethod = typeof(Program).GetMethod(nameof(HookInt32ToString), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            //AssemblyName.Name
            sourceMethod = typeof(AssemblyName).GetProperty("Name").GetMethod;
            targetMethod = typeof(Program).GetMethod(nameof(HookAssemblyNameGetName), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            //StringBuilderSetCapacity
            sourceMethod = typeof(System.Text.StringBuilder).GetProperty("Capacity").SetMethod;
            targetMethod = typeof(Program).GetMethod(nameof(HookStringBuilderSetCapacity), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            //泛型列表Add方法的Hook
            sourceMethod = _list.GetType().GetMethod("Add", allBindings);
            targetMethod = typeof(Program).GetMethod(nameof(HookListAdd), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            //运算符(DateTime.op_GreaterThan)的Hook
            sourceMethod = typeof(DateTime).GetMethod("op_GreaterThan", allBindings);
            targetMethod = typeof(Program).GetMethod(nameof(HookDateTimeGreaterThan), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            //string.Compare
            sourceMethod = typeof(string).GetMethod("Compare", allBindings, null, new[] { typeof(string), typeof(string) }, null);
            targetMethod = typeof(Program).GetMethod(nameof(HookStringCompare), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            //StreamReader.ReadToEnd
            sourceMethod = typeof(StreamReader).GetMethod("ReadToEnd", allBindings);
            targetMethod = typeof(Program).GetMethod(nameof(HookReadToEnd), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            //List<int>.ConvertAll
            sourceMethod = typeof(List<int>).GetMethod("ConvertAll", allBindings).MakeGenericMethod(typeof(string));
            targetMethod = typeof(Program).GetMethod(nameof(HookConvertAll), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            //MemoryStream.Write
            sourceMethod = typeof(MemoryStream).GetMethod("Write", allBindings, null, new[] { typeof(byte[]), typeof(int), typeof(int) }, null);
            targetMethod = typeof(Program).GetMethod(nameof(HookMemoryStreamWrite), allBindings);
            MethodHookManager.Instance.AddHook(new MethodHook(sourceMethod, targetMethod));

            MethodHookManager.Instance.StartHook();
        }

        public class TestResult
        {
            public string TestName { get; set; }
            public string MethodFullName { get; set; }
            public bool HookTriggered { get; set; }
            public bool InvokeOriginalSuccess { get; set; }
            public string OriginalResult { get; set; }
            public string HookResult { get; set; }
            public string ErrorMessage { get; set; }
            public bool IsPassed => HookTriggered && InvokeOriginalSuccess && string.IsNullOrEmpty(ErrorMessage);

            public TestResult()
            {
                TestName = string.Empty;
                MethodFullName = string.Empty;
                OriginalResult = string.Empty;
                HookResult = string.Empty;
                ErrorMessage = string.Empty;
            }
        }

        private static void RecordResult(string testName, string methodFullName, bool hookTriggered, bool invokeOriginalSuccess, string originalResult, string hookResult, string errorMessage = "")
        {
            if (_isRecording) return; // 防止递归重入
            if (_recordedTests.Contains(testName)) return; // 防止重复记录同一测试项
            _isRecording = true;
            try
            {
                _recordedTests.Add(testName);
                _testResults.Add(new TestResult
                {
                    TestName = testName,
                    MethodFullName = methodFullName,
                    HookTriggered = hookTriggered,
                    InvokeOriginalSuccess = invokeOriginalSuccess,
                    OriginalResult = originalResult ?? string.Empty,
                    HookResult = hookResult ?? string.Empty,
                    ErrorMessage = errorMessage ?? string.Empty
                });
            }
            finally
            {
                _isRecording = false;
            }
        }

        private static void TestAll()
        {
            try
            {
                //直接调用测试
                _ = DateTime.Now.ToString();
                _ = 123.ToString();
                _ = Assembly.GetExecutingAssembly().GetName().Name;
                new StringBuilder().Capacity = 100;
                _list.Add("abc");
                _ = DateTime.Now > DateTime.Now.AddDays(-1);
                _ = string.Compare("a", "b");
                _ = new StreamReader(new MemoryStream(new byte[] { 41, 44, 46 })).ReadToEnd();
                _ = new List<int> { 1, 2, 3 }.ConvertAll<string>(item => (item * 2).ToString());
                new MemoryStream().Write(new byte[] { 1, 2, 3 }, 0, 3);
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[测试异常] {e.Message}");
                Console.ResetColor();
            }
        }

        private static void PrintTestResults()
        {
            Console.WriteLine();
            Console.WriteLine("========================================");
            Console.WriteLine("  测试结果汇总");
            Console.WriteLine("========================================");
            Console.WriteLine();

            int passed = 0;
            int failed = 0;
            int notTriggered = 0;

            // 计算列宽
            int nameWidth = Math.Max(20, _testResults.Max(r => r.TestName.Length) + 2);
            int methodWidth = Math.Max(40, _testResults.Max(r => r.MethodFullName.Length) + 2);
            int triggeredWidth = 12;
            int originalWidth = 10;
            int resultWidth = 10;

            // 表头
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"{"测试项".PadRight(nameWidth)}{"目标方法".PadRight(methodWidth)}{"Hook触发".PadRight(triggeredWidth)}{"原始调用".PadRight(originalWidth)}{"结果".PadRight(resultWidth)}");
            Console.WriteLine(new string('-', nameWidth + methodWidth + triggeredWidth + originalWidth + resultWidth));
            Console.ResetColor();

            foreach (var result in _testResults)
            {
                // 测试项名称
                Console.Write(result.TestName.PadRight(nameWidth));

                // 目标方法
                Console.Write(result.MethodFullName.PadRight(methodWidth));

                // Hook触发状态
                if (result.HookTriggered)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("✓ 是".PadRight(triggeredWidth));
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("✗ 否".PadRight(triggeredWidth));
                    Console.ResetColor();
                    notTriggered++;
                }

                // 原始调用状态
                if (result.InvokeOriginalSuccess)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("✓ 成功".PadRight(originalWidth));
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("✗ 失败".PadRight(originalWidth));
                    Console.ResetColor();
                }

                // 整体结果
                if (result.IsPassed)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✓ 通过");
                    Console.ResetColor();
                    passed++;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("✗ 失败");
                    Console.ResetColor();
                    failed++;
                }

                // 详细信息（失败时显示）
                if (!result.IsPassed && !string.IsNullOrEmpty(result.ErrorMessage))
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine($"  └─ 错误: {result.ErrorMessage}");
                    Console.ResetColor();
                }
                if (!string.IsNullOrEmpty(result.OriginalResult) && result.OriginalResult.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  └─ 原始返回: {Truncate(result.OriginalResult, 60)}");
                    Console.ResetColor();
                }
                if (!string.IsNullOrEmpty(result.HookResult) && result.HookResult.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  └─ Hook返回: {Truncate(result.HookResult, 60)}");
                    Console.ResetColor();
                }
            }

            // 统计信息
            Console.WriteLine();
            Console.WriteLine("========================================");
            Console.WriteLine("  统计信息");
            Console.WriteLine("========================================");
            Console.WriteLine($"  总测试数: {_testResults.Count}");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  通过: {passed}");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  失败: {failed}");
            Console.ResetColor();
            if (notTriggered > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  未触发: {notTriggered}");
                Console.ResetColor();
            }

            // 总体结论
            Console.WriteLine();
            if (failed == 0 && notTriggered == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("✓ 所有测试通过！Hook 功能正常工作。");
                Console.ResetColor();
            }
            else if (failed == 0 && notTriggered > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("⚠ 部分 Hook 未触发，请检查。");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("✗ 存在失败的测试，请检查错误信息。");
                Console.ResetColor();
            }
        }

        private static string Truncate(string str, int maxLength)
        {
            if (string.IsNullOrEmpty(str)) return str;
            if (str.Length <= maxLength) return str;
            return str.Substring(0, maxLength) + "...";
        }

        public static int HookStringCompare(string str1, string str2)
        {
            bool invokeSuccess = false;
            string originalResult = string.Empty;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                var result = hook.InvokeOriginal<int>(null, str1, str2);
                originalResult = result.ToString();
                invokeSuccess = true;
                return 999;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return 999;
            }
            finally
            {
                RecordResult(
                    "string.Compare",
                    "System.String.Compare(String, String)",
                    true,
                    invokeSuccess,
                    originalResult,
                    "999",
                    error);
            }
        }

        public static string HookAssemblyNameGetName(AssemblyName ass)
        {
            bool invokeSuccess = false;
            string originalResult = string.Empty;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                originalResult = hook.InvokeOriginal<string>(ass) ?? string.Empty;
                invokeSuccess = true;
                return "hooked";
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return "hooked";
            }
            finally
            {
                RecordResult(
                    "AssemblyName.Name",
                    "System.Reflection.AssemblyName.Name",
                    true,
                    invokeSuccess,
                    originalResult,
                    "hooked",
                    error);
            }
        }

        public static void HookStringBuilderSetCapacity(System.Text.StringBuilder sb, int capacity)
        {
            bool invokeSuccess = false;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                hook.InvokeOriginal(sb, capacity);
                invokeSuccess = true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
            finally
            {
                RecordResult(
                    "StringBuilder.Capacity",
                    "System.Text.StringBuilder.Capacity",
                    true,
                    invokeSuccess,
                    "void",
                    "void",
                    error);
            }
        }

        public static string HookReadToEnd(object sr)
        {
            bool invokeSuccess = false;
            string originalResult = string.Empty;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                originalResult = hook.InvokeOriginal<string>(sr) ?? string.Empty;
                invokeSuccess = true;
                return "hooked.";
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return "hooked.";
            }
            finally
            {
                RecordResult(
                    "StreamReader.ReadToEnd",
                    "System.IO.StreamReader.ReadToEnd()",
                    true,
                    invokeSuccess,
                    originalResult,
                    "hooked.",
                    error);
            }
        }

        public static string HookDateTimeToString(DateTime dt)
        {
            bool invokeSuccess = false;
            string originalResult = string.Empty;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                originalResult = hook.InvokeOriginal<string>(dt) ?? string.Empty;
                invokeSuccess = true;
                return "hooked.";
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return "hooked.";
            }
            finally
            {
                RecordResult(
                    "DateTime.ToString",
                    "System.DateTime.ToString()",
                    true,
                    invokeSuccess,
                    originalResult,
                    "hooked.",
                    error);
            }
        }

        public static void HookListAdd(List<string> list, object item)
        {
            bool invokeSuccess = false;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                hook.InvokeOriginal(list, item);
                invokeSuccess = true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
            finally
            {
                RecordResult(
                    "List<string>.Add",
                    "System.Collections.Generic.List`1.Add(T)",
                    true,
                    invokeSuccess,
                    "void",
                    "void",
                    error);
            }
        }

        public static string HookInt32ToString(int num)
        {
            bool invokeSuccess = false;
            string originalResult = string.Empty;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                originalResult = hook.InvokeOriginal<string>(num) ?? string.Empty;
                invokeSuccess = true;
                return "hooked.";
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return "hooked.";
            }
            finally
            {
                RecordResult(
                    "Int32.ToString",
                    "System.Int32.ToString()",
                    true,
                    invokeSuccess,
                    originalResult,
                    "hooked.",
                    error);
            }
        }

        public static List<string> HookConvertAll(object list, object function)
        {
            bool invokeSuccess = false;
            string originalResult = string.Empty;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                var result = hook.InvokeOriginal<List<string>>(list, function);
                originalResult = result != null ? $"[{string.Join(", ", result)}]" : string.Empty;
                invokeSuccess = true;
                return new List<string> { "2", "4", "6" };
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return new List<string> { "2", "4", "6" };
            }
            finally
            {
                RecordResult(
                    "List<int>.ConvertAll",
                    "System.Collections.Generic.List`1.ConvertAll<TOutput>()",
                    true,
                    invokeSuccess,
                    originalResult,
                    "[2, 4, 6]",
                    error);
            }
        }

        public static void HookMemoryStreamWrite(MemoryStream ms, byte[] buffer, int offset, int count)
        {
            bool invokeSuccess = false;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                hook.InvokeOriginal(ms, buffer, offset, count);
                ms.Position = 0;
                hook.InvokeOriginal(ms, new byte[] { 9, 9, 9 }, offset, count);
                invokeSuccess = true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
            finally
            {
                RecordResult(
                    "MemoryStream.Write",
                    "System.IO.MemoryStream.Write(Byte[], Int32, Int32)",
                    true,
                    invokeSuccess,
                    "void",
                    "void (double write)",
                    error);
            }
        }

        public static bool HookDateTimeGreaterThan(DateTime left, DateTime right)
        {
            bool invokeSuccess = false;
            string originalResult = string.Empty;
            string error = string.Empty;
            try
            {
                var hook = Crane.MethodHook.MethodHookManager.Instance.GetHook(MethodBase.GetCurrentMethod());
                var result = hook.InvokeOriginal<bool>(null, left, right);
                originalResult = result.ToString();
                invokeSuccess = true;
                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
            finally
            {
                RecordResult(
                    "DateTime.op_GreaterThan",
                    "System.DateTime.op_GreaterThan(DateTime, DateTime)",
                    true,
                    invokeSuccess,
                    originalResult,
                    "False",
                    error);
            }
        }

    }
}
