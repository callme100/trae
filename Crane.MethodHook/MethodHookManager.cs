using System;
using System.Collections.Generic;
using System.Reflection;

namespace Crane.MethodHook
{
    public class MethodHookManager
    {
        public static readonly MethodHookManager Instance = new MethodHookManager();

        private readonly object _lock = new object();
        private readonly List<MethodHook> _hookList = new List<MethodHook>();

        /// <summary>
        /// 最近一次批量操作中收集的错误(StartHook/StopHook/RemoveAllHook)。
        /// 每次批量操作结束后原子替换。空列表表示无错误。
        /// 单个 hook 的失败不会中断其他 hook 的处理。
        /// </summary>
        public IReadOnlyList<Exception> LastErrors => _lastErrors;
        private IReadOnlyList<Exception> _lastErrors = Array.Empty<Exception>();

        private MethodHookManager()
        {
        }

        /// <summary>
        /// 启用所有已注册的 hook。单个 hook 启动失败不会中断其他 hook,
        /// 失败的异常收集到 <see cref="LastErrors"/>。
        /// </summary>
        public void StartHook()
        {
            List<MethodHook> snapshot;
            lock (_lock)
            {
                snapshot = new List<MethodHook>(_hookList);
            }
            var errors = new List<Exception>();
            foreach (var hook in snapshot)
            {
                if (hook == null) continue;
                try
                {
                    hook.StartHook();
                }
                catch (Exception ex)
                {
                    errors.Add(ex);
                }
            }
            _lastErrors = errors;
        }

        /// <summary>
        /// 停用所有已注册的 hook。单个 hook 停止失败不会中断其他 hook,
        /// 失败的异常收集到 <see cref="LastErrors"/>。
        /// </summary>
        public void StopHook()
        {
            List<MethodHook> snapshot;
            lock (_lock)
            {
                snapshot = new List<MethodHook>(_hookList);
            }
            var errors = new List<Exception>();
            foreach (var hook in snapshot)
            {
                if (hook == null) continue;
                try
                {
                    hook.StopHook();
                }
                catch (Exception ex)
                {
                    errors.Add(ex);
                }
            }
            _lastErrors = errors;
        }

        public MethodHook GetHook(MethodBase method)
        {
            if (method == null) return null;
            lock (_lock)
            {
                foreach (var item in _hookList)
                {
                    if (item == null) continue;
                    if (item.TargetMethod.Equals(method) || item.SourceMethod.Equals(method))
                    {
                        return item;
                    }
                }
            }
            return null;
        }

        public void AddHook(MethodHook hook)
        {
            if (hook == null)
                throw new ArgumentNullException(nameof(hook));
            lock (_lock)
            {
                if (!_hookList.Contains(hook))
                {
                    _hookList.Add(hook);
                }
            }
        }

        public void RemoveHook(MethodHook hook)
        {
            if (hook == null) return;
            lock (_lock)
            {
                if (!_hookList.Contains(hook)) return;
            }
            var errors = new List<Exception>();
            try
            {
                hook.StopHook();
            }
            catch (Exception ex)
            {
                errors.Add(ex);
            }
            lock (_lock)
            {
                _hookList.Remove(hook);
            }
            _lastErrors = errors;
        }

        public void RemoveAllHook()
        {
            List<MethodHook> snapshot;
            lock (_lock)
            {
                snapshot = new List<MethodHook>(_hookList);
                _hookList.Clear();
            }
            var errors = new List<Exception>();
            foreach (var hook in snapshot)
            {
                if (hook == null) continue;
                try
                {
                    hook.StopHook();
                }
                catch (Exception ex)
                {
                    errors.Add(ex);
                }
            }
            _lastErrors = errors;
        }
    }
}
