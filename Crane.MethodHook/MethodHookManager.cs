using System;
using System.Collections.Generic;
using System.Reflection;


namespace Crane.MethodHook
{
    public class MethodHookManager
    {
        public static readonly MethodHookManager Instance = new MethodHookManager();

        private MethodHookManager()
        {
            MethodHookList = new List<MethodHook>();
        }

        private List<MethodHook> MethodHookList { get; set; }


        /// <summary>
        /// 启用hook
        /// </summary>
        public void StartHook()
        {
            try
            {
                //start hook
                MethodHookList.ForEach(item =>
                {
                    if (item != null)
                    {
                        item.StartHook();
                    }
                });
            }
            catch (Exception)
            {

            }
        }

        /// <summary>
        /// 停用Hook
        /// </summary>
        public void StopHook()
        {
            MethodHookList.ForEach(item =>
            {
                try
                {
                    if (item != null)
                    {
                        item.StopHook();
                    }
                }
                catch (Exception)
                {

                }
            });
        }

        public MethodHook GetHook(MethodBase method)
        {
            foreach (var item in MethodHookList)
            {
                if (item.TargetMethod.Equals(method) || item.SourceMethod.Equals(method))
                {
                    return item;
                }
            }

            return null;
        }

        public void AddHook(MethodHook hook)
        {
            if (MethodHookList.Find(item => item.Equals(hook)) == null)
            {
                MethodHookList.Add(hook);
            }
        }

        public void RemoveHook(MethodHook hook)
        {
            if (MethodHookList.Find(item => item.Equals(hook)) != null)
            {
                hook.StopHook();
                MethodHookList.Remove(hook);
            }
        }

        public void RemoveAllHook()
        {
            foreach (var hook in MethodHookList)
            {
                hook.StopHook();
            }
            MethodHookList.Clear();
        }
    }
}