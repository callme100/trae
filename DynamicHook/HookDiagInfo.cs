using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DynamicHook
{
    public class HookDiagInfo
    {
        public string TargetMethod;

        public string HookMethod;

        public IntPtr PrecodeAddr;

        public byte[] PrecodeBytes;

        public int SlotCount;

        public List<long> SlotAddresses;

        public string SlotError;

        public string PatchType;

        public string PatchError;

        public bool NeedsGenericAdapter;

        public IntPtr AdapterAddr;

        public byte[] AdapterBytes;

        public IntPtr JumpTargetAddr;

        public byte[] InstalledBytes;

        public IntPtr JitCodeAddr;

        public byte[] JitCodeOriginalBytes;

        public byte[] JitCodePatchedBytes;

        public IntPtr PrecodeFirstTargetAddr;

        public IntPtr PrecodeSecondTargetAddr;

        public byte[] Target1Bytes;

        public byte[] MethodDescDump;

        public string DelegateStatus;

        public string CallOrigStatus;

        public override string ToString()
        {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.AppendLine("Target: " + TargetMethod);
            stringBuilder.AppendLine("Hook:   " + HookMethod);
            stringBuilder.AppendLine($"Precode:       0x{PrecodeAddr.ToInt64():X16}  Bytes: {FormatBytes(PrecodeBytes)}");
            stringBuilder.AppendLine($"Slots found:   {SlotCount}");
            if (SlotAddresses != null && SlotAddresses.Count > 0)
            {
                stringBuilder.AppendLine("Slot addrs:    " + string.Join(", ", from a in SlotAddresses.Take(5)
                                                                               select $"0x{a:X16}"));
            }
            if (!string.IsNullOrEmpty(SlotError))
            {
                stringBuilder.AppendLine("Slot error:    " + SlotError);
            }
            stringBuilder.AppendLine("Patch type:    " + (PatchType ?? "none"));
            if (!string.IsNullOrEmpty(PatchError))
            {
                stringBuilder.AppendLine("Patch error:   " + PatchError);
            }
            stringBuilder.AppendLine($"NeedsAdapter:  {NeedsGenericAdapter}");
            if (NeedsGenericAdapter && AdapterAddr != IntPtr.Zero)
            {
                stringBuilder.AppendLine($"Adapter:       0x{AdapterAddr.ToInt64():X16}  Bytes: {FormatBytes(AdapterBytes)}");
            }
            stringBuilder.AppendLine($"JumpTarget:    0x{JumpTargetAddr.ToInt64():X16}");
            stringBuilder.AppendLine("Installed:     Bytes: " + FormatBytes(InstalledBytes));
            if (JitCodeAddr != IntPtr.Zero)
            {
                stringBuilder.AppendLine($"JitCode:       0x{JitCodeAddr.ToInt64():X16}");
                stringBuilder.AppendLine("JitCodeOrig:   " + FormatBytes(JitCodeOriginalBytes));
                stringBuilder.AppendLine("JitCodePatched:" + FormatBytes(JitCodePatchedBytes));
            }
            if (PrecodeFirstTargetAddr != IntPtr.Zero)
            {
                stringBuilder.AppendLine($"Precode1stTarget: 0x{PrecodeFirstTargetAddr.ToInt64():X16}");
            }
            if (Target1Bytes != null)
            {
                stringBuilder.AppendLine("Target1Bytes:  " + FormatBytes(Target1Bytes));
            }
            if (PrecodeSecondTargetAddr != IntPtr.Zero)
            {
                stringBuilder.AppendLine($"Precode2ndTarget: 0x{PrecodeSecondTargetAddr.ToInt64():X16}");
            }
            if (MethodDescDump != null)
            {
                stringBuilder.AppendLine("MethodDesc:    " + FormatBytes(MethodDescDump));
            }
            if (!string.IsNullOrEmpty(DelegateStatus))
            {
                stringBuilder.AppendLine("Delegate:      " + DelegateStatus);
            }
            if (!string.IsNullOrEmpty(CallOrigStatus))
            {
                stringBuilder.AppendLine("CallOrig:      " + CallOrigStatus);
            }
            return stringBuilder.ToString();
        }

        private static string FormatBytes(byte[] bytes)
        {
            if (bytes == null)
            {
                return "<null>";
            }
            return string.Join(" ", from b in bytes.Take(32)
                                    select $"{b:X2}") + ((bytes.Length > 32) ? " ..." : "");
        }
    }
}
