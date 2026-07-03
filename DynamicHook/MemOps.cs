using System;
using System.Runtime.InteropServices;

namespace DynamicHook
{
    /// <summary>
    /// 统一的低层内存读写 API。封装 Marshal.Read/Write 与保护属性管理，
    /// 集中提供边界检查（IsReadable）和错误处理，避免在业务代码中散布
    /// 手写 Marshal 调用和 unsafe 指针解引用。
    /// </summary>
    internal static class MemOps
    {
        // ===== 基本读取 =====

        /// <summary>读取单字节。调用方需确保地址可读。</summary>
        public static byte ReadByte(IntPtr addr) => Marshal.ReadByte(addr);

        /// <summary>读取 32 位有符号整数。调用方需确保地址可读。</summary>
        public static int ReadInt32(IntPtr addr) => Marshal.ReadInt32(addr);

        /// <summary>读取 64 位有符号整数。调用方需确保地址可读。</summary>
        public static long ReadInt64(IntPtr addr) => Marshal.ReadInt64(addr);

        /// <summary>读取指针大小的值（x64 读 8 字节，x86 读 4 字节）。</summary>
        public static IntPtr ReadIntPtr(IntPtr addr)
        {
            return IntPtr.Size == 8
                ? new IntPtr(Marshal.ReadInt64(addr))
                : new IntPtr(Marshal.ReadInt32(addr));
        }

        /// <summary>
        /// 安全读取字节数组。若地址不可读或读取失败，返回 null 或部分数据。
        /// 用于诊断 dump 等容错场景。
        /// </summary>
        public static byte[] ReadBytesSafe(IntPtr addr, int count)
        {
            if (addr == IntPtr.Zero || count <= 0) return null;
            if (!Memory.IsReadable(addr, count)) return null;
            try
            {
                byte[] buf = new byte[count];
                Marshal.Copy(addr, buf, 0, count);
                return buf;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 读取字节数组。地址不可读时抛异常。
        /// 用于必须成功的读取场景。
        /// </summary>
        public static byte[] ReadBytes(IntPtr addr, int count)
        {
            if (addr == IntPtr.Zero) throw new ArgumentNullException(nameof(addr));
            byte[] buf = new byte[count];
            Marshal.Copy(addr, buf, 0, count);
            return buf;
        }

        // ===== 基本写入 =====
        // 这些方法假设目标地址已可写（调用方已调用 ProtectWritable/ProtectReadWrite）。

        public static void WriteByte(IntPtr addr, byte value) => Marshal.WriteByte(addr, value);

        public static void WriteInt32(IntPtr addr, int value) => Marshal.WriteInt32(addr, value);

        public static void WriteInt64(IntPtr addr, long value) => Marshal.WriteInt64(addr, value);

        public static void WriteIntPtr(IntPtr addr, IntPtr value)
        {
            if (IntPtr.Size == 8)
                Marshal.WriteInt64(addr, value.ToInt64());
            else
                Marshal.WriteInt32(addr, value.ToInt32());
        }

        public static void WriteBytes(IntPtr addr, byte[] bytes)
        {
            Marshal.Copy(bytes, 0, addr, bytes.Length);
        }

        // ===== 受保护的 Patch 操作 =====
        // 自动管理 ProtectWritable → 写入 → ProtectExecutable 流程。

        /// <summary>
        /// 写入字节数组到目标地址（通常为代码页），自动管理保护属性。
        /// 流程：读取原始字节 → ProtectWritable → 写入 → ProtectExecutable。
        /// 返回被覆盖的原始字节，用于后续 Restore。
        /// </summary>
        public static byte[] PatchBytes(IntPtr addr, byte[] newBytes)
        {
            byte[] original = ReadBytes(addr, newBytes.Length);
            Memory.ProtectWritable(addr, newBytes.Length);
            Marshal.Copy(newBytes, 0, addr, newBytes.Length);
            Memory.ProtectExecutable(addr, newBytes.Length);
            return original;
        }

        /// <summary>
        /// 写入字节数组到目标地址，不返回原始字节。用于不需要恢复的 patch。
        /// </summary>
        public static void WriteBytesProtected(IntPtr addr, byte[] bytes)
        {
            Memory.ProtectWritable(addr, bytes.Length);
            Marshal.Copy(bytes, 0, addr, bytes.Length);
            Memory.ProtectExecutable(addr, bytes.Length);
        }

        /// <summary>
        /// 恢复目标地址的原始字节。等价于 WriteBytesProtected，语义上表示恢复。
        /// </summary>
        public static void RestoreBytes(IntPtr addr, byte[] original)
        {
            Memory.ProtectWritable(addr, original.Length);
            Marshal.Copy(original, 0, addr, original.Length);
            Memory.ProtectExecutable(addr, original.Length);
        }

        /// <summary>
        /// 写入指针大小的值到数据单元（如 precode 间接目标 cell 或 MethodDesc slot）。
        /// 使用 ProtectReadWrite（写入后保持可写，不恢复为只读/可执行）。
        /// 代码页 cell 保持 RWX，数据页 cell 变为 RW。
        /// </summary>
        public static void WriteIntPtrCell(IntPtr addr, IntPtr value)
        {
            int size = IntPtr.Size;
            Memory.ProtectReadWrite(addr, size);
            WriteIntPtr(addr, value);
        }

        /// <summary>
        /// 写入 32 位值到数据单元（x86 precode 间接目标 cell）。
        /// 使用 ProtectReadWrite，写入后保持可写。
        /// </summary>
        public static void WriteInt32Cell(IntPtr addr, int value)
        {
            Memory.ProtectReadWrite(addr, 4);
            Marshal.WriteInt32(addr, value);
        }

        /// <summary>
        /// 写入 64 位值到数据单元（x64 precode 间接目标 cell）。
        /// 使用 ProtectReadWrite，写入后保持可写。
        /// </summary>
        public static void WriteInt64Cell(IntPtr addr, long value)
        {
            Memory.ProtectReadWrite(addr, 8);
            Marshal.WriteInt64(addr, value);
        }

        // ===== 安全读取（带边界检查，失败返回默认值） =====

        /// <summary>尝试读取 64 位整数。地址不可读时返回 false。</summary>
        public static bool TryReadInt64(IntPtr addr, out long value)
        {
            if (!Memory.IsReadable(addr, 8))
            {
                value = 0;
                return false;
            }
            try
            {
                value = Marshal.ReadInt64(addr);
                return true;
            }
            catch
            {
                value = 0;
                return false;
            }
        }

        /// <summary>尝试读取指针大小值。地址不可读时返回 false。</summary>
        public static bool TryReadIntPtr(IntPtr addr, out IntPtr value)
        {
            int size = IntPtr.Size;
            if (!Memory.IsReadable(addr, size))
            {
                value = IntPtr.Zero;
                return false;
            }
            try
            {
                value = ReadIntPtr(addr);
                return true;
            }
            catch
            {
                value = IntPtr.Zero;
                return false;
            }
        }
    }
}
