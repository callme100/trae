using System;

namespace DynamicHook
{
    internal static class Jumper
    {
        public static byte[] BuildJump(IntPtr fromAddr, IntPtr toAddr)
        {
            return Platform.Current switch
            {
                Platform.Arch.X64 => JumpX64(toAddr),
                Platform.Arch.X86 => JumpX86(fromAddr, toAddr),
                Platform.Arch.ARM64 => JumpARM64(toAddr),
                Platform.Arch.ARM32 => JumpARM32(toAddr),
                _ => JumpX64(toAddr),
            };
        }

        /// <summary>
        /// 构建 x64 12 字节绝对跳转: MOV RAX, imm64; JMP RAX (48 B8 .. FF E0)。
        /// </summary>
        public static byte[] BuildAbsJumpX64(IntPtr target) => JumpX64(target);

        /// <summary>
        /// 构建 x86/x64 5 字节相对跳转: JMP rel32 (E9 ..)。
        /// </summary>
        public static byte[] BuildRelJump(IntPtr from, IntPtr to)
        {
            byte[] array = new byte[5] { 0xE9, 0, 0, 0, 0 };
            BitConverter.GetBytes((int)(to.ToInt64() - (from.ToInt64() + 5))).CopyTo(array, 1);
            return array;
        }

        public static byte[] Install(IntPtr target, IntPtr replacement)
        {
            byte[] array = BuildJump(target, replacement);
            return MemOps.PatchBytes(target, array);
        }

        public static void WriteJump(IntPtr target, IntPtr replacement)
        {
            byte[] array = BuildJump(target, replacement);
            MemOps.WriteBytesProtected(target, array);
        }

        public static void Restore(IntPtr target, byte[] original)
        {
            MemOps.RestoreBytes(target, original);
        }

        private static byte[] JumpX64(IntPtr to)
        {
            byte[] array = new byte[12]
            {
            72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0
            };
            BitConverter.GetBytes(to.ToInt64()).CopyTo(array, 2);
            array[10] = byte.MaxValue;
            array[11] = 224;
            return array;
        }

        private static byte[] JumpX86(IntPtr from, IntPtr to)
        {
            byte[] array = new byte[5] { 233, 0, 0, 0, 0 };
            BitConverter.GetBytes(to.ToInt32() - (from.ToInt32() + 5)).CopyTo(array, 1);
            return array;
        }

        private static byte[] JumpARM64(IntPtr to)
        {
            byte[] array = new byte[16]
            {
            80, 0, 0, 88, 0, 2, 31, 214, 0, 0,
            0, 0, 0, 0, 0, 0
            };
            BitConverter.GetBytes(to.ToInt64()).CopyTo(array, 8);
            return array;
        }

        private static byte[] JumpARM32(IntPtr to)
        {
            byte[] array = new byte[12]
            {
            4, 192, 159, 229, 28, 240, 47, 225, 0, 0,
            0, 0
            };
            BitConverter.GetBytes(to.ToInt32()).CopyTo(array, 8);
            return array;
        }
    }
}
