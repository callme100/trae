using System;

namespace Crane.MethodHook
{
    /// <summary>
    /// Centralized constants for method hooking operations. Consolidates the magic
    /// numbers, byte patterns, and offsets used across the patching logic to improve
    /// maintainability and reduce the risk of typo-related bugs.
    /// </summary>
    internal static class HookConstants
    {
        // ===== Patch Types =====
        // Replaces the magic _patchType int values (1, 2, 3) with named constants.
        public const int PatchTypeIndirect = 1;    // FF 25 data cell patch
        public const int PatchTypeInstruction = 2;  // E9 relative jump on precode
        public const int PatchTypeAbsolute = 3;     // 12-byte absolute jump on JIT code

        // ===== Re-entrancy =====
        public const int MaxReentrancyCount = 3;

        // ===== Scan Sizes =====
        public const int MethodDescScanSize = 128;
        public const int MethodTableScanSize = 65536;
        public const int GenericDictScanSize = 8192;
        public const int MaxJitCodeReadSize = 32;       // Full prologue copy for trampoline
        public const int MaxMethodDescReadSize = 64;    // Diagnostic dump size

        // ===== x64 Precode Offsets =====
        public const int PrecodeFf25Size = 6;           // FF 25 <disp32>
        public const int PrecodeMovR10Offset = 6;       // 4C 8B 15 <disp32> at offset 6
        public const int PrecodeMovR10Size = 7;         // 4C 8B 15 <disp32> = 7 bytes
        public const int PrecodeSecondFf25Offset = 13;  // FF 25 <disp32> at offset 13
        public const int PrecodeSecondFf25DispOffset = 15; // disp32 of second FF 25
        public const int PrecodeTotalSize = 19;         // Total FixupPrecode size

        // ===== Fixup Thunk Offsets =====
        public const int FixupThunkDictOffset = 5;      // 8-byte dict at offset 5
        public const int FixupThunkJitAddrOffset = 15;  // 8-byte jit_addr at offset 15
        public const int FixupThunkMinSize = 23;        // Minimum readable size for pattern match

        // ===== MethodDesc Flag Bits =====
        // .NET 8+: m_wFlags3AndTokenRemainder at offset 0
        public const ushort Flag3IsEligibleForTieredCompilation = 0x8000;
        public const ushort Flag3HasStableEntryPoint = 0x1000;
        public const ushort Flag3HasPrecode = 0x2000;
        public const ushort Flag3StableMask = Flag3HasStableEntryPoint | Flag3HasPrecode;

        // .NET 6/7: m_bFlags2 at offset 3
        public const byte Flag2IsEligibleForTieredCompilation = 0x20;
        public const byte Flag2HasStableEntryPoint = 0x01;
        public const byte Flag2HasPrecode = 0x02;
        public const byte Flag2StableMask = Flag2HasStableEntryPoint | Flag2HasPrecode;

        // .NET Framework 4.x: m_wFlags at offset 6
        public const ushort NoInliningFlag = 0x2000;
        public const ushort HasStableEntryPointFlag = 0x0008;
        public const int MethodDescFlagsOffset = 6;

        // ===== Byte Patterns =====
        public const byte OpFf = 0xFF;  // Indirect jump prefix
        public const byte Op25 = 0x25;  // ModR/M for [rip+disp32]
        public const byte OpE8 = 0xE8;  // CALL rel32
        public const byte OpE9 = 0xE9;  // JMP rel32
        public const byte OpB8 = 0xB8;  // MOV EAX, imm32 (x86) / MOV RAX, imm64 prefix
        public const byte Op48 = 0x48;  // REX.W prefix
        public const byte Op49 = 0x49;  // REX.WB prefix
        public const byte Op4C = 0x4C;  // REX.WR prefix
        public const byte OpBA = 0xBA;  // MOV RDX, imm64 (Windows) / MOV RSI, imm64 (Unix)
        public const byte OpBE = 0xBE;  // MOV RSI, imm64 (Unix)
        public const byte OpE0 = 0xE0;  // JMP RAX ModR/M
        public const byte Op15 = 0x15;  // MOV R10,[rip+disp32] ModR/M

        // ===== Relative Jump Range =====
        public const long MaxRel32Range = 2147418112;  // ~2GB for E9 rel32

        // ===== Memory Allocation =====
        public const int PageSize = 4096;
        public const int MaxConsecutiveUnreadable = 4096;  // SlotPatcher scan tolerance
    }

    /// <summary>
    /// Enumerates the types of code patches that can be applied to a target method.
    /// Replaces the integer _patchType field for clarity. The integer values are
    /// preserved for backward compatibility with existing logic.
    /// </summary>
    internal enum PatchType
    {
        /// <summary>No patch applied.</summary>
        None = 0,

        /// <summary>FF 25 indirect data cell patch (patchType=1).</summary>
        Indirect = HookConstants.PatchTypeIndirect,

        /// <summary>E9 relative jump instruction patch on precode (patchType=2).</summary>
        Instruction = HookConstants.PatchTypeInstruction,

        /// <summary>12-byte absolute jump on JIT code (patchType=3).</summary>
        Absolute = HookConstants.PatchTypeAbsolute,
    }
}
