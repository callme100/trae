using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

[assembly: InternalsVisibleTo("DynamicHook.Tests")]

namespace DynamicHook
{
internal static class Platform
{
	public enum Arch
	{
		X86,
		X64,
		ARM32,
		ARM64,
		Unknown
	}

	private static readonly Lazy<Arch> _current = new Lazy<Arch>(Detect);

	public static Arch Current => _current.Value;

	public static bool Is64Bit => Current == Arch.X64 || Current == Arch.ARM64;

	public static int PatchSize => Current switch
	{
		Arch.X64 => 12, 
		Arch.X86 => 5, 
		Arch.ARM64 => 16, 
		Arch.ARM32 => 12, 
		_ => 12, 
	};

	private static Arch Detect()
	{
		try
		{
			switch (RuntimeInformation.ProcessArchitecture)
			{
			case Architecture.X86:
				return Arch.X86;
			case Architecture.X64:
				return Arch.X64;
			case Architecture.Arm:
				return Arch.ARM32;
			case Architecture.Arm64:
				return Arch.ARM64;
			}
		}
		catch
		{
		}
		return (IntPtr.Size == 8) ? Arch.X64 : Arch.X86;
	}
}
internal static class Memory
{
	private static readonly IntPtr CurrentProcess = new IntPtr(-1);

	private static int PageSize => 4096;

	public static IntPtr AlignToPage(IntPtr addr)
	{
		long num = PageSize;
		return new IntPtr(addr.ToInt64() / num * num);
	}

	public static UIntPtr AlignedSize(IntPtr addr, int size)
	{
		long num = PageSize;
		long num2 = AlignToPage(addr).ToInt64();
		long num3 = addr.ToInt64() + size;
		return (UIntPtr)(ulong)((num3 - num2 + num - 1) / num * num);
	}

	public static void ProtectWritable(IntPtr addr, int size)
	{
		IntPtr addr2 = AlignToPage(addr);
		UIntPtr uIntPtr = AlignedSize(addr, size);
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			VirtualProtect(addr2, uIntPtr, 64u, out var _);
		}
		else
		{
			mprotect(addr2, uIntPtr, 7);
		}
	}

	public static void ProtectExecutable(IntPtr addr, int size)
	{
		IntPtr addr2 = AlignToPage(addr);
		UIntPtr uIntPtr = AlignedSize(addr, size);
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			VirtualProtect(addr2, uIntPtr, 64u, out var _);
			FlushInstructionCache(CurrentProcess, addr, (UIntPtr)(ulong)size);
		}
		else
		{
			mprotect(addr2, uIntPtr, 7);
		}
	}

	public static void ProtectReadWrite(IntPtr addr, int size)
	{
		IntPtr addr2 = AlignToPage(addr);
		UIntPtr uIntPtr = AlignedSize(addr, size);
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			VirtualProtect(addr2, uIntPtr, 64u, out var _);
		}
		else
		{
			mprotect(addr2, uIntPtr, 7);
		}
	}

	public static IntPtr AllocExec(int size)
	{
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)size, 12288u, 64u);
		}
		return mmap(IntPtr.Zero, (UIntPtr)(ulong)size, 7, 34, -1, 0L);
	}

	public static IntPtr AllocExecNear(IntPtr nearAddr, int size)
	{
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			long num = nearAddr.ToInt64();
			long num2 = (size + 4095) & -4096;
			long num3 = num - 2147418112;
			if (num3 < 65536)
			{
				num3 = 65536L;
			}
			long num4 = num + 2147418112;
			for (long num5 = 0L; num5 < 2147418112; num5 += 65536)
			{
				long num6 = num + num5;
				if (num6 >= num3 && num6 + num2 <= num4)
				{
					IntPtr intPtr = VirtualAlloc(new IntPtr(num6), (UIntPtr)(ulong)num2, 12288u, 64u);
					if (intPtr != IntPtr.Zero)
					{
						long num7 = intPtr.ToInt64() - num;
						if (num7 >= -2147483647 && num7 <= int.MaxValue)
						{
							return intPtr;
						}
						VirtualFree(intPtr, UIntPtr.Zero, 32768u);
					}
				}
				if (num5 <= 0)
				{
					continue;
				}
				num6 = num - num5;
				if (num6 < num3 || num6 + num2 > num4)
				{
					continue;
				}
				IntPtr intPtr2 = VirtualAlloc(new IntPtr(num6), (UIntPtr)(ulong)num2, 12288u, 64u);
				if (intPtr2 != IntPtr.Zero)
				{
					long num8 = intPtr2.ToInt64() - num;
					if (num8 >= -2147483647 && num8 <= int.MaxValue)
					{
						return intPtr2;
					}
					VirtualFree(intPtr2, UIntPtr.Zero, 32768u);
				}
			}
			return VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)size, 12288u, 64u);
		}
		long num9 = nearAddr.ToInt64();
		long num10 = 4096L;
		long num11 = (size + 4095) & -4096;
		long num12 = num9 - 2147418112;
		if (num12 < 0)
		{
			num12 = 65536L;
		}
		long num13 = num9 + 2147418112;
		for (long num14 = 0L; num14 < 2147418112; num14 += num10)
		{
			long num15 = num9 + num14;
			if (num15 >= num12 && num15 + num11 <= num13)
			{
				IntPtr intPtr3 = mmap(new IntPtr(num15), (UIntPtr)(ulong)num11, 7, 50, -1, 0L);
				if (intPtr3.ToInt64() != -1 && intPtr3 != IntPtr.Zero)
				{
					long num16 = intPtr3.ToInt64() - num9;
					if (num16 >= -2147483647 && num16 <= int.MaxValue)
					{
						return intPtr3;
					}
					munmap(intPtr3, (UIntPtr)(ulong)num11);
				}
			}
			if (num14 <= 0)
			{
				continue;
			}
			num15 = num9 - num14;
			if (num15 < num12 || num15 + num11 > num13)
			{
				continue;
			}
			IntPtr intPtr4 = mmap(new IntPtr(num15), (UIntPtr)(ulong)num11, 7, 50, -1, 0L);
			if (intPtr4.ToInt64() != -1 && intPtr4 != IntPtr.Zero)
			{
				long num17 = intPtr4.ToInt64() - num9;
				if (num17 >= -2147483647 && num17 <= int.MaxValue)
				{
					return intPtr4;
				}
				munmap(intPtr4, (UIntPtr)(ulong)num11);
			}
		}
		return AllocExec(size);
	}

	public static void FreeExec(IntPtr ptr, int size)
	{
		if (!(ptr == IntPtr.Zero))
		{
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			{
				VirtualFree(ptr, UIntPtr.Zero, 32768u);
			}
			else
			{
				munmap(ptr, (UIntPtr)(ulong)size);
			}
		}
	}

	[DllImport("kernel32.dll")]
	private static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint prot, out uint old);

	[DllImport("kernel32.dll")]
	private static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint prot);

	[DllImport("kernel32.dll")]
	private static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint type);

	[DllImport("kernel32.dll")]
	private static extern void FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

	[DllImport("libc", SetLastError = true)]
	private static extern int mprotect(IntPtr addr, UIntPtr len, int prot);

	[DllImport("libc", SetLastError = true)]
	private static extern IntPtr mmap(IntPtr addr, UIntPtr len, int prot, int flags, int fd, long off);

	[DllImport("libc", SetLastError = true)]
	private static extern int munmap(IntPtr addr, UIntPtr len);
}
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

	public static byte[] Install(IntPtr target, IntPtr replacement)
	{
		byte[] array = BuildJump(target, replacement);
		byte[] array2 = new byte[array.Length];
		Marshal.Copy(target, array2, 0, array.Length);
		Memory.ProtectWritable(target, array.Length);
		Marshal.Copy(array, 0, target, array.Length);
		Memory.ProtectExecutable(target, array.Length);
		return array2;
	}

	public static void WriteJump(IntPtr target, IntPtr replacement)
	{
		byte[] array = BuildJump(target, replacement);
		Memory.ProtectWritable(target, array.Length);
		Marshal.Copy(array, 0, target, array.Length);
		Memory.ProtectExecutable(target, array.Length);
	}

	public static void Restore(IntPtr target, byte[] original)
	{
		Memory.ProtectWritable(target, original.Length);
		Marshal.Copy(original, 0, target, original.Length);
		Memory.ProtectExecutable(target, original.Length);
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
internal static class MethodEntryResolver
{
	public static IntPtr ResolveRealEntry(IntPtr ptr)
	{
		if (ptr == IntPtr.Zero)
		{
			return IntPtr.Zero;
		}
		Platform.Arch current = Platform.Current;
		IntPtr intPtr = ptr;
		for (int i = 0; i < 10; i++)
		{
			IntPtr intPtr2;
			try
			{
				switch (current)
				{
				case Platform.Arch.X64:
					intPtr2 = ResolveOneX64(intPtr);
					break;
				case Platform.Arch.X86:
					intPtr2 = ResolveOneX86(intPtr);
					break;
				default:
					return intPtr;
				}
			}
			catch
			{
				return intPtr;
			}
			if (intPtr2 == intPtr || intPtr2 == IntPtr.Zero)
			{
				return intPtr;
			}
			intPtr = intPtr2;
		}
		return intPtr;
	}

	public static bool IsJump(IntPtr ptr)
	{
		if (ptr == IntPtr.Zero)
		{
			return false;
		}
		try
		{
			return Platform.Current switch
			{
				Platform.Arch.X64 => IsJumpX64(ptr), 
				Platform.Arch.X86 => IsJumpX86(ptr), 
				_ => false, 
			};
		}
		catch
		{
			return false;
		}
	}

	private unsafe static bool IsJumpX64(IntPtr ptr)
	{
		byte* ptr2 = (byte*)(void*)ptr;
		byte b = *ptr2;
		byte b2 = ptr2[1];
		if (b == byte.MaxValue && b2 == 37)
		{
			return true;
		}
		switch (b)
		{
		case 233:
			return true;
		case 72:
			if (b2 == 184 && ptr2[10] == byte.MaxValue && ptr2[11] == 224)
			{
				return true;
			}
			break;
		}
		switch (b)
		{
		case 232:
			return true;
		case 76:
			if (b2 == 141)
			{
				return true;
			}
			break;
		}
		if (b == 76 && b2 == 139 && ptr2[2] == 21)
		{
			return true;
		}
		if (b == 76 && b2 == 139 && ptr2[2] == 208)
		{
			return true;
		}
		if (b == 72 && b2 == 137 && ptr2[2] == 242)
		{
			return true;
		}
		return false;
	}

	private unsafe static bool IsJumpX86(IntPtr ptr)
	{
		byte* ptr2 = (byte*)(void*)ptr;
		byte b = *ptr2;
		byte b2 = ptr2[1];
		if (b == byte.MaxValue && b2 == 37)
		{
			return true;
		}
		return b switch
		{
			233 => true, 
			232 => true, 
			_ => false, 
		};
	}

	private unsafe static IntPtr ResolveOneX64(IntPtr ptr)
	{
		byte* ptr2 = (byte*)(void*)ptr;
		byte b = *ptr2;
		byte b2 = ptr2[1];
		if (b == byte.MaxValue && b2 == 37)
		{
			int num = *(int*)(ptr2 + 2);
			long num2 = ptr.ToInt64() + 6 + num;
			long value = *(long*)num2;
			return new IntPtr(value);
		}
		switch (b)
		{
		case 233:
		{
			int num3 = *(int*)(ptr2 + 1);
			return new IntPtr(ptr.ToInt64() + 5 + num3);
		}
		case 72:
			if (b2 == 184 && ptr2[10] == byte.MaxValue && ptr2[11] == 224)
			{
				long value2 = *(long*)(ptr2 + 2);
				return new IntPtr(value2);
			}
			break;
		}
		if (b == 76 && b2 == 141)
		{
			byte* ptr3 = ptr2 + 7;
			if (*ptr3 == byte.MaxValue && ptr3[1] == 37)
			{
				int num4 = *(int*)(ptr3 + 2);
				long num5 = (long)ptr3 + 6L + num4;
				long value3 = *(long*)num5;
				return new IntPtr(value3);
			}
		}
		if (b == 232 && ptr2[5] == 94)
		{
			return ptr;
		}
		if (b == 76 && b2 == 139 && ptr2[2] == 21)
		{
			byte* ptr4 = ptr2 + 7;
			if (*ptr4 == byte.MaxValue && ptr4[1] == 37)
			{
				int num6 = *(int*)(ptr4 + 2);
				long num7 = (long)ptr4 + 6L + num6;
				long value4 = *(long*)num7;
				return new IntPtr(value4);
			}
		}
		for (int i = 0; i <= 24; i++)
		{
			if (ptr2[i] == 72 && ptr2[i + 1] == 184 && i + 11 < 64 && ptr2[i + 10] == byte.MaxValue && ptr2[i + 11] == 224)
			{
				long value5 = *(long*)(ptr2 + i + 2);
				return new IntPtr(value5);
			}
		}
		return ptr;
	}

	private unsafe static IntPtr ResolveOneX86(IntPtr ptr)
	{
		byte* ptr2 = (byte*)(void*)ptr;
		byte b = *ptr2;
		byte b2 = ptr2[1];
		if (b == byte.MaxValue && b2 == 37)
		{
			int num = *(int*)(ptr2 + 2);
			int value = *(int*)num;
			return new IntPtr(value);
		}
		if (b == 233)
		{
			int num2 = *(int*)(ptr2 + 1);
			return new IntPtr(ptr.ToInt32() + 5 + num2);
		}
		return ptr;
	}
}
internal static class SlotPatcher
{
	public static List<IntPtr> FindSlots(IntPtr methodDesc, IntPtr methodTable, IntPtr value)
	{
		List<IntPtr> list = new List<IntPtr>();
		int size = IntPtr.Size;
		long num = value.ToInt64();
		long num2 = MethodEntryResolver.ResolveRealEntry(value).ToInt64();
		if (methodDesc != IntPtr.Zero)
		{
			for (int i = 0; i < 128; i += size)
			{
				try
				{
					long num3 = ReadPointer(methodDesc + i);
					if (num3 == num || num3 == num2)
					{
						list.Add(methodDesc + i);
					}
				}
				catch
				{
					break;
				}
			}
		}
		if (methodTable != IntPtr.Zero)
		{
			for (int j = 0; j < 16384; j += size)
			{
				try
				{
					long num4 = ReadPointer(methodTable + j);
					if (num4 == num || num4 == num2)
					{
						list.Add(methodTable + j);
					}
				}
				catch
				{
					break;
				}
			}
		}
		return list;
	}

	public static void ReplaceSlot(IntPtr slot, IntPtr newValue)
	{
		int size = IntPtr.Size;
		Memory.ProtectReadWrite(slot, size);
		WritePointer(slot, newValue.ToInt64());
	}

	private static long ReadPointer(IntPtr addr)
	{
		if (IntPtr.Size == 8)
		{
			return Marshal.ReadInt64(addr);
		}
		return Marshal.ReadInt32(addr);
	}

	private static void WritePointer(IntPtr addr, long value)
	{
		if (IntPtr.Size == 8)
		{
			Marshal.WriteInt64(addr, value);
		}
		else
		{
			Marshal.WriteInt32(addr, (int)value);
		}
	}
}
internal static class GenericAdapter
{
	public static IntPtr Create(IntPtr hookEntry, MethodBase targetMethod, IntPtr nearAddr)
	{
		Platform.Arch current = Platform.Current;
		if (current != Platform.Arch.X64)
		{
			return hookEntry;
		}
		bool isStatic = targetMethod.IsStatic;
		int userParamCount = targetMethod.GetParameters().Length;
		bool flag = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
		List<byte> list = new List<byte>();
		if (flag)
		{
			BuildSystemVAdapter(list, isStatic, userParamCount);
		}
		else
		{
			BuildWindowsX64Adapter(list, isStatic, userParamCount);
		}
		list.Add(72);
		list.Add(184);
		list.AddRange(BitConverter.GetBytes(hookEntry.ToInt64()));
		list.Add(byte.MaxValue);
		list.Add(224);
		IntPtr intPtr = Memory.AllocExecNear(nearAddr, list.Count);
		if (intPtr == IntPtr.Zero || intPtr == new IntPtr(-1))
		{
			return IntPtr.Zero;
		}
		Marshal.Copy(list.ToArray(), 0, intPtr, list.Count);
		Memory.ProtectExecutable(intPtr, list.Count);
		return intPtr;
	}

	private static void BuildWindowsX64Adapter(List<byte> code, bool isStatic, int userParamCount)
	{
		int num = ((!isStatic) ? 1 : 0);
		int num2 = (isStatic ? 1 : 2) + userParamCount;
		int num3 = Math.Min(num2 - 2, 3);
		for (int i = num; i <= num3; i++)
		{
			int num4 = i + 1;
			if (num4 < 4)
			{
				EmitMovRegReg(code, i, num4);
				continue;
			}
			int offset = 32 + (num4 - 3) * 8;
			EmitMovRegFromStack(code, i, offset);
		}
		if (num2 > 4)
		{
			int num5 = num2 - 5;
			for (int j = 0; j < num5; j++)
			{
				int value = 40 + j * 8;
				int value2 = 48 + j * 8;
				code.Add(72);
				code.Add(139);
				code.Add(132);
				code.Add(36);
				code.AddRange(BitConverter.GetBytes(value2));
				code.Add(72);
				code.Add(137);
				code.Add(132);
				code.Add(36);
				code.AddRange(BitConverter.GetBytes(value));
			}
		}
		int num6 = Math.Min(num2 - 1, 4);
		for (int num7 = Math.Min(3, num6 - 1); num7 >= 0; num7--)
		{
			int offset2 = 8 + num7 * 8;
			EmitMovShadowFromReg(code, num7, offset2);
		}
	}

	private static void EmitMovRegReg(List<byte> code, int dst, int src)
	{
		byte b = 72;
		if (src >= 2)
		{
			b |= 0x44;
		}
		if (dst >= 2)
		{
			b |= 1;
		}
		code.Add(b);
		code.Add(137);
		int num = src & 3;
		int num2 = dst & 3;
		code.Add((byte)(0xC0 | (num << 3) | num2));
	}

	private static void EmitMovRegFromStack(List<byte> code, int reg, int offset)
	{
		byte b = 72;
		if (reg >= 2)
		{
			b |= 1;
		}
		code.Add(b);
		code.Add(139);
		int num = reg & 3;
		code.Add((byte)(4 | (num << 3)));
		code.Add(36);
		code.Add((byte)offset);
	}

	private static void EmitMovShadowFromReg(List<byte> code, int reg, int offset)
	{
		byte b = 72;
		if (reg >= 2)
		{
			b |= 0x44;
		}
		code.Add(b);
		code.Add(137);
		int num = reg & 3;
		code.Add((byte)(0x44 | (num << 3)));
		code.Add(36);
		code.Add((byte)offset);
	}

	private static void BuildSystemVAdapter(List<byte> code, bool isStatic, int userParamCount)
	{
		int num = ((!isStatic) ? 1 : 0);
		int num2 = (isStatic ? 1 : 2) + userParamCount;
		int num3 = Math.Min(num2 - 2, 5);
		for (int i = num; i <= num3; i++)
		{
			int num4 = i + 1;
			if (num4 < 6)
			{
				EmitMovRegRegSystemV(code, i, num4);
				continue;
			}
			int offset = (num4 - 6) * 8;
			EmitMovRegFromStackSystemV(code, i, offset);
		}
		if (num2 > 6)
		{
			int num5 = num2 - 7;
			for (int j = 0; j < num5; j++)
			{
				int value = j * 8;
				int value2 = (j + 1) * 8;
				code.Add(72);
				code.Add(139);
				code.Add(132);
				code.Add(36);
				code.AddRange(BitConverter.GetBytes(value2));
				code.Add(72);
				code.Add(137);
				code.Add(132);
				code.Add(36);
				code.AddRange(BitConverter.GetBytes(value));
			}
		}
	}

	private static void EmitMovRegRegSystemV(List<byte> code, int dst, int src)
	{
		byte b = 72;
		if (src >= 4)
		{
			b |= 0x44;
		}
		if (dst >= 4)
		{
			b |= 1;
		}
		code.Add(b);
		code.Add(137);
		int num = src & 3;
		int num2 = dst & 3;
		code.Add((byte)(0xC0 | (num << 3) | num2));
	}

	private static void EmitMovRegFromStackSystemV(List<byte> code, int reg, int offset)
	{
		byte b = 72;
		if (reg >= 4)
		{
			b |= 1;
		}
		code.Add(b);
		code.Add(139);
		int num = reg & 3;
		code.Add((byte)(4 | (num << 3)));
		code.Add(36);
		code.Add((byte)offset);
	}
}
public sealed class MethodHook : IDisposable
{
	private class OverridePatch
	{
		public IntPtr Entry;

		public byte[] OriginalBytes;

		public List<IntPtr> Slots;
	}

	private readonly MethodBase _targetMethod;

	private readonly MethodBase _hookMethod;

	private List<IntPtr> _slotAddresses;

	private IntPtr _originalSlotValue;

	private IntPtr _newSlotValue;

	private int _patchType;

	private IntPtr _patchAddress;

	private byte[] _originalBytes;

	private IntPtr _indirectTargetLoc;

	private IntPtr _originalIndirectTarget;

	private IntPtr _nearTrampoline;

	private bool _hasSecondaryPatch;

	private IntPtr _secondaryJitAddress;

	private byte[] _secondaryJitOriginalBytes;

	private IntPtr _secondaryTrampoline;

	private IntPtr _genericAdapter;

	private bool _needsGenericAdapter;

	private Delegate _originalCallDelegate;

	private IntPtr _originalCallStub;

	private Delegate _originalCallStubDelegate;

	private Func<object[], object> _originalCallWrapper;

	private List<OverridePatch> _overridePatches;

	private bool _isInstalled;

	private bool _isDisposed;

	public bool IsInstalled => _isInstalled;

	public HookDiagInfo DiagInfo { get; private set; }

	public MethodHook(MethodBase targetMethod, MethodBase hookMethod)
	{
		_targetMethod = targetMethod ?? throw new ArgumentNullException("targetMethod");
		_hookMethod = hookMethod ?? throw new ArgumentNullException("hookMethod");
	}

	public void Install()
	{
		if (_isInstalled)
		{
			return;
		}
		if (_isDisposed)
		{
			throw new ObjectDisposedException("MethodHook");
		}
		HookDiagInfo hookDiagInfo = new HookDiagInfo();
		hookDiagInfo.TargetMethod = _targetMethod.ToString();
		hookDiagInfo.HookMethod = _hookMethod.ToString();
		PrepareMethod(_targetMethod);
		PrepareMethod(_hookMethod);
		IntPtr functionPointer = _targetMethod.MethodHandle.GetFunctionPointer();
		IntPtr functionPointer2 = _hookMethod.MethodHandle.GetFunctionPointer();
		hookDiagInfo.PrecodeAddr = functionPointer;
		hookDiagInfo.PrecodeBytes = ReadBytesSafe(functionPointer, 32);
		_originalSlotValue = functionPointer;
		if (_targetMethod is MethodInfo { IsGenericMethod: not false } methodInfo)
		{
			(Delegate del, string error) tuple = TryCreateOriginalDelegate(methodInfo);
			Delegate item = tuple.del;
			string item2 = tuple.error;
			_originalCallDelegate = item;
			hookDiagInfo.DelegateStatus = (((object)item != null) ? ("Expr (" + item.GetType().Name + ")") : ("Failed: " + item2));
			// Also create a native stub that explicitly loads R10 (generic dictionary)
			// before jumping to the JIT code. This is needed for CallOriginal because
			// mi.Invoke() and Expression-compiled delegates may bypass the precode's
			// MOV R10 instruction, causing the JIT code to crash (0x80131506).
			var stub = TryCreateOriginalCallStub(methodInfo, functionPointer);
			_originalCallStubDelegate = stub.del;
			if (stub.del != null)
				hookDiagInfo.DelegateStatus += "; Stub (" + stub.del.GetType().Name + ")";
			else
				hookDiagInfo.DelegateStatus += "; Stub failed: " + stub.error;
		}
		_needsGenericAdapter = _targetMethod.IsGenericMethod;
		hookDiagInfo.NeedsGenericAdapter = _needsGenericAdapter;
		IntPtr intPtr = functionPointer2;
		if (_needsGenericAdapter)
		{
			// CoreCLR: generic dictionary is in R10 (loaded by precode/callsite).
			// User args are already in correct registers (RCX=this, RDX=arg1, ...).
			// The adapter's MOV RCX,R10 would overwrite 'this' with the generic dict.
			// Skip adapter and jump directly to hook.
			_genericAdapter = IntPtr.Zero;
			hookDiagInfo.AdapterAddr = IntPtr.Zero;
			hookDiagInfo.AdapterBytes = null;
		}
		_newSlotValue = intPtr;
		hookDiagInfo.JumpTargetAddr = intPtr;
		InstallSlotReplacement(functionPointer, intPtr, hookDiagInfo);
		InstallCodePatch(functionPointer, intPtr, hookDiagInfo);
		DiagInfo = hookDiagInfo;
		_isInstalled = true;
	}

	private void PrepareMethod(MethodBase method)
	{
		RuntimeHelpers.PrepareMethod(method.MethodHandle);
		if (!method.IsGenericMethod)
		{
			return;
		}
		try
		{
			Type[] genericArguments = method.GetGenericArguments();
			RuntimeTypeHandle[] instantiation = genericArguments.Select((Type t) => t.TypeHandle).ToArray();
			RuntimeHelpers.PrepareMethod(method.MethodHandle, instantiation);
		}
		catch
		{
		}
	}

	private void InstallSlotReplacement(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
	{
		// Skip slot replacement for generic methods to avoid potential MethodTable corruption
		if (_needsGenericAdapter)
		{
			diag.SlotError = "Skipped for generic method";
			_slotAddresses = new List<IntPtr>();
			return;
		}
		try
		{
			IntPtr value = _targetMethod.MethodHandle.Value;
			IntPtr methodTable = IntPtr.Zero;
			Type declaringType = _targetMethod.DeclaringType;
			if (declaringType != null)
			{
				methodTable = declaringType.TypeHandle.Value;
			}
			_slotAddresses = SlotPatcher.FindSlots(value, methodTable, targetPtr);
			diag.SlotCount = _slotAddresses.Count;
			diag.SlotAddresses = (from a in _slotAddresses.Take(10)
				select a.ToInt64()).ToList();
			foreach (IntPtr slotAddress in _slotAddresses)
			{
				SlotPatcher.ReplaceSlot(slotAddress, jumpTarget);
			}
		}
		catch (Exception ex)
		{
			diag.SlotError = ex.Message;
		}
	}

	private void InstallCodePatch(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
	{
		try
		{
			switch (Platform.Current)
			{
			case Platform.Arch.X64:
				InstallCodePatchX64(targetPtr, jumpTarget, diag);
				return;
			case Platform.Arch.X86:
				InstallCodePatchX86(targetPtr, jumpTarget, diag);
				return;
			}
			_patchType = 3;
			_patchAddress = targetPtr;
			_originalBytes = Jumper.Install(targetPtr, jumpTarget);
			diag.InstalledBytes = ReadBytesSafe(targetPtr, _originalBytes.Length);
		}
		catch (Exception ex)
		{
			diag.PatchError = ex.Message;
		}
	}

	private unsafe void InstallCodePatchX64(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
	{
		byte* ptr = (byte*)(void*)targetPtr;
		byte b = *ptr;
		byte b2 = ptr[1];
		if (b == byte.MaxValue && b2 == 37)
		{
			bool flag = ptr[6] == 76 && ptr[7] == 139 && ptr[8] == 21 && ptr[13] == byte.MaxValue && ptr[14] == 37;
			// Read first FF 25's indirect target for diagnostics
			int disp1 = *(int*)(ptr + 2);
			long target1Loc = targetPtr.ToInt64() + 6 + disp1;
			diag.PrecodeFirstTargetAddr = new IntPtr(*(long*)target1Loc);
			if (flag)
			{
				int disp2 = *(int*)(ptr + 15);
				long target2Loc = targetPtr.ToInt64() + 19 + disp2;
				diag.PrecodeSecondTargetAddr = new IntPtr(*(long*)target2Loc);
			}
			// Patch the SECOND FF 25's indirect target (for FixupPrecode).
			// The first FF 25 is the one actually executed, but patching it can cause
			// issues with CallOriginal re-entrancy. The secondary JIT patch handles
			// interception for direct JIT calls.
			int num = (flag ? 13 : 0);
			byte* ptr2 = ptr + num;
			int num2 = *(int*)(ptr2 + 2);
			long num3 = targetPtr.ToInt64() + num + 6 + num2;
			_patchType = 1;
			_patchAddress = targetPtr;
			_indirectTargetLoc = new IntPtr(num3);
			_originalIndirectTarget = new IntPtr(*(long*)num3);
			Memory.ProtectReadWrite(_indirectTargetLoc, 8);
			*(long*)num3 = jumpTarget.ToInt64();
			diag.PatchType = (flag ? "Indirect(FF 25 2nd, FixupPrecode)" : "Indirect(FF 25)");
			diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
			if (flag)
			{
				InstallSecondaryJitPatch(targetPtr, jumpTarget, diag);
			}
		}
		else if (b == 232 || b == 233)
		{
			_nearTrampoline = Memory.AllocExecNear(targetPtr, 12);
			if (_nearTrampoline == IntPtr.Zero || _nearTrampoline == new IntPtr(-1))
			{
				diag.PatchError = "Failed to allocate near trampoline for E8/E9 patch";
				return;
			}
			byte[] array = new byte[12]
			{
				72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0
			};
			BitConverter.GetBytes(jumpTarget.ToInt64()).CopyTo(array, 2);
			array[10] = byte.MaxValue;
			array[11] = 224;
			Marshal.Copy(array, 0, _nearTrampoline, 12);
			Memory.ProtectExecutable(_nearTrampoline, 12);
			_patchType = 2;
			_patchAddress = targetPtr;
			_originalBytes = new byte[6];
			Marshal.Copy(targetPtr, _originalBytes, 0, 6);
			int value = (int)(_nearTrampoline.ToInt64() - (targetPtr.ToInt64() + 5));
			byte[] array2 = new byte[5] { 233, 0, 0, 0, 0 };
			BitConverter.GetBytes(value).CopyTo(array2, 1);
			Memory.ProtectWritable(targetPtr, 5);
			Marshal.Copy(array2, 0, targetPtr, 5);
			Memory.ProtectExecutable(targetPtr, 5);
			diag.PatchType = ((b == 232) ? "FixupPrecode(E8->E9)" : "DirectJump(E9)");
			diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
		}
		else if (!MethodEntryResolver.IsJump(targetPtr))
		{
			_patchType = 3;
			_patchAddress = targetPtr;
			_originalBytes = Jumper.Install(targetPtr, jumpTarget);
			diag.PatchType = "JitCode(12-byte)";
			diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
		}
		else
		{
			IntPtr intPtr = MethodEntryResolver.ResolveRealEntry(targetPtr);
			if (intPtr != IntPtr.Zero && intPtr != targetPtr && !MethodEntryResolver.IsJump(intPtr))
			{
				_patchType = 3;
				_patchAddress = intPtr;
				_originalBytes = Jumper.Install(intPtr, jumpTarget);
				diag.PatchType = "ResolvedJitCode(12-byte)";
				diag.InstalledBytes = ReadBytesSafe(intPtr, 16);
			}
			else
			{
				diag.PatchType = "None(relies on slot replacement)";
			}
		}
	}

	private void InstallSecondaryJitPatch(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
	{
		try
		{
			IntPtr intPtr = MethodEntryResolver.ResolveRealEntry(targetPtr);
			if (intPtr == IntPtr.Zero || intPtr == targetPtr)
			{
				diag.SlotError += "; cannot resolve JIT entry for secondary patch";
				return;
			}
			diag.JitCodeAddr = intPtr;
			diag.JitCodeOriginalBytes = ReadBytesSafe(intPtr, 16);

			// Use a 5-byte relative jump (E9) with a near trampoline instead of a 12-byte
			// absolute jump. This overwrites only 5 bytes of the prologue, minimizing GC
			// info corruption. The trampoline is allocated within 2GB of the patch site.
			IntPtr trampoline = Memory.AllocExecNear(intPtr, 12);
			if (trampoline == IntPtr.Zero || trampoline == new IntPtr(-1))
			{
				diag.SlotError += "; failed to allocate near trampoline for JIT patch";
				return;
			}
			// Trampoline: MOV RAX, jumpTarget; JMP RAX (12 bytes)
			byte[] trampBytes = new byte[12]
			{
				72, 184, 0, 0, 0, 0, 0, 0, 0, 0,
				byte.MaxValue, 224
			};
			BitConverter.GetBytes(jumpTarget.ToInt64()).CopyTo(trampBytes, 2);
			Marshal.Copy(trampBytes, 0, trampoline, 12);
			Memory.ProtectExecutable(trampoline, 12);

			// Patch JIT code with 5-byte relative jump to trampoline
			_secondaryJitAddress = intPtr;
			int patchSize = 5;
			_secondaryJitOriginalBytes = new byte[patchSize];
			Marshal.Copy(intPtr, _secondaryJitOriginalBytes, 0, patchSize);
			int rel32 = (int)(trampoline.ToInt64() - (intPtr.ToInt64() + 5));
			byte[] patch = new byte[5] { 233, 0, 0, 0, 0 };
			BitConverter.GetBytes(rel32).CopyTo(patch, 1);
			Memory.ProtectWritable(intPtr, 5);
			Marshal.Copy(patch, 0, intPtr, 5);
			Memory.ProtectExecutable(intPtr, 5);
			_hasSecondaryPatch = true;
			_secondaryTrampoline = trampoline;
			diag.JitCodePatchedBytes = ReadBytesSafe(intPtr, 16);
			diag.SlotError += $"; SecondaryJitPatch(5-byte) at 0x{intPtr.ToInt64():X} -> tramp 0x{trampoline.ToInt64():X}";
		}
		catch (Exception ex)
		{
			diag.SlotError = diag.SlotError + "; SecondaryJitPatch error: " + ex.Message;
		}
	}

	private static string BytesToHex(byte[] bytes)
	{
		if (bytes == null)
		{
			return "null";
		}
		StringBuilder stringBuilder = new StringBuilder(bytes.Length * 3);
		foreach (byte b in bytes)
		{
			stringBuilder.Append(b.ToString("X2")).Append(" ");
		}
		return stringBuilder.ToString().TrimEnd(Array.Empty<char>());
	}

	private unsafe void InstallCodePatchX86(IntPtr targetPtr, IntPtr jumpTarget, HookDiagInfo diag)
	{
		byte* ptr = (byte*)(void*)targetPtr;
		byte b = *ptr;
		byte b2 = ptr[1];
		if (b == byte.MaxValue && b2 == 37)
		{
			int num = *(int*)(ptr + 2);
			_patchType = 1;
			_patchAddress = targetPtr;
			_indirectTargetLoc = new IntPtr(num);
			_originalIndirectTarget = new IntPtr(*(int*)num);
			Memory.ProtectReadWrite(_indirectTargetLoc, 4);
			*(int*)num = jumpTarget.ToInt32();
			diag.PatchType = "Indirect(FF 25) x86";
			diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
			if (_needsGenericAdapter)
			{
				InstallSecondaryJitPatch(targetPtr, jumpTarget, diag);
			}
		}
		else if (b == 232 || b == 233)
		{
			_patchType = 2;
			_patchAddress = targetPtr;
			_originalBytes = new byte[5];
			Marshal.Copy(targetPtr, _originalBytes, 0, 5);
			byte[] array = Jumper.BuildJump(targetPtr, jumpTarget);
			Memory.ProtectWritable(targetPtr, array.Length);
			Marshal.Copy(array, 0, targetPtr, array.Length);
			Memory.ProtectExecutable(targetPtr, array.Length);
			diag.PatchType = ((b == 232) ? "FixupPrecode(E8->E9) x86" : "DirectJump(E9) x86");
			diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
		}
		else if (!MethodEntryResolver.IsJump(targetPtr))
		{
			_patchType = 3;
			_patchAddress = targetPtr;
			_originalBytes = Jumper.Install(targetPtr, jumpTarget);
			diag.PatchType = "JitCode(5-byte) x86";
			diag.InstalledBytes = ReadBytesSafe(targetPtr, 16);
		}
		else
		{
			IntPtr intPtr = MethodEntryResolver.ResolveRealEntry(targetPtr);
			if (intPtr != IntPtr.Zero && intPtr != targetPtr && !MethodEntryResolver.IsJump(intPtr))
			{
				_patchType = 3;
				_patchAddress = intPtr;
				_originalBytes = Jumper.Install(intPtr, jumpTarget);
				diag.PatchType = "ResolvedJitCode(5-byte) x86";
				diag.InstalledBytes = ReadBytesSafe(intPtr, 16);
			}
			else
			{
				diag.PatchType = "None(relies on slot replacement) x86";
			}
		}
	}

	public object CallOriginal(object instance, params object[] args)
	{
		if (!_isInstalled)
		{
			throw new InvalidOperationException("Hook is not installed");
		}
		MethodInfo methodInfo = _targetMethod as MethodInfo;
		if (methodInfo == null)
		{
			throw new NotSupportedException("Cannot call original for constructor or void method");
		}
		RestoreAll();
		try
		{
			// For generic methods, mi.Invoke() and Expression-compiled delegates crash
			// with 0x80131506 because the call bypasses the precode's MOV R10 (generic
			// dictionary setup), causing the JIT code to dereference garbage R10.
			// The native stub (TryCreateOriginalCallStub) explicitly loads R10 with the
			// generic dictionary before jumping to the restored JIT code.
			if (methodInfo.IsGenericMethod && _originalCallStubDelegate != null)
			{
				object[] stubArgs;
				if (methodInfo.IsStatic)
					stubArgs = args;
				else
				{
					stubArgs = new object[args.Length + 1];
					stubArgs[0] = instance;
					Array.Copy(args, 0, stubArgs, 1, args.Length);
				}
				return _originalCallStubDelegate.DynamicInvoke(stubArgs);
			}
			if (methodInfo.IsStatic)
			{
				return methodInfo.Invoke(null, args);
			}
			return methodInfo.Invoke(instance, args);
		}
		finally
		{
			ReapplyAll();
		}
	}

	private unsafe (Delegate del, string error) TryCreateOriginalCallStub(MethodInfo mi, IntPtr precodeAddr)
	{
		try
		{
			if (Platform.Current != Platform.Arch.X64)
			{
				return (del: null, error: $"Arch {Platform.Current} not supported for native stub");
			}
			long value = 0L;
			bool flag = false;
			byte* ptr = (byte*)(void*)precodeAddr;
			if (ptr[6] == 76 && ptr[7] == 139 && ptr[8] == 21)
			{
				int num = *(int*)(ptr + 9);
				long num2 = precodeAddr.ToInt64() + 13 + num;
				value = *(long*)num2;
				flag = true;
			}
			else if (ptr[6] == 76 && ptr[7] == 141 && ptr[8] == 21)
			{
				int num3 = *(int*)(ptr + 9);
				value = precodeAddr.ToInt64() + 13 + num3;
				flag = true;
			}
			if (!flag)
			{
				return (del: null, error: "Cannot decode r10 from precode");
			}
			IntPtr intPtr = IntPtr.Zero;
			byte* ptr2 = (byte*)(void*)precodeAddr;
			if (ptr2[13] == byte.MaxValue && ptr2[14] == 37)
			{
				int num4 = *(int*)(ptr2 + 15);
				long num5 = precodeAddr.ToInt64() + 13 + 6 + num4;
				intPtr = new IntPtr(*(long*)num5);
			}
			if (intPtr == IntPtr.Zero)
			{
				intPtr = MethodEntryResolver.ResolveRealEntry(precodeAddr);
			}
			if (intPtr == IntPtr.Zero || intPtr == precodeAddr)
			{
				return (del: null, error: "Cannot resolve JIT entry");
			}
			byte[] array = new byte[22]
			{
				73, 186, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0
			};
			BitConverter.GetBytes(value).CopyTo(array, 2);
			array[10] = 72;
			array[11] = 184;
			BitConverter.GetBytes(intPtr.ToInt64()).CopyTo(array, 12);
			array[20] = byte.MaxValue;
			array[21] = 224;
			_originalCallStub = Memory.AllocExec(array.Length);
			if (_originalCallStub == IntPtr.Zero)
			{
				return (del: null, error: "Failed to allocate stub memory");
			}
			Marshal.Copy(array, 0, _originalCallStub, array.Length);
			Memory.ProtectExecutable(_originalCallStub, array.Length);
			ParameterInfo[] parameters = mi.GetParameters();
			int num6 = ((!mi.IsStatic) ? 1 : 0);
			Type[] array2 = new Type[parameters.Length + num6 + 1];
			if (!mi.IsStatic)
			{
				array2[0] = mi.DeclaringType;
			}
			for (int i = 0; i < parameters.Length; i++)
			{
				array2[i + num6] = parameters[i].ParameterType;
			}
			array2[array2.Length - 1] = mi.ReturnType;
			Type funcType = Expression.GetFuncType(array2);
			Delegate delegateForFunctionPointer = Marshal.GetDelegateForFunctionPointer(_originalCallStub, funcType);
			return (del: delegateForFunctionPointer, error: null);
		}
		catch (Exception ex)
		{
			return (del: null, error: ex.GetType().Name + ": " + ex.Message);
		}
	}

	private static Func<object[], object> CreateDelegateWrapper(Delegate del, MethodInfo mi)
	{
		try
		{
			ParameterExpression parameterExpression = Expression.Parameter(typeof(object[]), "args");
			Type type = del.GetType();
			MethodInfo method = type.GetMethod("Invoke");
			ParameterInfo[] parameters = method.GetParameters();
			Expression[] array = new Expression[parameters.Length];
			for (int i = 0; i < parameters.Length; i++)
			{
				array[i] = Expression.Convert(Expression.ArrayAccess(parameterExpression, Expression.Constant(i)), parameters[i].ParameterType);
			}
			InvocationExpression invocationExpression = Expression.Invoke(Expression.Constant(del, type), array);
			Expression body = ((!(mi.ReturnType == typeof(void))) ? ((Expression)Expression.Convert(invocationExpression, typeof(object))) : ((Expression)Expression.Block(invocationExpression, Expression.Constant(null, typeof(object)))));
			return Expression.Lambda<Func<object[], object>>(body, new ParameterExpression[1] { parameterExpression }).Compile();
		}
		catch
		{
			return null;
		}
	}

	private static (Delegate del, string error) TryCreateOriginalDelegate(MethodInfo mi)
	{
		try
		{
			ParameterInfo[] parameters = mi.GetParameters();
			int num = ((!mi.IsStatic) ? 1 : 0);
			ParameterExpression[] array = new ParameterExpression[parameters.Length + num];
			Expression[] array2 = new Expression[parameters.Length];
			if (!mi.IsStatic)
			{
				array[0] = Expression.Parameter(mi.DeclaringType, "this");
			}
			for (int i = 0; i < parameters.Length; i++)
			{
				array[i + num] = Expression.Parameter(parameters[i].ParameterType, $"arg{i}");
				array2[i] = array[i + num];
			}
			Expression body = ((!mi.IsStatic) ? Expression.Call(array[0], mi, array2) : Expression.Call(mi, array2));
			Type[] array3 = array.Select((ParameterExpression p) => p.Type).ToArray();
			Type delegateType;
			if (mi.ReturnType == typeof(void))
			{
				delegateType = Expression.GetActionType(array3);
			}
			else
			{
				Type[] array4 = new Type[array3.Length + 1];
				Array.Copy(array3, array4, array3.Length);
				array4[array3.Length] = mi.ReturnType;
				delegateType = Expression.GetFuncType(array4);
			}
			LambdaExpression lambdaExpression = Expression.Lambda(delegateType, body, array);
			return (del: lambdaExpression.Compile(), error: null);
		}
		catch (Exception ex)
		{
			return (del: null, error: "Expression: " + ex.GetType().Name + ": " + ex.Message);
		}
	}

	private static void DebugLog(string msg)
	{
		try
		{
			File.AppendAllText("C:\\trae\\DynamicHook\\calloiginal_debug.log", $"{DateTime.Now:HH:mm:ss.fff} {msg}\n");
		}
		catch
		{
		}
	}

	private object InvokeViaDelegate(MethodInfo mi, object instance, object[] args)
	{
		if ((object)_originalCallDelegate != null)
		{
			object[] array;
			if (mi.IsStatic)
			{
				array = args;
			}
			else
			{
				array = new object[args.Length + 1];
				array[0] = instance;
				Array.Copy(args, 0, array, 1, args.Length);
			}
			return _originalCallDelegate.DynamicInvoke(array);
		}
		var (obj2, text) = TryCreateOriginalDelegate(mi);
		if ((object)obj2 != null)
		{
			_originalCallDelegate = obj2;
			object[] array2;
			if (mi.IsStatic)
			{
				array2 = args;
			}
			else
			{
				array2 = new object[args.Length + 1];
				array2[0] = instance;
				Array.Copy(args, 0, array2, 1, args.Length);
			}
			return obj2.DynamicInvoke(array2);
		}
		throw new InvalidOperationException($"CallOriginal for generic method '{mi}' failed: delegate creation failed. " + "Install error: " + (DiagInfo?.DelegateStatus ?? "unknown") + ". Runtime error: " + text);
	}

	public void Uninstall()
	{
		if (!_isInstalled)
		{
			return;
		}
		RestoreAll();
		if (_nearTrampoline != IntPtr.Zero)
		{
			try
			{
				Memory.FreeExec(_nearTrampoline, 12);
			}
			catch
			{
			}
			_nearTrampoline = IntPtr.Zero;
		}
		if (_secondaryTrampoline != IntPtr.Zero)
		{
			try
			{
				Memory.FreeExec(_secondaryTrampoline, 12);
			}
			catch
			{
			}
			_secondaryTrampoline = IntPtr.Zero;
		}
		if (_genericAdapter != IntPtr.Zero)
		{
			try
			{
				Memory.FreeExec(_genericAdapter, 128);
			}
			catch
			{
			}
			_genericAdapter = IntPtr.Zero;
		}
		if (_originalCallStub != IntPtr.Zero)
		{
			try
			{
				Memory.FreeExec(_originalCallStub, 22);
			}
			catch
			{
			}
			_originalCallStub = IntPtr.Zero;
		}
		_originalCallStubDelegate = null;
		_originalCallWrapper = null;
		_isInstalled = false;
	}

	private void RestoreAll()
	{
		if (_slotAddresses != null)
		{
			foreach (IntPtr slotAddress in _slotAddresses)
			{
				try
				{
					SlotPatcher.ReplaceSlot(slotAddress, _originalSlotValue);
				}
				catch
				{
				}
			}
		}
		RestoreCodePatch();
		if (_overridePatches == null)
		{
			return;
		}
		foreach (OverridePatch overridePatch in _overridePatches)
		{
			try
			{
				Jumper.Restore(overridePatch.Entry, overridePatch.OriginalBytes);
			}
			catch
			{
			}
		}
	}

	private void RestoreCodePatch()
	{
		switch (_patchType)
		{
		case 1:
			if (!(_indirectTargetLoc != IntPtr.Zero))
			{
				break;
			}
			try
			{
				int size = IntPtr.Size;
				Memory.ProtectReadWrite(_indirectTargetLoc, size);
				if (size == 8)
				{
					Marshal.WriteInt64(_indirectTargetLoc, _originalIndirectTarget.ToInt64());
				}
				else
				{
					Marshal.WriteInt32(_indirectTargetLoc, _originalIndirectTarget.ToInt32());
				}
			}
			catch
			{
			}
			break;
		case 2:
			if (_patchAddress != IntPtr.Zero && _originalBytes != null)
			{
				try
				{
					Jumper.Restore(_patchAddress, _originalBytes);
				}
				catch
				{
				}
			}
			break;
		case 3:
			if (_patchAddress != IntPtr.Zero && _originalBytes != null)
			{
				try
				{
					Jumper.Restore(_patchAddress, _originalBytes);
				}
				catch
				{
				}
			}
			break;
		}
		if (_hasSecondaryPatch && _secondaryJitAddress != IntPtr.Zero && _secondaryJitOriginalBytes != null)
		{
			try
			{
				Jumper.Restore(_secondaryJitAddress, _secondaryJitOriginalBytes);
			}
			catch
			{
			}
		}
	}

	private void ReapplyAll()
	{
		if (_slotAddresses != null)
		{
			foreach (IntPtr slotAddress in _slotAddresses)
			{
				try
				{
					SlotPatcher.ReplaceSlot(slotAddress, _newSlotValue);
				}
				catch
				{
				}
			}
		}
		ReapplyCodePatch();
		if (_overridePatches == null)
		{
			return;
		}
		foreach (OverridePatch overridePatch in _overridePatches)
		{
			try
			{
				Jumper.WriteJump(overridePatch.Entry, _newSlotValue);
			}
			catch
			{
			}
		}
	}

	private void ReapplyCodePatch()
	{
		switch (_patchType)
		{
		case 1:
			if (!(_indirectTargetLoc != IntPtr.Zero))
			{
				break;
			}
			try
			{
				int size = IntPtr.Size;
				Memory.ProtectReadWrite(_indirectTargetLoc, size);
				if (size == 8)
				{
					Marshal.WriteInt64(_indirectTargetLoc, _newSlotValue.ToInt64());
				}
				else
				{
					Marshal.WriteInt32(_indirectTargetLoc, _newSlotValue.ToInt32());
				}
			}
			catch
			{
			}
			break;
		case 2:
			if (_patchAddress != IntPtr.Zero && _nearTrampoline != IntPtr.Zero)
			{
				try
				{
					int value = (int)(_nearTrampoline.ToInt64() - (_patchAddress.ToInt64() + 5));
					byte[] array = new byte[5] { 233, 0, 0, 0, 0 };
					BitConverter.GetBytes(value).CopyTo(array, 1);
					Memory.ProtectWritable(_patchAddress, 5);
					Marshal.Copy(array, 0, _patchAddress, 5);
					Memory.ProtectExecutable(_patchAddress, 5);
				}
				catch
				{
				}
			}
			break;
		case 3:
			if (_patchAddress != IntPtr.Zero)
			{
				try
				{
					Jumper.WriteJump(_patchAddress, _newSlotValue);
				}
				catch
				{
				}
			}
			break;
		}
		if (_hasSecondaryPatch && _secondaryJitAddress != IntPtr.Zero && _secondaryTrampoline != IntPtr.Zero)
		{
			try
			{
				int rel = (int)(_secondaryTrampoline.ToInt64() - (_secondaryJitAddress.ToInt64() + 5));
				byte[] patch = new byte[5] { 233, 0, 0, 0, 0 };
				BitConverter.GetBytes(rel).CopyTo(patch, 1);
				Memory.ProtectWritable(_secondaryJitAddress, 5);
				Marshal.Copy(patch, 0, _secondaryJitAddress, 5);
				Memory.ProtectExecutable(_secondaryJitAddress, 5);
			}
			catch
			{
			}
		}
	}

	public void Dispose()
	{
		if (!_isDisposed)
		{
			Uninstall();
			_isDisposed = true;
		}
	}

	private void PatchVirtualOverrides(IntPtr jumpTarget)
	{
		try
		{
			MethodInfo methodInfo = _targetMethod as MethodInfo;
			Type type = methodInfo?.DeclaringType;
			if (type == null)
			{
				return;
			}
			Type[] types = (from p in methodInfo.GetParameters()
				select p.ParameterType).ToArray();
			List<MethodInfo> list = new List<MethodInfo>();
			Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
			foreach (Assembly assembly in assemblies)
			{
				if (assembly.IsDynamic)
				{
					continue;
				}
				Type[] types2;
				try
				{
					types2 = assembly.GetTypes();
				}
				catch
				{
					continue;
				}
				Type[] array = types2;
				foreach (Type type2 in array)
				{
					if (type2 == type || !type.IsAssignableFrom(type2) || !type2.IsClass || type2.IsAbstract)
					{
						continue;
					}
					MethodInfo method;
					try
					{
						method = type2.GetMethod(methodInfo.Name, BindingFlags.Instance | BindingFlags.Public, null, types, null);
					}
					catch
					{
						continue;
					}
					if (method == null || method.DeclaringType == type)
					{
						continue;
					}
					try
					{
						if (method.GetBaseDefinition() == methodInfo)
						{
							list.Add(method);
						}
					}
					catch
					{
					}
				}
			}
			if (list.Count == 0)
			{
				return;
			}
			_overridePatches = new List<OverridePatch>();
			foreach (MethodInfo item in list)
			{
				RuntimeHelpers.PrepareMethod(item.MethodHandle);
				IntPtr functionPointer = item.MethodHandle.GetFunctionPointer();
				IntPtr value = item.MethodHandle.Value;
				IntPtr methodTable = IntPtr.Zero;
				if (item.DeclaringType != null)
				{
					methodTable = item.DeclaringType.TypeHandle.Value;
				}
				List<IntPtr> list2 = SlotPatcher.FindSlots(value, methodTable, functionPointer);
				foreach (IntPtr item2 in list2)
				{
					SlotPatcher.ReplaceSlot(item2, jumpTarget);
				}
				byte[] originalBytes = Jumper.Install(functionPointer, jumpTarget);
				_overridePatches.Add(new OverridePatch
				{
					Entry = functionPointer,
					OriginalBytes = originalBytes,
					Slots = list2
				});
			}
		}
		catch
		{
		}
	}

	private static byte[] ReadBytesSafe(IntPtr addr, int count)
	{
		try
		{
			byte[] array = new byte[count];
			Marshal.Copy(addr, array, 0, count);
			return array;
		}
		catch
		{
			return null;
		}
	}
}
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

	public string DelegateStatus;

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
		if (PrecodeSecondTargetAddr != IntPtr.Zero)
		{
			stringBuilder.AppendLine($"Precode2ndTarget: 0x{PrecodeSecondTargetAddr.ToInt64():X16}");
		}
		if (!string.IsNullOrEmpty(DelegateStatus))
		{
			stringBuilder.AppendLine("Delegate:      " + DelegateStatus);
		}
		return stringBuilder.ToString();
	}

	private static string FormatBytes(byte[] bytes)
	{
		if (bytes == null)
		{
			return "<null>";
		}
		return string.Join(" ", from b in bytes.Take(16)
			select $"{b:X2}") + ((bytes.Length > 16) ? " ..." : "");
	}
}
}
