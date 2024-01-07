#pragma once
#include "Windows.h"
#include "MsgAPI.h"
#include "opcode_len_calc.h"
//#include <Windows.h>  // Äëÿ VirtualProtect
//#include <cstdint>


//---------DK--MOD 31/08

/**
* Get value at specified address.
*
* @param address    Address to leak.
* @param offset     Offset from address.
*
* @returns          Leak.
*/
template<typename T> T Leak(void* address, int offset = 0)
{
	if (!address)
		return T();

	uintptr_t ptr_value = *reinterpret_cast<uintptr_t*>((reinterpret_cast<unsigned char*>(address) + offset));
	return *reinterpret_cast<T*>(static_cast<unsigned char*>(address) + offset);
}
template<typename T> T Leakx86(void* address, int offset = 0)
{
	if (!address)
		return T();

	return *(T*)&((unsigned char*)address)[offset];
}


/**
* Calculate memory address relatively to another memory.
*
* @param to       Address result relatives to.
* @param address  Address to call/jump code.
*
* @returns        Relative address.
*/
inline static void* Relative(void* to, void* address)
{
	return (void*)((uintptr_t)to - (uintptr_t)address - sizeof(address));
}

inline static void *Relativex86(void* to, void* address)
{
	return (void *)((int)to - (unsigned int)address - sizeof address);
}

/**
* Offsets address at specified bytes count.
*
* @param addr    Address that will be offsetted.
* @param offset  Bytes count.
*
* @returns       Offsetted address.
*/
inline static void* Transpose(void* addr, intptr_t offset, bool deref = false)
{
	auto res = (void*)((intptr_t)addr + offset);

	return deref ? *(void**)res : res;
}

inline static void *Transposex86(void* addr, int offset, bool deref = false)
{
	auto res = (void *)((int)addr + offset);

	return deref ? *(void **)res : res;
}

/**
* Allocated executable heap memory for splicing.
*
* @param uSize   Memory size to allocate.
*
* @returns       Allocated memory.
*/
inline static void *AllocateExecutableMemory(unsigned int uSize)
{
	auto ret = malloc(uSize);
	if (!ret)
		return nullptr;

	DWORD oldProtect;
	if (!VirtualProtect(ret, uSize, PAGE_EXECUTE_READWRITE, &oldProtect))
		return nullptr;

	return ret;
}

/**
* Writes data in memory address.
*
* @param address    Address where value will be written.
* @param value      Data.
*
* @returns          Address offsetted by size of value type.
*/
template<typename T> void* Write(void* address, T value, int offset = 0)
{
	if (address == nullptr)
		XM_Error("Incorrect address.");

	uintptr_t new_address = reinterpret_cast<uintptr_t>(address) + offset;

	DWORD oldProtect;
	if (!VirtualProtect(reinterpret_cast<void*>(new_address), sizeof(T), PAGE_READWRITE, &oldProtect))
		XM_Error("XM_Error while calling VirtualProtect.");

	memcpy(reinterpret_cast<void*>(new_address), &value, sizeof(T));

	VirtualProtect(reinterpret_cast<void*>(new_address), sizeof(T), oldProtect, &oldProtect);

	return reinterpret_cast<void*>(new_address + sizeof(T));
}

template<typename T> void* Writex86(void* address, T value, int offset = 0)
{
	if (address == nullptr)
		XM_Error("Incorrect address.");

	address = (void *)((int)address + offset);

	unsigned long oldProtect;
	if (!VirtualProtect(address, sizeof T, PAGE_READWRITE, &oldProtect))
		XM_Error("XM_Error while calling VirtualProtect.");

	CopyMemory(address, &value, sizeof T);

	VirtualProtect(address, sizeof T, oldProtect, &oldProtect);

	return &((unsigned char *)address)[sizeof T];
}

/**
* Checks value at specified address.
*
* @param address    Address to check.
* @param value      Value.
* @param offset     Offset from address.
*
* @returns          True if address deref value is equal to value from arguments, false otherwise.
*/
template<typename T> bool Check(void* address, T value, int offset = 0)
{
	if (!address)
		return false;

	return *(T *)&((unsigned char *)address)[offset] == value;
}

/**
* Inserts call/jmp instruction at specified address.
*
* @param addrFrom    Call from.
* @param addrTo      Call to.
* @param bIsCall     If true, then 0xE8 (call) will be written, otherwise - 0xE9 (jmp).
*/
static void InsertFunc(void* addrFrom, void* addrTo, bool bIsCall)
{
	if (!addrFrom || !addrTo) { XM_Error("Incorrect arguments."); }

	auto pAddr = Write<unsigned char>(addrFrom, bIsCall ? 0xE8 : 0xE9);
	auto pRelAddr = Relative(addrTo, pAddr);

	Write<void *>(pAddr, pRelAddr);
}

/**
* Inserts jmp instruction at specified address.
*
* @param pFunc    Jump address.
*/
inline static void InsertJump(void* pStart, void* pFunc)
{
	InsertFunc(pStart, pFunc, false);
}

/**
* Inserts call instruction at specified address.
*
* @param pStart   Position to insert opcode.
* @param pFunc    Jump address.
*/
inline static void InsertCall(void* pStart, void* pFunc)
{
	InsertFunc(pStart, pFunc, true);
}

/**
* Writes NOP sled. Pretty slow algo, but legit for single uses.
*
* @param address   Position to write.
* @param count     NOPs count.
*/
inline static void WriteNOPs(void *address, int count)
{
	for (int i = 0; i < count; i++)
	{
		Write<unsigned char>(&((unsigned char *)address)[i], 0x90);
	}
}

/**
* Hooks function.
*
* @param pStart     Function to hook.
* @param pNewFunc   New function.
* @param uCodeSize  NOP sled size.
*
* @returns          Function trampoline.
*/
template <typename T> T HookRegular(void* pStart, T pNewFunc, unsigned int uCodeSize = 0)
{
	if (!pStart)
		XM_Error("Incorrect arguments.");

	if (!pNewFunc)
		return nullptr;

	if (uCodeSize == 0)
	{
		while (uCodeSize < 5)
		{
			auto size = InstructionLength(Transpose(pStart, uCodeSize));

			if (size == 0)
				XM_Error("Could not calculate instruction size.");

			uCodeSize += size;
		}
	}

	auto pTrampoline = AllocateExecutableMemory(sizeof(unsigned char) + sizeof(void *) + uCodeSize);

	if (!pTrampoline)
		XM_Error("Could not allocate memory for trampoline.");

	CopyMemory(pTrampoline, pStart, uCodeSize);
	InsertFunc(Transpose(pTrampoline, uCodeSize), Transpose(pStart, uCodeSize), false);
	InsertFunc(pStart, pNewFunc, false);

	if (uCodeSize > 5)
	{
		auto sled = Transpose(pStart, 5);
		WriteNOPs(sled, uCodeSize - 5);
	}

	return (T)pTrampoline;
}

/**
* Hooks exported function in module.
*
* @param hInstance  Module base address
* @param pszName    Export function name.
* @param pNewFunc   Inserted function address.
*
* @returns          Function trampoline.
*/
template <typename T> T HookExport(HMODULE hInstance, const char* pszName, T pNewFunc, unsigned int uCodeSize = 0)
{
	if (pszName == nullptr || *pszName == '\0' || pNewFunc == nullptr)
		XM_Error("Invalid arguments.");

	auto pFunc = GetProcAddress(hInstance, pszName);
	if (pFunc == NULL)
		XM_Error("Function not found.");

	return HookRegular(pFunc, pNewFunc, uCodeSize);
}