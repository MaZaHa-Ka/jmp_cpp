#include "Windows.h"
#include <iostream>

#include "CHud.h"
#include "CCamera.h"
#include "CPed.h"
#include "CPlayerPed.h"
#include "plugin.h"

using namespace plugin;



//------------------------------------------------------------------
HANDLE InitConsole() // with proto
{
	AllocConsole();

	//SetConsoleOutputCP(866);
	setlocale(LC_ALL, "Russian");
	SetConsoleOutputCP(1251);
	SetConsoleCP(1251);


	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);

	return hConsole;
}

//void LeaveConsole(HANDLE hConsole = nullptr)
void LeaveConsole(HANDLE hConsole) // with proto
{
	if (hConsole != nullptr) { SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); } // Reset to default color
	FreeConsole();
}




uintptr_t PD_VoidPtr2IntPtr(void* _addr) { return reinterpret_cast<uintptr_t>(_addr); }
void* PD_IntPtr2VoidPtr(uintptr_t _addr) { return reinterpret_cast<void*>(_addr); }
template <typename T> T PD_ReadPtrDanger(void* ptr) { return *(static_cast<T*>(ptr)); } //  0x80000001 ERROR NO CATCHABLE
template <typename T> void PD_WriteDanger(void* ptr, const T& value) { (*(static_cast<T*>(ptr))) = value; }


//inline static void* Transpose(void* addr, intptr_t offset, bool deref = false)
static void* Transpose(void* addr, intptr_t offset, bool deref = false)
{
	auto res = (void*)((intptr_t)addr + offset);
	return deref ? *(void**)res : res;
}




bool _CheckPointerBoundsRead(void* pointer) // ���� �� ����� �����?
{
	if (!pointer) { return false; }

	MEMORY_BASIC_INFORMATION memInfo;
	if (VirtualQuery(pointer, &memInfo, sizeof(memInfo)) == sizeof(memInfo))
	{
		//if (memInfo.State == MEM_COMMIT && (memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_MAPPED)) { return true; } // ORIG!!!
		//if ((memInfo.State == MEM_COMMIT) && ((memInfo.Protect & PAGE_READWRITE) || (memInfo.Protect & PAGE_READONLY))) { return true; }
		//if ((memInfo.State == MEM_COMMIT) && ((memInfo.Protect & PAGE_READWRITE) || (memInfo.Protect & PAGE_READONLY)) && (memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_MAPPED)) { return true; }

		if (memInfo.State == MEM_COMMIT)
		{
			if (((memInfo.Protect & PAGE_READONLY) ||
				(memInfo.Protect & PAGE_EXECUTE_READ) ||
				(memInfo.Protect & PAGE_EXECUTE_WRITECOPY) ||
				(memInfo.Protect & PAGE_READWRITE) ||
				(memInfo.Protect & PAGE_EXECUTE_READWRITE)) && !(memInfo.Protect & PAGE_GUARD)) // PAGE_GUARD 0x80000001 ������ ������������
			{
				return true;
			}
		}
	}
	return false;
}


template <typename T> bool _CheckPointerReadByType(void* ptr) // ����� �� ������ ��� ��� ������?
{
	int SZ = sizeof(T); // unintptr_t x86 4b, x64 8b
	for (int byte_offset = 0; byte_offset < SZ; byte_offset++) // ��������� ��������� ������� ����� ��� T ����
	{
		ptr = Transpose(ptr, byte_offset);
		if (!_CheckPointerBoundsRead(ptr)) { return false; }
	}
	return true;
}



bool _CheckPointerBoundsWrite(void* pointer) // �����
{
	if (!pointer) { return false; }

	MEMORY_BASIC_INFORMATION memInfo;
	if (VirtualQuery(pointer, &memInfo, sizeof(memInfo)) == sizeof(memInfo))
	{
		if (memInfo.State == MEM_COMMIT)
		{
			if (((memInfo.Protect & PAGE_READWRITE) ||
				(memInfo.Protect & PAGE_EXECUTE_READWRITE) ||
				(memInfo.Protect & PAGE_EXECUTE_WRITECOPY)) && !(memInfo.Protect & PAGE_GUARD))
			{
				return true;
			}
		}
	}
	return false;
}


template <typename T> bool _CheckPointerWriteByType(void* ptr) // ����� �� ������ ��� ��� ������?
{
	int SZ = sizeof(T); // unintptr_t x86 4b, x64 8b
	for (int byte_offset = 0; byte_offset < SZ; byte_offset++) // ��������� ��������� ������� ����� ��� T ����
	{
		ptr = Transpose(ptr, byte_offset);
		if (!_CheckPointerBoundsWrite(ptr)) { return false; }
	}
	return true;
}









void Test()
{
	void* RegionPtr = (void*)0x401000; // sz 1E4000
	void* RenderMotionBlur_Ptr = (void*)0x46F940;

	bool res = _CheckPointerWriteByType<char>(Transpose(RenderMotionBlur_Ptr, 11));
	std::cout << "RES: " << res << "\n";
}



void PatchProtectMem()
{
	void* RegionPtr = (void*)0x401000; // sz 1E4000
	int page_sz = 0x1E4000;

	void* RenderMotionBlur_Ptr = (void*)0x46F940; // our patched byte ptr
	bool res = _CheckPointerWriteByType<char>(Transpose(RenderMotionBlur_Ptr, 11));
	if (!res)
	{ // need change rules
		DWORD oldProtect;
		VirtualProtect((LPVOID)RegionPtr, page_sz, PAGE_EXECUTE_READWRITE, &oldProtect);
	}
}




void Patch1(bool disable = true)
{
	//CPlayerPed* player = FindPlayerPed();
	//if (!player) { return 0; }

	//int __thiscall CCamera::RenderMotionBlur(int this) //++
	//int __cdecl CMBlur::MotionBlurRender(int a1, char a2, char a3, char a4, char a5, int a6, int a7)
	//int __cdecl CMBlur::OverlayRender(int a1, int a2, int a3, int a4, signed int a5)

	//RenderMotionBlur -> MotionBlurRender -> OverlayRender
	void* RenderMotionBlur_Ptr = (void*)0x46F940;
	void* MotionBlurRender_Ptr = (void*)0x50AD70;
	void* OverlayRender_Ptr = (void*)0x50A9C0;


	//int op = PD_ReadPtrDanger<char>(Transpose(RenderMotionBlur_Ptr, 11));
	//if (op != 0xEB) { PD_WriteDanger<char>(Transpose(RenderMotionBlur_Ptr, 11), 0xEB); }

	bool res = _CheckPointerWriteByType<char>(Transpose(RenderMotionBlur_Ptr, 11));
	if (!res) { PatchProtectMem(); }



	//.text:0046F94B 74 33               jz      short loc_46F980 // on
	//.text:0046F94B EB 33               jmp     short loc_46F980 // off

	if (disable) { PD_WriteDanger<char>(Transpose(RenderMotionBlur_Ptr, 11), 0xEB); } // disable filter
	else { PD_WriteDanger<char>(Transpose(RenderMotionBlur_Ptr, 11), 0x74); } // enable 
	//std::cout << "PTR: " << Transpose(RenderMotionBlur_Ptr, 11) << "\n";

	/*int buff = 0;
	if (disable) { buff = TheCamera.m_nBlurType; TheCamera.m_nBlurType = 0; return buff; }
	else { TheCamera.m_nBlurType = _buff; return 0; }*/



	//PD_WriteDanger<char>(Transpose(CRGBAWeapon_Ptr, 1), 255); // R
	//PD_WriteDanger<char>(Transpose(CRGBAWeapon_Ptr, 3), 255); // G
	//PD_WriteDanger<char>(Transpose(CRGBAWeapon_Ptr, 5), 255); // B

}





void MiniButtonsHandler()
{
	char action1 = 'T';
	int sleep_val = 10;
	int button_delay = 150;
	char shift = VK_SHIFT;

	bool tmp_flag = true;
	while (true)
	{
		//if ((GetAsyncKeyState(shift) & 0x8000) && IS_PLAYER_CHAR_IN_VEHICLE) { ReloadPlayerWeapoon(); Sleep(button_delay); } // reload in car
		if ((GetAsyncKeyState(action1) & 0x8000)) { Patch1(tmp_flag); tmp_flag = !tmp_flag; Sleep(button_delay); }
		Sleep(sleep_val);
	}
}


DWORD CALLBACK HandlersEntry(LPVOID)
{
	//InitConsole();
	MiniButtonsHandler();
	//Patch1();
	return TRUE;
}


void CreateHandlersThread() { CreateThread(NULL, 0, HandlersEntry, NULL, 0, NULL); }





int GetRegionSizeByPointer(void* ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	//if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) { } // err handler
	VirtualQuery(ptr, &mbi, sizeof(mbi));
	return mbi.RegionSize;
}

void* GetRegionBaseByPointer(void* ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	//if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) { } // err handler
	VirtualQuery(ptr, &mbi, sizeof(mbi));
	return mbi.BaseAddress;
}

MEMORY_BASIC_INFORMATION GetRegionInfoByPointer(void* ptr) // if (mbi.BaseAddress == nullptr) {} err
{
	MEMORY_BASIC_INFORMATION mbi;
	//if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) { } // err handler
	VirtualQuery(ptr, &mbi, sizeof(mbi));
	return mbi;
}


uintptr_t CalcJMPE9Offset(void* op_addr, void* dest_ptr) // ������� ����� ��� ������ jmp. ����� -��������, ������� �� ������ ����� ���� ����� ����������, E9 00 00 00 00 + offset
{
	uintptr_t op_address = (uintptr_t)op_addr;
	uintptr_t dest_address = (uintptr_t)dest_ptr;
	uintptr_t offset = (uintptr_t)(dest_address - (op_address + 1 + sizeof(uintptr_t))); // -16 fffffff0 jump upper
	return offset;
}

void Patch2()
{
	void* originalCodeBlock = (void*)0x505505;
	size_t block_sz = 34; // bytes je - je

	//if (!_CheckPointerReadByType<char>(originalCodeBlock)) { return; } // no readable
	if (!_CheckPointerBoundsRead(originalCodeBlock)) { return; } // no readable mini optimize

	//if (!_CheckPointerWriteByType<char>(originalCodeBlock)) // cant patch
	if (!_CheckPointerBoundsWrite(originalCodeBlock)) // cant patch mini optimize
	{
		MEMORY_BASIC_INFORMATION mbi = GetRegionInfoByPointer(originalCodeBlock);
		if (!mbi.RegionSize) { return; } // cant find base+sz
		DWORD oldProtect;
		VirtualProtect((LPVOID)mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	}

	void* TmpPtr = nullptr;
	char nop = 0x90;
	char jmp = 0xE9; // ������ �� ��������� 4����� (opcode addr + sz(0xE9) + sz(offset) + *offset(*(start+sz(opcode))))
	uint16_t jz = 0x78; // 74 OFFSET 1byte
	size_t patched_block_sz = (block_sz + 1 + sizeof(void*));


	// ��������� ������ �����, block_sz + jmp 0xPTR (5)
	//-------MKBLOCK
	void* patchBlock = VirtualAlloc(nullptr, patched_block_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //(LPVOID) nullptr => random memory
	if (patchBlock == nullptr) { return; } // cant create memblock 4 patch

	DWORD oldProtect;
	VirtualProtect(patchBlock, patched_block_sz, PAGE_EXECUTE_READWRITE, &oldProtect); // PAGE_EXECUTE_READ



	//-------------------------PREPEARE--PATCHED--BLOCK
	//memset(buffer, 0, sizeof(buffer));
	MEMORY_BASIC_INFORMATION mbi = GetRegionInfoByPointer(patchBlock);
	memset(patchBlock, nop, mbi.RegionSize);
	memset(patchBlock, nop, patched_block_sz);
	std::memcpy(patchBlock, originalCodeBlock, block_sz); // to from sz
	PD_WriteDanger<char>(Transpose(patchBlock, block_sz), jmp); // jmp
	uintptr_t offset1 = CalcJMPE9Offset(Transpose(patchBlock, block_sz), Transpose(originalCodeBlock, block_sz));
	PD_WriteDanger<uintptr_t>(Transpose(patchBlock, block_sz + 1), offset1); // pointer to jump (ret to orig block)
	//PD_WriteDanger<uintptr_t>(Transpose(patchBlock, block_sz + 1), PD_VoidPtr2IntPtr(Transpose(originalCodeBlock, block_sz))); // bug !!only offset




	//---------------------------PREPEARE--ORIGINAL--BLOCK
	////TmpPtr = originalCodeBlock;
	//for (int i = 0; i < block_sz; i++) // memset
	//{
	//	//TmpPtr = Transpose(originalCodeBlock, i);
	//	//PD_WriteDanger<char>(TmpPtr, nop);
	//	PD_WriteDanger<char>(Transpose(originalCodeBlock, i), nop);
	//}
	memset(originalCodeBlock, nop, block_sz); // nop
	PD_WriteDanger<char>(Transpose(originalCodeBlock, 0), jmp); // jmp
	uintptr_t offset2 = CalcJMPE9Offset(Transpose(originalCodeBlock, 0), patchBlock);
	PD_WriteDanger<uintptr_t>(Transpose(originalCodeBlock, 1), offset2); // pointer to jump (ret to orig block)
	//PD_WriteDanger<uintptr_t>(Transpose(originalCodeBlock, 1), PD_VoidPtr2IntPtr(patchBlock)); // pointer to jump (jmp 2 patch)


	//std::cout << "ORIG: 0x" << originalCodeBlock << "  SZ: " << block_sz << "\n";
	//std::cout << "PATCH: 0x" << patchBlock << "  SZ: " << patched_block_sz << "\n";

	//PD_WriteDanger<char>(Transpose(CRGBAWeapon_Ptr, 3), 255); // G
	//VirtualFree(patchBlock, 0, MEM_RELEASE);
}






bool initRwEventFIX = false;

class gta3_patches_testing {
public:
	gta3_patches_testing() {

		//InitConsole();
		//Patch1();
		//CreateHandlersThread();
		Patch2();


		Events::initGameEvent += [] {
			if (initRwEventFIX) { return; } // adapter to initRwEvent
			else { initRwEventFIX = true; }
			//InitConsole();
			//Patch1();
			//PatchProtectMem();
		};

		Events::drawHudEvent += []
		{
			//PatchProtectMem();
			//Test();
		};

		//Events::shutdownRwEvent += [] {};   

	}
} _gta3_patches_testing;