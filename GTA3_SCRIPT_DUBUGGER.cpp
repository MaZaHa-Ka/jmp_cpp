//----BY Вова Петров aka Ma-ZaHaKa
#pragma once
#include "Windows.h";
#include <iostream>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
//#include <random>


#include "plugin.h"
#include "CCamera.h"
#include "CHud.h"
#include "CMenuManager.h"
#include "CPed.h"
#include "CTheScripts.h"
#include "CStreaming.h"
#include "CPopulation.h"
#include "CModelInfo.h"
#include "CBoat.h"
#include "CWorld.h"
#include "CPlaceable.h"
#include "CMatrix.h"
#include "CVehicle.h"
#include "CAutomobile.h"

#include <extensions\ScriptCommands.h>
#include "CFont.h"
#include "CWanted.h"
#include "CPlayerPed.h"
#include "CTimer.h"
#include "CSprite.h"
#include "CUserDisplay.h"
#include "CCheat.h"
#include "CTimer.h"
#include "CEntity.h"
#include "CWeapon.h"
#include "CWeaponInfo.h"
#include "CAnimManager.h"

#include "ePedModel.h"
#include "eScriptCommands.h"
#include "eVehicleModel.h"
#include "eAnimations.h" // anims enums
#include "eWeaponModel.h"

#include "ScriptDebug.h"

//#include "eVehicleIndex.h"


//#include "CVehicle.cpp" // f12
//#include "CHud.cpp" // f12 only


using namespace plugin;
//using namespace std;

uintptr_t T_VoidPtr2IntPtr(void* _addr) { return reinterpret_cast<uintptr_t>(_addr); }
void* T_IntPtr2VoidPtr(uintptr_t _addr) { return reinterpret_cast<void*>(_addr); }
char* T_constchar2char(const char* constString) { return const_cast<char*>(constString); }
char* T_string2char(std::string constString) { return const_cast<char*>(constString.c_str()); }
std::string T_Pointer2String(void* pointer) { std::stringstream ss; ss << pointer; return "0x" + ss.str(); }


uintptr_t VoidPtr2IntPtr(void* _addr) { return reinterpret_cast<uintptr_t>(_addr); }
void* IntPtr2VoidPtr(uintptr_t _addr) { return reinterpret_cast<void*>(_addr); }
template <typename T> T ReadPtrDanger(void* ptr) { return *(static_cast<T*>(ptr)); } //  0x80000001 ERROR NO CATCHABLE
template <typename T> void WriteDanger(void* ptr, const T& value) { (*(static_cast<T*>(ptr))) = value; }

//PD_WriteDanger<char>(Transpose((void*)0x12345678, 5), 255);

//inline static void* Transpose(void* addr, intptr_t offset, bool deref = false)
static void* Transpose(void* addr, intptr_t offset, bool deref = false)
{
	auto res = (void*)((intptr_t)addr + offset);
	return deref ? *(void**)res : res;
}



std::string ToUpper(std::string strToConvert)
{
	std::transform(strToConvert.begin(), strToConvert.end(), strToConvert.begin(), std::toupper); //::toupper
	return strToConvert;
}
std::string ToLower(std::string strToConvert)
{
	std::transform(strToConvert.begin(), strToConvert.end(), strToConvert.begin(), std::tolower);
	return strToConvert;
}

std::string Trim(std::string str)
{
	// Find the first non-whitespace character from the beginning.
	size_t start = str.find_first_not_of(" \t\n\r\f\v");

	if (start == std::string::npos) {
		// If the string consists only of whitespace, return an empty string.
		return "";
	}

	// Find the last non-whitespace character from the end.
	size_t end = str.find_last_not_of(" \t\n\r\f\v");

	// Calculate the length of the trimmed substring.
	size_t length = end - start + 1;

	// Extract and return the trimmed substring.
	return str.substr(start, length);
}

std::string Replace(std::string input, std::string target, std::string replacement)
{
	std::string result = input;
	size_t startPos = 0;

	while ((startPos = result.find(target, startPos)) != std::string::npos)
	{
		result.replace(startPos, target.length(), replacement);
		startPos += replacement.length();
	}

	return result;
}

void AsciiToUnicode(const char* src, uint16_t* dst) // wchar
{
	while ((*dst++ = (unsigned char)*src++) != '\0');
}

std::string intToHexString(int value, bool ox = true)
{
	std::ostringstream stream;
	if (ox) { stream << "0x"; }
	stream << std::hex << value;// << std::dec;
	return stream.str();
}


//----------------------------------------SIMPLE---HANDLER
//void MiniButtonsHandler()
//{
//	char action1 = 'T';
//	int sleep_val = 10;
//	int button_delay = 150;
//	char shift = VK_SHIFT;
//
//	bool tmp_flag = true;
//	while (true)
//	{
//		//if ((GetAsyncKeyState(shift) & 0x8000) && IS_PLAYER_CHAR_IN_VEHICLE) { ReloadPlayerWeapoon(); Sleep(button_delay); } // reload in car
//		if ((GetAsyncKeyState(action1) & 0x8000)) { Sleep(button_delay); }
//		Sleep(sleep_val);
//	}
//}
//
//
//DWORD CALLBACK HandlersEntry(LPVOID)
//{
//	//InitConsole();
//	MiniButtonsHandler();
//	//Patch1();
//	return TRUE;
//}
//
//
//void CreateHandlersThread() { CreateThread(NULL, 0, HandlersEntry, NULL, 0, NULL); }
//
//BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
//{
//	if (fdwReason == DLL_PROCESS_ATTACH)
//	{
//		DisableThreadLibraryCalls(hinstDLL);
//		CreateHandlersThread();
//		//CreateThread(NULL, 0, Entry, NULL, 0, NULL);
//		//main();
//	}
//	return TRUE; // crash if no return;
//}



#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))


#define DEFAULT_SCREEN_WIDTH  (640)
#define DEFAULT_SCREEN_HEIGHT (480)
#define SCREEN_STRETCH_X(a)   ((a) * (float) SCREEN_WIDTH / DEFAULT_SCREEN_WIDTH)
#define SCREEN_STRETCH_Y(a)   ((a) * (float) SCREEN_HEIGHT / DEFAULT_SCREEN_HEIGHT)


#define DEFAULT_ASPECT_RATIO (4.0f/3.0f)
#define SCREEN_ASPECT_RATIO (DEFAULT_ASPECT_RATIO)
#define DEFAULT_VIEWWINDOW (0.7f)
#define SCREEN_SCALE_AR(a) ((a) * DEFAULT_ASPECT_RATIO / SCREEN_ASPECT_RATIO)
#define SCREEN_SCALE_X(a) SCREEN_SCALE_AR(SCREEN_STRETCH_X(a))
#define SCREEN_SCALE_Y(a) SCREEN_STRETCH_Y(a)
#define SCREEN_SCALE_FROM_RIGHT(a) (SCREEN_WIDTH - SCREEN_SCALE_X(a))
#define SCREEN_SCALE_FROM_BOTTOM(a) (SCREEN_HEIGHT - SCREEN_SCALE_Y(a))


struct tZonePrint
{
	char name[12];
	CRect rect;
};

tZonePrint ZonePrint[] =
{
	{ "suburban", CRect(-1639.4f,  1014.3f, -226.23f, -1347.9f) },
	{ "comntop",  CRect(-223.52f,  203.62f,  616.79f, -413.6f)  },
	{ "comnbtm",  CRect(-227.24f, -413.6f,   620.51f, -911.84f) },
	{ "comse",    CRect(200.35f, -911.84f,  620.51f, -1737.3f) },
	{ "comsw",    CRect(-223.52f, -911.84f,  200.35f, -1737.3f) },
	{ "industsw", CRect(744.05f, -473.0f,   1067.5f, -1331.5f) },
	{ "industne", CRect(1067.5f,  282.19f,  1915.3f, -473.0f)  },
	{ "industnw", CRect(744.05f,  324.95f,  1067.5f, -473.0f)  },
	{ "industse", CRect(1070.3f, -473.0f,   1918.1f, -1331.5f) },
	{ "no zone",  CRect(0.0f,     0.0f,     0.0f,    0.0f)     }
};

enum {
	FONT_BANK,
	FONT_PAGER,
	FONT_HEADING,
#ifdef MORE_LANGUAGES
	FONT_JAPANESE,
#endif
	MAX_FONTS
};




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



bool CheckPointerBoundsRead(void* pointer) // есть ли такой адрес?
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
				(memInfo.Protect & PAGE_EXECUTE_READWRITE)) && !(memInfo.Protect & PAGE_GUARD)) // PAGE_GUARD 0x80000001 нельзя разименовать
			{
				return true;
			}
		}
	}
	return false;
}


template <typename T> bool CheckPointerReadByType(void* ptr) // может ли данный тип там лежать?
{
	int SZ = sizeof(T); // unintptr_t x86 4b, x64 8b
	for (int byte_offset = 0; byte_offset < SZ; byte_offset++) // проверяем адресацию каждого байта для T типа
	{
		ptr = Transpose(ptr, byte_offset);
		if (!CheckPointerBoundsRead(ptr)) { return false; }
	}
	return true;
}



bool CheckPointerBoundsWrite(void* pointer) // робит
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


template <typename T> bool CheckPointerWriteByType(void* ptr) // может ли данный тип там лежать?
{
	int SZ = sizeof(T); // unintptr_t x86 4b, x64 8b
	for (int byte_offset = 0; byte_offset < SZ; byte_offset++) // проверяем адресацию каждого байта для T типа
	{
		ptr = Transpose(ptr, byte_offset);
		if (!CheckPointerBoundsWrite(ptr)) { return false; }
	}
	return true;
}


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


int CalcJMPE9Offset(void* op_addr, void* dest_ptr) // считает офсет для прыжка jmp. можно -значения, прыгает по офсету после ласт байта инструкции, E9 00 00 00 00 + offset
{
	uintptr_t op_address = (uintptr_t)op_addr;
	uintptr_t dest_address = (uintptr_t)dest_ptr;
	int offset = (int)(dest_address - (op_address + 1 + sizeof(uintptr_t))); // -16 fffffff0 jump upper
	return offset;
}



// переносит exec байты в новую расширенную область через jmp
// sz patch redirect x86 5bytes 1 + 4
// OrigPtr указатель на инструкцию для хука
// OrigSzBlock размер байтов для патча
// PatchSzBlock кол-во байт для патча помиио нужных патчу mysz+ret+sz(void*)
// OutPatchPtr выходной параметр patch sz (на скопированный опкод)
// OutPatchSzBlock выделенный размер (больше чем запрашиваемый)
//jmp_patch_in_end_region false jmp после нашего блока PatchSzBlock, true в конце региона
//offset оффсет переноса кода от начала блока
// !!!!!!!!!!!!!!!!!!!!!!!!!OrigSzBlock минимум 5 байт, не использовать перенос комманд mov jz jmp так как они работачт через оффсет своего адреса
// !!!!!!!!!!!!!!!!!!!!!!!!!если юзаешь mov jz jmp нужно патчить их оффсет
bool SetPatchBlock(void* OrigPtr, int OrigSzBlock, int PatchSzBlock, void*& OutPatchPtr, int& OutPatchSzBlock, bool jmp_patch_in_end_region = false, uintptr_t offset = 0) // !! NO MOVE OFFSETS INSTRUCTIONS (jmp, mov) они раюотают по оффсету из своего адреса
{
	MEMORY_BASIC_INFORMATION mbi_orig = GetRegionInfoByPointer(OrigPtr);
	if (!mbi_orig.RegionSize) { return false; } // cant find base+sz
	if (offset < 0) { return false; }
	DWORD oldProtect_orig;
	bool orig_protect_ch = false; // флаг для возврата оригинальных прав блока
	char nop = 0x90;
	char jmp = 0xE9; // прыжок со смещением 4байта (opcode addr + sz(0xE9) + sz(offset) + *offset(*(start+sz(opcode))))
	uintptr_t jmp_sz = (sizeof(char) + sizeof(void*));
	uintptr_t need_block_sz = (OrigSzBlock + PatchSzBlock + jmp_sz); // orig opcode + patch + jmp

	bool return_orig_protect = true;

	//if (!_CheckPointerReadByType<char>(OrigPtr)) { return; } // no readable
	if (!CheckPointerBoundsRead(OrigPtr)) { return false; } // no readable mini optimize


	//if (!_CheckPointerWriteByType<char>(OrigPtr)) // cant patch
	if (!CheckPointerBoundsWrite(OrigPtr)) // cant patch mini optimize
	{
		//MEMORY_BASIC_INFORMATION mbi = GetRegionInfoByPointer(originalCodeBlock);
		//if (!mbi.RegionSize) { return; } // cant find base+sz
		orig_protect_ch = true;
		VirtualProtect((LPVOID)mbi_orig.BaseAddress, mbi_orig.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect_orig);
	}


	//-------MK PATCH BLOCK
	// patched_block_sz чисто для выделения памяти, VirtualAlloc даёт больше памяти
	//void* patchBlock = VirtualAlloc(nullptr, need_block_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //(LPVOID) nullptr => random memory
	void* patchBlock = VirtualAlloc(nullptr, need_block_sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //(LPVOID) nullptr => random memory
	if (patchBlock == nullptr) { return false; } // cant create memblock 4 patch
	MEMORY_BASIC_INFORMATION mbi_patched = GetRegionInfoByPointer(patchBlock);

	//DWORD oldProtect_patched; // можно выше установить PAGE_EXECUTE_READWRITE в VirtualAlloc
	///////VirtualProtect(patchBlock, patched_block_sz, PAGE_EXECUTE_READWRITE, &oldProtect_patched); // PAGE_EXECUTE_READ // !!выделяеться больше чем запрашиваем
	//VirtualProtect(patchBlock, mbi_patched.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect_patched); // PAGE_EXECUTE_READ для alloc PAGE_READWRITE

	//----INIT OUT PARAMS
	OutPatchPtr = patchBlock; //OutPatchPtr = mbi_patched.BaseAddress;
	OutPatchSzBlock = mbi_patched.RegionSize;



	// orig block jmp -> patched block(istruction from orig + my instr) jmp -> orig block
	//-------------------------PREPEARE--PATCHED--BLOCK
	//memset(buffer, 0, sizeof(buffer));
	memset(patchBlock, nop, mbi_patched.RegionSize);
	//memset(patchBlock, nop, patched_block_sz);

	uintptr_t full_block_sz = jmp_patch_in_end_region ? (mbi_patched.RegionSize - jmp_sz) : (need_block_sz - jmp_sz);
	if (offset > (full_block_sz - OrigSzBlock)) { offset = 0; } // можно офсетить больше PatchSzBlock если jmp в конце
	//if (offset > (full_block_sz - OrigSzBlock)) { VirtualFree(patchBlock, 0, MEM_RELEASE); return false; } // можно офсетить больше PatchSzBlock если jmp в конце
	//if (offset > PatchSzBlock) { offset = 0; } // only patch block. additional not used
	std::memcpy(Transpose(patchBlock, offset), OrigPtr, OrigSzBlock); // to from sz  OrigSzBlock=6

	void* ptr_to_orig_jmp = nullptr;
	//---JMP IN END BLOCK !! universal
	//ptr_to_orig_jmp = Transpose(patchBlock, (mbi_patched.RegionSize - sizeof(char) - sizeof(void*)));
	//---JMP AFTER PATCH SZ !! logical
	//ptr_to_orig_jmp = Transpose(patchBlock, (OrigSzBlock + PatchSzBlock));
	//---JMP AFTER ORIG OPCODE IN PATCHED BLOCK !! no patching space in patched region
	//ptr_to_orig_jmp = Transpose(patchBlock, OrigSzBlock);

	if (jmp_patch_in_end_region) { ptr_to_orig_jmp = Transpose(patchBlock, (mbi_patched.RegionSize - jmp_sz)); }
	else { ptr_to_orig_jmp = Transpose(patchBlock, (OrigSzBlock + PatchSzBlock)); }

	WriteDanger<char>(ptr_to_orig_jmp, jmp); // jmp to orig block
	int offset1 = CalcJMPE9Offset(ptr_to_orig_jmp, Transpose(OrigPtr, OrigSzBlock));
	WriteDanger<int>(Transpose(ptr_to_orig_jmp, sizeof(char)), offset1); // pointer to jump (ret to orig block)
	//PD_WriteDanger<uintptr_t>(Transpose(patchBlock, block_sz + 1), PD_VoidPtr2IntPtr(Transpose(originalCodeBlock, block_sz))); // bug !!only offset




	//---------------------------PREPEARE--ORIGINAL--BLOCK
	memset(OrigPtr, nop, OrigSzBlock); // nop // nop 6, patch 5 bytes

	void* ptr_to_patched_jmp = Transpose(OrigPtr, 0);
	WriteDanger<char>(ptr_to_patched_jmp, jmp); // jmp
	int offset2 = CalcJMPE9Offset(ptr_to_patched_jmp, patchBlock);
	WriteDanger<int>(Transpose(ptr_to_patched_jmp, sizeof(char)), offset2); // pointer to jump (ret to orig block)
	//PD_WriteDanger<uintptr_t>(Transpose(originalCodeBlock, 1), PD_VoidPtr2IntPtr(patchBlock)); // pointer to jump (jmp 2 patch)




	//------------------------ORIG---PROTECT
	if (return_orig_protect && orig_protect_ch)
	{
		DWORD oldProtect_ch;
		VirtualProtect((LPVOID)mbi_orig.BaseAddress, mbi_orig.RegionSize, oldProtect_orig, &oldProtect_ch);
	}

	//------------------------PATCHED--PROTECT
	//{ // modify block after func
	//	DWORD oldProtect_ptch;
	//	VirtualProtect(patchBlock, patched_block_sz, PAGE_EXECUTE_READ, &oldProtect_ptch); // PAGE_EXECUTE_READWRITE
	//}



	//std::cout << "ORIG: 0x" << originalCodeBlock << "\n";
	//std::cout << "PATCH: 0x" << patchBlock << "\n";
	//std::cout << "PATCH SZ BLOCK: " << mbi_patched.RegionSize << "\n";
	//VirtualFree(patchBlock, 0, MEM_RELEASE);
	return true;
}
void* MkMem(int sz, int protect = PAGE_READWRITE) { return VirtualAlloc(nullptr, sz, MEM_COMMIT, protect); }

void RmMem(void* ptr) { VirtualFree(ptr, 0, MEM_RELEASE); }


//----XMEMORY USAGE
//void* g_mem_block = nullptr;
//void HelperFunc()
//{
//	if (!g_mem_block) { return; }
//	std::cout << "\n";
//	//std::cout << "TestFunc!!!" << "\n";
//
//	void* _this = (void*)ReadPtrDanger<uintptr_t>(Transpose(g_mem_block, (0 * sizeof(void*)))); // CPed target
//	int method = ReadPtrDanger<int>(Transpose(g_mem_block, (1 * sizeof(void*)))); // eWeaponType
//	int pedPiece = ReadPtrDanger<int>(Transpose(g_mem_block, (2 * sizeof(void*)))); // ePedPieceTypes
//	//bool willLinger = ReadPtrDanger<char>(Transpose(g_mem_block, (3 * sizeof(void*)))); // not remove el flag  ??
//
//	if (!_this) { return; }
//
//	//std::cout << "_this: " << intToHexString((uintptr_t)_this) << std::endl;
//	//std::cout << "method: " << intToHexString(method) << std::endl;
//	//std::cout << "pedPiece: " << intToHexString(pedPiece) << std::endl;
//	//std::cout << "willLinger: " << intToHexString(willLinger) << std::endl;
//
//
//	if ((((method > WEAPONTYPE_BASEBALLBAT) && (method < WEAPONTYPE_ROCKETLAUNCHER)) && (pedPiece == PEDPIECE_HEAD)))
//	{
//		((CPed*)_this)->m_fHealth = 0.0f;
//	}
//
//	//----CLS
//	//WriteDanger<int>(Transpose(g_mem_block, (0 * sizeof(void*))), 0x00);
//	//WriteDanger<int>(Transpose(g_mem_block, (1 * sizeof(void*))), 0x00);
//	//WriteDanger<int>(Transpose(g_mem_block, (2 * sizeof(void*))), 0x00);
//	//WriteDanger<int>(Transpose(g_mem_block, (3 * sizeof(void*))), 0x00);
//}
//
//void PatchTest()
//{
//	//https://eax.me/assembler-basics/
//	//InitConsole();
//
//
//	//CPed::InflictDamage
//	void* orig_ptr_for_patch_reference = (void*)0x4EACC0; // !jmp !jz !mov NO OFFSETS OPCODES (def patch sz 5bytes)
//	int available_sz_patch = 51; // дёрнуть байты из орига
//	int need_sz_patch = 200; // bytes // доп блок
//	int offset = 50; // max need_sz_patch(будет в конце перед jmp)  block(200+51+1+4)
//	bool jmp_patch_in_end_region = false;
//
//	//---OUT
//	void* out_patch_ptr = nullptr;
//	int out_patch_sz = 0; // mbi.region_sz
//	//bool res = SetPatchBlock(orig_ptr_for_patch_reference, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, true, offset); // jmp in the end region
//	bool res = SetPatchBlock(orig_ptr_for_patch_reference, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, jmp_patch_in_end_region, offset); // jmp after need_sz_patch
//	void* moved_block = Transpose(out_patch_ptr, offset);
//	void* jmp = Transpose(moved_block, 46); // 0x4EACEE old  // 0xE9 jmp (4b)
//	void* retn_false_label_ptr = (void*)0x4EADDA;
//
//
//	//----fix jmp offset   JMP  РАБОТАЕТ МОИМ МЕТОДОМ И ЧЕРЕЗ InsertJump
//	//int offset_4_jmp = CalcJMPE9Offset(jmp, retn_false_label_ptr); // работает также, InsertJump элегантнее
//	//WriteDanger<int>(Transpose(jmp, sizeof(char)), offset_4_jmp); // InsertJump ?
//	InsertJump(jmp, retn_false_label_ptr);
//	//-----------------END----FIX----MATH
//
//
//
//
//	// write patch
//	/*; Байты для загрузки значения float из памяти по адресу 0x12345 в регистр eax
//	8b 05 23 01 00        ; mov eax, 0x123
//	; Байты для сохранения значения float в регистре eax по адресу [esp + 14]
//	89 44 24 14           ; mov dword [esp + 14], eax*/
//	//mov destination, source
//
//
//	void* patch_ptr = Transpose(out_patch_ptr, 0);
//	void* buff = MkMem((4 * sizeof(void*))); // bytes // usage 4 * 3
//	if (!buff) { return; }
//	g_mem_block = buff;
//	// _this method pedPiece willLinger
//
//
//
//
//	//-----this thiscall в ecx но код иногда перезаписывает его в 1, хукай начало для перехвата ecx
//	//--offset esp
//	//!!!через esp + 0x50
//	// buff = [esp + 0x50] (this CPed target)
//	//WriteDanger<char>(Transpose(nop_test_fld, 18), 0x8B); // mov
//	//WriteDanger<char>(Transpose(nop_test_fld, 19), 0x44);
//	//WriteDanger<char>(Transpose(nop_test_fld, 20), 0x24);
//	//WriteDanger<char>(Transpose(nop_test_fld, 21), 0x50); // offset
//	////----mov ptr, eax
//	//WriteDanger<char>(Transpose(nop_test_fld, 22), 0xA3); // mov ptr eax
//	//WriteDanger<uintptr_t>(Transpose(nop_test_fld, 23), (uintptr_t)Transpose(buff, (2 * sizeof(void*))));
//
//	//--ecx => ptr (мусор 1)
//	// 0x89 0x0D PO IN TE RR  загрузит ecx в адрес !!!!
//	// 0x8B 0x0D PO IN TE RR загрузит из адреса в ecx
//	//WriteDanger<char>(Transpose(nop_test_fld, 18), 0x89);  // mov ptr ecx   // 89 0D ?? mov [0AB70000], ecx
//	//WriteDanger<char>(Transpose(nop_test_fld, 19), 0x0D);
//	//WriteDanger<uintptr_t>(Transpose(nop_test_fld, 20), (uintptr_t)Transpose(buff, (2 * sizeof(void*))));
//
//	// копируем ebp в первый блок, this pointer
//	//--через ebp, thiscall юзает ecx в начале, функция затирает
//	// buff = ebp (this CPed target) // untested [esp + 0x50] ///BASE 004EA420
//	WriteDanger<char>(Transpose(patch_ptr, 0), 0x89); // mov ptr, ebp
//	WriteDanger<char>(Transpose(patch_ptr, 1), 0x2D);
//	WriteDanger<uintptr_t>(Transpose(patch_ptr, 2), (uintptr_t)Transpose(buff, (0 * sizeof(void*))));
//
//
//
//	// копируем [esp + 0x38] через eax во второй блок, method
//	// buff = [esp + 0x38] (method)
//	//!!!!!!!!!!!!!!!!!!!!!!!!!!!
//	//mov eax, [esp + 0x38]						8B 44 54 38
//	//mov [адрес_памяти], eax  без офсета		A3 PO IN TE RR
//
//	//---mov eax [esp + 0x38]
//	WriteDanger<char>(Transpose(patch_ptr, 6), 0x8B); // work mov 2 eax
//	WriteDanger<char>(Transpose(patch_ptr, 7), 0x44); // mov esp + offset to eax
//	WriteDanger<char>(Transpose(patch_ptr, 8), 0x24);
//	WriteDanger<char>(Transpose(patch_ptr, 9), 0x38); // offset
//
//	//----mov ptr, eax
//	WriteDanger<char>(Transpose(patch_ptr, 10), 0xA3); // mov ptr eax  load eax to pointer
//	WriteDanger<uintptr_t>(Transpose(patch_ptr, 11), (uintptr_t)Transpose(buff, (1 * sizeof(void*))));
//
//
//
//
//	// копируем [esp + 0x40] через eax в третий блок, pedpice
//	// buff = [esp + 0x40] (pedpice)
//	WriteDanger<char>(Transpose(patch_ptr, 15), 0x8B); // mov
//	WriteDanger<char>(Transpose(patch_ptr, 16), 0x44); // mov esp + offset to eax
//	WriteDanger<char>(Transpose(patch_ptr, 17), 0x24);
//	WriteDanger<char>(Transpose(patch_ptr, 18), 0x40); // offset
//
//	//----mov ptr, eax
//	WriteDanger<char>(Transpose(patch_ptr, 19), 0xA3); // mov ptr eax  load eax to pointer
//	WriteDanger<uintptr_t>(Transpose(patch_ptr, 20), (uintptr_t)Transpose(buff, (2 * sizeof(void*))));
//
//
//
//
//	//---------------------------------------------------------------------fix offsets (willLinger) не используеться
//	//// buff = [esp + 0x0C] (willLinger) или часть тела 
//	//WriteDanger<char>(Transpose(nop_test_fld, 24), 0x8B); // mov
//	//WriteDanger<char>(Transpose(nop_test_fld, 25), 0x44);
//	//WriteDanger<char>(Transpose(nop_test_fld, 26), 0x24);
//	//WriteDanger<char>(Transpose(nop_test_fld, 27), 0x0C); // offset
//
//	////----mov ptr, eax
//	//WriteDanger<char>(Transpose(nop_test_fld, 28), 0xA3); // mov ptr eax
//	//WriteDanger<uintptr_t>(Transpose(nop_test_fld, 29), (uintptr_t)Transpose(buff, (3 * sizeof(void*)))); // char !!!
//
//	////---очистка байта на байт больше
//	//WriteDanger<char>(Transpose(nop_test_fld, 33), 0xC7); // mov [aab000C], 00 00 00 00
//	////WriteDanger<char>(Transpose(nop_test_fld, 33), 0xC6); // mov [aab000C], 00
//	//WriteDanger<char>(Transpose(nop_test_fld, 34), 0x05);
//	//WriteDanger<uintptr_t>(Transpose(nop_test_fld, 35), (uintptr_t)Transpose(buff, (3 * sizeof(void*)) + 1)); // char !!!
//	//WriteDanger<int>(Transpose(nop_test_fld, 39), 0x00);
//	//// write buff * (3*szof()) + 1   3 zero
//
//
//	//---------вызываем call myfunc без аргументов
//	WriteDanger<char>(Transpose(patch_ptr, 24), 0xE8); // call
//	InsertCall(Transpose(patch_ptr, 24), HelperFunc);
//	//WriteDanger<int>(Transpose(patch_ptr, 25), CalcJMPE9Offset(Transpose(patch_ptr, 24), HelperFunc)); // call func
//
//}






void PatchTest()
{
	void* orig_ptr_for_patch_reference = (void*)0x4EACC0; // !jmp !jz !mov NO OFFSETS OPCODES (def patch sz 5bytes)
	int available_sz_patch = 51;
	int need_sz_patch = 200; // bytes
	int offset = need_sz_patch; // max need_sz_patch(будет в конце перед jmp)  block(200+51+1+4)
	bool jmp_patch_in_end_region = false;

	//---OUT
	void* out_patch_ptr = nullptr;
	int out_patch_sz = 0; // mbi.region_sz
	//bool res = SetPatchBlock(orig_ptr_for_patch_reference, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, true, offset); // jmp in the end region
	bool res = SetPatchBlock(orig_ptr_for_patch_reference, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, jmp_patch_in_end_region, offset); // jmp after need_sz_patch

	//std::cout << "ORIG: 0x" << orig_ptr_for_patch_reference << "\n";
	//std::cout << "PATCH: 0x" << out_patch_ptr << "\n";
	//std::cout << "PATCH SZ BLOCK: " << out_patch_sz << "\n";
}







//---GAME--HELPERS-------------------------------
void PrintPlayerCoords()
{
	CPlayerPed* player = FindPlayerPed();
	if (!player) { return; }

	float x_offset = -30.0f;
	float y_offset = -30.0f;

	char str[200];
	//uint16_t ustr[200];

	//CVector pos = FindPlayerCoors(); // crash 
	CVector pos = player->GetPosition();

	int32_t ZoneId = ARRAY_SIZE(ZonePrint) - 1; // no zone //10
	//int32_t ZoneId = 10;

	for (int32_t i = 0; i < ARRAY_SIZE(ZonePrint) - 1; i++)
	{
		if (pos.x > ZonePrint[i].rect.left
			&& pos.x < ZonePrint[i].rect.right
			&& pos.y > ZonePrint[i].rect.bottom
			&& pos.y < ZonePrint[i].rect.top)
		{
			ZoneId = i;
		}
	}

	sprintf(str, "X:%5.1f, Y:%5.1f, Z:%5.1f, %s", pos.x, pos.y, pos.z, ZonePrint[ZoneId].name);
	//AsciiToUnicode(str, ustr);

	CFont::SetPropOff();
	CFont::SetBackgroundOff();

	CFont::SetScale(SCREEN_SCALE_X(0.4f), SCREEN_SCALE_Y(1.2f)); // меньше
	//CFont::SetScale(SCREEN_SCALE_X(0.7f), SCREEN_SCALE_Y(1.5f)); // orig
	//CFont::SetScale(0.7f, 1.5f); // bug

	CFont::SetCentreOff();
	CFont::SetRightJustifyOff();
	CFont::SetJustifyOff();
	CFont::SetBackGroundOnlyTextOff();

	CFont::SetWrapx(SCREEN_STRETCH_X(DEFAULT_SCREEN_WIDTH));
	//CFont::SetWrapx(SCREEN_WIDTH); // my custom
	//CFont::SetWrapx(DEFAULT_SCREEN_WIDTH); // bug

	CFont::SetFontStyle(FONT_HEADING);



	//----BLACK
	CFont::SetColor(CRGBA(0, 0, 0, 255));
	CFont::PrintString(SCREEN_SCALE_X(40.0f + 2.0f) + x_offset, SCREEN_SCALE_Y(40.0f + 2.0f) + y_offset, str);
	//CFont::PrintString(40.0f + 2.0f, 40.0f + 2.0f, str); // bug


	//---ORANGE
	CFont::SetColor(CRGBA(255, 108, 0, 255));
	CFont::PrintString(SCREEN_SCALE_X(40.0f) + x_offset, SCREEN_SCALE_Y(40.0f) + y_offset, str);
	//CFont::PrintString(40.0f, 40.0f, str); // bug

}


//CPlayerPed* player = FindPlayerPed();
//if (!player) { return; }
//for (CPed* ped : CPools::ms_pPedPool)
//{
//	if (!ped || ped == player || !ped->m_fHealth) continue;
//
//	Wallhack(ped);
//}
void Wallhack(CPed* ped)
{
	CVector position = ped->GetPosition();
	RwV3d pos = { position.x + 0.1f, position.y, position.z + 0.9f };

	RwV3d coords;
	float w, h;

	if (!CSprite::CalcScreenCoors(pos, &coords, &w, &h, true)) { /*std::cout << "ERROR PED!! " << "\n";*/ return; }


	//CFont::SetOrientation(ALIGN_LEFT);
	CFont::SetColor(color::White);
	CFont::SetDropShadowPosition(1);

	CFont::SetBackgroundOff();
	//CFont::SetBackground(false, false);

	CFont::SetWrapx(SCREEN_WIDTH);
	CFont::SetScale(1.0, 2.0);

	//CFont::SetFontStyle(1); //?
	//CFont::SetFontStyle(FONT_SUBTITLES);

	CFont::SetPropOn();
	//CFont::SetProportional(true);

	//std::string text = "Skin ID: " + std::to_string(ped->m_nModelIndex) + "~n~";
	//std::string text = "123 " + std::to_string(ped->m_nModelIndex) + "";
	std::string text = "DESPAIR";

	//text.append(std::format("Position: {:.2f}, {:.2f}, {:.2f}~n~", pos.x,		pos.y, pos.z));
	//text.append(std::format("Health: {:.2f}~n~", ped->m_fHealth));
	//text.append(std::format("Armor: {:.2f}~n~", ped->m_fArmour));
	//text.append(std::format("Weapon: {}~n~", GetActivePedWeapon(ped)));
	//text.append(std::format("In Vehicle: {}~n~", IsPedInCar(ped)));

	CFont::PrintString(coords.x, coords.y, (char*)text.c_str());
	//std::cout << "PED!! " << "\n";
}


void
KillPlayer()
{
	CPlayerPed* player = FindPlayerPed();
	if (!player) { return; }
	Command<eScriptCommands::COMMAND_SET_CHAR_HEALTH>(player, 0);
}

void
KillPed(CPed* pPed)
{
	CPlayerPed* player = FindPlayerPed();
	if (player && pPed == player) { Command<eScriptCommands::COMMAND_SET_CHAR_HEALTH>(player, 0); return; } // with anim

	//COMMAND_SET_CHAR_HEALTH
	pPed->m_fHealth = 0.0f; // ??

	// if in car
	pPed->SetDead();
	if (!pPed->IsPlayer()) { pPed->FlagToDestroyWhenNextProcessed(); }

	// else
	//pPed->SetDie(); // last argument = 13 (default? TODO)
}

void
KillPedPool(int mode) // 0 player, 1 all, 2 in car, 3 walking
{
	if ((mode < 0) || (mode > 4)) { return; }
	CPlayerPed* player = FindPlayerPed();
	if (!player) { std::cout << "!player" << "\n"; return; }
	if (mode == 0) { KillPed(player); }

	int cnt = 0;
	//CPools::ms_pPedPool->Clear(); // kill player
	//CPools::ms_pPedPool->Flush();
	//return;

	for (CPed* pPed : CPools::ms_pPedPool)
	{
		if (!pPed || pPed == player || !pPed->m_fHealth) { continue; }
		++cnt;

		if (mode == 1) // all kill
		{
			// not continue skip;
		}
		else if (mode == 2) // only drivers
		{
			if (!pPed->m_bInVehicle) { continue; }
		}
		else // only walking peds
		{
			if (pPed->m_bInVehicle) { continue; }
		}


		KillPed(pPed);
		////COMMAND_SET_CHAR_HEALTH
		//pPed->m_fHealth = 0.0f; // ??

		//// if in car
		//pPed->SetDead();
		//if (!pPed->IsPlayer()) { pPed->FlagToDestroyWhenNextProcessed(); }

		//// else
		////pPed->SetDie(); // last argument = 13 (default? TODO)

		//std::cout << pPed->IsPedInControl() << "\n";
	}
	std::cout << "killed: " << cnt << "\n";
}


void
KillVehiclePool(int mode = 0)
{
	CPlayerPed* player = FindPlayerPed();
	if (!player) { std::cout << "!player" << "\n"; return; }

	float min_nofire_health = 251.0f;
	float fire_health = 100.0f;

	/*CVehicle* vehicle = FindPlayerVehicle();
	if (vehicle)
	{
		if ((vehicle->m_fHealth > sethealth) && !car_flag)
		{
			vehicle->m_fHealth = sethealth;
			//Command<eScriptCommands::COMMAND_SET_CAR_HEALTH>(vehicle, 252);
			//Command<eScriptCommands::COMMAND_SET_6_PHONE_MESSAGES>("123");
			car_flag = true;
		}
	}*/

	int cnt = 0;
	for (CVehicle* vehicle : CPools::ms_pVehiclePool)
	{
		if (!vehicle || (!vehicle->m_fHealth)) { continue; }
		if ((mode != 1) && (vehicle->m_pDriver == player)) { continue; } // mode0 !player, mode1 all
		//Command<eScriptCommands::COMMAND_SET_CAR_HEALTH>(vehicle, (int)fire_health);
		vehicle->m_fHealth = fire_health; // !! доработать, горят при прикосновении
		++cnt;
	}
	std::cout << "damaged cnt: " << cnt << "\n";
}



void DisplayPagerMsg(std::string msg) { CUserDisplay::Pager.AddMessage(T_constchar2char(msg.c_str()), 140, 2, 0); }

int NormalizeStars(int _input) { return _input % 7; } // ограничение до 7

bool SetWanted(int _wnt)
{
	if ((_wnt < 0) || (_wnt > 6)) { return false; }
	CPlayerPed* playerPed = FindPlayerPed();
	if (playerPed)
	{
		CWanted* wanted = playerPed->m_pWanted;
		if (!wanted) return false;
		wanted->SetMaximumWantedLevel(6);
		//CWanted::SetMaximumWantedLevel(6); //??

		//playerPed->SetWantedLevelNoDrop(_wnt);
		playerPed->SetWantedLevel(_wnt);
		return true;
	}
	return false;
}

bool Cheat(std::string cheat, bool player_check = true)
{
	if (cheat.length() != 0)
	{
		CPlayerPed* playerPed = FindPlayerPed();
		if (player_check && (!playerPed)) { return false; } // !player

		std::string text = ToUpper(cheat);
		if (text == "GUNSGUNSGUNS") { WeaponCheat(); }                  // Все оружие
		else if (text == "IFIWEREARICHMAN") { MoneyCheat(); }                   // Получить деньги
		else if (text == "TORTOISE") { ArmourCheat(); }                  // Полная броня
		else if (text == "GESUNDHEIT") { HealthCheat(); }                  // Полное здоровье
		else if (text == "MOREPOLICEPLEASE") { WantedLevelUpCheat(); }           // Повысить уровень розыска
		else if (text == "NOPOLICEPLEASE") { WantedLevelDownCheat(); }         // Убрать уровень розыска
		else if (text == "GIVEUSATANK") { TankCheat(); }                    // Получить танк
		else if (text == "BANGBANGBANG") { BlowUpCarsCheat(); }              // Взорвать все машины
		else if (text == "ITSALLGOINGMAAAD") { MayhemCheat(); }                  // Безумные пешеходы
		else if (text == "NOBODYLIKESME") { EverybodyAttacksPlayerCheat(); }  // Пешеходы атакуют игрока
		else if (text == "WEAPONSFORALL") { WeaponsForAllCheat(); }           // Пешеходы дерутся + оружие
		else if (text == "TIMEFLIESWHENYOU") { FastWeatherCheat(); }             // Ускорить время погоды
		else if (text == "SKINCANCERFORME") { SunnyWeatherCheat(); }            // Ясная погода
		else if (text == "ILIKESSCOTLAND") { CloudyWeatherCheat(); }           // Пасмурная погода
		else if (text == "ILOVESCOTLAND") { RainyWeatherCheat(); }            // Дождливая погода
		else if (text == "PEASOUP") { FoggyWeatherCheat(); }            // Туманная погода
		else if (text == "MADWEATHER") { FastTimeCheat(); }                // Ускорить игровые часы
		else if (text == "BOOOOORING") { SlowTimeCheat(); }                // Замедление
		else if (text == "ILIKEDRESSINGUP") { ChangePlayerCheat(); }            // Сменить модель игрока на случайную
		else if (text == "ANICESETOFWHEELS") { OnlyRenderWheelsCheat(); }        // Невидимые машины, видны только колёса
		else if (text == "CORNERSLIKEMAD") { StrongGripCheat(); }              // Улучшенное управление машинами
		else if (text == "CHITTYCHITTYBB") { ChittyChittyBangBangCheat(); }    // Машины летают
		else if (text == "NASTYLIMBSCHEAT") { NastyLimbsCheat(); }              // Кровавый режим
		//else if (text == "TEST") { }
		else { return false; } // NOT FOUND
	}
	else { return false; } // empty string

	return true;
}



//MK PED
//CPed* newPed = nullptr;
//
//CPed* playa = FindPlayerPed();
//if (playa) {
//	CVector pedPos = playa->TransformFromObjectSpace(CVector(0.0f, 3.0f, 0.0f));
//	if (newPed == nullptr) {
//		//newPed = СreateChar(PEDTYPE_CIVMALE, MODEL_B_MAN3, pedPos);
//		newPed = СreateChar(PEDTYPE_GANG2, MODEL_NULL, pedPos);
//	}
//}

//---DS
//auto playa = FindPlayerPed();
//if (playa) {
//	if (CPad::NewMouseControllerState.rmb) {
//		if (CStreaming::ms_aInfoForModel[MODEL_BANSHEE].m_nLoadState == LOADSTATE_LOADED) {
//			vecPos = playa->TransformFromObjectSpace(CVector(0.0f, 5.0f, 1.0f));
//			Command<Commands::CREATE_CAR>(MODEL_BANSHEE, vecPos.x, vecPos.y, vecPos.z, &vehHandle);
//			if (vehHandle) {
//				veh_1 = CPools::GetVehicle(vehHandle);
//				veh_1->m_fHealth = 1000.0f;
//			}
//		}
//		else {
//			CStreaming::RequestModel(MODEL_BANSHEE, 22);  //  22 ---> opcode_0247 flag
//			CStreaming::LoadAllRequestedModels(false);
//		}
//	}
//}

static CPed* СreateChar(ePedType ped_Type, int ped_model, CVector ped_pos) {
	if (CStreaming::ms_aInfoForModel[ped_model].m_nLoadState == LOADSTATE_LOADED) {
		CPed* ped_2 = CPopulation::AddPed(ped_Type, ped_model, ped_pos);
		if (ped_2) {
			ped_2->m_nCharCreatedBy = 2;
			return ped_2;
		}
		else {
			return nullptr;
		}
	}
	else {
		CStreaming::RequestModel(ped_model, GAME_REQUIRED);
		CStreaming::LoadAllRequestedModels(false);
		return nullptr;
	}
}


//static void _CreateCar(int id = 119) // banshee // bad CVehicle ctors. fix
//{
//	CVector playerpos;
//	CStreaming::AddToLoadedVehiclesList(id);
//	CStreaming::LoadAllRequestedModels(false);
//	//if(CStreaming::ms_aInfoForModel[ped_model].m_nLoadState == LOADSTATE_LOADED) {
//	//if (CStreaming::ms_vehiclesLoaded)
//	{
//		playerpos = FindPlayerCoors();
//		int node;
//		/*if (!CModelInfo::IsBoatModel(id)) {
//			node = ThePaths.FindNodeClosestToCoors(playerpos, 0, 100.0f, false, false);
//			if (node < 0)
//				return;
//		}*/
//		std::cout << "LOADED!\n";
//
//		CVehicle* v;
//		if (CModelInfo::IsBoatModel(id))
//		{
//			//v = new CBoat(id, RANDOM_VEHICLE);
//			std::cout << "BOAT!\n";
//		}
//		else
//		{
//			std::cout << "start createAutomobile!\n";
//			//v = new CAutomobile(RANDOM_VEHICLE, id, true);
//			if (!v) { std::cout << "!V!!!!\n"; }
//			std::cout << v << "\n";
//		}
//
//		return;
//		//v->bHasBeenOwnedByPlayer = true;
//
//		if (CModelInfo::IsBoatModel(id))
//		{
//			//v->SetPosition(TheCamera.GetPosition() + TheCamera.m_matrix. * 15.0f);
//		}
//		else
//		{
//			CVector vec = ThePaths.m_aPathNodes[node].m_vecPos;
//			v->SetPosition(vec.x, vec.y, vec.z);
//
//		}
//
//
//		v->m_matrix.pos.z += 4.0f;
//		v->SetOrientation(0.0f, 0.0f, 3.49f);
//		v->SetState(STATUS_ABANDONED);
//		v->m_eDoorLock = eDoorLock::DOORLOCK_UNLOCKED;
//		CWorld::Add(v);
//	}
//	//else { std::cout << "NOT LOADED!\n"; }
//}



static CVehicle* CreateVehicle(int vehicleID, CVector position, float orientation)
{
	CVehicle* vehicle = nullptr;

	unsigned char oldFlags = CStreaming::ms_aInfoForModel[vehicleID].m_nFlags;
	CStreaming::RequestModel(vehicleID, 1);
	CStreaming::LoadAllRequestedModels(false);
	if (CStreaming::ms_aInfoForModel[vehicleID].m_nLoadState == LOADSTATE_LOADED) {
		if (!(oldFlags & 1)) {
			CStreaming::SetModelIsDeletable(vehicleID);
			CStreaming::SetModelTxdIsDeletable(vehicleID);
		}

		Command<eScriptCommands::COMMAND_CREATE_CAR>(vehicleID, position.x, position.y, position.z, &vehicle);

		if (vehicle) {
			CTheScripts::ClearSpaceForMissionEntity(position, vehicle);
		}
	}
	return vehicle;
}

static void CreateCar(int vehicleID = eVehicleModel::MODEL_BANSHEE) // banshee 119 (modified fast handling 4 testing scripts)
{
	CPlayerPed* player = FindPlayerPed();
	if (player) {
		CVector position = player->TransformFromObjectSpace(CVector(0.0f, 5.0f, 0.0f));
		CVehicle* vehicle = CreateVehicle(vehicleID, position, player->m_fRotationCur + 1.5707964f);
	}
}

void TeleportPlayer(CVector destination)
{
	CEntity* entity = FindPlayerEntity();
	if (entity) {
		entity->Teleport(destination);

		CWorld::Remove(entity);
		CWorld::Add(entity);

		CPed* player = FindPlayerPed();
		if (player) {
			CWorld::Remove(player);
			CWorld::Add(player);
		}

		CStreaming::StreamZoneModels(destination);
	}
}


//------------------------SCRIPTS-------------------------------------
int DebugScriptIPsSetIP(int script_num, int IP, bool add_ip = false)
{
	CRunningScript* scr = CTheScripts::pActiveScripts;
	for (int i = 0; i < script_num; i++) { if (!scr) { continue; } scr = scr->m_pNext; }
	if (!scr) { return -1; }
	if (add_ip) { scr->m_nIp += IP; }
	else { scr->m_nIp = IP; }
	return  scr->m_nIp;
}




//-------------------------------WEAPON

CWeaponInfo* GetPlayerCurrentWeaponInfo()
{
	if (!FindPlayerPed()) { return nullptr; }
	CWeaponInfo* info = CWeaponInfo::GetWeaponInfo(FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].m_eWeaponType);
	return info;
}

//eWeaponType GetPlayerCurrentWeaponType()
int32_t GetPlayerCurrentWeaponType()
{
	//if (!FindPlayerPed()) { return eWeaponType::WEAPONTYPE_UNARMED; }
	if (!FindPlayerPed()) { return eWeaponType::WEAPONTYPE_UNARMED; }
	//int32_t WeaponType = FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].m_eWeaponType;
	return FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].m_eWeaponType;
}

//bool IsWeaponM16Player()
//{
//	if (!FindPlayerPed()) { return false; }
//	int32_t WeaponType = FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].m_eWeaponType;
//	bool is_m16 = (WeaponType == WEAPONTYPE_M16);
//	return is_m16;
//}

bool IsWeaponM16Player()
{
	if (!FindPlayerPed()) { return false; }
	return (GetPlayerCurrentWeaponType() == WEAPONTYPE_M16);
}

bool IsWeaponUziPlayer()
{
	if (!FindPlayerPed()) { return false; }
	return (GetPlayerCurrentWeaponType() == WEAPONTYPE_UZI);
}

bool IsWeaponAK47Player()
{
	if (!FindPlayerPed()) { return false; }
	return (GetPlayerCurrentWeaponType() == WEAPONTYPE_AK47);
}

bool IsUnArmedPlayer()
{
	if (!FindPlayerPed()) { return false; }
	return (GetPlayerCurrentWeaponType() == WEAPONTYPE_UNARMED);
}

RpClump* GetPlayerClump()
{
	if (!FindPlayerPed()) { return nullptr; }
	//CWeaponInfo::GetWeaponInfo(FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon]
	return (RpClump*)FindPlayerPed()->m_pRwObject;
}

bool IsPlayerDriveVehicle()
{
	if (!FindPlayerPed()) { return false; }
	//return FindPlayerPed()->m_pVehicle != nullptr; // NOT WORK. тачка педа остаёться если он вышел
	return FindPlayerPed()->m_bInVehicle; // work
}

bool IsPlayerActive()
{
	return !(!FindPlayerPed());
}

bool IsMenuActive()
{
	return FrontEndMenuManager.m_bMenuActive;
}

bool IsReloadableWeapon(int32_t m_eWeaponType)
{
	switch (m_eWeaponType)
	{
	case WEAPONTYPE_COLT45:
	case WEAPONTYPE_UZI:
	case WEAPONTYPE_AK47:
	case WEAPONTYPE_M16:
		return true;
	default:
		return false;
	}
}

bool IsPlayerFullCurrentAmmo()
{
	CPlayerPed* player = FindPlayerPed();
	if (!player) { return false; }
	//if (!FindPlayerPed()) { return false; }
	CWeaponInfo* info = CWeaponInfo::GetWeaponInfo(FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].m_eWeaponType);
	int max_patrons_in_clip = info->m_nAmountofAmmunition;
	int full_patrons = player->m_aWeapons[player->m_nCurrentWeapon].m_nAmmoTotal; // max patrons has player
	int now_patrons = player->m_aWeapons[player->m_nCurrentWeapon].m_nAmmoInClip; // current clip

	//std::cout << "max_patrons_in_clip: " << max_patrons_in_clip << "\n";
	//std::cout << "full_patrons: " << full_patrons << "\n";
	//std::cout << "now_patrons: " << now_patrons << "\n";
	return now_patrons == max_patrons_in_clip;
}

bool IsPlayerCanReloadCurrentAmmo()
{
	CPlayerPed* player = FindPlayerPed();
	if (!player) { return false; }
	//if (!FindPlayerPed()) { return false; }
	CWeaponInfo* info = CWeaponInfo::GetWeaponInfo(player->m_aWeapons[player->m_nCurrentWeapon].m_eWeaponType);
	int max_patrons_in_clip = info->m_nAmountofAmmunition;
	int full_patrons = player->m_aWeapons[player->m_nCurrentWeapon].m_nAmmoTotal; // max patrons has player
	int now_patrons = player->m_aWeapons[player->m_nCurrentWeapon].m_nAmmoInClip; // current clip

	//std::cout << "max_patrons_in_clip: " << max_patrons_in_clip << "\n";
	//std::cout << "full_patrons: " << full_patrons << "\n";
	//std::cout << "now_patrons: " << now_patrons << "\n";
	//std::cout << "full_patrons > max_patrons_in_clip: " << (full_patrons > max_patrons_in_clip) << "\n";

	//return (full_patrons > max_patrons_in_clip);
	return ((full_patrons - now_patrons) > 0);
	//////return now_patrons == max_patrons_in_clip;
}

bool IsPlayerReloadingWeapon()
{
	CPlayerPed* player = FindPlayerPed();
	if (!player) { return false; }
	return player->m_aWeapons[player->m_nCurrentWeapon].m_eWeaponState == WEAPONSTATE_RELOADING;
}

void ReloadPlayerWeapoon()
{
	CPlayerPed* player = FindPlayerPed();
	if (!player) { return; }

	//bool USE_RELOAD_ANIM = !IsPlayerDriveVehicle(); // not used
	bool USE_RELOAD_ANIM = true;
	bool IS_RELOADABLE = IsReloadableWeapon(GetPlayerCurrentWeaponType());
	bool IS_FULL_CLIP = IsPlayerFullCurrentAmmo();
	bool IS_CAN_RELOAD = IsPlayerCanReloadCurrentAmmo();
	bool IS_NOW_RELOADING = IsPlayerReloadingWeapon();
	bool IS_PLAYER_LIVE = !(!player->m_fHealth); // !(died)
	bool QUICK_RELOAD = false;

	//std::cout << "IS_RELOADABLE?: " << IS_RELOADABLE << "\n";
	if (!IS_RELOADABLE || IS_FULL_CLIP || IS_NOW_RELOADING || (!IS_CAN_RELOAD) || (!IS_PLAYER_LIVE)) { return; }

	if (USE_RELOAD_ANIM)
	{
		//Mod CPed.h
		//https://raw.githubusercontent.com/imring/plugin-sdk/a17c5d933cb8b06e4959b370092828a6a7aa00ef/plugin_III/game_III/CPed.h
		//-------PedFight.cpp
		//CAnimBlendAssociation* reloadAnimAssoc = nullptr;
		AnimationId reloadAnim = AnimationId::ANIM_STD_NUM; //emanAnimGroup::ANIM_STD_NUM;
		//CAnimBlendAssociation* weaponAnimAssoc = RpAnimBlendClumpGetAssociation(GetPlayerClump(), ourWeapon->m_nAnimToPlay);
		CWeaponInfo* ourWeapon = GetPlayerCurrentWeaponInfo();
		int32_t weaponAnim = ourWeapon->m_nAnimToPlay;
		if (weaponAnim == AnimationId::ANIM_STD_WEAPON_HGUN_BODY) { reloadAnim = AnimationId::ANIM_STD_HGUN_RELOAD; }
		else if (weaponAnim == AnimationId::ANIM_STD_WEAPON_AK_BODY) { reloadAnim = AnimationId::ANIM_STD_AK_RELOAD; }
		CAnimManager::BlendAnimation(GetPlayerClump(), eAnimGroup::ANIM_GROUP_MAN, reloadAnim, 8.0f);
	}

	//int32_t WeaponType = FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].m_eWeaponType;
	//eWeaponType WeaponType = GetPlayerCurrentWeaponType();

	//emanAnimGroup reloadAnim = emanAnimGroup::ANIM_MAN_WEAPON_AK_RLOAD;
	//CAnimManager::BlendAnimation(GetPlayerClump(), eAnimGroup::ANIM_GROUP_MAN, reloadAnim, 8.0f);
	//CAnimManager::BlendAnimation(GetClump(), ASSOCGRP_STD, reloadAnim, 8.0f);

	if (QUICK_RELOAD) { player->m_aWeapons[player->m_nCurrentWeapon].Reload(); return; } // quick reload (!anim, !timeout)

	//----Weapon.cpp ()
	player->m_aWeapons[player->m_nCurrentWeapon].m_eWeaponState = WEAPONSTATE_RELOADING;
	player->m_aWeapons[player->m_nCurrentWeapon].m_nTimer = CTimer::m_snTimeInMilliseconds + GetPlayerCurrentWeaponInfo()->m_nReload;
	//if (CWorld::Players[CWorld::PlayerInFocus].m_bFastReload)
	//{
	//	player->m_aWeapons[player->m_nCurrentWeapon].m_nTimer = CTimer::m_snTimeInMilliseconds + GetPlayerCurrentWeaponInfo()->m_nReload / 4;
	//}

}





//------------------------FUCKU---ANIM
//------IN CPed.cpp
bool GetPlayerIsFuncUAnimPlayingNow()
{
	CAnimBlendAssociation* fuckUAssoc = RpAnimBlendClumpGetAssociation(GetPlayerClump(), ANIM_STD_PARTIAL_FUCKU);
	return (fuckUAssoc && fuckUAssoc->IsRunning());
}

void
CustomFinishFuckUCB(CAnimBlendAssociation* animAssoc, void* arg) // testing remove 
{
	CPed* ped = (CPed*)arg;
	CPlayerPed* player = FindPlayerPed();
	if ((ped != player) || (!player)) // default
	{
		if (animAssoc->m_nAnimID == ANIM_STD_PARTIAL_FUCKU && ped->m_aWeapons[ped->m_nCurrentWeapon].m_eWeaponType == WEAPONTYPE_UNARMED)
		{
			//ped->RemoveWeaponModel(0); // default
			ped->RemoveWeaponModel(MODEL_FINGERS);
		}
	}
	else // player
	{
		//bool is_armed_player = !IsUnArmedPlayer();
		bool is_uzi_player = IsWeaponUziPlayer(); // pistol armed when !uzi
		bool is_player_in_car = IsPlayerDriveVehicle();

		// can armed by uzi in vehicle
		//if (animAssoc->m_nAnimID == ANIM_STD_PARTIAL_FUCKU && ped->m_aWeapons[ped->m_nCurrentWeapon].m_eWeaponType == WEAPONTYPE_UNARMED)

		if (is_player_in_car && is_uzi_player && animAssoc->m_nAnimID == ANIM_STD_PARTIAL_FUCKU) // вернуть узи
		{ // remove finger (remove all weapons model). add uzi fix
			//ped->RemoveWeaponModel(0);
			ped->RemoveWeaponModel(MODEL_FINGERS);
			//CWeaponInfo* ourWeapon = GetPlayerCurrentWeaponInfo(); // может появиться пистолет если без проверки is_uzi_player
			//ped->AddWeaponModel(ourWeapon->m_nModelId);
			ped->AddWeaponModel(MODEL_UZI);
			//std::cout << "UZI+VEH" << "\n";
		}
		else if (is_player_in_car && animAssoc->m_nAnimID == ANIM_STD_PARTIAL_FUCKU) // pistol. player not have uzi. not add other weapon model
		{ // мы в машине убрать палец (m_eWeaponType pistol (ARMED))
			ped->RemoveWeaponModel(MODEL_FINGERS);
		}
		else // not in car
		{
			if (animAssoc->m_nAnimID == ANIM_STD_PARTIAL_FUCKU && ped->m_aWeapons[ped->m_nCurrentWeapon].m_eWeaponType == WEAPONTYPE_UNARMED)
			{ // убрать если чисто MODEL_FINGERS без других моделей
				//ped->RemoveWeaponModel(0);
				ped->RemoveWeaponModel(MODEL_FINGERS);
				//ped->RemoveWeaponModel(MODEL_FINGERS);
			} // else remove 0 and add armed model?
			else if (animAssoc->m_nAnimID == ANIM_STD_PARTIAL_FUCKU) // armed !car
			{
				ped->RemoveWeaponModel(MODEL_FINGERS); // no weapon model now
				CWeaponInfo* ourWeapon = GetPlayerCurrentWeaponInfo();
				ped->AddWeaponModel(ourWeapon->m_nModelId);
			}
		}


		//std::cout << "GetPlayerCurrentWeaponType(): " << GetPlayerCurrentWeaponType() << "\n";
		//std::cout << "is_uzi_player: " << is_uzi_player << "\n";
		//std::cout << "is_player_in_car: " << is_player_in_car << "\n";
		//ped->RemoveWeaponModel(0);
		//ped->RemoveWeaponModel(MODEL_FINGERS);
	}
}


void FuckUAnimPlayer(bool kuzkina_mat = false)
{
	CPlayerPed* player = FindPlayerPed();
	if (!player) { return; } // can fucku from car
	//if ((!player) || IsPlayerDriveVehicle()) { return; }
	//CAnimBlendAssociation* fuckUAssoc = RpAnimBlendClumpGetAssociation(GetPlayerClump(), ANIM_STD_PARTIAL_FUCKU);
	//CAnimManager::BlendAnimation(GetPlayerClump(), eAnimGroup::ANIM_GROUP_MAN, ANIM_STD_PARTIAL_FUCKU, 8.0f);
	bool IS_FUCKU_ANIM_NOW = GetPlayerIsFuncUAnimPlayingNow();
	bool is_uzi_player = IsWeaponUziPlayer(); // pistol armed when !uzi
	bool IS_PLAYER_LIVE = !(!player->m_fHealth); // !(died)
	bool is_player_in_car = IsPlayerDriveVehicle();
	bool is_remove_in_car_uzi_fucku = true;

	if (IS_FUCKU_ANIM_NOW || (!IS_PLAYER_LIVE)) { return; } // already playing
	if (is_player_in_car && is_uzi_player && is_remove_in_car_uzi_fucku) { player->RemoveWeaponModel(MODEL_UZI); }

	if (!kuzkina_mat) { player->AddWeaponModel(MODEL_FINGERS); }
	CAnimBlendAssociation* newAssoc = CAnimManager::BlendAnimation(GetPlayerClump(), eAnimGroup::ANIM_GROUP_MAN, ANIM_STD_PARTIAL_FUCKU, 4.0f);
	//if (newAssoc && (!kuzkina_mat)) // for returning uzi if in car + armed uzi
	if (newAssoc)
	{
		newAssoc->m_nFlags |= ASSOC_FADEOUTWHENDONE;
		newAssoc->m_nFlags |= ASSOC_DELETEFADEDOUT;
		if (newAssoc->m_nAnimID == ANIM_STD_PARTIAL_FUCKU)
		{
			//newAssoc->SetDeleteCallback(FinishFuckUCB, player);
			newAssoc->SetDeleteCallback(CustomFinishFuckUCB, player);
			player->AnnoyPlayerPed(true);
		}

	}
}


//void FuckUAnimPlayer()
//{
//	CPlayerPed* player = FindPlayerPed();
//	if (!player) { return; } // can fucku from car
//	//if ((!player) || IsPlayerDriveVehicle()) { return; }
//	//CAnimBlendAssociation* fuckUAssoc = RpAnimBlendClumpGetAssociation(GetPlayerClump(), ANIM_STD_PARTIAL_FUCKU);
//	CAnimManager::BlendAnimation(GetPlayerClump(), eAnimGroup::ANIM_GROUP_MAN, ANIM_STD_PARTIAL_FUCKU, 8.0f);
//}








//----HANDLERS-------------------------------------------------------------------------------------------------------
int glob_bpress_delay = 150;
void DebugScriptNamesHandler()
{
	int sleep_val = 1000 * 3; // sec update
	while (true)
	{
		system("cls");
		int cnt = 0;

		bool line_format = true;
		int line_cnt = 3;
		int line_cnt_tmp = 0;

		int num_offset = 0;

		for (CRunningScript* scr = CTheScripts::pActiveScripts; scr; scr = scr->m_pNext, ++cnt)
		{
			//if (i->m_bIsMission && i->m_bIsActive && !i->m_bIsExternal)
			//if (i->m_bIsMission && i->m_bIsActive)
			//---ALL---SCRIPTS
			{
				//std::string missionName = ToUpper(std::string(scr->m_szName));
				std::string missionName = std::string(scr->m_szName);
				//if (line_format) { std::cout << (cnt + 1) << ". " << missionName << ",  "; }
				//else { std::cout << (cnt + 1) << ". " << missionName << "\n"; } // stolbik

				if (line_format)
				{
					std::cout << (cnt + num_offset) << ". " << missionName;
					++line_cnt_tmp;
					if (line_cnt_tmp >= line_cnt) { line_cnt_tmp = 0; std::cout << "\n"; }
					else { std::cout << ",  "; }
				}
				else { std::cout << (cnt + num_offset) << ". " << missionName << "\n"; } // stolbik
			}
		}
		std::cout << "\n";
		std::cout << "TOTAL COUNT: " << cnt << "\n";
		std::cout << "\n";

		Sleep(sleep_val);
	}
}


int DebugScriptIPsReadJMPIPHandler(int script_num, std::string script_name = "")
{
	//std::string str = "";
	//std::cout << "" << "\n";
	//std::cin >> str;

	int val = 0;
	bool add_flag = false;
	std::cout << "\n"; // padding log
	while (true)
	{
		std::string input;
		if (script_name != "") { script_name = (script_name + " "); }
		std::cout << "Enter " << script_name << "IP(exit)(+val => ip+=val): ";
		std::cin >> input;
		input = Trim(input);
		if (input == "exit") { return -1; }

		try
		{
			if ((input != "") && (input[0])) { input = Replace(Replace(input, "+", ""), " ", ""); add_flag = true; }
			val = std::stoi(input);
			break;
		}
		catch (const std::exception& e) { std::cout << "INVALID IP!\n"; }
	}
	return DebugScriptIPsSetIP(script_num, val, add_flag);
}



//CRunningScript* GetScriptByNum(int num_script)
//{
//	CRunningScript* scr = CTheScripts::pActiveScripts;
//	for (int i = 0; i < num_script; i++) { /*if (!scr) { continue; }*/ scr = scr->m_pNext; }
//	return scr;
//}

CRunningScript* GetScriptByNum(int index_script)
{
	CRunningScript* scr = CTheScripts::pActiveScripts;
	int cnt = 0;
	for (; scr; scr = scr->m_pNext) { ++cnt; if (cnt >= index_script) { return scr; } }
	return scr;
}
int GetScriptCounts()
{
	int cnt = 0;
	for (CRunningScript* scr = CTheScripts::pActiveScripts; scr; scr = scr->m_pNext) { ++cnt; }
	return cnt;
}

void DebugScriptIPsHandler()
{
	int sleep_val = 10;

	int num_script = 0;
	std::string missionName = "";

	char next = 'T';
	char prev = 'R';
	char reset = 'Y';
	char b_ipmod = VK_SHIFT; // shift+T => enter IP

	while (true)
	{
		int max_scripts_num = GetScriptCounts();
		CRunningScript* scr = GetScriptByNum(num_script);
		//CRunningScript* scr = CTheScripts::pActiveScripts;

		if (scr) { missionName = std::string(scr->m_szName); }

		if (missionName == "") { missionName = std::string(scr->m_szName); }
		//if (scr) { missionName = std::string(scr->m_szName); }




		//for (int i = 0; i < num_script; i++) { if (!scr) { continue; } scr = scr->m_pNext; } //!!!!!!
		//if (scr) { missionName = std::string(scr->m_szName); }
		if (scr)
		{
			if (IsMenuActive()) { continue; }
			int base_ptr = reinterpret_cast<int>(CRunningScript::GetScriptSpaceBase());
			std::cout << num_script << "/" << max_scripts_num << ". " << missionName << " (IP: " << scr->m_nIp << ") (BASE: " << intToHexString(base_ptr) << ") (RES: " << intToHexString((scr->m_nIp) + base_ptr) << ")" << "\n";
			tScriptCommandData res = GetCMDByIP(base_ptr + (scr->m_nIp));
			if (res.name != "") { std::cout << "CODE:" << intToHexString(res.id, false) << ", (T:" << getTotalNumArgs(res) << ") COMM: " << res.name << "\n"; }
			//std::cout << "COMM: " << GetCMDNameByIP(base_ptr + (scr->m_nIp)) << "\n";
			//std::cout << num_script << ". " << missionName << " (IP: " << scr->m_nIp << ") (BASE: " << intToHexString(base_ptr) << " , " << base_ptr << ")" << "\n";
			//std::cout << num_script << ". " << missionName << " (IP: " << scr->m_nIp << ")" << "\n";

			//std::cout << num_script << ". " << missionName << " (IP: " << scr->m_nIp << ")";
			//std::cout << " (SP: " << scr->m_nSP << ")"; // 0
			////std::cout << " (SP: " << (int)scr->GetScriptSpaceBase() << ")"; // 0
			//std::cout << " (base: " << intToHexString(base) << ")"; // 0
			//std::cout << "\n";
			////CTheScripts::BaseBriefIdForContact;
		}


		//-----------BUTTONS---------
		//if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) && (GetAsyncKeyState('T') & 0x8000)) { /*scr = scr->m_pPrev;*/ --num_script; Sleep(button_delay); if (scr) { missionName = std::string(scr->m_szName); } }
		if ((GetAsyncKeyState(b_ipmod) & 0x8000) && (GetAsyncKeyState(next) & 0x8000) && (num_script >= 0))
		{
			int new_ip = DebugScriptIPsReadJMPIPHandler(num_script, missionName);
			std::cout << num_script << "/" << max_scripts_num << ". " << missionName << " (IP: " << new_ip << ")" << "\n"; // src not prepeare now
			Sleep(100);
			continue;
		}

		if ((GetAsyncKeyState(prev) & 0x8000) && (num_script > 0)) { /*scr = scr->m_pPrev;*/ --num_script; Sleep(glob_bpress_delay); }
		else if ((GetAsyncKeyState(next) & 0x8000) && (max_scripts_num > num_script)) { /*scr = scr->m_pNext;*/ ++num_script; Sleep(glob_bpress_delay); }
		else if (GetAsyncKeyState(reset) & 0x8000) { /*scr = CTheScripts::pActiveScripts;*/ num_script = 0; Sleep(glob_bpress_delay); }

		Sleep(sleep_val);
	}
}

void CreateCarHandler()
{
	char action = 'Y';

	while (true)
	{
		//CreateCar(eVehicleModel::MODEL_BANSHEE);
		if ((GetAsyncKeyState(action) & 0x8000)) { CreateCar(eVehicleModel::MODEL_BANSHEE); }
		Sleep(glob_bpress_delay);
	}
}

void KillPedPoolHandler()
{
	char action = 'T';

	while (true)
	{ // action all, SHIFT+action only car peds, CTRL+action only walking peds

		//  KillPool(0); kill player char
		// доп клавиши в начале
		if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) && (GetAsyncKeyState(action) & 0x8000)) { KillPedPool(2); } // only drivers
		else if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(action) & 0x8000)) { KillPedPool(3); } // only walked peds
		else if ((GetAsyncKeyState(action) & 0x8000)) { KillPedPool(1); } // all
		Sleep(glob_bpress_delay);
	}
}


void KillVehiclePoolHandler()
{
	char action = 'T';

	while (true)
	{
		if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) && (GetAsyncKeyState(action) & 0x8000)) { KillVehiclePool(1); }
		else if ((GetAsyncKeyState(action) & 0x8000)) { KillVehiclePool(0); }
		Sleep(glob_bpress_delay);
	}
}

void KillPoolsAndCreateCarHandler() // ctrl+shift+t vehiche pool
{
	char PPoolaction = 'T'; // ped
	char VPoolaction = 'R'; // vehicle
	char Caraction = 'Y';	// spawn banshee

	while (true)
	{ // action all, SHIFT+action only car peds, CTRL+action only walking peds

		//  KillPool(0); kill player char
		// доп клавиши в начале
		if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) && (GetAsyncKeyState(PPoolaction) & 0x8000)) { KillPedPool(2); } // only drivers
		else if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(PPoolaction) & 0x8000)) { KillPedPool(3); } // only walked peds
		else if ((GetAsyncKeyState(PPoolaction) & 0x8000)) { KillPedPool(1); } // all

		if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) && (GetAsyncKeyState(VPoolaction) & 0x8000)) { KillVehiclePool(1); } // all cars
		else if ((GetAsyncKeyState(VPoolaction) & 0x8000)) { KillVehiclePool(0); } // all pool but !player car

		if ((GetAsyncKeyState(Caraction) & 0x8000)) { CreateCar(eVehicleModel::MODEL_BANSHEE); }

		Sleep(glob_bpress_delay);
	}
}

void KillProcHandler()
{
	int sleep_val = 50;
	while (true)
	{
		//if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) && (GetAsyncKeyState(action) & 0x8000)) { KillPool(2); }
		if ((GetAsyncKeyState(VK_F10) & 0x8000)) { ExitProcess(0); }
		Sleep(sleep_val);
	}
}


void ReloadWeaponHandler()
{
	char action = 'R';
	//char reload_automobile = VK_SHIFT;
	//if ((GetAsyncKeyState(reload_automobile) & 0x8000) && IS_PLAYER_CHAR_IN_VEHICLE) { ReloadPlayerWeapoon(); Sleep(button_delay); } // reload in car

	while (true)
	{
		if ((GetAsyncKeyState(action) & 0x8000)) { ReloadPlayerWeapoon(); }
		Sleep(glob_bpress_delay);
	}
}



void FuckAnimHandler()
{
	char b_fucku = 'T';
	char shift = VK_SHIFT;

	while (true)
	{
		if ((GetAsyncKeyState(shift) & 0x8000) && (GetAsyncKeyState(b_fucku) & 0x8000)) { FuckUAnimPlayer(true); } // kuzkina mat
		else if ((GetAsyncKeyState(b_fucku) & 0x8000)) { FuckUAnimPlayer(); }
		Sleep(glob_bpress_delay);
	}
}

void TeleportPlayerHandler()
{
	std::string inputString;
	float x = 0.0f;
	float y = 0.0f;
	float z = 0.0f;
	bool print_flag = true;

	while (true)
	{
		Sleep(10);
		//if ((!IsPlayerActive()) || (IsMenuActive())) { continue; }
		if ((!IsPlayerActive())) { continue; }

		if (print_flag) { std::cout << "ENTER X Y Z LIKE 123.4: "; }
		print_flag = true;

		std::getline(std::cin, inputString);
		inputString = Trim(inputString);

		std::istringstream iss(inputString);
		if (iss >> x >> y >> z)
		{
			CVector destination = CVector(x, y, z);
			TeleportPlayer(destination);
			std::cout << "OK!" << std::endl;
		}
		else if (inputString != "") { std::cout << "ERROR VALS!" << std::endl; }
		else { print_flag = false; }
	}
}







//--------------------------TESTING
void TestFunc()
{
	//Command<eScriptCommands::COMMAND_CREATE_CAR>();
	//ANIM_STD_NUM 
	//emanAnimGroup reloadAnim = emanAnimGroup::ANIM_STD_AK_RELOAD;
	emanAnimGroup reloadAnim = emanAnimGroup::ANIM_MAN_WEAPON_AK_RLOAD;
	CAnimManager::BlendAnimation(GetPlayerClump(), eAnimGroup::ANIM_GROUP_MAN, reloadAnim, 8.0f);
	//CAnimManager::BlendAnimation(GetClump(), ASSOCGRP_STD, reloadAnim, 8.0f);


	FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].m_eWeaponState = WEAPONSTATE_RELOADING;
	FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].m_nTimer = CTimer::m_snTimeInMilliseconds + GetPlayerCurrentWeaponInfo()->m_nReload;
	if (CWorld::Players[CWorld::PlayerInFocus].m_bFastReload)
	{
		FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].m_nTimer = CTimer::m_snTimeInMilliseconds + GetPlayerCurrentWeaponInfo()->m_nReload / 4;
	}


	//FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].Reload(); // only patrons
	//std::cout << "TestFunc!!" << "\n";
}

void TestFuncHandler()
{
	char action = 'T';

	while (true)
	{
		//if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) && (GetAsyncKeyState(action) & 0x8000)) { KillPool(2); }
		if ((GetAsyncKeyState(action) & 0x8000)) { TestFunc(); }
		Sleep(glob_bpress_delay);
	}
}

void Test_eCommands()
{
	CPlayerPed* player = FindPlayerPed();
	if (!player) { return; }
	//Command<eScriptCommands::COMMAND_SET_CHAR_HEALTH>(player, 0);
	//Command<eScriptCommands::COMMAND_SET_CHAR_HEALTH>(player, 0); // CollectParameters(&m_nIp, 4); (id, CVector*)
	//FindPlayerPed()->m_aWeapons[FindPlayerPed()->m_nCurrentWeapon].Reload();
}

bool OnceFlagOnDraw = false;
void OnDraw()
{
	return;
	if (!OnceFlagOnDraw)
	{
		OnceFlagOnDraw = true;
		// once code
		InitConsole();
	}

	// testing IsPlayerDriveVehicle();
	//std::cout << "IsPlayerDriveVehicle?: " << IsPlayerDriveVehicle() << "\n";

}
//-----------------------------------------------------------------END TESTING







DWORD CALLBACK DebugScriptEntry(LPVOID)
{
	////InitConsole();
	int mode = 1; // 0 <=

	if (mode == 0) { InitConsole(); DebugScriptNamesHandler(); } // dump all script names
	else if (mode == 1) { InitConsole(); DebugScriptIPsHandler(); } // dump ip target ip
	else if (mode == 2) { KillPedPoolHandler(); } // kill pedpoll (!console) (only log cnt pool)
	else if (mode == 3) { KillVehiclePoolHandler(); } // KillVehiclePoolHandler(T) (!console)
	else if (mode == 4) { CreateCarHandler(); } // spawn car(Y) (!console)
	else if (mode == 5) { KillPoolsAndCreateCarHandler(); } // kill ped(T)+vehiclepoll(R) + spawn car(Y) (!console)
	else if (mode == 6) { ReloadWeaponHandler(); } // ReloadWeaponHandler(R) (!console)
	else if (mode == 7) { FuckAnimHandler(); } // FuckAnimHandler(T) (!console)
	else if (mode == 8) { TeleportPlayerHandler(); } // TeleportPlayerHandler() (!console)
	else if (mode == 9) { KillProcHandler(); } // KillProcHandler(F10) (!console)
	else if (mode == 777) { InitConsole(); TestFuncHandler(); } // TestFuncHandler(T) (!console)

	else { return FALSE; }

	//DebugScriptNamesHandler();
	//DebugScriptIPsHandler();
	//KillPedPoolHandler();
	//KillVehiclePoolHandler();
	//CreateCarHandler();
	//KillPoolsAndCreateCarHandler();
	//KillProcHandler();

	return TRUE;
}

void
StartDebugScriptThread()
{
	CreateThread(NULL, 0, DebugScriptEntry, NULL, 0, NULL);
}






void OnStart()
{
	//InitConsole();
	StartDebugScriptThread();
}


bool initRwEventFIX = false;

class GTA3_SCRIPT_DUBUGGER {
public:
	GTA3_SCRIPT_DUBUGGER() {

		//OnStart();

		Events::initGameEvent += [] {
			if (initRwEventFIX) { return; } // adapter to initRwEvent
			else { initRwEventFIX = true; }
			//---1st init
			//StartEntryThread();
			OnStart();
		};


		Events::drawHudEvent += [] { OnDraw(); };

		//Events::shutdownRwEvent += [] {};

	}
} gTA3_SCRIPT_DUBUGGER;




//void InitCFG(std::string& config_path)
//{
//	if (!FileExists(config_path))
//	{ // mk ini
//		//std::ofstream outfile(config_path);
//		if (!MkCFG(config_path)) { Mbox("InitCFG couldnt create ini file!", "ERROR"); return; }
//	}
//	//if (!FileExists(config_path)) { Mbox("InitCFG couldnt create ini file!", "ERROR"); return; }
//
//	//std::ifstream infile(config_path);
//	//std::locale loc("C");
//	//infile.imbue(loc); // для парсинга 1.2f
//
//	//if (infile.is_open())
//	//{
//	//	std::string firstLine = ""; // soundline
//
//	//	std::string line;
//	//	int i = 0;
//	//	while (getline(infile, line)) // FUCKING getline(infile >> std::ws, tmp) coudnt parse
//	//	{
//	//		++i;
//	//		int s5 = std::stoi(line);
//	//		int SpinStartSpeed = std::stof(line);
//	//	}
//	//	infile.close();
//	//}
//
//	std::vector<std::string> cfg = FileReadAllLines(config_path);
//
//	std::string _delayDuration = cfg[1];
//	std::string _healthdiff = cfg[3];
//	//std::string _maxdamage = cfg[5];
//	std::string _healthdamagekoef = cfg[5];
//
//	// Устанавливаем временную локаль с точкой в качестве разделителя
//	std::locale prevLoc = std::locale::global(std::locale("C"));
//
//	delayDuration = std::stof(_delayDuration);
//	healthdiff = std::stof(_healthdiff);
//	//maxdamage = std::stof(_maxdamage);
//	healthdamagekoef = std::stof(_healthdamagekoef);
//
//	// Восстанавливаем предыдущую локаль
//	std::locale::global(prevLoc);
//}
