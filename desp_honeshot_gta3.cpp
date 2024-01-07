#include "XMemory/XMemory.h"

#include "Windows.h"
#include <iostream>
//#include <sstream>

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

void LeaveConsole(HANDLE hConsole) // with proto
{
	if (hConsole != nullptr) { SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); } // Reset to default color
	FreeConsole();
}






void* g_mem_block = nullptr;
void HelperFunc()
{
	if (!g_mem_block) { return; }
	std::cout << "\n";
	//std::cout << "TestFunc!!!" << "\n";

	void* _this = (void*)ReadPtrDanger<uintptr_t>(Transpose(g_mem_block, (0 * sizeof(void*)))); // CPed target
	int method = ReadPtrDanger<int>(Transpose(g_mem_block, (1 * sizeof(void*)))); // eWeaponType
	int pedPiece = ReadPtrDanger<int>(Transpose(g_mem_block, (2 * sizeof(void*)))); // ePedPieceTypes
	//bool willLinger = ReadPtrDanger<char>(Transpose(g_mem_block, (3 * sizeof(void*)))); // not remove el flag  ??

	if (!_this) { return; }

	//std::cout << "_this: " << intToHexString((uintptr_t)_this) << std::endl;
	//std::cout << "method: " << intToHexString(method) << std::endl;
	//std::cout << "pedPiece: " << intToHexString(pedPiece) << std::endl;
	//std::cout << "willLinger: " << intToHexString(willLinger) << std::endl;


	if ((((method > WEAPONTYPE_BASEBALLBAT) && (method < WEAPONTYPE_ROCKETLAUNCHER)) && (pedPiece == PEDPIECE_HEAD)))
	{
		((CPed*)_this)->m_fHealth = 0.0f;
	}

	//----CLS
	//WriteDanger<int>(Transpose(g_mem_block, (0 * sizeof(void*))), 0x00);
	//WriteDanger<int>(Transpose(g_mem_block, (1 * sizeof(void*))), 0x00);
	//WriteDanger<int>(Transpose(g_mem_block, (2 * sizeof(void*))), 0x00);
	//WriteDanger<int>(Transpose(g_mem_block, (3 * sizeof(void*))), 0x00);
}






void PatchTest()
{
	//https://eax.me/assembler-basics/
	//InitConsole();


	//CPed::InflictDamage
	void* orig_ptr_for_patch_reference = (void*)0x4EACC0; // !jmp !jz !mov NO OFFSETS OPCODES (def patch sz 5bytes)
	int available_sz_patch = 51; // дёрнуть байты из орига
	int need_sz_patch = 200; // bytes // доп блок
	int offset = 50; // max need_sz_patch(будет в конце перед jmp)  block(200+51+1+4)
	bool jmp_patch_in_end_region = false;

	//---OUT
	void* out_patch_ptr = nullptr;
	int out_patch_sz = 0; // mbi.region_sz
	//bool res = SetPatchBlock(orig_ptr_for_patch_reference, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, true, offset); // jmp in the end region
	bool res = SetPatchBlock(orig_ptr_for_patch_reference, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, jmp_patch_in_end_region, offset); // jmp after need_sz_patch
	void* moved_block = Transpose(out_patch_ptr, offset);
	void* jmp = Transpose(moved_block, 46); // 0x4EACEE old  // 0xE9 jmp (4b)
	void* retn_false_label_ptr = (void*)0x4EADDA;


	//----fix jmp offset   JMP  РАБОТАЕТ МОИМ МЕТОДОМ И ЧЕРЕЗ InsertJump
	//int offset_4_jmp = CalcJMPE9Offset(jmp, retn_false_label_ptr); // работает также, InsertJump элегантнее
	//WriteDanger<int>(Transpose(jmp, sizeof(char)), offset_4_jmp); // InsertJump ?
	InsertJump(jmp, retn_false_label_ptr);
	//-----------------END----FIX----MATH




	// write patch
	/*; Байты для загрузки значения float из памяти по адресу 0x12345 в регистр eax
	8b 05 23 01 00        ; mov eax, 0x123
	; Байты для сохранения значения float в регистре eax по адресу [esp + 14]
	89 44 24 14           ; mov dword [esp + 14], eax*/
	//mov destination, source


	void* patch_ptr = Transpose(out_patch_ptr, 0);
	void* buff = MkMem((4 * sizeof(void*))); // bytes // usage 4 * 3
	if (!buff) { return; }
	g_mem_block = buff;
	// _this method pedPiece willLinger




	//-----this thiscall в ecx но код иногда перезаписывает его в 1, хукай начало для перехвата ecx
	//--offset esp
	//!!!через esp + 0x50
	// buff = [esp + 0x50] (this CPed target)
	//WriteDanger<char>(Transpose(nop_test_fld, 18), 0x8B); // mov
	//WriteDanger<char>(Transpose(nop_test_fld, 19), 0x44);
	//WriteDanger<char>(Transpose(nop_test_fld, 20), 0x24);
	//WriteDanger<char>(Transpose(nop_test_fld, 21), 0x50); // offset
	////----mov ptr, eax
	//WriteDanger<char>(Transpose(nop_test_fld, 22), 0xA3); // mov ptr eax
	//WriteDanger<uintptr_t>(Transpose(nop_test_fld, 23), (uintptr_t)Transpose(buff, (2 * sizeof(void*))));

	//--ecx => ptr (мусор 1)
	// 0x89 0x0D PO IN TE RR  загрузит ecx в адрес !!!!
	// 0x8B 0x0D PO IN TE RR загрузит из адреса в ecx
	//WriteDanger<char>(Transpose(nop_test_fld, 18), 0x89);  // mov ptr ecx   // 89 0D ?? mov [0AB70000], ecx
	//WriteDanger<char>(Transpose(nop_test_fld, 19), 0x0D);
	//WriteDanger<uintptr_t>(Transpose(nop_test_fld, 20), (uintptr_t)Transpose(buff, (2 * sizeof(void*))));

	// копируем ebp в первый блок, this pointer
	//--через ebp, thiscall юзает ecx в начале, функция затирает
	// buff = ebp (this CPed target) // untested [esp + 0x50] ///BASE 004EA420
	WriteDanger<char>(Transpose(patch_ptr, 0), 0x89); // mov ptr, ebp
	WriteDanger<char>(Transpose(patch_ptr, 1), 0x2D);
	WriteDanger<uintptr_t>(Transpose(patch_ptr, 2), (uintptr_t)Transpose(buff, (0 * sizeof(void*))));



	// копируем [esp + 0x38] через eax во второй блок, method
	// buff = [esp + 0x38] (method)
	//!!!!!!!!!!!!!!!!!!!!!!!!!!!
	//mov eax, [esp + 0x38]						8B 44 54 38
	//mov [адрес_памяти], eax  без офсета		A3 PO IN TE RR

	//---mov eax [esp + 0x38]
	WriteDanger<char>(Transpose(patch_ptr, 6), 0x8B); // work mov 2 eax
	WriteDanger<char>(Transpose(patch_ptr, 7), 0x44); // mov esp + offset to eax
	WriteDanger<char>(Transpose(patch_ptr, 8), 0x24);
	WriteDanger<char>(Transpose(patch_ptr, 9), 0x38); // offset

	//----mov ptr, eax
	WriteDanger<char>(Transpose(patch_ptr, 10), 0xA3); // mov ptr eax  load eax to pointer
	WriteDanger<uintptr_t>(Transpose(patch_ptr, 11), (uintptr_t)Transpose(buff, (1 * sizeof(void*))));




	// копируем [esp + 0x40] через eax в третий блок, pedpice
	// buff = [esp + 0x40] (pedpice)
	WriteDanger<char>(Transpose(patch_ptr, 15), 0x8B); // mov
	WriteDanger<char>(Transpose(patch_ptr, 16), 0x44); // mov esp + offset to eax
	WriteDanger<char>(Transpose(patch_ptr, 17), 0x24);
	WriteDanger<char>(Transpose(patch_ptr, 18), 0x40); // offset

	//----mov ptr, eax
	WriteDanger<char>(Transpose(patch_ptr, 19), 0xA3); // mov ptr eax  load eax to pointer
	WriteDanger<uintptr_t>(Transpose(patch_ptr, 20), (uintptr_t)Transpose(buff, (2 * sizeof(void*))));




	//---------------------------------------------------------------------fix offsets (willLinger) не используеться
	//// buff = [esp + 0x0C] (willLinger) или часть тела 
	//WriteDanger<char>(Transpose(nop_test_fld, 24), 0x8B); // mov
	//WriteDanger<char>(Transpose(nop_test_fld, 25), 0x44);
	//WriteDanger<char>(Transpose(nop_test_fld, 26), 0x24);
	//WriteDanger<char>(Transpose(nop_test_fld, 27), 0x0C); // offset

	////----mov ptr, eax
	//WriteDanger<char>(Transpose(nop_test_fld, 28), 0xA3); // mov ptr eax
	//WriteDanger<uintptr_t>(Transpose(nop_test_fld, 29), (uintptr_t)Transpose(buff, (3 * sizeof(void*)))); // char !!!

	////---очистка байта на байт больше
	//WriteDanger<char>(Transpose(nop_test_fld, 33), 0xC7); // mov [aab000C], 00 00 00 00
	////WriteDanger<char>(Transpose(nop_test_fld, 33), 0xC6); // mov [aab000C], 00
	//WriteDanger<char>(Transpose(nop_test_fld, 34), 0x05);
	//WriteDanger<uintptr_t>(Transpose(nop_test_fld, 35), (uintptr_t)Transpose(buff, (3 * sizeof(void*)) + 1)); // char !!!
	//WriteDanger<int>(Transpose(nop_test_fld, 39), 0x00);
	//// write buff * (3*szof()) + 1   3 zero


	//---------вызываем call myfunc без аргументов
	WriteDanger<char>(Transpose(patch_ptr, 24), 0xE8); // call
	InsertCall(Transpose(patch_ptr, 24), HelperFunc);
	//WriteDanger<int>(Transpose(patch_ptr, 25), CalcJMPE9Offset(Transpose(patch_ptr, 24), HelperFunc)); // call func

}







bool initRwEventFIX = false;

class desp_honeshot_gta3 {
public:
	desp_honeshot_gta3() {

		//InitConsole();
		//Patch1();
		//CreateHandlersThread();
		PatchTest();


		Events::initGameEvent += [] {
			if (initRwEventFIX) { return; } // adapter to initRwEvent
			else { initRwEventFIX = true; }
			//InitConsole();
			//Patch1();
			//PatchProtectMem();
		};

		Events::drawHudEvent += []
		{
			//CPlayerPed* player = FindPlayerPed();
			//if (!player) { return; }

			//PatchProtectMem();
			//Test();
			//std::cout << "test: " << test << "\n";
		};

		//Events::shutdownRwEvent += [] {};           
	}
} _desp_honeshot_gta3;
