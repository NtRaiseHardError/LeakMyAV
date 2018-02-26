#include <iostream>
#include <string>
#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

typedef enum _HOOK_TYPE {
	NOT_HOOKED,
	RELATIVE_TRAMPOLINE,
	ABSOLUTE_TRAMPOLINE,
	RELATIVE_HOOK,
	ABSOLUTE_HOOK
} HOOK_TYPE;


// https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/master/anticuckoo.cpp
HOOK_TYPE checkHook(const unsigned char *address, unsigned int& addressOffset) {
	if (address[0] == 0xE9) {																			// jmp address
		addressOffset = 1;
		return RELATIVE_TRAMPOLINE;
	} else if (address[0] == 0xFF && address[1] == 0x25) {												// call address
		addressOffset = 2;
		return ABSOLUTE_TRAMPOLINE;
	} else if ((address[0] == 0xB8 && address[5] == 0xFF && address[6] == 0xE0) ||						// mov address into r16/32, jmp eax
		(address[0] == 0xB8 && address[5] == 0x50 && address[6] == 0xC3) ||								// mov address into r16/32, push r16/32, ret
		(address[0] == 0xA1 && address[5] == 0xFF && address[6] == 0xE0) ||								// mov address into eax, jmp eax
		(address[0] == 0xA1 && address[5] == 0x50 && address[6] == 0xC3) ||								// mov address into eax, push r16/32, ret
		(address[0] == 0x68 && address[5] == 0xC3)) {													// push address, ret
		addressOffset = 1;
		return ABSOLUTE_HOOK;
	} else if (address[0] == 0x90 && address[1] == 0xE9) {												// nop, jump rel32 address
		addressOffset = 2;
		return RELATIVE_HOOK;
	} else if (address[0] == 0x90 && address[1] == 0x68 && address[6] == 0xC3) {						// nop, push address, ret
		addressOffset = 2;
		return ABSOLUTE_HOOK;
	} else if (address[0] == 0x8B && address[1] == 0xFF && address[2] == 0xE9) {
		addressOffset = 3;
		return RELATIVE_HOOK;
	} else if ((address[0] == 0x8B && address[1] == 0xFF && address[2] == 0xFF && address[3] == 0x25) ||		// mov address into r16/32, call address
		(address[0] == 0x90 && address[1] == 0x90 && address[3] == 0xE9)) {								// nop, nop, jmp rel32 address
		addressOffset = 4;
		return ABSOLUTE_HOOK;
	} else if (address[5] == 0xFF && address[6] == 0x25) {												// call address indirect, far?, absolute
		addressOffset = 7;
		return ABSOLUTE_HOOK;
	}

	return NOT_HOOKED;
}

bool getModuleNameByAddress(const DWORD_PTR dwBaseAddress, std::string& hModuleName) {
	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, ::GetCurrentProcessId());
	if (!hProcess)
		return false;

	// get base address module name
	DWORD cbNeeded = 0;
	HMODULE hMods[1024];
	if (::EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			if ((DWORD_PTR)hMods[i] == dwBaseAddress) {
				CHAR szModName[MAX_PATH];

				// Get the full path to the module's file.
				if (::GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
					hModuleName = ::PathFindFileNameA(szModName);
					::CloseHandle(hProcess);
					return true;
				}
			}
		}
	}

	hModuleName = "<not found>";
	return false;
}

void iterateModuleFunctions(const HMODULE hModule) {
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pidh->e_lfanew);

	// get export table
	PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// walk export table
	for (unsigned int ordinal = pied->Base; ordinal < pied->NumberOfFunctions; ordinal++) {
		// get proc address
		FARPROC fpFunc = (FARPROC)((DWORD_PTR)hModule + ((LPDWORD)((DWORD_PTR)hModule + pied->AddressOfFunctions))[ordinal]);
		
		// get func name
		std::string funcName = "<no name>";
		if (ordinal < pied->NumberOfNames)
			funcName = (char *)((DWORD_PTR)hModule + ((LPDWORD)((DWORD_PTR)hModule + pied->AddressOfNames))[ordinal]);

		// check hook
		unsigned int addrOffset = 0;
		HOOK_TYPE ht = checkHook((unsigned char *)fpFunc, addrOffset);
		// if hooked, log
		if (ht != HOOK_TYPE::NOT_HOOKED) {
			// query module address and name
			MEMORY_BASIC_INFORMATION mbi;
			LPVOID lpAddress = nullptr;

			// calculate address of hook
			if (ht == HOOK_TYPE::RELATIVE_HOOK || ht == HOOK_TYPE::RELATIVE_TRAMPOLINE) {
				//								relative distance							relative address
				lpAddress = (LPVOID)(*(PINT)((LPBYTE)fpFunc + addrOffset) + (DWORD_PTR)((LPBYTE)fpFunc + addrOffset + 4));
			} else if (ht == HOOK_TYPE::ABSOLUTE_HOOK || ht == HOOK_TYPE::ABSOLUTE_TRAMPOLINE)
#ifdef _WIN64
				lpAddress = (LPVOID)(*(PINT)((LPBYTE)fpFunc + addrOffset) + (DWORD_PTR)((LPBYTE)fpFunc + addrOffset + 4));
#else
				lpAddress = (LPVOID)(*(LPDWORD)((LPBYTE)fpFunc + addrOffset));
#endif // _WIN64


			// query base address
			std::string hModuleName;
			if (::VirtualQuery(lpAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
				// query associated module
				getModuleNameByAddress((DWORD_PTR)mbi.AllocationBase, hModuleName);
			//	if (!getModuleNameByAddress((DWORD_PTR)mbi.AllocationBase, hModuleName))
			//		std::cout << "[-] Get Module Name error: " << ::GetLastError() << "\n";
			} //else
			//	std::cout << "[-] VirtualQuery error: " << ::GetLastError() << "\n";

			if ((DWORD_PTR)mbi.AllocationBase != (DWORD_PTR)hModule) {
				std::cout << "[!] " << funcName << " (ordinal: 0x" << std::hex << ordinal << ")";
				if (ht == HOOK_TYPE::RELATIVE_TRAMPOLINE || ht == HOOK_TYPE::ABSOLUTE_TRAMPOLINE)
					std::cout << " has a trampoline (potentially hooked)!\n>>> Location: " << hModuleName << " (0x" << std::hex << lpAddress << ")\n";
				else if (ht == HOOK_TYPE::ABSOLUTE_HOOK || ht == HOOK_TYPE::RELATIVE_HOOK)
					std::cout << " is hooked!\n>>> Location: " << hModuleName << " (0x" << std::hex << lpAddress << ")\n";
			}
		}
	}

	std::cout << "\n";
}

int main(int argc, char *argv[]) {
	std::cout << "[*] Checking hooks in kernel32.dll...\n";
	iterateModuleFunctions(::GetModuleHandle(TEXT("kernel32.dll")));
	std::cout << "[*] Checking hooks in ntdll.dll...\n";
	iterateModuleFunctions(::GetModuleHandle(TEXT("ntdll.dll")));
	std::cout << "[*] Checking hooks in user32.dll...\n";
	iterateModuleFunctions(::LoadLibrary(TEXT("user32.dll")));
	std::cout << "[*] Checking hooks in KernelBase.dll...\n";
	iterateModuleFunctions(::LoadLibrary(TEXT("KernelBase.dll")));
	std::cout << "[*] Checking hooks in shlwapi.dll...\n";
	iterateModuleFunctions(::GetModuleHandle(TEXT("shlwapi.dll")));
	std::cout << "[*] Checking hooks in msvcrt.dll...\n";
	iterateModuleFunctions(::GetModuleHandle(TEXT("msvcrt.dll")));
	std::cout << "[*] Checking hooks in WinHTTP.dll...\n";
	iterateModuleFunctions(::LoadLibrary(TEXT("WinHTTP.dll")));
	std::cout << "[*] Checking hooks in ws2_32.dll...\n";
	iterateModuleFunctions(::LoadLibrary(TEXT("ws2_32.dll")));
	std::cout << "[*] Checking hooks in WinINet.dll...\n";
	iterateModuleFunctions(::LoadLibrary(TEXT("WinINet.dll")));
	std::cout << "[*] Checking hooks in Ole32.dll...\n";
	iterateModuleFunctions(::LoadLibrary(TEXT("Ole32.dll")));

	int i;
	std::cin >> i;

	return 0;
}