#pragma once

#include "..//Eyestep/memedit.hpp"
#include "..//Eyestep/memscan.hpp"
#include "..//Eyestep/routine_mgr.hpp"

#include <Windows.h>
#include <iostream>

using namespace std;

void Console(LPCSTR Name)
{
	// Bypass Roblox's anti-console
	DWORD Old = 0;
	VirtualProtect(FreeConsole, 1, PAGE_EXECUTE_READWRITE, &Old); // Change protection of FreeConsole to ReadWrite
	*(uintptr_t*)FreeConsole = 0xC3; // ret

	// Allocate our console
	AllocConsole();

	// Open out streams
	freopen("CONOUT$", "w", stdout); // Open output stream to the console
	freopen("CONIN$", "r", stdin); // Open input stream from the console

	SetWindowLong(
		GetConsoleWindow(),
		GWL_STYLE, WS_CAPTION | WS_MINIMIZEBOX | WS_SYSMENU
	);

	SetWindowPos(
		GetConsoleWindow(),
		HWND_TOPMOST,
		0, 0, // X and Y
		0, 0,  // uX and uY
		SWP_DRAWFRAME | SWP_NOSIZE | SWP_SHOWWINDOW // Flags
	);

	SetConsoleTitleA(Name);
}

/*
	This function fix aslr plus add on 0x4000 as the disassembler is typically off by
	that exact amount on every address
*/
uint32_t aslr(uint32_t address)
{
	return (address - reinterpret_cast<uint32_t>(disassembler::base_module)) + 0x400000 + 0x4000;
}

double AddressCount = 0;

/*
	This function prints addresses to the console with the callinv conv
*/
void PrintAddress(string Name, uintptr_t Address)
{
	AddressCount++;
	cout << Name << ": " << "0x" << std::hex << aslr(Address) << " " << str_conv(routine_mgr::get_conv(Address, get_arg_count(Address))) << endl;
}

/*
	This function can get a address that contains a string and the xref of it so if their are multiple you
	can get a different one
*/
uintptr_t GetCallingFunctionFromString(const char* string, int xref)
{
	auto functions_scan = new scanner::memscan();
	functions_scan->scan_xrefs(string, xref);
	auto results = functions_scan->get_results();
	auto first_xref = results.front();
	auto address = get_prologue<behind>(first_xref);
	delete functions_scan;
	return address;
}

/*
	This function gets a specific xref of an address for where it is used
	in other functions
*/
uintptr_t GetXref(uintptr_t Address, int xref)
{
	auto xref_scan = new scanner::memscan();
	xref_scan->scan_xrefs(Address);
	auto results = xref_scan->get_results();
	auto xrefn = results[xref];
	auto address = get_prologue<behind>(xrefn);
	delete xref_scan;
	return address;
}

/*
	This function gets all xrefs of an address
*/
std::vector<uintptr_t> GetXrefs(uintptr_t Address)
{
	auto xref_scan = new scanner::memscan();
	xref_scan->scan_xrefs(Address);
	auto results = xref_scan->get_results();

	std::vector<uintptr_t> Final = {};

	for (auto i : results)
	{
		Final.push_back(get_prologue<behind>(i));
	}
	return Final;
}

/*
	This function finds asm code in a given string then returns
	true or false if it found it
*/
bool FindASM(string ASM, string ToFind)
{
	return ASM.find(ToFind) != std::string::npos;
}

/*
	This function gets the size of a portion of asm code starting
	at an address then ending at a specific instruction, useful for
	getting the size of functions
*/
int GetSizeTo(uintptr_t Address, string Instruction, int MaxSearch)
{
	double size = 0;
	for (disassembler::inst i : disassembler::read(Address, MaxSearch))
	{
		// Check if we have found the instruciton to stop at
		// add one more to size to count for the instruction we hit
		if (FindASM(i.data, Instruction)) { size++; break; }

		// add to size as long as we dont hit break
		size++;
	}
	return size;
}