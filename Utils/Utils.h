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
