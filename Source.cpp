#include "Utils/Utils.h"

/*
	( This dumper was inspired by code i saw in Xenon's Dumper, actually i litterally just saw them using )
	( Xrefs of index2adr and retcheck and recreated it in C++ so yeah credits to them for the idea, lmao )
	( https://github.com/LegitH3x0R/Xenon/ )

	How this dumper works:
		This dumper works by getting xrefs of two functions called Index2adr and Retcheck
		xrefs are functions where the function appears and is used, index2adr is used in
		many lua functions and is self explanitory, retcheck is a check roblox implemented
		into a slew of their lua functions that we can also use to grab addresses, with both
		of these combined we can get 72 addresses from only two functions, what a steal!
		from those we could get hundreds of addresses from getting functions above and below,
		getting calls those funtions make, wow we could do so much! but i will only show us getting
		all these functions, its not like roblox can do much about it other then change the order
		of xrefs which is easily updated!
*/

// Function Scan

uintptr_t LOADED = GetCallingFunctionFromString("_LOADED", 1);
std::vector<uintptr_t> LOADEDInternal = get_calls(LOADED);

// End Function Scan

std::vector<string> Index2AdrList =
{
	"lua_rawvalue",
	"lua_getfenv", 
	"lua_getfield",
	"lua_getmetatable",
	"lua_gettable",
	"lua_getupvalue",
	"lua_insert",
	"lua_isuserdata",
	"lua_iscfunction",
	"lua_isnumber",
	"lua_isstring",
	"lua_lessthan", "lua_lessthan",
	"lua_next",
	"lua_objlen",
	"lua_pcall",
	"lua_pushvalue",
	"lua_rawequal", "lua_rawequal",
	"lua_rawget",
	"Undefined",
	"lua_rawgeti",
	"lua_rawset",
	"lua_rawseti",
	"luaL_ref",
	"lua_remove",
	"lua_replace",
	"lua_setfenv",
	"lua_setfield",
	"lua_setmetatable",
	"lua_setreadonly",
	"lua_setsafeenv",
	"lua_settable",
	"lua_setupvalue",
	"lua_toboolean",
	"lua_tointeger",
	"lua_tolstring", "lua_tolstring",
	"lua_tonumber",
	"lua_topointer", "lua_topointer",
	"lua_tostring",
	"Undefined",
	"lua_tothread",
	"lua_tounsigned",
	"lua_touserdata",
	"Undefined",
	"Undefined",
	"lua_type",
	"Undefined"
};

std::vector<string> RetcheckList =
{
	"", // "vector out of range" go kill yourself vs
	"f_call",
	"lua_call",
	"Undefined",
	"lua_concat",
	"lua_createtable",
	"lua_gc",
	"AlreadyFound", //"lua_getfenv",
	"AlreadyFound", //"lua_getfield",
	"AlreadyFound", //"lua_getmetatable",
	"AlreadyFound", //"lua_gettable",
	"AlreadyFound", //"lua_getupvalue",
	"AlreadyFound", //"lua_insert",
	"AlreadyFound", //"lua_lessthan",
	"lua_newthread",
	"lua_newuserdata",
	"AlreadyFound", //"lua_next",
	"lua_objlen",
	"AlreadyFound", //"lua_pcall",
	"lua_pushboolean",
	"lua_pushcclosure",
	"lua_pushfstring",
	"lua_pushinteger",
	"lua_pushlightuserdata",
	"lua_pushlstring",
	"lua_pushnil",
	"lua_pushnumber",
	"lua_pushstring",
	"lua_pushthread",
	"Undefined",
	"AlreadyFound", //"lua_pushvalue",
	"Undefined",
	"lua_pushvfstring",
	"lua_checkstack",
	"AlreadyFound", //"lua_rawget",
	"Undefined",
	"AlreadyFound", //"lua_rawgeti",
	"AlreadyFound", //"lua_rawset",
	"AlreadyFound", //"lua_rawseti",
	"AlreadyFound", //"luaL_ref",
	"AlreadyFound", //"lua_remove",
	"AlreadyFound", //"lua_replace",
	"AlreadyFound", //"lua_setfenv",
	"AlreadyFound", //"lua_setfield",
	"AlreadyFound", //"lua_setmetatable",
	"AlreadyFound", //"lua_setreadonly",
	"AlreadyFound", //"lua_setsafeenv",
	"AlreadyFound", //"lua_settable",
	"lua_settop",
	"AlreadyFound", //"lua_setupvalue",
	"AlreadyFound", //"lua_tolstring",
	"AlreadyFound", //"lua_tolstring",
	"Undefined",
	"lua_xmove",
	"Undefined",
	"lua_resume",
	"Undefined",
	"lua_yield",
	"resume_error",
	"luaU_callhook",
	"lua_getarguments",
	"lua_getinfo",
	"lua_getlocal",
	"lua_setlocal",
};

void main()
{
	Console("Arcana Dumper (XREF VERSION)");

	disassembler::open(GetCurrentProcess());

	// Use my smart asm scanning
	uintptr_t Getfield = LOADEDInternal[1];

	// get calls from getfield
	vector<uintptr_t> GetfieldCalls = get_calls(Getfield);

	// get first call in getfield which is usually index2adr
	uintptr_t Index2adr = GetfieldCalls[0];

	// get the last call in getfield which is usually retcheck
	uintptr_t Retcheck = GetfieldCalls[GetfieldCalls.size() - 1];

	// Get xrefs of Index2adr
	vector<uintptr_t> Index2adrXREFs = GetXrefs(Index2adr);

	// Get xrefs of Retcheck
	vector<uintptr_t> RetcheckXREFs = GetXrefs(Retcheck);

	system("cls");

	PrintAddress("Index2adr", Index2adr);
	PrintAddress("Retcheck", Retcheck);

	for (int idx = 1; idx < Index2adrXREFs.size(); idx++)
	{
		string Name = Index2AdrList[idx];
		if (Name != "Undefined")
		{
			if (Index2AdrList[idx - 1] != Name)
			{
				PrintAddress(Name, Index2adrXREFs[idx]);
			}
		}
	}

	for (int idx = 1; idx < RetcheckList.size(); idx++)
	{
		string Name = RetcheckList[idx];
		if (Name != "Undefined")
		{
			if (Name != "AlreadyFound")
			{
				if (RetcheckList[idx - 1] != Name)
				{
					PrintAddress(Name, RetcheckXREFs[idx-1]);
				}
			}
		}
	}

	cout << "\n";

	cout << "Printed " << AddressCount << " Addresses!" << endl;
}

BOOL WINAPI DllMain(
	HINSTANCE Module,  // handle to DLL module
	DWORD Reason,     // reason for calling function
	LPVOID Reserved)  // reserved
{
	// Perform actions based on the reason for calling.
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(Module);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)main, NULL, NULL, NULL);
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}