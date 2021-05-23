#include "memscan.hpp"


using namespace scanner;

static MEMORY_BASIC_INFORMATION get_region(uintptr_t location)
{
    MEMORY_BASIC_INFORMATION page = { 0 };
    VirtualQuery(reinterpret_cast<void*>(location), &page, sizeof(page));

    return page;
}

static uintptr_t get_section(const char* section)
{
	uintptr_t start = *reinterpret_cast<uintptr_t*>(__readfsdword(0x30) + 8);

	while (!(memcmp(reinterpret_cast<void*>(start), section, strlen(section)) == 0))
	{
		start += 4;
	}

	return start + *reinterpret_cast<uintptr_t*>(start + 12);
}

uint8_t* safe_bytes = nullptr;
uintptr_t safe_loc = 0;
uintptr_t safe_size = 0;

bool do_safe_copy()
{
	bool success = true;

	__try
	{
		memcpy(reinterpret_cast<void*>(safe_bytes), reinterpret_cast<void*>(safe_loc), safe_size);
	}
	__except (1)
	{
		success = false;
		Sleep(1);
	}

	return success;
}

memscan::memscan()
{
    pattern = nullptr;
	pattern_size = 0;
    mask = nullptr;

	scan_start = *reinterpret_cast<uintptr_t*>(__readfsdword(0x30) + 8) + 0x1000;
	scan_end = get_section(".rodata");
	scan_at = 0;
	align = 1;

	printf("%p, %p\n", scan_start, scan_end);

	results_list = {};
	scan_checks = {};
}

memscan::memscan(uintptr_t start_address, uintptr_t end_address)
{
    pattern = nullptr;
	pattern_size = 0;
    mask = nullptr;

    scan_start = start_address;
    scan_end = end_address;
	scan_at = 0;

	align = 1;

	results_list = {};
	scan_checks = {};
}


void memscan::add_check(scan_check check)
{
    scan_checks.push_back(check);
}

void memscan::set_scan(uintptr_t begin, uintptr_t end)
{
	scan_start = begin;
	scan_end = end;
}

void memscan::set_align(const size_t alignment)
{
    align = alignment;
}

void memscan::scan(const char* str_pattern, const size_t endresult)
{
	results_list.clear();
	pattern_size = 0;

    char* new_pattern = new char[1 + strlen(str_pattern)];

    for (int i = 0; i < strlen(str_pattern); i++)
    {
		if (str_pattern[i] == 0x20)
		{
			continue;
		}

        new_pattern[pattern_size++] = str_pattern[i];
    }

	new_pattern[pattern_size] = 0;

    pattern_size /= 2;

	pattern = new uint8_t[pattern_size];
	ZeroMemory(pattern, pattern_size);

	mask = new int8_t[pattern_size];
	ZeroMemory(mask, pattern_size);

	std::vector<int>wild_indices = {};

    // translate the AOB (string) to a literal
	// byte array and corresponding mask (string)
	// 
	for (int i = 0, n = 0, id = 0, at = 0; i < strlen(new_pattern); i += 2)
	{
		char x[2];
		x[0] = new_pattern[i + 0];
		x[1] = new_pattern[i + 1];

		if (x[0] == '?') // '??'
		{
			// append "wildchar"
			wild_indices.push_back(at);

			// ignore these 2 chars
			pattern[at] = 0;
			mask[at++] = '?';
		}
		else 
		{
			id = 0;

			// convert 2 chars to byte
		convert:
			if (x[id] > 0x60) 
				n = x[id] - 0x57; // n = A-F (10-16)
			else if (x[id] > 0x40) 
				n =	x[id] - 0x37; // n = a-f (10-16)
			else if (x[id] >= 0x30) 
				n = x[id] - 0x30; // number chars

			switch (id)
			{
			case 0:
				id = 1;
				pattern[at] += (n * 16);
				goto convert;
			case 1:
				pattern[at] += n;
				break;
			}

			mask[at++] = '.';
		}
	}

	scan_at = scan_start;

	while (scan_at < scan_end)
	{
		auto page = get_region(scan_at);

		if ( (page.State & MEM_COMMIT)
		 && !(page.Protect & PAGE_NOACCESS)
		 && !(page.Protect & PAGE_NOCACHE)
		 && !(page.Protect & PAGE_GUARD)
		){
			if (scan_at > reinterpret_cast<uintptr_t>(page.BaseAddress))
			{
				page.RegionSize -= (scan_at - reinterpret_cast<uintptr_t>(page.BaseAddress));
			}
			
			uint8_t* read_bytes = new uint8_t[page.RegionSize];

			safe_bytes = read_bytes;
			safe_loc = scan_at;
			safe_size = page.RegionSize;

			if (do_safe_copy())
			{
				// scan all memory in the memory region
				// 
				for (size_t i = 0; i < page.RegionSize - pattern_size; i += align)
				{
					// fill in any wildchar indices('??') with the
					// bytes read, and now check if the pattern matches
					// 
					for (const auto& x : wild_indices)
					{
						pattern[x] = read_bytes[i + x];
					}

					if (memcmp(read_bytes + i, pattern, pattern_size) == 0)
					{
						if (!scan_checks.size())
						{
							results_list.push_back(scan_at + i);
						}
						else
						{
							// Go through a series of extra checks,
							// make sure all are passed before it's a valid result
							size_t checks_passed = 0;

							for (const scan_check& check : scan_checks)
							{
								switch (check.type)
								{
								case byte_equal:
									if (*reinterpret_cast<uint8_t*>(read_bytes + i + check.offset) == reinterpret_cast<uint8_t>(check.value))
										checks_passed++;
									break;
								case word_equal:
									if (*reinterpret_cast<uint16_t*>(read_bytes + i + check.offset) == reinterpret_cast<uint16_t>(check.value))
										checks_passed++;
									break;
								case int_equal:
									if (*reinterpret_cast<uint32_t*>(read_bytes + i + check.offset) == reinterpret_cast<uint32_t>(check.value))
										checks_passed++;
									break;
								case byte_notequal:
									if (*reinterpret_cast<uint8_t*>(read_bytes + i + check.offset) != reinterpret_cast<uint8_t>(check.value))
										checks_passed++;
									break;
								case word_notequal:
									if (*reinterpret_cast<uint16_t*>(read_bytes + i + check.offset) != reinterpret_cast<uint16_t>(check.value))
										checks_passed++;
									break;
								case int_notequal:
									if (*reinterpret_cast<uint32_t*>(read_bytes + i + check.offset) != reinterpret_cast<uint32_t>(check.value))
										checks_passed++;
									break;
								}
							}

							if (checks_passed == scan_checks.size())
							{
								results_list.push_back(scan_at + i);
							}
						}

						if (endresult && results_list.size() >= endresult)
						{
							delete[] read_bytes;
							delete[] new_pattern;
							delete[] pattern;
							delete[] mask;

							return;
						}
					}
				}
			}
			else {
				printf("Failed to copy memory at %p [size: %p]\nSkipping...\n", safe_loc, safe_size);
			}

			delete[] read_bytes;
		}

		scan_at += page.RegionSize;
	}

	delete[] new_pattern;
	delete[] pattern;
	delete[] mask;
}



void memscan::scan_xrefs(const char* str, const size_t n_str_result)
{
	const int len = strlen(str);
	const int aob_len = 1 + (len * 2);

	// convert the string to bytes
	char* str_aob = new char[aob_len];

	ZeroMemory(str_aob, aob_len);

	// Convert the string to a hex-string aob
	// 
	for (int i = 0, at = 0; i < len; i++)
	{
		char c[8];
		sprintf(c, "%02X", static_cast<uint8_t>(str[i]));

		// append uint8_t to aob string
		str_aob[at++] = c[0];
		str_aob[at++] = c[1];
	}

	auto old_scan_start = scan_start;
	auto old_scan_align = align;

	align = 4;
	scan_start += get_region(scan_start).RegionSize;

	scan(str_aob, n_str_result);

	scan_start = old_scan_start;

	delete[] str_aob;

	if (results_list.size())
	{
		int result = results_list[0];

		uint8_t bytes[4];
		memcpy(&bytes, reinterpret_cast<void*>(&result), sizeof(int));

		// lol, this is a sad minimum effort way to do it
		// 
		char str_pointer[32];
		sprintf_s(str_pointer, "%02X%02X%02X%02X", bytes[0], bytes[1], bytes[2], bytes[3]);

		// change alignment to 1 byte, since a pointer
		// to the string can be anywhere in the code section,
		// at any memory address
		// 
		align = 1;

		scan(str_pointer, 1);

		align = old_scan_align;
	}
	else {
		printf("No results found for string\n");
	}
}


void memscan::scan_xrefs(uintptr_t func)
{
	results_list.clear();
	scan_at = reinterpret_cast<uintptr_t>(get_region(scan_start).BaseAddress);

	while (scan_at < scan_end)
	{
		auto page = get_region(scan_at);
		if (page.Protect == PAGE_EXECUTE_READ)
		{
			uint8_t* bytes = new uint8_t[page.RegionSize];

			memcpy(bytes, reinterpret_cast<void*>(scan_at), page.RegionSize);

			for (size_t i = 0; i < page.RegionSize; i++)
			{
				if (bytes[i] == rel_call
				 || bytes[i] == rel_jmp
				){
					if (scan_at + i + 5 + *reinterpret_cast<uintptr_t*>(scan_at + i + 1) == func)
					{
						results_list.push_back(scan_at + i);
					}
				}
			}

			delete[] bytes;
		}

		scan_at = reinterpret_cast<uintptr_t>(page.BaseAddress) + page.RegionSize;
	}
}


scan_results memscan::get_results()
{
    return results_list;
}

