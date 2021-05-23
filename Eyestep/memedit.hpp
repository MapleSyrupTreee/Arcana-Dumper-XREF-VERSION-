#pragma once
#include "dx86.hpp"

// used to determine what relative instruction
// to place, when using 'memplace'
// 
constexpr auto rel_call = 0xE8;
constexpr auto rel_jmp = 0xE9;

#define get_rel(x) x + 5 + *reinterpret_cast<uintptr_t*>(x + 1)

// determines whether to go backwards (decrementing)
// or forwards (incrementing) in memory to reach the
// destination
// 
const enum direction 
{ 
    behind, 
    next 
};

// returns whether or not the address is the
// beginning of a function (a common prologue)
// 
extern bool is_function(uintptr_t address);

// determines whether the address is used
// in a relative call, in which case it will
// return a relative non-zero value
// 
extern uintptr_t is_call(uintptr_t address);

// returns -1 if there is no epilogue here.
// Otherwise, it returns 0 for a retn
// or it returns the value in a ret.
// 
extern uint32_t get_return(uintptr_t address);

extern bool is_valid_code(uintptr_t address);


// strictly non-void-pointer
// 
template<direction dir>
uintptr_t get_prologue(uintptr_t start)
{
    uintptr_t at = start;

    // ignore the current prologue if we're at one
    // 
    if (is_function(at))
    {
        switch (dir)
        {
        case direction::next:
            at += 0x10;
            break;
        case direction::behind:
            at -= 0x10;
            break;
        }
    }

    while (!is_function(at))
    {
        if (!is_valid_code(at)) break;

        switch (dir)
        {
        case direction::next:
            // proper alignment
            // 
            if (at % 0x10 != 0)
                at += at % 0x10;
            else
                at += 0x10;

            break;
        case direction::behind:
            // proper alignment
            // 
            if (at % 0x10 != 0)
                at -= at % 0x10;
            else
                at -= 0x10;

            break;
        }
    }

    return at;
}

// strictly non-void-pointer
// 
// This will keep scanning in either direction for the very
// next call (or jmp) instruction, and will return the function that
// it calls.
// 
// if 'func' is set to a function's address, this function will look for the
// very next call instruction that calls that function.
// in other words, it finds the next XREF of the function,
// starting at the address 'start'.
// 
template<direction dir>
uintptr_t get_call(uintptr_t start, uintptr_t func = 0)
{
    uintptr_t at = start;
    uintptr_t call = is_call(at);

    // ignore the current prologue if we're at one
    // 
    if (call)
    {
        switch (dir)
        {
        case next:
            at++;
            break;
        case behind:
            at--;
            break;
        }
    }

    while (1)
    {
        call = is_call(at);

        if (call != 0)
        {
            if (func == 0)
            {
                break;
            }
            else if (call == func)
            {
                // return location (XREF) of where
                // 'func' gets called
                return at;
            }
        }

        switch (dir)
        {
        case next:
            at++;
            break;
        case behind:
            at--;
            break;
        }
    }

    return call;
}


// strictly non-void-pointer
// 
// This will collect all of the calls made in a function
// and return them in a vector.
// 
std::vector<uintptr_t> get_calls(uintptr_t func);


int get_arg_count(uintptr_t func);



// Typically used for jmps where we need to
// overwrite 5 bytes, but we can only do 2, 4, 8 atomically
//
void memcpy_safe_padded(void* destination, void* source, const size_t size);


// Usage:
// memwrite<uint8_t>(address, 0xEB);
//
template<typename write_type>
void memwrite(void* address, const write_type value, bool make_page_writeable = false)
{
    if (make_page_writeable)
    {
        DWORD old;
        VirtualProtect(address, sizeof(write_type), PAGE_EXECUTE_READWRITE, &old);

        *reinterpret_cast<write_type*>(address) = value;
        //memcpy(address, reinterpret_cast<void*>(value), sizeof(write_type));

        VirtualProtect(address, sizeof(write_type), old, &old);
    }
    else
    {
        *reinterpret_cast<write_type*>(address) = value;
        //memcpy(address, reinterpret_cast<void*>(value), sizeof(write_type));
    }
}


// non-void-pointer memory location
//
template<typename write_type>
void memwrite(uintptr_t address, const write_type value, bool make_page_writeable = false)
{
    if (make_page_writeable)
    {
        DWORD old;
        VirtualProtect(reinterpret_cast<void*>(address), sizeof(write_type), PAGE_EXECUTE_READWRITE, &old);

        *reinterpret_cast<write_type*>(address) = value;

        VirtualProtect(reinterpret_cast<void*>(address), sizeof(write_type), old, &old);
    }
    else
    {
        *reinterpret_cast<write_type*>(address) = value;
    }
}



// Usage:
// memwrite<uint8_t>(address, { 0xDE, 0xAD, 0xBE, 0xEF });
//
template<typename vector_write_type>
void memwrite(void* address, const std::vector<vector_write_type>& value, bool make_page_writeable = false)
{
    if (make_page_writeable)
    {
        DWORD old_protect;
        VirtualProtect(address, sizeof(vector_write_type), PAGE_EXECUTE_READWRITE, &old_protect);

        memcpy(address, value.data(), value.size());

        VirtualProtect(address, sizeof(vector_write_type), old_protect, &old_protect);
    }
    else
    {
        memcpy(address, value.data(), value.size());
    }
}


// non-void-pointer memory location
//
template<typename vector_write_type>
void memwrite(uintptr_t address, const std::vector<vector_write_type>& value, bool make_page_writeable = false)
{
    if (make_page_writeable)
    {
        DWORD old;
        VirtualProtect(reinterpret_cast<void*>(address), sizeof(vector_write_type), PAGE_EXECUTE_READWRITE, &old);

        memcpy(reinterpret_cast<void*>(address), value.data(), value.size());

        VirtualProtect(reinterpret_cast<void*>(address), sizeof(vector_write_type), old, &old);
    }
    else
    {
        memcpy(reinterpret_cast<void*>(address), value.data(), value.size());
    }
}



// Usage:
// *reinterpret_cast<uint8_t*>(address); <--- 0xDE
//
template<typename read_type>
read_type memread(void* address)
{
    return *reinterpret_cast<read_type*>(address);
}


// non-void-pointer memory location
//
template<typename read_type>
read_type memread(uintptr_t address)
{
    return *reinterpret_cast<read_type*>(address);
}



// Usage:
// *reinterpret_cast<uint8_t*>(address, 4); <--- { 0xDE, 0xAD, 0xBE, 0xEF }
//
template<typename vector_read_type>
std::vector<vector_read_type> memread(void* address, size_t count)
{
    const auto output = std::vector<vector_read_type>(count);

    memcpy(const_cast<vector_read_type*>(output.data()), address, count);

    return output;
}


// non-void-pointer memory location
//
template<typename vector_read_type>
std::vector<vector_read_type> memread(uintptr_t address, size_t count)
{
    const auto output = std::vector<vector_read_type>(count);

    memcpy(const_cast<vector_read_type*>(output.data()), reinterpret_cast<void*>(address), count);

    return output;
}



// Compare the bytes contained in two uint8_t tables
extern bool memcmp(const std::vector<uint8_t>& bytes_a, const std::vector<uint8_t>& bytes_b);

// Compare the bytes located at address with the uint8_t table
extern bool memcmp(void* address, const std::vector<uint8_t>& bytes);

// non-void-pointer memory location
extern bool memcmp(uintptr_t address, const std::vector<uint8_t>& bytes);



// injects a jmp instruction at address, which jumps to function
//
template<uint8_t opcode>
std::vector<uint8_t> memplace(void* from, void* to)
{
    const auto hook_size = 5;

    DWORD old;
    size_t size = 0;

    while (size < hook_size)
    {
        size += disassembler::read(reinterpret_cast<uintptr_t>(from) + size).len;
    }

    const auto old_bytes = memread<uint8_t>(from, size);
    auto rel = reinterpret_cast<int>(to) - (reinterpret_cast<int>(from) + hook_size);
    auto brel = reinterpret_cast<uint8_t*>(&rel);

    std::vector<uint8_t> bytes = { opcode, brel[0], brel[1], brel[2], brel[3] };

    // fill remaining overwritten bytes with nops
    for (size_t i = 0; i < size - hook_size; i++)
    {
        bytes.push_back(0x90);
    }

    VirtualProtect          (from, size, PAGE_EXECUTE_READWRITE, &old);
    memcpy_safe_padded      (from, bytes.data(), bytes.size());
    VirtualProtect          (from, size, old, &old);

    FlushInstructionCache   (GetCurrentProcess(), from, size);

    return old_bytes;
}

// non-void-pointer memory location
//
template<uint8_t opcode>
std::vector<uint8_t> memplace(uintptr_t address, void* function)
{
    return memplace<opcode>(reinterpret_cast<void*>(address), function);
}

// non-void-pointer function
//
template<uint8_t opcode>
std::vector<uint8_t> memplace(void* address, uintptr_t function)
{
    return memplace<opcode>(address, reinterpret_cast<void*>(function));
}
// non-void-pointer function
//
template<uint8_t opcode>
std::vector<uint8_t> memplace(uintptr_t address, uintptr_t function)
{
    return memplace<opcode>(reinterpret_cast<void*>(address), reinterpret_cast<void*>(function));
}


// strictly non-void-pointer
// 
template<direction dir>
uintptr_t find_aob(uintptr_t start, std::vector<uint8_t> bytes)
{
    uintptr_t at = start;

    while (!memcmp(at, bytes))
    {
        switch (dir)
        {
        case behind:
            at--;
            break;
        case next:
            at++;
            break;
        }
    }

    return at;
}



struct saved_detour
{
    uintptr_t address;
    BYTE old_bytes[16];
    size_t hook_size;
};

extern saved_detour create_detour(uintptr_t address, void* func);
extern void remote_detour(saved_detour detour_data);


// Usage/example:
//
// auto results = debug_register(r_lua_gettop, R32_EBP, +8, 1);
// auto r_lua_thread = results[0];
// 
extern std::vector<uintptr_t> debug_register(uintptr_t address, int reg32, int offset, size_t count);


