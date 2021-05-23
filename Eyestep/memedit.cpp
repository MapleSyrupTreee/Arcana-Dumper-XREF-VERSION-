// memedit.hpp - goal:
// declare most of the api that isn't associated with a template
//
#include "memedit.hpp"

bool is_function(uintptr_t address)
{
    const auto bytes = memread<uint8_t>(address, 3);

    // DLL export prologue...
    // some games dynamically allocate their own
    // copies of these functions, and they're not
    // 16-uint8_t aligned.
    // 
    if (memcmp(bytes, { 0x8B, 0xFF, 0x55 }))
        return true;

    if (address % 0x10 != 0)
        return false;

    // run through the most common prologues
    // 
    if (
        memcmp(bytes, { 0x53, 0x8B, 0xDC }) // push ebx  |  mov ebx, esp
     || memcmp(bytes, { 0x55, 0x8B, 0xEC }) // push ebp  |  mov ebp, esp
     || memcmp(bytes, { 0x56, 0x8B, 0xF4 }) // push esi  |  mov esi, esp
     || memcmp(bytes, { 0x57, 0x8B, 0xFC }) // push edi  |  mov edi, esp
    ){ 
        return true;
    }

    // Was this followed by 16-byte alignment?
    // 
    if (
        *reinterpret_cast<uint8_t*>(address - 1) == 0xCC
     && *reinterpret_cast<uint8_t*>(address - 2) == 0xCC
    ){
        // This is a naked function
        return true;
    }
    
    return false;
}


uintptr_t is_call(uintptr_t address)
{
    // check if it's a call or a jmp
    //
    if (*reinterpret_cast<uint8_t*>(address) == 0xE8 // call rel32
     || *reinterpret_cast<uint8_t*>(address) == 0xE9 // jmp rel32
    ){
        // get the relative offset and its destination
        // 
        uintptr_t rel = *reinterpret_cast<uintptr_t*>(address + 1);
        uintptr_t func = address + 5 + rel;

        // check if it lies almost within code bounds
        // 
        if (func % 0x10 == 0 && func > *reinterpret_cast<uintptr_t*>(__readfsdword(0x30) + 8) && func < 0x07FFFFFF)
        {
            // Query the page now that it's more appropriate
            // to make this call
            // 
            MEMORY_BASIC_INFORMATION page = { 0 };
            VirtualQuery(reinterpret_cast<void*>(func), &page, sizeof(page));

            // Verify that this is IS part of the code page
            //
            if (page.State & MEM_COMMIT && page.Protect & PAGE_EXECUTE_READ)
            {
                // Verify that this is the beginning address of
                // a function.
                // 
                if (is_function(func)) 
                {
                    return func;
                }
            }
        }
    }

    return 0;
}

uint32_t get_return(uintptr_t address)
{
    auto bytes = memread<uint8_t>(address - 1, 2);

    uint8_t prev = bytes[0];
    uint8_t ep = bytes[1];

    // check if it's a common epilogue
    // 
    switch (ep)
    {
    case 0xC2: // ret
    case 0xC3: // retn
    case 0xC9: // leave
        // run through the most common registers
        // that a function is initialized with...
        // to be sure that this is the EOF
        // 
        switch (prev)
        {
        case 0xC9: // leave (occasionally precedes an epilogue)
        case 0x5B: // pop ebx
        case 0x5D: // pop ebp
        case 0x5E: // pop esi
        case 0x5F: // pop edi

            if (ep == 0xC2)
            {
                uint16_t r = memread<uint16_t>(address + 1);

                // double check that this is not a false reading
                // I guess
                if (r % 4 == 0 && r < 1024)
                {
                    return r;
                }
            }
            else
            {
                return 0;
            }

            break;
        }

        break;
    }

    return -1;
}


bool is_valid_code(uintptr_t address)
{
    if (*reinterpret_cast<uint64_t*>(address) == 0
     && *reinterpret_cast<uint64_t*>(address + 8) == 0
    ){
        return false;
    }
    else 
    {
        return true;
    }
}


std::vector<uintptr_t> get_calls(uintptr_t func)
{
    std::vector<uintptr_t> calls = { };

    uintptr_t call;
    uintptr_t at = func;
    uintptr_t end = get_prologue<next>(func);

    while (at < end)
    {
        call = is_call(at++);

        if (call)
        {
            calls.push_back(call);
            call = 0;
        }
    }

    return calls;
}


// search through the function for all occurences 
// where EBP is used with a POSITIVE offset, starting at 8.
// This means it's an arg and we want to go all the way 
// to the end, then see which offset was the HIGHEST.
// Whatever the highest number is, this shows
// how many args the function has altogether.
// We just subtract 4 from it and then divide it by 4
// (args start at +8, +C, +10, +14, and so on..*)
// 
// * this function will NOT work with 64 bit args
// as they get handled much differently :[
// 
int get_arg_count(uintptr_t func)
{
    int count = 0;

    for (auto& i : disassembler::read_range(func, get_prologue<next>(func)))
    {
        if (i.src().flags & OP_R32 && i.src().flags & OP_IMM8)
        {
            if (i.src().reg.front() == disassembler::R32_EBP)
            {
                auto temp = i.src().imm8; 
                
                if (temp % 4 == 0 && temp >= 8 && temp <= 0x7C)
                {
                    if (temp > count)
                    {
                        count = temp;
                    }
                }
            }
        }
        else if (i.dest().flags & OP_R32 && i.dest().flags & OP_IMM8)
        {
            if (i.dest().reg.front() == disassembler::R32_EBP)
            {
                auto temp = i.dest().imm8;

                if (temp % 4 == 0 && temp >= 8 && temp <= 0x7C)
                {
                    if (temp > count)
                    {
                        count = temp;
                    }
                }
            }
        }
    }

    return (count - 4) / 4;
}



void memcpy_safe_padded(void* destination, void* source, const size_t size)
{
    uint8_t source_buffer[8];

    if (size <= 8)
    {
        // Pad the source buffer with bytes from destination
        memcpy(source_buffer, destination, 8);
        memcpy(source_buffer, source, size);

        // Perform an interlocked exchange on the
        // source and destination
        // 
        #ifndef NO_INLINE_ASM
        __asm
        {
            lea esi, source_buffer;
            mov edi, destination;

            mov eax, [edi];
            mov edx, [edi + 4];
            mov ebx, [esi];
            mov ecx, [esi + 4];

            lock cmpxchg8b[edi];
        }
        #else
        _InterlockedCompareExchange64(
             reinterpret_cast<uint64_t*>(destination), 
            *reinterpret_cast<uint64_t*>(source_buffer),
            *reinterpret_cast<uint64_t*>(destination)
        );
        #endif
    }
}

bool memcmp(const std::vector<uint8_t>& bytes_a, const std::vector<uint8_t>& bytes_b)
{
    if (bytes_a.size() != bytes_b.size())
    {
        return false;
    }

    size_t count = 0;

    for (const auto& uint8_t : bytes_a)
    {
        if (bytes_b[count] != uint8_t)
        {
            break;
        }

        count++;
    }

    return count == bytes_b.size();
}

bool memcmp(void* address, const std::vector<uint8_t>& bytes_compare)
{
    auto bytes = memread<uint8_t>(address, bytes_compare.size());

    return memcmp(bytes, bytes_compare);
}

bool memcmp(uintptr_t address, const std::vector<uint8_t>& bytes)
{
    return memcmp(reinterpret_cast<void*>(address), bytes);
}


// Give our detouring functions a body
// 

saved_detour create_detour(uintptr_t address, void* func)
{
    size_t hook_size = 0;

    while (hook_size < 5) 
    {
        hook_size += disassembler::read(address + hook_size).len;
    }

    saved_detour detour_data;
    detour_data.address = address;
    detour_data.hook_size = hook_size;
    memcpy(&detour_data.old_bytes, reinterpret_cast<void*>(detour_data.address), hook_size);

    DWORD old_protect;
    VirtualProtect(reinterpret_cast<void*>(detour_data.address), hook_size, PAGE_EXECUTE_READWRITE, &old_protect);

    *reinterpret_cast<uint8_t*>(detour_data.address) = 0xE9;
    *reinterpret_cast<uint32_t*>(detour_data.address + 1) = (reinterpret_cast<uint32_t>(func) - detour_data.address) - 5;

    for (int i = 5; i < hook_size; i++)
    {
        *reinterpret_cast<uint8_t*>(detour_data.address + i) = 0x90;
    }

    VirtualProtect(reinterpret_cast<void*>(detour_data.address), hook_size, old_protect, &old_protect);

    return detour_data;
}

void remote_detour(saved_detour detour_data)
{
    DWORD old_protect;
    VirtualProtect(reinterpret_cast<void*>(detour_data.address), detour_data.hook_size, PAGE_EXECUTE_READWRITE, &old_protect);

    for (int i = 0; i < detour_data.hook_size; i++)
    {
        *reinterpret_cast<uint8_t*>(detour_data.address + i) = detour_data.old_bytes[i];
    }

    VirtualProtect(reinterpret_cast<void*>(detour_data.address), detour_data.hook_size, old_protect, &old_protect);
}



// Quick assembling api
// These append instructions to memory with ease

// pushad
#define memapp_pushad(at)\
*at++ = 0x60;


// popad
#define memapp_popad(at)\
*at++ = 0x61;


// push r1
#define memapp_push_r32(at, r1)\
*at++ = 0x50 + r1;


// pop r1
#define memapp_pop_r32(at, r1)\
*at++ = 0x58 + r1;


// mov r1, r2
#define memapp_mov_r32_r32(at, r1, r2)\
*at++ = 0x8B;\
*at++ = 0xC0 + (r1 * 8) + r2;


// mov [r1], r2
#define memapp_mov_rm_r32(at, r1, r2)\
*at++ = 0x89;\
*at++ = (r2 * 8) + r1;


// mov r1, [r2]
#define memapp_mov_r32_rm(at, r1, r2)\
*at++ = 0x8B;\
*at++ = (r1 * 8) + r2;


// lea r1, [r2]
#define memapp_lea_r32_rm(at, r1, r2)\
*at++ = 0x8D;\
*at++ = (r1 * 8) + r2;


// mov [r1+??], eax
#define memapp_mov_rm_off8_r32(at, r1, o, r2)\
*at++ = 0x89;\
*at++ = 0x40 + (r2 * 8) + r1;\
*at++ = o;


// mov r1, [r2+??]
#define memapp_mov_r32_rm_off8(at, r1, r2, o)\
*at++ = 0x8B;\
*at++ = 0x40 + (r1 * 8) + r2;\
*at++ = o;


// lea r1, [r2+??]
#define memapp_lea_r32_rm_off8(at, r1, r2, o)\
*at++ = 0x8D;\
*at++ = 0x40 + (r1 * 8) + r2;\
*at++ = o;


// mov [r1+????????], r2
#define memapp_mov_rm_off32_r32(at, r1, o, r2)\
*at++ = 0x89;\
*at++ = 0x80 + (r2 * 8) + r1;\
*reinterpret_cast<uint32_t*>(at) = o;\
at += sizeof(uint32_t);


// mov r1, [r2+????????]
#define memapp_mov_r32_rm_off32(at, r1, r2, o)\
*at++ = 0x8B;\
*at++ = 0x80 + (r1 * 8) + r2;\
*reinterpret_cast<uint32_t*>(at) = o;\
at += sizeof(uint32_t);


// lea r1, [r2+????????]
#define memapp_lea_r32_rm_off32(at, r1, r2, o)\
*at++ = 0x8D;\
*at++ = 0x80 + (r1 * 8) + r2;\
*reinterpret_cast<uint32_t*>(at) = o;\
at += sizeof(uint32_t);


// mov r1, ????????
#define memapp_mov_r32_disp32(at, r1, value)\
if (r1 == disassembler::R32_EAX)\
    *at++ = 0xA1;\
else\
    *at++ = 0xB8 + r1;\
*reinterpret_cast<uint32_t*>(at) = value;\
at += sizeof(uint32_t);


// lea r1, [????????]
#define memapp_lea_r32_off32(at, r1, value)\
*at++ = 0x8D;\
*at++ = 0x05 + (r1 * 8);\
*reinterpret_cast<uint32_t*>(at) = value;\
at += sizeof(uint32_t);

// mov [r1], ????????
#define memapp_mov_rm_disp32(at, r1, value)\
*at++ = 0xC7;\
*at++ = r1;\
*reinterpret_cast<uint32_t*>(at) = value;\
at += sizeof(uint32_t);


// mov [r1+??], ????????
#define memapp_mov_rm_off8_disp32(at, r1, o, value)\
*at++ = 0xC7;\
*at++ = 0x40 + r1;\
*at++ = o;\
*reinterpret_cast<uint32_t*>(at) = value;\
at += sizeof(uint32_t);


// mov [????????], r1
#define memapp_mov_off32_r32(at, r1, value)\
if (r1 == EyeStep::R32_EAX)\
	*at++ = 0xA3;\
*reinterpret_cast<uint32_t*>(at) = value;\
at += sizeof(uint32_t);


// push ????????
#define memapp_push_disp32(at, value)\
*at++ = 0x68;\
*reinterpret_cast<uint32_t*>(at) = value;\
at += sizeof(uint32_t);


// push ??
#define memapp_push_disp8(at, value)\
*at++ = 0x6A;\
*at++ = value;


// call loc_??????
#define memapp_call(at, func, cleanup)\
*at = 0xE8;\
*reinterpret_cast<uint32_t*>(at + 1) = (reinterpret_cast<uint32_t>(func) - reinterpret_cast<uint32_t>(at)) - 5;\
at += 5;\
if (cleanup > 0) {\
    *at++ = 0x83;\
	*at++ = 0xC4;\
	*at++ = cleanup;\
}

// jmp loc_??????
#define memapp_jmp(at, func)\
*at = 0xE9;\
*reinterpret_cast<uint32_t*>(at + 1) = (reinterpret_cast<uint32_t>(func) - reinterpret_cast<uint32_t>(at)) - 5;\
at += 5;



std::vector<uintptr_t> debug_register(uintptr_t address, int reg32, int offset, size_t count)
{
    std::vector<uintptr_t> output = {};

    void* new_func = VirtualAlloc(nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    uintptr_t ready = reinterpret_cast<uintptr_t>(new_func) + 128;
    uintptr_t output_location = reinterpret_cast<uintptr_t>(new_func) + 132;

    size_t hook_size = 0;

    // figure out the stray bytes to NOP
    while (hook_size < 5)
    {
        hook_size += disassembler::read(address + hook_size).len;
    }

    uint8_t* at = reinterpret_cast<uint8_t*>(new_func);
    uint8_t* old_bytes = new uint8_t[hook_size];
    memcpy(old_bytes, reinterpret_cast<void*>(address), hook_size);

    // Load ASM instructions to read out the local registers
    // This is EXE-supported (coming soon), because
    // we are manually writing the instructions
    //

    memapp_pushad(at)
    memapp_push_r32(at, disassembler::R32_EDI)
    memapp_push_r32(at, disassembler::R32_EAX)

    for (int i = 0; i < count; i++)
    {
        // Place their values at our output location
        memapp_lea_r32_off32(at, disassembler::R32_EDI, output_location + (i * 4))
        if (offset == -1)
        {
            memapp_mov_r32_r32(at, disassembler::R32_EAX, reg32)
        }
        else {
            memapp_mov_r32_rm_off32(at, disassembler::R32_EAX, reg32, offset + (i * 4))
        }
        memapp_mov_rm_r32(at, disassembler::R32_EDI, disassembler::R32_EAX);
    }

    memapp_mov_r32_disp32(at, disassembler::R32_EDI, ready)
    memapp_mov_rm_disp32(at, disassembler::R32_EDI, 1)
    memapp_pop_r32(at, disassembler::R32_EAX)
    memapp_pop_r32(at, disassembler::R32_EDI)
    memapp_popad(at)

    // Place original code
    memcpy(at, old_bytes, hook_size);

    at += hook_size;

    memapp_jmp(at, reinterpret_cast<void*>(address + hook_size))


    saved_detour detour_data = create_detour(address, new_func);

    while (*reinterpret_cast<int*>(ready) != 1)
    {
        Sleep(10);
    }

    remote_detour(detour_data);

    for (int i = 0; i < count; i++)
    {
        // add output values to the list
        output.push_back(*reinterpret_cast<int*>(output_location + i * 4));
    }

    VirtualFree(new_func, 0, MEM_RELEASE);

    return output;
};


