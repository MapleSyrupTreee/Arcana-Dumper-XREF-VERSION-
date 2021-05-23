#pragma once
#include "memedit.hpp"

namespace scanner
{
    typedef std::vector<uintptr_t> scan_results;

    enum
    {
        byte_equal,
        word_equal,
        int_equal,
        byte_notequal,
        word_notequal,
        int_notequal
    };

    struct scan_check
    {
        int type;
        int offset;
        void* value;
    };

    class memscan
    {
    private:
        scan_results results_list;

        std::vector<scan_check> scan_checks;

        uintptr_t scan_start;
        uintptr_t scan_end;
        uintptr_t scan_at;

        size_t align;
        size_t pattern_size;

        int8_t * mask;
        uint8_t* pattern;
    public:
        memscan();
        memscan(uintptr_t start_address, uintptr_t end_address);

        ~memscan(){}

        void add_check(scan_check);
        void set_scan(uintptr_t begin, uintptr_t end);
        void set_align(const size_t alignment);

        void scan(const char* str_pattern, const size_t end_result = 0);
        void scan_xrefs(const char* str, const size_t str_result = 1);
        void scan_xrefs(uintptr_t func);

        scan_results get_results();
    };
}
