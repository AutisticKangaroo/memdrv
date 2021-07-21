#ifndef _UTIL_HPP_
#define _UTIL_HPP_

#include "stdint.hpp"

namespace util {
    uint64_t get_kernel_module(const char* name);
    uint64_t find_pattern(uint64_t base, size_t range, const char* pattern, const char* mask);
    uint64_t find_pattern_module(uint64_t base, const char* pattern, const char* mask);
}

#endif