#ifndef _DETOUR_HPP_
#define _DETOUR_HPP_

#include "kdef.hpp"

namespace detour {
    _IRQL_requires_max_(APC_LEVEL)
    bool apply(void* target, void* hook, size_t length, void** original);

    _IRQL_requires_max_(APC_LEVEL)
    bool restore(void* target, void* original);
}

#endif