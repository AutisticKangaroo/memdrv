#ifndef _STDINT_HPP_
#define _STDINT_HPP_

using int8_t = signed __int8;
using int16_t = signed __int16;
using int32_t = signed __int32;
using int64_t = signed __int64;

using uint8_t = unsigned __int8;
using uint16_t = unsigned __int16;
using uint32_t = unsigned __int32;
using uint64_t = unsigned __int64;

#ifdef _WIN64

using intptr_t = int64_t;
using uintptr_t = uint64_t;

#else

using intptr_t = int32_t;
using uintptr_t = uint32_t;

#endif

#endif