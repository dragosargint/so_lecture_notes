#include <unistd.h>
#include <stdint.h>

#define PRINT_MSG(msg)                  \
    do                                  \
    {                                   \
        write(1, msg, sizeof(msg) - 1); \
    } while (0);

#define PRINT_PTR(msg, ptr)                                                  \
    do                                                                       \
    {                                                                        \
        char _buf[2 + sizeof(void *) * 2];                                   \
        uintptr_t _val = (uintptr_t)(ptr);                                   \
        _buf[0] = '0';                                                       \
        _buf[1] = 'x';                                                       \
        for (size_t _i = 0; _i < sizeof(void *) * 2; _i++)                   \
        {                                                                    \
            int _shift = (sizeof(void *) * 8 - 4) - _i * 4;                  \
            int _nib = (_val >> _shift) & 0xF;                               \
            _buf[2 + _i] = (_nib < 10) ? ('0' + _nib) : ('a' + (_nib - 10)); \
        }                                                                    \
        write(1, msg, sizeof(msg) - 1);                                      \
        write(1, " ", 1);                                                    \
        write(1, _buf, sizeof(_buf));                                        \
        write(1, "\n", 1);                                                   \
    } while (0)
