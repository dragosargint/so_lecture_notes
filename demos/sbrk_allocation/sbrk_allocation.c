#include "print_helpers.h"

int main()
{
    char c;
    void *new_brk, *initial_brk, *old_brk;

    initial_brk = sbrk(0);
    PRINT_PTR("The initial program break is:", initial_brk);
    PRINT_MSG("Press anything to coninue\n\n");
    read(0, &c, sizeof(c));

    PRINT_MSG("Allocate 1024 bytes from System Memory using sbrk(1024)\n")
    old_brk = sbrk(1024);
    new_brk = sbrk(0);
    if (new_brk == (void *)-1)
    {
        PRINT_MSG("sbrk() failed\n");
    }
    PRINT_PTR("OLD program break is:", old_brk);
    PRINT_PTR("NEW program break is:", new_brk);
    PRINT_MSG("Press anything to coninue\n\n");
    read(0, &c, sizeof(c));

    PRINT_MSG("Allocate 2048 bytes from System Memory using sbrk(2048)\n")
    old_brk = sbrk(2048);
    new_brk = sbrk(0);
    if (new_brk == (void *)-1)
    {
        PRINT_MSG("sbrk() failed\n");
    }
    PRINT_PTR("OLD program break is:", old_brk);
    PRINT_PTR("NEW program break is:", new_brk);
    PRINT_MSG("Press anything to coninue\n\n");
    read(0, &c, sizeof(c));

    PRINT_MSG("Allocate 4096 bytes from System Memory using sbrk(4096)\n")
    old_brk = sbrk(4096);
    new_brk = sbrk(0);
    if (new_brk == (void *)-1)
    {
        PRINT_MSG("sbrk() failed\n");
    }
    PRINT_PTR("OLD program break is:", old_brk);
    PRINT_PTR("NEW program break is:", new_brk);
    PRINT_MSG("Press anything to coninue\n\n");
    read(0, &c, sizeof(c));

    return 0;
}