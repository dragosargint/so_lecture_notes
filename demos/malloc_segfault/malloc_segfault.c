#include <stdio.h>
#include <stdlib.h>

int main()
{
    char *buf;
    size_t i;

    printf("Allocate an 100B array of chars\n");
    buf = malloc(100);

    printf("Trying to access element 1000 in the array\n");
    buf[1000] = 0;

    printf("That's weird accesing element 1000 doesn't result in Seg Fault because address is %p\n", &buf[1000]);

    printf("Press ENTER if you want to trigger a SEG FAULT\n");
    getchar();

    for(i = 0; i < 1000000; i++)
    {
        printf("Access element at index %ld address %p\n", i, &buf[i]);
        buf[i] = 0;
    }

    return 0;
}
