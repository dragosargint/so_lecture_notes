#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char msg[] = "Hello world";
int global_init_var = 80;
char global_uninit_array[10];

int function(void)
{
    return 0;
}

int main()
{
    int stack_var = 5;
    char *heap_var = malloc(10);
    heap_var[0] = 'H';
    heap_var[1] = 'E';
    heap_var[2] = 'L';
    heap_var[3] = 'L';
    heap_var[4] = 'O';
    heap_var[5] = 0;

    printf("msg[address %p]: %s\n", msg, msg);
    printf("global_init_var[address %p]: %d\n", &global_init_var, global_init_var);
    printf("global_uninit_array[address %p]: %s\n", &global_uninit_array, global_uninit_array);
    printf("stack_var[address %p]: %d\n", &stack_var, stack_var);
    printf("heap_var[address %p]: %p\n", &heap_var, heap_var);
    printf("*heap_var[address %p]: %s\n", heap_var, heap_var);
    printf("function[address %p]\n", function);
    sleep(20);
}
