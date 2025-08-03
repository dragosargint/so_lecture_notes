#include <stdio.h>
#include <unistd.h>

int var;

int main()
{
    printf("Enter an integer: ");
    scanf("%d", &var);

    while(1) {
        printf("Address of var: %p, Value of var: %d\n", (void*)&var, var);
        sleep(1);
    }

    return 0;
}

