#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int var;

void usage(char **argv)
{
    fprintf(stderr, "usage: %s <integer>\n", argv[0]);
    exit(1);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        usage(argv);

    var = atoi(argv[1]);
    while (1)
    {
        printf("[%s pid=%d] Address of var: %p, Value of var: %d\n", argv[0], getpid(), &var, var);
        sleep(1);
    }

    return 0;
}
