#include <stdio.h>
#include <unistd.h>

void recurse(int depth) {
    int local_var;
    printf("Depth: %d, Address of local_var: %p\n", depth, (void*)&local_var);
    recurse(depth + 1);
}

int main() {
    recurse(1);
}
