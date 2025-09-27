#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

int main(void)
{
    void *region_rw = NULL;
    void *region_rwx = NULL;
    int nr_pages = 10;
    size_t alloc_size = nr_pages * 4096;

    printf("Press ENTER to allocate %zu bytes (%d pages) as rwx\n", (size_t)alloc_size, nr_pages);
    getchar();

    region_rwx = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region_rwx == MAP_FAILED)
    {
        fprintf(stderr, "mmap failed");
        exit(1);
    }
    printf("Allocated rwx region at %p (size: %zu)\n\n", region_rwx, (size_t)alloc_size);

    printf("Press ENTER to allocate %zu bytes (%d pages) as rw-\n", (size_t)alloc_size, nr_pages);
    getchar();

    region_rw = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region_rw == MAP_FAILED)
    {
        fprintf(stderr, "mmap failed");
        exit(1);
    }
    printf("Allocated rw- region at %p (size: %zu)\n\n", region_rw, (size_t)alloc_size);

    printf("Press ENTER to unmap rwx region\n");
    getchar();

    if (munmap(region_rwx, alloc_size) == -1)
    {
        fprintf(stderr, "munmap failed");
        exit(1);
    }
    printf("Unmaped rwx region\n\n");

    printf("Press ENTER to unmap rw- region\n");
    getchar();
    if (munmap(region_rw, alloc_size) == -1)
    {
        fprintf(stderr, "munmap failed");
        exit(1);
    }
    printf("Unmaped rw- region\n\n");

    printf("Done. Press ENTER to exit.\n");
    getchar();
    return 0;
}
