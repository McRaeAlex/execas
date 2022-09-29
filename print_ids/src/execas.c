#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

int main()
{
    uid_t ruid, euid;
    ruid = getuid();
    euid = geteuid();

    printf("real: %d effective: %d\n", ruid, euid);

    return 0;
}