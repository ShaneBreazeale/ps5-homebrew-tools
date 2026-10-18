/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    static const char ready[] = "minimal-payload: ready\n";
    write(STDERR_FILENO, ready, sizeof(ready) - 1);
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("minimal-payload: pid=%d\n", (int)getpid());
    puts("minimal-payload: complete");
    return 0;
}
