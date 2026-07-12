/*
 * Test program for mini-gdb heap tracing (set heap-trace on).
 *
 * Expected result after "run leak_target" + "c":
 *   show leaks  -> 2 leaks, 360 bytes total
 *     - malloc(200)          200 bytes
 *     - calloc(10, 16)       160 bytes
 *
 * Usage:
 *   make leak_target
 *   ./tdb
 *   (tdb) set heap-trace on
 *   (tdb) run ./leak_target
 *   (tdb) c
 *   (tdb) show leaks
 */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    void *ok = malloc(100);
    void *leak_a = malloc(200);
    void *leak_b = calloc(10, 16);

    if (!ok || !leak_a || !leak_b) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    free(ok);

    /* leak_a and leak_b are intentionally not freed. */
    (void)leak_a;
    (void)leak_b;

    printf("done: expect 2 leaks (200 + 160 bytes)\n");
    return 0;
}
