#include <stdint.h>
#include <signal.h>
#include <stdlib.h>

static int exercise_realloc(void)
{
    void *buffer = malloc(37);
    if (!buffer) {
        return 1;
    }

    size_t oversize = SIZE_MAX;
    void *failed = realloc(buffer, oversize);
    if (failed) { /* inspect allocation after failed realloc */
        free(failed);
        return 2;
    }

    void *resized = realloc(buffer, 73);
    if (!resized) {
        free(buffer);
        return 3;
    }
    void *released = malloc(149);
    if (!released) {
        return 4;
    }
    /* glibc releases a non-null allocation for realloc(ptr, 0). */
    return realloc(released, 0) != NULL;
}

int main(int argc, char **argv)
{
    char message[] = "coverage-test";
    char *text = message;
    double fraction = 1.25;
    float single = -2.5f;
    int matrix[2][2] = {{1, 2}, {3, 4}};

    if (argc > 1 && argv[1][0] == 'r') { /* inspect initialized locals here */
        return exercise_realloc();
    }
    if (argc > 1 && argv[1][0] == 'k') {
        raise(SIGKILL);
    }
    return text[0] == 'c' && fraction > single && matrix[1][1] == 4 ? 0 : 1;
}
