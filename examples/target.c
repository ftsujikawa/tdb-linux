#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

struct test_struct {
    int a;
    int b;
    int c;
};

int add(struct test_struct *ts, int a, int b)
{
    int c = a + b;
    return c;
}

int main()
{
    int x = 10;
    int y = 20;
    struct test_struct ts = {0};
    struct test_struct *ts_ptr = &ts;
    struct test_struct sa[3] = {0};
    struct test_struct *sa_ptr = sa;

    void *pm = malloc(100);

    while (1) {

        int z = add(&ts, x, y);

        printf("result=%d\n", z);

        sleep(1);
    }

    return 0;
}
