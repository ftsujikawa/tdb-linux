#include <stdio.h>

static int add(int left, int right)
{
    int sum = left + right;
    return sum;
}

int main(void)
{
    int total = 0;

    for (int i = 1; i <= 3; ++i) {
        total = add(total, i);
        printf("i=%d total=%d\n", i, total);
    }

    return 0;
}
