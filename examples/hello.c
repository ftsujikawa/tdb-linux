#include <stdio.h>

int add(int a, int b) {
    int c = a + b;
    return c;
}

int main(void) {
    int x = 1;
    int y = 2;
    int z = add(x, y);
    printf("z = %d\n", z);

    int i = 0;
    while (1) {
        printf("result = %d\n", i++);
    }

    return 0;
}
