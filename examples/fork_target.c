/*
 * tdb のマルチプロセス対応(fork(2) 由来の子プロセスの自動追跡)を試すための
 * テストプログラム。fork() 直後に親・子の両方が同じ work() 関数を呼び出す。
 *
 * 使い方の例:
 *   gcc -g -O0 -o fork_target fork_target.c
 *   tdb ./fork_target
 *   (tdb) break work        # fork() 前に設定 -> 子プロセスにもメモリコピーで自動的に反映される
 *   (tdb) run
 *   (tdb) continue           # 親または子のどちらかが work() に到達
 *   (tdb) info threads       # 子プロセスには [process] の印が付く
 *   (tdb) break finish_msg   # fork() 後に設定 -> 既知の全プロセスへ反映される
 *   (tdb) thread apply all backtrace
 */
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int work(const char *label, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += i;
        printf("%s: total=%d\n", label, total);
        usleep(30000);
    }
    return total;
}

void finish_msg(const char *label, int total) {
    printf("%s: done total=%d\n", label, total);
}

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        int r = work("child", 3);
        finish_msg("child", r);
        return 0;
    }
    int r = work("parent", 3);
    finish_msg("parent", r);
    waitpid(pid, NULL, 0);
    return 0;
}
