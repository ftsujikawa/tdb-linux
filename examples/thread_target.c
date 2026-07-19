/*
 * tdb のスレッド対応(`info threads`/`thread <n>`)を試すためのテスト
 * プログラム。2つのワーカースレッドが共有の `counter` を(意図的に排他
 * 制御なしで)インクリメントする。
 *
 * 使い方の例:
 *   gcc -g -O0 -pthread -o thread_target thread_target.c
 *   tdb ./thread_target
 *   (tdb) break worker
 *   (tdb) run
 *   (tdb) continue        # 1つ目のワーカースレッドが worker() に到達
 *   (tdb) info threads     # スレッド一覧(現在のスレッドに * が付く)
 *   (tdb) watch counter    # counter への書き込みを監視(全スレッド対象)
 *   (tdb) continue         # 書き込みのたびに停止する
 */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

volatile int counter = 0;

void *worker(void *arg) {
    int id = *(int *)arg;
    for (int i = 0; i < 3; i++) {
        counter++;
        printf("worker %d: counter=%d\n", id, counter);
        usleep(50000);
    }
    return NULL;
}

int main(void) {
    pthread_t t1, t2;
    int id1 = 1, id2 = 2;
    printf("main: starting threads\n");
    pthread_create(&t1, NULL, worker, &id1);
    pthread_create(&t2, NULL, worker, &id2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    printf("main: done, counter=%d\n", counter);
    return 0;
}
