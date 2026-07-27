//! スレッド/マルチプロセス制御 (REQ-THR-*) の結合テスト。
//! テスト仕様書 4章 (TC-THR-*) 対応。
//!
//! 実スレッドのスケジューリング順序に依存する部分(どのスレッド番号が
//! 先に停止するか等)は環境によってばらつくため、アサーションは
//! 「特定の番号になること」ではなく「観測できるべき性質」に留める。

#[path = "support/mod.rs"]
mod support;

use support::*;

/// TC-THR-01 / TC-THR-02: `info threads` はメインスレッド+ワーカー
/// スレッドを一覧表示し、フォーカス中のスレッドにだけ `*` が付く。
/// 停止中スレッドの位置表示は `関数名+オフセット at file:line` 形式。
#[test]
fn info_threads_lists_threads_with_single_focus_marker() {
    let target = target_thread();
    let out = run_script(&target, &[], &["break worker", "run", "continue", "info threads", "quit"]);

    assert_contains(&out, "in worker+0x");
    assert_contains(&out, "thread_target.c:23");

    let focus_marker_lines = out.lines().filter(|l| l.trim_start().starts_with('*')).count();
    assert_eq!(focus_marker_lines, 1, "expected exactly one focused thread line\n{out}");

    // メインスレッド + ワーカー2つで、番号付きの行が複数存在する。
    let numbered_lines = out.lines().filter(|l| l.trim_start().chars().next().is_some_and(|c| c.is_ascii_digit())).count();
    assert!(numbered_lines >= 2, "expected at least 2 thread entries\n{out}");
}

/// `info threads` の出力から、`*` が付いた(フォーカス中の)スレッド番号を
/// 取り出す。
fn focused_thread_id(info_threads_output: &str) -> String {
    info_threads_output
        .lines()
        .find(|l| l.trim_start().starts_with('*'))
        .and_then(|l| l.trim_start().trim_start_matches('*').trim().split(':').next())
        .expect("could not find focused thread id in info threads output")
        .to_string()
}

/// TC-THR-03: 停止中のスレッドへは `thread <n>` でフォーカスを切り替えられる。
///
/// どのスレッド番号が最初に `worker` へ到達するかはスケジューリングに
/// 依存するため、2回に分けて別プロセスを起動して番号を使い回すのではなく、
/// 同一セッション内で `info threads` の結果を読み取ってから、その番号を
/// 使って `thread <n>` を送る(`Session::sync` で同期を取る)。
#[test]
fn thread_switch_to_currently_stopped_thread_succeeds() {
    let target = target_thread();
    let mut session = Session::spawn(&target, &[]);
    session.send(&["break worker", "run", "continue", "info threads"]);
    let out = session.sync();
    let focused_id = focused_thread_id(&out);

    let switch_cmd = format!("thread {focused_id}");
    session.send(&[switch_cmd.as_str()]);
    let out2 = session.sync();
    assert_contains(&out2, "に切り替えました");

    session.send(&["quit"]);
    let final_out = session.finish();
    assert_not_contains(&final_out, "エラー:");
}

/// `info threads` の出力から、位置表示が `(?)`(= 現在 ptrace 停止中でなく
/// バックグラウンドで動作中)になっている行の番号を1つ取り出す。
fn a_background_thread_id(info_threads_output: &str) -> Option<String> {
    info_threads_output.lines().find(|l| l.contains("(?)")).and_then(|l| {
        l.trim_start().trim_start_matches('*').trim().split(':').next().map(str::to_string)
    })
}

/// TC-THR-04 (異常系): バックグラウンドで動作中(停止していない)スレッド
/// へは切り替えられない。
///
/// メインスレッドは、`pthread_create` (`clone(2)`) 由来の ptrace イベント
/// をまだ読み飛ばしていない間、実際にはバックグラウンドで動いていなくても
/// 一時的に「停止中」に見えることがある(そのイベントは次の `continue` が
/// 処理するまで tdb 側で汲み取られないため)。そのため `continue` を
/// 重ねながら `info threads` の `(?)` 表示(=バックグラウンド動作中)を
/// 探す。
#[test]
fn thread_switch_to_running_thread_is_rejected() {
    let target = target_thread();
    let mut session = Session::spawn(&target, &[]);
    session.send(&["break worker", "run", "continue"]);

    // 初回停止直後は保留中の clone イベントの都合で全スレッドが一時的に
    // 「停止中」に見えることがあるため、`continue` を重ねながら探す。
    let mut found: Option<String> = None;
    let mut last_out = String::new();
    for _ in 0..4 {
        session.send(&["continue", "info threads"]);
        last_out = session.sync();
        if let Some(id) = a_background_thread_id(&last_out) {
            found = Some(id);
            break;
        }
    }
    let Some(bg_id) = found else {
        session.send(&["quit"]);
        session.finish();
        panic!("no background (\"(?)\") thread found after retries\n{last_out}");
    };

    let switch_cmd = format!("thread {bg_id}");
    session.send(&[switch_cmd.as_str()]);
    let out2 = session.sync();
    assert_contains(&out2, "現在停止していません");

    session.send(&["quit"]);
    session.finish();
}

/// `info threads` の出力から、既知の全スレッド番号を取り出す
/// (先頭が `*` またはそのまま数字で始まる行)。
fn known_thread_ids(info_threads_output: &str) -> Vec<String> {
    info_threads_output
        .lines()
        .filter_map(|l| {
            let trimmed = l.trim_start().trim_start_matches('*').trim_start();
            let id: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
            (!id.is_empty() && trimmed[id.len()..].starts_with(':')).then_some(id)
        })
        .collect()
}

/// TC-THR-05: `thread apply all <cmd>` は既知の全スレッドへ順にフォーカス
/// を切り替えながらコマンドを実行する。
///
/// 2つ目のワーカースレッドの `pthread_create` がまだ実行されていない
/// タイミングでは `info threads` に現れるスレッド数が2つのこともあるため、
/// 期待するスレッド番号の集合は固定値 (1〜3) ではなく、直前の
/// `info threads` の結果から動的に求める。各スレッドは、その時点で
/// ptrace 停止中なら `スレッド <n>:` ヘッダに続けて `backtrace` の結果を、
/// そうでなければスキップメッセージを出す。
#[test]
fn thread_apply_all_runs_backtrace_on_every_known_thread() {
    let target = target_thread();
    let mut session = Session::spawn(&target, &[]);
    session.send(&["break worker", "run", "continue", "info threads"]);
    let out = session.sync();
    let ids = known_thread_ids(&out);
    assert!(!ids.is_empty(), "expected at least one known thread\n{out}");

    session.send(&["thread apply all backtrace"]);
    let out2 = session.sync();

    for id in &ids {
        let header = format!("スレッド {id}:");
        let skipped = format!("スレッド {id} をスキップしました");
        assert!(
            out2.contains(&header) || out2.contains(&skipped),
            "expected thread {id} to be either applied or skipped\n{out2}"
        );
    }
    // 停止中のスレッドについては実際に backtrace の #0 フレームが出る。
    assert_contains(&out2, "#0  0x");

    session.send(&["quit"]);
    session.finish();
}

/// TC-THR-06 / TC-THR-07: 現在フォーカス中の
/// (停止している)スレッドをロックし、解除できる。番号の決定方法は
/// `thread_switch_to_currently_stopped_thread_succeeds` と同様、同一
/// セッション内での同期読み取りによる。
#[test]
fn lock_currently_stopped_thread_then_unlock() {
    let target = target_thread();
    let mut session = Session::spawn(&target, &[]);
    session.send(&["break worker", "run", "continue", "info threads"]);
    let out = session.sync();
    let focused_id = focused_thread_id(&out);

    let lock_cmd = format!("lock {focused_id}");
    session.send(&[lock_cmd.as_str(), "unlock"]);
    let out2 = session.sync();
    assert_contains(&out2, "をロックしました");
    assert_contains(&out2, "スレッドロックを解除しました");

    session.send(&["quit"]);
    session.finish();
}

/// TC-THR-08: `fork(2)` 由来の子プロセスが自動検出され `[プロセス]` の
/// 印が付く。子プロセスが終了してもセッションは継続する。
#[test]
fn fork_child_process_is_tracked_and_reported_on_exit() {
    let target = target_fork();
    let out = run_script(&target, &[], &["break work", "run", "continue", "continue", "info threads", "continue", "quit"]);

    assert_contains(&out, "[プロセス]");
    assert_contains(&out, "が終了しました (code=0)]");
}
