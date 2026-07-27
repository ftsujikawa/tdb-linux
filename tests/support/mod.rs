//! tdb の REPL を子プロセスとして起動し、標準入力へコマンド列を流し込んで
//! 標準出力を検証するための結合テスト用ヘルパー。
//!
//! テスト仕様書 (docs/テスト仕様書.md) の各テストケース (TC-*) を自動化した
//! `tests/*.rs` から `#[path = "support/mod.rs"] mod support;` で読み込む。

#![allow(dead_code)]

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// ハングしたセッションを強制終了するまでの上限時間。全テストケースは
/// 正常系であれば数百ミリ秒〜数秒で完了する想定のため、十分に余裕を
/// 持たせつつ CI 環境での遅延も吸収できる値にしている。
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(20);

/// `Session::wait_for`/`Session::sync` のデフォルトタイムアウト。
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

pub fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples")
}

/// テスト対象の tdb バイナリ (`cargo test` がビルドしたもの)。
pub fn tdb_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tdb")
}

/// `examples/<src_name>` を任意の gcc 引数でコンパイルし `examples/<bin_name>`
/// を生成する。ソースより新しいバイナリが既にあれば再利用する。
///
/// 複数のテストバイナリ (`tests/*.rs` はそれぞれ独立したプロセスとして
/// ビルド・実行される) から並行に呼ばれても安全なように、一時ファイルへ
/// 出力してから `rename` (同一ファイルシステム上ではアトミック) で
/// 差し替える。2つのプロセスが同時に「未ビルド」と判定して2回コンパイル
/// しても、どちらも同じソース・同じ引数から生成した妥当なバイナリなので
/// 実害はない。
pub fn build_example_custom(bin_name: &str, src_name: &str, gcc_args: &[&str]) -> PathBuf {
    let dir = examples_dir();
    let src = dir.join(src_name);
    let out = dir.join(bin_name);
    let up_to_date = match (fs::metadata(&src), fs::metadata(&out)) {
        (Ok(s), Ok(o)) => o.modified().unwrap() >= s.modified().unwrap(),
        _ => false,
    };
    if !up_to_date {
        let tmp = dir.join(format!(".{}.tmp.{}", bin_name, std::process::id()));
        let mut cmd = Command::new("gcc");
        cmd.arg("-o").arg(&tmp).arg(&src);
        cmd.args(gcc_args);
        let status = cmd.status().unwrap_or_else(|e| panic!("failed to invoke gcc: {e}"));
        assert!(status.success(), "gcc failed to build {bin_name} from {src_name}");
        fs::rename(&tmp, &out).unwrap_or_else(|e| panic!("failed to install {bin_name}: {e}"));
    }
    out
}

/// `-g -O0` (+ 追加引数) でビルドする、通常のデバッグ情報付きテスト対象。
pub fn build_example(bin_name: &str, src_name: &str, extra_gcc_args: &[&str]) -> PathBuf {
    let mut args = vec!["-g", "-O0"];
    args.extend_from_slice(extra_gcc_args);
    build_example_custom(bin_name, src_name, &args)
}

pub fn target_hello() -> PathBuf {
    build_example("hello", "hello.c", &[])
}

/// デバッグ情報を持たないビルド (TC-VIEW-08: 逆アセンブルへのフォール
/// バック確認用)。
pub fn target_hello_nodbg() -> PathBuf {
    build_example_custom("hello_nodbg", "hello.c", &["-O0"])
}

pub fn target_struct() -> PathBuf {
    build_example("target", "target.c", &[])
}

pub fn target_thread() -> PathBuf {
    build_example("thread_target", "thread_target.c", &["-pthread"])
}

pub fn target_fork() -> PathBuf {
    build_example("fork_target", "fork_target.c", &[])
}

pub fn target_leak() -> PathBuf {
    build_example("leak_target", "leak_target.c", &[])
}

fn pump(mut reader: impl Read + Send + 'static, buf: Arc<Mutex<Vec<u8>>>) {
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.lock().unwrap().extend_from_slice(&chunk[..n]),
        }
    }
}

/// tdb の対話セッション1本を表す。`send` でコマンドを流し込み、
/// `finish` で標準入力を閉じて終了を待ち、出力をまとめて回収する。
/// 標準出力・標準エラー出力はバックグラウンドスレッドで随時読み取って
/// いるため、`output_so_far`/`wait_for`/`sync` でセッション途中の出力を
/// 検査することもできる(スレッド番号のようにスケジューリングに依存する
/// 値を読み取ってから、それを使って次のコマンドを組み立てる場合に使う)。
pub struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    out_buf: Arc<Mutex<Vec<u8>>>,
    done: Arc<AtomicBool>,
}

impl Session {
    pub fn spawn(target: &Path, args: &[&str]) -> Self {
        Self::spawn_with_env(target, args, &[])
    }

    /// `envs` に `LANG`/`LC_ALL` を含めない限り、`LANG=ja_JP.UTF-8` を
    /// 既定にする(テスト実行環境のロケールに依存せず、日本語表示を
    /// 前提にしたアサーションを安定させるため)。
    pub fn spawn_with_env(target: &Path, args: &[&str], envs: &[(&str, &str)]) -> Self {
        let mut cmd = Command::new(tdb_bin());
        cmd.arg(target);
        cmd.args(args);
        if !envs.iter().any(|(k, _)| *k == "LANG" || *k == "LC_ALL") {
            cmd.env("LANG", "ja_JP.UTF-8");
        }
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().unwrap_or_else(|e| panic!("failed to spawn tdb: {e}"));
        let stdin = child.stdin.take().expect("tdb stdin should be piped");
        let stdout = child.stdout.take().expect("tdb stdout should be piped");
        let stderr = child.stderr.take().expect("tdb stderr should be piped");
        let pid = child.id();

        let out_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let buf = out_buf.clone();
            thread::spawn(move || pump(stdout, buf));
        }
        {
            let buf = out_buf.clone();
            thread::spawn(move || pump(stderr, buf));
        }

        let done = Arc::new(AtomicBool::new(false));
        let watchdog_done = done.clone();
        thread::spawn(move || {
            thread::sleep(WATCHDOG_TIMEOUT);
            if !watchdog_done.load(Ordering::SeqCst) {
                let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
            }
        });

        Session { child, stdin: Some(stdin), out_buf, done }
    }

    pub fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    /// コマンド列を標準入力へ書き込む(まだ閉じない。続けて `send`/
    /// `interrupt` を呼べる)。
    pub fn send(&mut self, lines: &[&str]) -> &mut Self {
        let stdin = self.stdin.as_mut().expect("stdin already closed");
        for line in lines {
            writeln!(stdin, "{line}").expect("failed to write to tdb stdin");
        }
        stdin.flush().expect("failed to flush tdb stdin");
        self
    }

    /// テストプロセス側の実時間待ち。デバッグ対象がバックグラウンドで
    /// 一定時間動くのを待ってから SIGINT を送る、等の用途にのみ使う
    /// (コマンドの実行順序自体は標準入出力のブロッキングにより保証される
    /// ため、通常のコマンド間では不要)。
    pub fn wait_millis(&self, ms: u64) -> &Self {
        thread::sleep(Duration::from_millis(ms));
        self
    }

    /// tdb プロセス自身へ SIGINT を送る(Ctrl-C 相当。REQ-EXEC-09)。
    pub fn interrupt(&self) -> &Self {
        signal::kill(Pid::from_raw(self.pid()), Signal::SIGINT).expect("failed to send SIGINT");
        self
    }

    /// これまでに届いた標準出力・標準エラー出力を返す(非ブロッキング)。
    pub fn output_so_far(&self) -> String {
        String::from_utf8_lossy(&self.out_buf.lock().unwrap()).into_owned()
    }

    /// `pattern` を含む出力が届くまでポーリングして待つ。タイムアウトすれば
    /// その時点までの出力を添えてパニックする。
    #[track_caller]
    pub fn wait_for(&self, pattern: &str, timeout: Duration) -> String {
        let start = Instant::now();
        loop {
            let out = self.output_so_far();
            if out.contains(pattern) {
                return out;
            }
            if start.elapsed() > timeout {
                panic!(
                    "timed out waiting for {pattern:?}\n--- output so far ---\n{out}\n--- end ---"
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// これまでに送ったコマンドの出力が確実に届いていることを保証する
    /// バリア。ユニークな値を `print` させ、その出力が現れるまで待って
    /// から、ここまでの全出力を返す。スレッド番号のようにセッション途中の
    /// 出力を見てから次のコマンドを組み立てたい場合、直前のコマンド列の
    /// 後にこれを呼ぶ。
    #[track_caller]
    pub fn sync(&mut self) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0x5a5a0000);
        let marker = COUNTER.fetch_add(1, Ordering::SeqCst);
        let cmd = format!("print {marker}");
        self.send(&[cmd.as_str()]);
        let needle = format!("{marker} = 0x");
        self.wait_for(&needle, WAIT_TIMEOUT)
    }

    /// 標準入力を閉じ(EOF)、プロセス終了を待って、これまでに届いた
    /// 標準出力・標準エラー出力をまとめて返す。
    pub fn finish(mut self) -> String {
        self.stdin.take(); // drop => クローズ (EOF)
        self.child.wait().expect("failed to wait for tdb process");
        self.done.store(true, Ordering::SeqCst);
        // プロセス終了直後、読み取りスレッドが最後のバイト列を
        // バッファへ反映し終えるまでの猶予。
        thread::sleep(Duration::from_millis(50));
        self.output_so_far()
    }
}

/// コマンド列を一括で流し込み、そのまま終了させて出力を得る単発セッション
/// 用のショートカット。`commands` は通常 `"quit"` で終える(実行中の
/// デバッグ対象がいれば `quit` が `kill` してから終了するため、確実に
/// プロセスが後始末される)。
pub fn run_script(target: &Path, args: &[&str], commands: &[&str]) -> String {
    let mut session = Session::spawn(target, args);
    session.send(commands);
    session.finish()
}

#[track_caller]
pub fn assert_contains(output: &str, needle: &str) {
    assert!(
        output.contains(needle),
        "expected output to contain {needle:?}\n--- full output ---\n{output}\n--- end ---"
    );
}

#[track_caller]
pub fn assert_not_contains(output: &str, needle: &str) {
    assert!(
        !output.contains(needle),
        "expected output NOT to contain {needle:?}\n--- full output ---\n{output}\n--- end ---"
    );
}

/// `needle` が出力中にちょうど `count` 回現れることを確認する。
#[track_caller]
pub fn assert_count(output: &str, needle: &str, count: usize) {
    let actual = output.matches(needle).count();
    assert_eq!(
        actual, count,
        "expected {needle:?} to appear {count} time(s), found {actual}\n--- full output ---\n{output}\n--- end ---"
    );
}
