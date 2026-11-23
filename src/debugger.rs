mod breakpoints;
mod execution;
mod inspection;
mod leak_tracking;
mod process;

use crate::breakpoint::Breakpoint;
use crate::dwarf_info::DwarfInfo;
use crate::elf_info::ElfInfo;
use crate::leak::LeakTracker;
use anyhow::{Context, Result};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use rust_i18n::t;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

/// 現在デバッグ対象として実行中の子プロセスの pid (無ければ 0)。
/// SIGINT 転送スレッドから読むための、プロセス全体で共有する状態。
static DEBUGGEE_PID: AtomicI32 = AtomicI32::new(0);

/// tdb 自身が SIGINT (Ctrl-C) を受け取った際、デバッグ対象プロセスにも
/// SIGINT を転送するバックグラウンドスレッドを起動する。これにより:
/// - tdb 自身は(デフォルトの「終了」ではなく)SIGINT を無視して動き続ける。
/// - `continue` 等で待機中のデバッグ対象は SIGINT を受けて ptrace 経由で
///   停止し、通常のシグナル停止として `waitpid` に報告される。
/// プログラム起動時に一度だけ呼び出す。
pub fn install_sigint_forwarder() {
    use signal_hook::consts::SIGINT;
    use signal_hook::iterator::Signals;

    let mut signals = match Signals::new([SIGINT]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", t!("dbg.sigint_setup_failed", err = e));
            return;
        }
    };
    std::thread::spawn(move || {
        for _ in signals.forever() {
            let pid = DEBUGGEE_PID.load(Ordering::SeqCst);
            if pid > 0 {
                let _ = nix::sys::signal::kill(Pid::from_raw(pid), Signal::SIGINT);
            }
        }
    });
}

pub struct Debugger {
    program: PathBuf,
    args: Vec<String>,
    elf: ElfInfo,
    dwarf: DwarfInfo,
    pid: Option<Pid>,
    /// PIE バイナリの実行時ロードベースアドレス(非PIEなら0)。
    load_bias: u64,
    breakpoints: HashMap<u64, Breakpoint>,
    /// `run` 前に指定されたシンボル名ブレークポイント。起動時に解決する。
    pending_breaks: Vec<String>,
    next_bp_id: u32,
    bp_ids: HashMap<u32, u64>,
    exited: bool,
    /// `set print pretty on|off` (GDB 同様、デフォルトは off = 1行表示)。
    print_pretty: bool,
    /// `set print elements <n>|unlimited`。文字列 (`/s`) や構造体表示の
    /// 要素数上限 (GDB のデフォルトである 200 に合わせる)。`None` は無制限。
    print_elements: Option<usize>,
    /// `leak on/off`/`leaks` で使うメモリリーク追跡状態。
    leak: LeakTracker,
    /// `nexti`/`up` が `cont()` 経由で待っている「ここで止まってほしい」
    /// 一時ブレークポイントのアドレス。メモリリーク追跡用の戻り値捕捉
    /// ブレークポイントが偶然同じアドレスになった場合に、追跡側が
    /// 勝手に実行を継続してしまわないようにするために参照する。
    skip_target: Option<u64>,
    /// ハードウェアウォッチポイント (`watch` コマンド)。x86-64 のデバッグ
    /// レジスタ DR0-DR3 に対応するため最大4つ。`None` は未使用スロット。
    /// プロセスの再起動 (`run`) では引き継がない(`break *addr` と同様)。
    watchpoints: [Option<Watchpoint>; 4],
    /// ウォッチポイントID -> DRスロット番号 (0-3)。`bp_ids`/`next_bp_id` と
    /// 番号を共有する(GDBと同様、ブレークポイントとウォッチポイントを
    /// 同じ通し番号で管理する)。
    wp_ids: HashMap<u32, usize>,
    /// スレッドグループ内の既知のスレッド(tid)一覧。メインスレッド
    /// (`self.pid`)を含む。`PTRACE_O_TRACECLONE` により新規スレッドは
    /// 自動的にアタッチされ、`wait_and_report` で検出・登録する。
    threads: HashSet<Pid>,
    /// 現在フォーカスしているスレッドの tid。レジスタ表示・`print`・
    /// `step`/`stepi`/`backtrace` 等、`pid()` を経由するほぼ全ての操作は
    /// このスレッドを対象にする。ブレークポイント/ウォッチポイントの
    /// ヒットで自動的に切り替わる(`thread <n>` でも手動切り替え可能)。
    current_tid: Option<Pid>,
    /// ユーザー向けの小さいスレッド番号 -> tid (`thread <n>`/`info threads`
    /// で使う)。
    thread_ids: HashMap<u32, Pid>,
    next_thread_id: u32,
    /// まだ「自動アタッチ直後の初回停止」を消化していないスレッドの集合。
    /// `PTRACE_O_TRACECLONE` で自動アタッチされた新規スレッドの最初の
    /// 停止は、カーネル/タイミングによって `SIGTRAP` だったり `SIGSTOP`
    /// だったりする(観測上両方あり得た)ため、シグナル種別では判別せず、
    /// 「このスレッドについて最初に受け取った `Stopped` イベントかどうか」
    /// で判定し、該当すれば無条件に `continue` して読み飛ばす。
    pending_initial_stop: HashSet<Pid>,
    /// `lock <n>` でロックされているスレッドの tid。`Some` の間、
    /// `continue`/`step` 系はこのスレッドのみを実行させ、他の既知の
    /// スレッド(新規に作られたものも含む)は明示的に停止させたままにする
    /// (GDB の `set scheduler-locking on` に相当する簡易実装)。
    locked_tid: Option<Pid>,
    /// 既知の「プロセスリーダー」(それぞれ独立したアドレス空間を持つ
    /// プロセス)の tid 集合。最初に起動したプロセス自身に加え、
    /// `PTRACE_O_TRACEFORK`/`PTRACE_O_TRACEVFORK` により自動アタッチされた
    /// `fork(2)`/`vfork(2)` 由来の子プロセスもここに入る(`pthread_create`
    /// 等の `clone(2)` によるスレッドは親と同じアドレス空間を共有するため
    /// 含めない)。ブレークポイントはメモリ上のバイト列書き換えなので、
    /// ここに載っている各プロセスへ個別にインストールする必要がある
    /// (`threads` はスレッド単位、こちらはプロセス単位の集合)。
    processes: HashSet<Pid>,
}

/// ハードウェアウォッチポイント1つ分の情報。

/// ハードウェアウォッチポイント1つ分の情報。
struct Watchpoint {
    /// 監視するメモリアドレス(実行時アドレス)。
    addr: u64,
    /// 監視する幅 (1/2/4/8バイトのいずれか)。
    len: u8,
    /// 表示用ラベル(変数名 または `*addr`)。
    label: String,
    /// 直前に観測した値。トリガー時の「旧値」として使い、その後は新しい
    /// 値で更新する。
    last_value: u64,
}

impl Debugger {
    pub fn new(program: PathBuf, args: Vec<String>) -> Result<Self> {
        let elf = ElfInfo::load(&program)?;
        let dwarf = DwarfInfo::load(&program)?;
        Ok(Debugger {
            program,
            args,
            elf,
            dwarf,
            pid: None,
            load_bias: 0,
            breakpoints: HashMap::new(),
            pending_breaks: Vec::new(),
            next_bp_id: 1,
            bp_ids: HashMap::new(),
            exited: false,
            print_pretty: false,
            print_elements: Some(200),
            leak: LeakTracker::default(),
            skip_target: None,
            watchpoints: [None, None, None, None],
            wp_ids: HashMap::new(),
            threads: HashSet::new(),
            current_tid: None,
            thread_ids: HashMap::new(),
            next_thread_id: 1,
            pending_initial_stop: HashSet::new(),
            locked_tid: None,
            processes: HashSet::new(),
        })
    }

    // ---- `set print ...` 設定 ----

    pub fn set_print_pretty(&mut self, on: bool) {
        self.print_pretty = on;
    }

    pub fn print_pretty(&self) -> bool {
        self.print_pretty
    }

    /// `n = None` は無制限 (`unlimited`)。
    pub fn set_print_elements(&mut self, n: Option<usize>) {
        self.print_elements = n;
    }

    pub fn print_elements(&self) -> Option<usize> {
        self.print_elements
    }

    pub fn is_running(&self) -> bool {
        self.pid.is_some() && !self.exited
    }
}

fn parse_addr(s: &str) -> Result<u64> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).context(t!("dbg.addr_parse_failed").to_string())
}

fn source_path_matches(path: &Path, spec: &str) -> bool {
    let full_path = path.to_string_lossy();
    full_path == spec
        || path.file_name().and_then(|name| name.to_str()) == Some(spec)
        || full_path.ends_with(&format!("/{spec}"))
}
