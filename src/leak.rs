use std::collections::HashMap;

/// 追跡対象のヒープアロケータ関数の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocFn {
    Malloc,
    Calloc,
    Realloc,
    Free,
}

/// 解放されずに残っている1つのヒープ確保。
#[derive(Debug, Clone)]
pub struct LiveAlloc {
    pub size: u64,
    /// 確保元の呼び出し位置(リンク時アドレス。`malloc` 等の戻りアドレス)。
    pub call_site: u64,
}

/// malloc/calloc/realloc の呼び出し(エントリ)を捕捉してから、戻りアドレス
/// でリターン値(確保されたポインタ)を捕捉するまでの間、保持しておく情報。
/// `free` は引数(解放するポインタ)だけで完結するためエントリ時点で
/// 即座に処理し、ここには入らない。
#[derive(Debug, Clone)]
pub struct PendingCall {
    pub func: AllocFn,
    /// malloc/calloc: 要求サイズ。realloc: 新しいサイズ。
    pub size: u64,
    /// realloc の場合のみ、再確保元のポインタ(それ以外は 0)。
    pub old_ptr: u64,
    /// 呼び出し元の位置(リンク時アドレス)。リーク一覧の「確保元」表示に使う。
    pub call_site: u64,
}

/// メモリリーク検出用の状態一式。`leak on`/`leak off` で有効/無効を切り替え、
/// 実行中に malloc/calloc/realloc/free の呼び出しをブレークポイントで捕捉して
/// 追跡する(`Debugger::cont` 経由の実行時のみ。詳細は debugger.rs 側を参照)。
#[derive(Default)]
pub struct LeakTracker {
    pub enabled: bool,
    /// エントリブレークポイントの実行時アドレス -> 関数種別。
    /// `run` ごとに解決し直す(プロセスが変われば libc のロードアドレスも
    /// 変わりうるため)。
    pub entries: HashMap<u64, AllocFn>,
    /// 戻りアドレス(実行時アドレス) -> そこで完了するはずの呼び出し情報。
    pub pending: HashMap<u64, PendingCall>,
    /// 解放されていない確保: ポインタ(実行時アドレス) -> 確保情報。
    pub live: HashMap<u64, LiveAlloc>,
    pub total_allocs: u64,
    pub total_frees: u64,
    /// 追跡中の確保と対応しない free (二重解放・追跡外ポインタの可能性)。
    pub bad_frees: Vec<u64>,
}

impl LeakTracker {
    /// 新しいプロセスの起動時に呼ぶ。`enabled` はユーザー設定なので保持し、
    /// それ以外の実行中状態(解決済みアドレス・追跡データ)をすべて捨てる。
    pub fn reset_for_run(&mut self) {
        self.entries.clear();
        self.pending.clear();
        self.live.clear();
        self.total_allocs = 0;
        self.total_frees = 0;
        self.bad_frees.clear();
    }
}
