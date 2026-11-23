#[path = "support/mod.rs"]
mod support;

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;
use std::thread;

#[test]
fn concurrent_cold_build_compiles_once_and_publishes_a_runnable_binary() {
    let output = Command::new("mktemp").arg("-d").output().unwrap();
    assert!(output.status.success());
    let dir = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    let source = support::examples_dir().join("break_target.c");
    let workers = 8;
    let ready = Barrier::new(workers);
    let compilations = AtomicUsize::new(0);

    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                ready.wait();
                let target = support::build_if_stale(&dir, "target", &source, |tmp| {
                    compilations.fetch_add(1, Ordering::Relaxed);
                    Command::new("gcc").arg("-o").arg(tmp).arg(&source).status()
                });
                let output = Command::new(target).output().unwrap();
                assert!(output.status.success());
                assert_eq!(output.stdout, b"i=1 total=1\ni=2 total=3\ni=3 total=6\n");
            });
        }
    });
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(compilations.load(Ordering::Relaxed), 1);
}
