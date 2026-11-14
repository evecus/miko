//! 可选常驻进程：开机恢复 + 崩溃兜底 + 健康检查。
//!
//! 设计原则：
//! - **有 daemon 更省心，没 daemon 也能用**
//! - **默认只监控不托管**：退出时不 halt，容器继续跑（`--halt-on-exit` 可改）
//! - 用户 `miko stop` 写 stop marker；daemon 只对 always / unless-stopped 且无 marker 的容器做恢复/拉起

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::lifecycle;
use crate::state::{self, ContainerState, Healthcheck};

static STOPPING: AtomicBool = AtomicBool::new(false);

pub fn pid_path(root: &Path) -> PathBuf {
    root.join("daemon.pid")
}

pub fn run(root: &Path, interval_secs: u64, halt_on_exit: bool) -> Result<i32> {
    fs::create_dir_all(root)
        .with_context(|| format!("创建状态目录 {} 失败", root.display()))?;

    if let Some(old) = read_daemon_pid(root) {
        if state::alive(old) {
            bail!(
                "miko daemon 已在运行（pid={old}），pid 文件 {}",
                pid_path(root).display()
            );
        }
    }
    write_daemon_pid(root, std::process::id() as i32)?;
    install_signal_handlers()?;

    eprintln!(
        "miko: daemon 启动 root={} interval={}s halt_on_exit={halt_on_exit}",
        root.display(),
        interval_secs.max(1)
    );
    recover(root);

    let mut last_health: HashMap<String, Instant> = HashMap::new();
    let interval = Duration::from_secs(interval_secs.max(1));
    while !STOPPING.load(Ordering::SeqCst) {
        monitor_once(root);
        health_once(root, &mut last_health);

        let slice = Duration::from_millis(200);
        let mut waited = Duration::ZERO;
        while waited < interval && !STOPPING.load(Ordering::SeqCst) {
            thread::sleep(slice);
            waited += slice;
        }
    }

    if halt_on_exit {
        eprintln!("miko: daemon 退出，halt 全部运行中容器（--halt-on-exit）…");
        if let Err(e) = lifecycle::halt(root, &["*".into()], 10) {
            eprintln!("miko: halt 过程有错误: {e:#}");
        }
    } else {
        eprintln!("miko: daemon 退出，容器继续运行（默认不托管）");
    }
    let _ = fs::remove_file(pid_path(root));
    eprintln!("miko: daemon 已退出");
    Ok(0)
}

fn recover(root: &Path) {
    let list = match state::list(root) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("miko: 扫描容器失败: {e:#}");
            return;
        }
    };
    for s in list {
        if lifecycle::effective_status_pub(&s) == "running" {
            continue;
        }
        if !lifecycle::should_auto_start(root, &s) {
            continue;
        }
        eprintln!("miko: 恢复容器 {}", s.id);
        if let Err(e) = lifecycle::start(root, &[s.id.clone()]) {
            eprintln!("miko: 恢复 {} 失败: {e:#}", s.id);
        }
    }
}

fn monitor_once(root: &Path) {
    let list = match state::list(root) {
        Ok(v) => v,
        Err(_) => return,
    };
    for s in list {
        if lifecycle::effective_status_pub(&s) == "running" {
            continue;
        }
        if !lifecycle::should_auto_start(root, &s) {
            continue;
        }
        eprintln!("miko: 监控拉起容器 {}", s.id);
        if let Err(e) = lifecycle::start(root, &[s.id.clone()]) {
            eprintln!("miko: 拉起 {} 失败: {e:#}", s.id);
        }
    }
}

fn health_once(root: &Path, last: &mut HashMap<String, Instant>) {
    let list = match state::list(root) {
        Ok(v) => v,
        Err(_) => return,
    };
    let now = Instant::now();
    for s in list {
        if lifecycle::effective_status_pub(&s) != "running" {
            last.remove(&s.id);
            continue;
        }
        let Some(hc) = s.healthcheck.clone() else {
            continue;
        };
        let interval = Duration::from_secs(hc.interval_secs.max(1));
        if let Some(t) = last.get(&s.id) {
            if now.duration_since(*t) < interval {
                continue;
            }
        }
        last.insert(s.id.clone(), now);
        run_healthcheck(root, &s, &hc);
    }
}

fn run_healthcheck(root: &Path, s: &ContainerState, hc: &Healthcheck) {
    let in_start_period = s
        .started_at
        .map(|t| state::now().saturating_sub(t) < hc.start_period_secs)
        .unwrap_or(true);

    let ok = probe_in_container(root, &s.id, &hc.test, hc.timeout_secs);
    let mut streak = s.health_fail_streak;
    let mut status = s.health_status.clone().unwrap_or_else(|| "starting".into());

    if ok {
        streak = 0;
        status = "healthy".into();
    } else if in_start_period {
        status = "starting".into();
    } else {
        streak = streak.saturating_add(1);
        status = if streak >= hc.retries {
            "unhealthy".into()
        } else {
            "starting".into()
        };
    }

    {
        let _g = match state::lock(root) {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Ok(mut cur) = state::load(root, &s.id) {
            cur.health_status = Some(status.clone());
            cur.health_fail_streak = streak;
            let _ = state::save(root, &cur);
        }
    }

    if !ok && !in_start_period && streak >= hc.retries {
        eprintln!(
            "miko: 容器 {} 健康检查连续失败 {streak} 次，执行 reload",
            s.id
        );
        if let Err(e) = lifecycle::reload(root, &[s.id.clone()], 10) {
            eprintln!("miko: reload {} 失败: {e:#}", s.id);
        } else if let Ok(_g) = state::lock(root) {
            if let Ok(mut cur) = state::load(root, &s.id) {
                cur.health_fail_streak = 0;
                cur.health_status = Some("starting".into());
                let _ = state::save(root, &cur);
            }
        }
    }
}

fn probe_in_container(root: &Path, id: &str, test: &str, timeout_secs: u64) -> bool {
    let self_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut child = match Command::new(&self_exe)
        .args([
            "--state-dir",
            root.to_str().unwrap_or("/var/lib/miko"),
            "exec",
            id,
            "--",
            "sh",
            "-c",
            test,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("miko: health exec 启动失败: {e}");
            return false;
        }
    };

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
}

fn write_daemon_pid(root: &Path, pid: i32) -> Result<()> {
    let path = pid_path(root);
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .with_context(|| format!("写 {} 失败", path.display()))?;
    writeln!(f, "{pid}")?;
    Ok(())
}

fn read_daemon_pid(root: &Path) -> Option<i32> {
    let data = fs::read_to_string(pid_path(root)).ok()?;
    data.trim().parse().ok()
}

fn install_signal_handlers() -> Result<()> {
    extern "C" fn on_signal(_: libc::c_int) {
        STOPPING.store(true, Ordering::SeqCst);
    }
    unsafe {
        let handler = on_signal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGHUP, handler);
    }
    Ok(())
}
