//! -d 后台运行：双 fork + setsid 脱离终端，由一个轻量 supervisor 进程接管。
//! 无常驻 daemon、无 socket；状态全在状态目录里，ps/kill/rm 直接读写文件。

use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::options::RestartPolicy;
use crate::{container, runtime, state};

/// 返回给 `run` 的是「第一层父进程」的退出码；真正的工作在孤儿 supervisor 里。
pub fn spawn_supervisor(p: container::Prepared) -> Result<i32> {
    let log_path = state::log_path(&p.state_root, &p.id);
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("创建日志 {} 失败", log_path.display()))?;
    let log_fd = log.as_raw_fd();

    let first = unsafe { libc::fork() };
    if first < 0 {
        bail!("fork supervisor 失败: {}", std::io::Error::last_os_error());
    }
    if first > 0 {
        // 父进程：回收中间子进程，打印容器 id 后立即返回
        let mut status = 0i32;
        unsafe { libc::waitpid(first, &mut status, 0) };
        println!("{}", p.id);
        return Ok(0);
    }

    // 第一层子进程：新会话，脱离控制终端
    if unsafe { libc::setsid() } < 0 {
        unsafe { libc::_exit(1) };
    }
    let second = unsafe { libc::fork() };
    if second < 0 {
        unsafe { libc::_exit(1) };
    }
    if second > 0 {
        // 中间进程退出，让 supervisor 成为孤儿（被 init 收养），
        // 同时让上面的 waitpid 立即返回、父进程不会僵住。
        unsafe { libc::_exit(0) };
    }

    // ---- supervisor 本体 ----
    unsafe {
        libc::dup2(log_fd, 1);
        libc::dup2(log_fd, 2);
        if let Ok(c) = std::ffi::CString::new("/dev/null") {
            let nfd = libc::open(c.as_ptr(), libc::O_RDONLY);
            if nfd >= 0 {
                libc::dup2(nfd, 0);
                if nfd > 2 {
                    libc::close(nfd);
                }
            }
        }
        if log_fd > 2 {
            libc::close(log_fd);
        }
    }
    let code = run_loop(&p).unwrap_or(1);
    unsafe { libc::_exit(code) };
}

fn run_loop(p: &container::Prepared) -> Result<i32> {
    let root: &Path = &p.state_root;
    {
        let _g = state::lock(root)?;
        let mut s = state::load(root, &p.id)?;
        s.supervisor_pid = Some(std::process::id() as i32);
        state::save(root, &s)?;
    }

    // 转发器只启动一次：容器重启时 IP 不变，监听端口保持占用
    let _forwarders = runtime::network::PortForwarders::start(&p.opts.ports, p.opts.container_ip)?;
    let stop = || runtime::stop_flag_set() || state::has_stop_marker(root, &p.id);

    loop {
        if stop() {
            break;
        }
        {
            let _g = state::lock(root)?;
            let mut s = state::load(root, &p.id)?;
            s.status = "running".into();
            s.started_at = Some(state::now());
            state::save(root, &s)?;
        }

        let code = container::start_once(p, &stop)?;
        println!("miko: 容器 {} 退出，code={code}", p.id);

        // 所有 load -> 修改 -> save 都在锁内；start_once 自己也会取锁，
        // 所以锁段必须在调用它之前结束（StateLock 可重入，但仍避免长临界区）。
        let restarts = {
            let _g = state::lock(root)?;
            let mut s = state::load(root, &p.id)?;
            s.status = if state::has_stop_marker(root, &p.id) {
                "stopped"
            } else {
                "exited"
            }
            .into();
            s.exit_code = Some(code);
            s.finished_at = Some(state::now());
            state::save(root, &s)?;
            s.restarts
        };

        if !p.opts.restart.should_restart(code, stop()) {
            break;
        }
        if let RestartPolicy::OnFailure(Some(max)) = &p.opts.restart {
            if restarts >= *max {
                println!("miko: 达到 on-failure:{max} 重试上限，停止重启");
                break;
            }
        }

        let restarts = {
            let _g = state::lock(root)?;
            let mut s = state::load(root, &p.id)?;
            s.restarts += 1;
            state::save(root, &s)?;
            s.restarts
        };
        let delay_ms = (100u64 * restarts as u64).clamp(100, 5000);
        let mut waited = 0u64;
        while waited < delay_ms && !stop() {
            thread::sleep(Duration::from_millis(50));
            waited += 50;
        }
    }

    {
        let _g = state::lock(root)?;
        let mut s = state::load(root, &p.id)?;
        s.status = if state::has_stop_marker(root, &p.id) {
            "stopped"
        } else {
            "exited"
        }
        .into();
        s.supervisor_pid = None;
        state::save(root, &s)?;
    }
    container::cleanup_bundle(p);
    Ok(0)
}
