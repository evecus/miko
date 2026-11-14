//! 容器 PID 1：完成挂载/安全设置后 fork 出真正的用户进程，
//! 自己留下做信号转发 + 僵尸回收，并以用户进程的退出码退出。

use anyhow::{bail, Context, Result};
use nix::errno::Errno;
use nix::sys::signal::{kill, pthread_sigmask, SigSet, SigmaskHow, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, fork, ForkResult, Pid};
use std::ffi::{c_char, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process;

use super::{network, rootfs, seccomp, security};
use crate::cli::InitArgs;
use crate::spec::{self, OciSpec};

pub fn init_main(args: &InitArgs) -> Result<()> {
    wait_go(args.sync_fd)?;

    let spec = spec::read(&args.bundle)?;
    // 网络配置需要 CAP_NET_ADMIN，必须在 security::apply 裁剪 capabilities 之前完成。
    // endpoint 列表从 networks.json 动态读取，network connect 后重启也自动生效。
    let attachments = network::container_attachments(&spec)?;
    network::prepare_rootfs_etc(&args.bundle, &spec, &attachments)?;
    network::setup_container(&spec, &attachments)?;
    rootfs::setup(&args.bundle, &spec, args.pre_mounted)?;
    security::apply(&spec)?;

    // PID 1 用 sigwait 同步收信号（pidns init 会忽略默认 dispositions，不能用普通 handler）
    let mut blocked = SigSet::empty();
    for s in [
        Signal::SIGCHLD,
        Signal::SIGTERM,
        Signal::SIGINT,
        Signal::SIGQUIT,
        Signal::SIGHUP,
    ] {
        blocked.add(s);
    }
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), None).context("阻塞信号失败")?;

    let child = match unsafe { fork() }? {
        ForkResult::Child => {
            // 子进程继承的阻塞掩码必须清掉，否则用户进程收不到任何信号
            pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
                .context("恢复信号掩码失败")?;
            exec_user(&spec);
        }
        ForkResult::Parent { child } => child,
    };

    let code = reap(blocked, child)?;
    process::exit(code);
}

fn wait_go(fd: i32) -> Result<()> {
    let mut buf = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        if n == 1 {
            break;
        }
        if n == 0 {
            bail!("父进程在同步前关闭了 pipe");
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        bail!("读取同步 pipe 失败: {err}");
    }
    let _ = close(fd);
    Ok(())
}

fn reap(set: SigSet, child: Pid) -> Result<i32> {
    loop {
        let sig = match set.wait() {
            Ok(s) => s,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        };
        if sig == Signal::SIGCHLD {
            loop {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(p, code)) => {
                        if p == child {
                            return Ok(code);
                        }
                    }
                    Ok(WaitStatus::Signaled(p, s, _)) => {
                        if p == child {
                            return Ok(128 + s as i32);
                        }
                    }
                    Ok(WaitStatus::StillAlive) => break,
                    Ok(_) => continue,
                    Err(Errno::ECHILD) => break,
                    Err(e) => return Err(e.into()),
                }
            }
        } else {
            let _ = kill(child, sig);
        }
    }
}

fn exec_user(spec: &OciSpec) -> ! {
    match do_exec(spec) {
        Ok(_) => {}
        Err(e) => eprintln!("miko: {e:#}"),
    }
    unsafe { libc::_exit(127) }
}

fn do_exec(spec: &OciSpec) -> Result<()> {
    let args = &spec.process.args;
    let path = resolve_exec(&args[0], &spec.process.env);
    let cpath = CString::new(path.as_os_str().as_bytes())?;

    let argv: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    let env: Vec<CString> = spec
        .process
        .env
        .iter()
        .map(|e| CString::new(e.as_str()))
        .collect::<Result<Vec<_>, _>>()?;

    let mut argv_ptrs: Vec<*const c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<*const c_char> = env.iter().map(|s| s.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());

    std::env::set_current_dir(&spec.process.cwd)
        .with_context(|| format!("切换工作目录 {} 失败", spec.process.cwd))?;

    // seccomp / AppArmor 必须在 execve 之前装到「用户进程」上，
    // 而不是 PID 1 —— PID 1 自己还需要 waitpid/kill 等 syscall。
    seccomp::apply(spec).context("应用容器安全策略失败")?;

    unsafe { libc::execve(cpath.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr()) };
    bail!(
        "execve {} 失败: {}",
        path.display(),
        io::Error::last_os_error()
    );
}

/// OCI 语义：args[0] 含 `/` 直接用；否则按 PATH 查找可执行文件。
fn resolve_exec(cmd: &str, env: &[String]) -> PathBuf {
    if cmd.contains('/') {
        return PathBuf::from(cmd);
    }
    let path = env
        .iter()
        .find_map(|e| e.strip_prefix("PATH="))
        .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    for dir in path.split(':') {
        let p = Path::new(dir).join(cmd);
        if executable(&p) {
            return p;
        }
    }
    PathBuf::from(cmd)
}

fn executable(p: &Path) -> bool {
    match CString::new(p.as_os_str().as_bytes()) {
        Ok(c) => unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 },
        Err(_) => false,
    }
}
