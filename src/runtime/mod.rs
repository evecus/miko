pub mod cgroup;
pub mod firewall;
pub mod init;
pub mod netdrv;
pub mod netlink;
pub mod network;
pub mod rootfs;
pub mod seccomp;
pub mod security;

pub use init::init_main;

use anyhow::{bail, Context, Result};
use nix::mount::{umount2, MntFlags};
use nix::unistd::Pid;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::spec::{Mapping, OciSpec};

/// clone 时的 namespace 与安全相关开关（父进程据此准备 netns / id map）。
#[derive(Debug, Clone, Default)]
pub struct SpawnConfig {
    pub new_net: bool,
    pub new_user: bool,
    pub uid_maps: Vec<Mapping>,
    pub gid_maps: Vec<Mapping>,
    /// userns 下由父进程（初始 userns 权限）预先挂好标准文件系统
    pub pre_mounted: bool,
    /// 前台 run：把子进程 stdout/stderr 接到这个 pipe 写端，由父进程 tee 到日志文件。
    /// -d 时为 None（supervisor 已把自身 1/2 重定向到日志文件，子进程直接继承）。
    pub stdout_fd: Option<i32>,
}

static CHILD_PID: AtomicI32 = AtomicI32::new(0);
/// 收到外部信号时置位；supervisor 据此停止 restart 循环（kill 会同时写 stop 标记）
static STOP_FLAG: AtomicBool = AtomicBool::new(false);

/// 父进程把终端信号转发给容器 init（PID 1），由它再转给真正的用户进程
extern "C" fn forward_signal(sig: libc::c_int) {
    STOP_FLAG.store(true, Ordering::Relaxed);
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

pub fn stop_flag_set() -> bool {
    STOP_FLAG.load(Ordering::Relaxed)
}

pub fn clear_stop_flag() {
    STOP_FLAG.store(false, Ordering::Relaxed);
}

pub fn install_signal_forwarder() -> Result<()> {
    clear_stop_flag();
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT] {
        let old = unsafe { libc::signal(sig, forward_signal as *const () as libc::sighandler_t) };
        if old == libc::SIG_ERR {
            bail!("安装信号转发 handler 失败: {}", io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn set_child_pid(pid: Pid) {
    CHILD_PID.store(pid.as_raw(), Ordering::Relaxed);
}

struct ChildArgs {
    exe: CString,
    // 保持 argv 字符串内存存活，子进程只读指针数组，不做任何堆分配
    _argv: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    write_fd: i32,
    /// 前台 run 的日志 pipe 写端（None 表示继承父进程已有的 1/2）
    log_fd: Option<i32>,
}

/// clone 出来的子进程只做两件事：关掉 pipe 写端，立刻 re-exec 自身为 `__init`。
/// 这样 Rust 运行时在干净的新 PID namespace 里重新初始化，避开 clone + Rust std 的坑。
extern "C" fn child_main(raw: *mut libc::c_void) -> libc::c_int {
    let args = unsafe { &*(raw as *const ChildArgs) };
    unsafe {
        libc::close(args.write_fd);
        if let Some(fd) = args.log_fd {
            // 容器 init 及其后代的 stdout/stderr 全部写入日志 pipe；
            // 父进程负责 tee 到终端 + 日志文件。
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                libc::close(fd);
            }
        }
        libc::execv(args.exe.as_ptr(), args.argv_ptrs.as_ptr());
    }
    let msg = b"miko: execv(/proc/self/exe) failed\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(127);
    }
}

/// 一次性 clone：NEWNS / NEWPID / NEWUTS / NEWIPC，按 cfg 追加 NEWNET / NEWUSER。
pub fn spawn(
    bundle: &Path,
    sync_read_fd: i32,
    sync_write_fd: i32,
    cfg: &SpawnConfig,
) -> Result<Pid> {
    let exe = CString::new("/proc/self/exe")?;
    let mut argv = vec![
        CString::new("miko")?,
        CString::new("__init")?,
        CString::new("--bundle")?,
        CString::new(bundle.as_os_str().as_bytes())?,
        CString::new("--sync-fd")?,
        CString::new(sync_read_fd.to_string())?,
    ];
    if cfg.pre_mounted {
        argv.push(CString::new("--pre-mounted")?);
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let args = Box::new(ChildArgs {
        exe,
        _argv: argv,
        argv_ptrs,
        write_fd: sync_write_fd,
        log_fd: cfg.stdout_fd,
    });

    let mut flags = libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::SIGCHLD;
    if cfg.new_net {
        flags |= libc::CLONE_NEWNET;
    }
    if cfg.new_user {
        flags |= libc::CLONE_NEWUSER;
    }

    let mut stack = vec![0u8; 1024 * 1024];
    let top = unsafe { stack.as_mut_ptr().add(stack.len()) } as usize;
    let top = (top & !0x0fusize) as *mut libc::c_void;

    let pid = unsafe {
        libc::clone(
            child_main,
            top,
            flags,
            Box::into_raw(args) as *mut libc::c_void,
        )
    };
    if pid < 0 {
        bail!("clone 创建容器进程失败: {}", io::Error::last_os_error());
    }
    Ok(Pid::from_raw(pid))
}

// ---------------------------------------------------------------- user namespace

/// 父进程（初始 userns）在子进程 wait_go 之前写好 uid/gid 映射。
/// 顺序要求：setgroups=deny -> uid_map -> gid_map；任意一步失败直接报错。
pub fn write_id_maps(pid: Pid, cfg: &SpawnConfig) -> Result<()> {
    let base = PathBuf::from(format!("/proc/{}", pid.as_raw()));
    let setgroups = base.join("setgroups");
    if setgroups.exists() {
        fs::write(&setgroups, "deny")
            .with_context(|| format!("写 {} 失败", setgroups.display()))?;
    }
    let render = |maps: &[Mapping]| -> String {
        maps.iter()
            .map(|m| format!("{} {} {}\n", m.container_id, m.host_id, m.size))
            .collect()
    };
    fs::write(base.join("uid_map"), render(&cfg.uid_maps))
        .with_context(|| format!("写 {} 失败", base.join("uid_map").display()))?;
    fs::write(base.join("gid_map"), render(&cfg.gid_maps))
        .with_context(|| format!("写 {} 失败", base.join("gid_map").display()))?;
    Ok(())
}

/// 父进程预挂载产生的挂载点，容器退出后按「先子后父」lazy umount。
pub struct PreMounted {
    points: Vec<PathBuf>,
}

impl PreMounted {
    pub fn cleanup(&mut self) {
        // 逆序：先卸载最深层子挂载（/dev/null 等），最后卸载 /dev、/proc、/sys
        for p in self.points.iter().rev() {
            let _ = umount2(p, MntFlags::MNT_DETACH);
        }
        self.points.clear();
    }
}

impl Drop for PreMounted {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// userns 路径：子 userns 内挂 procfs/sysfs 会 EPERM，改由父进程预先挂好。
/// __init 收到 --pre-mounted 后跳过挂载，直接 pivot_root。
pub fn pre_mount_standard(bundle: &Path, spec: &OciSpec) -> Result<PreMounted> {
    let rootfs = bundle.join(&spec.root.path);
    let points = rootfs::mount_all(&rootfs, spec, false)
        .context("父进程预挂载标准文件系统失败（userns 需要初始 userns 权限）")?;
    Ok(PreMounted { points })
}
