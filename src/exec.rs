//! `miko exec`：进入正在运行的容器执行新进程。
//!
//! 对齐 Docker / runc 的 setns 路径（OCI runtime `exec`）：
//! 1. 打开目标 init 的 `/proc/<pid>/ns/*` 文件描述符；
//! 2. 在子进程里按正确顺序 `setns` 加入各 namespace；
//! 3. 加入 PID namespace 后再 `fork` 一次（内核要求：setns(CLONE_NEWPID)
//!    后只有子进程才真正处于该 pidns）；
//! 4. 可选加入容器 cgroup、配置 TTY、切换用户、chdir、execve。
//!
//! 不依赖 runc / containerd；父进程留在宿主命名空间，负责 wait / TTY 转发。

use anyhow::{bail, Context, Result};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{close, fork, ForkResult, Gid, Pid, Uid};
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::Duration;

use crate::cli::ExecArgs;
use crate::spec::{self, OciSpec};
use crate::state;

/// Linux namespace 类型与 setns 标志。
struct NsTarget {
    name: &'static str,
    flag: libc::c_int,
    /// 是否与当前进程同一 namespace（相同则跳过）
    skip: bool,
    fd: Option<RawFd>,
}

pub fn exec(root: &Path, args: &ExecArgs) -> Result<i32> {
    if args.command.is_empty() {
        bail!("必须指定要在容器内执行的命令");
    }

    let id = state::resolve_id(root, &args.container)?;
    let st = state::load(root, &id)?;
    if st.status != "running" || !state::alive(st.pid) {
        bail!("容器 {id} 未在运行");
    }
    let init_pid = st.pid;

    // 读容器 OCI 配置：默认 env / cwd / user
    let spec = spec::read(&st.bundle).with_context(|| {
        format!(
            "读取容器 config.json 失败（bundle={}）",
            st.bundle.display()
        )
    })?;

    let (uid, gid) = resolve_exec_user(args.user.as_deref(), &spec, &st.bundle)?;
    let cwd = args
        .workdir
        .clone()
        .unwrap_or_else(|| spec.process.cwd.clone());
    let env = merge_env(&spec.process.env, &args.envs);

    // 打开目标 namespace fd（必须在 setns 之前，mnt ns 切换后 /proc 视图会变）
    let mut namespaces = open_namespaces(init_pid)?;

    // 容器 cgroup（若有）
    let cgroup_procs = find_cgroup_procs(&id);

    // 管道：中间进程把「最终 exec 进程的宿主可见 pid」回传给父进程
    let mut pid_pipe = [0i32; 2];
    if unsafe { libc::pipe(pid_pipe.as_mut_ptr()) } != 0 {
        bail!("创建 pid pipe 失败: {}", io::Error::last_os_error());
    }

    // TTY：在**宿主 mnt ns** 里同时打开 master 与 slave。
    // setns 进入容器 mnt ns 后，宿主的 /dev/pts/N 路径不可见，
    // 但已经打开的 slave fd 仍然有效（与 runc 一致）。
    let pty = if args.tty {
        Some(open_pty().context("分配伪终端失败")?)
    } else {
        None
    };

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            unsafe {
                close(pid_pipe[1]).ok();
            }
            // 父进程不需要 slave
            if let Some(ref p) = pty {
                unsafe {
                    let _ = close(p.slave);
                }
            }
            // 读最终子进程 pid
            let mut buf = [0u8; 8];
            let n = read_full(pid_pipe[0], &mut buf)?;
            unsafe {
                close(pid_pipe[0]).ok();
            }
            if n < 4 {
                // 子进程在回传前失败
                let _ = waitpid(child, None);
                bail!("exec 子进程启动失败（未回报 pid）");
            }
            let exec_pid = i32::from_le_bytes(buf[0..4].try_into().unwrap());
            if exec_pid <= 0 {
                let _ = waitpid(child, None);
                bail!("exec 子进程启动失败");
            }

            // 关闭已不需要的 ns fd（父进程未 setns，但 fd 仍占着）
            for ns in &mut namespaces {
                if let Some(fd) = ns.fd.take() {
                    unsafe {
                        let _ = close(fd);
                    }
                }
            }

            if args.detach {
                // 脱离：中间进程已退出（或很快退出），业务进程由容器 init 收养
                if let Some(ref p) = pty {
                    unsafe {
                        let _ = close(p.master);
                    }
                }
                let _ = waitpid(child, None);
                println!("{exec_pid}");
                return Ok(0);
            }

            // 中间进程会 wait 业务进程并以相同退出码退出；
            // 外层只能 wait 中间进程（业务进程不是自己的子进程）。
            // TTY 模式下外层负责转发 master ↔ 终端，直到业务进程结束。
            if let Some(ref p) = pty {
                // 转发直到业务进程退出；真正退出码来自中间进程的 wait
                let _ = relay_pty_until(p.master, exec_pid, args.interactive);
            }
            // 非 TTY：stdio 已由业务进程继承；TTY：中间进程同样 wait 了业务进程
            Ok(wait_for_pid(child.as_raw())?)
        }
        ForkResult::Child => {
            // 中间进程：setns + 再 fork 进入 pidns + exec
            unsafe {
                close(pid_pipe[0]).ok();
            }
            // 关闭父进程侧 pty master（若有）；保留 slave fd 传给最终子进程
            let slave_fd = if let Some(ref p) = pty {
                unsafe {
                    let _ = close(p.master);
                }
                Some(p.slave)
            } else {
                None
            };

            let result = child_enter_and_exec(
                &mut namespaces,
                cgroup_procs.as_deref(),
                slave_fd,
                args,
                uid,
                gid,
                &cwd,
                &env,
                pid_pipe[1],
            );
            if let Err(e) = result {
                eprintln!("miko: exec 失败: {e:#}");
                // 尽量通知父进程
                let bad: i32 = -1;
                let _ = write_all(pid_pipe[1], &bad.to_le_bytes());
                unsafe {
                    libc::_exit(127);
                }
            }
            unsafe {
                libc::_exit(0);
            }
        }
    }
}

fn child_enter_and_exec(
    namespaces: &mut [NsTarget],
    cgroup_procs: Option<&Path>,
    slave_fd: Option<RawFd>,
    args: &ExecArgs,
    uid: u32,
    gid: u32,
    cwd: &str,
    env: &[String],
    pid_report_fd: RawFd,
) -> Result<()> {
    // ---- setns 顺序（对齐 runc）：user → 其它 → pid 最后 ----
    // 先处理 user ns：加入后成为该 userns 的 root，才能操作其下属 ns。
    for ns in namespaces.iter_mut() {
        if ns.name == "user" && !ns.skip {
            if let Some(fd) = ns.fd {
                setns_fd(fd, ns.flag).with_context(|| format!("setns({}) 失败", ns.name))?;
                // 进入容器 userns 后切换到该 ns 内的 root
                let _ = unsafe { libc::setresuid(0, 0, 0) };
                let _ = unsafe { libc::setresgid(0, 0, 0) };
            }
        }
    }
    for ns in namespaces.iter_mut() {
        if ns.name == "user" || ns.name == "pid" || ns.skip {
            continue;
        }
        if let Some(fd) = ns.fd {
            setns_fd(fd, ns.flag).with_context(|| format!("setns({}) 失败", ns.name))?;
        }
    }
    // PID 命名空间最后加入
    for ns in namespaces.iter_mut() {
        if ns.name == "pid" && !ns.skip {
            if let Some(fd) = ns.fd {
                setns_fd(fd, ns.flag).context("setns(pid) 失败")?;
            }
        }
    }

    // 关闭 ns fd
    for ns in namespaces.iter_mut() {
        if let Some(fd) = ns.fd.take() {
            unsafe {
                let _ = close(fd);
            }
        }
    }

    // setns(pid) 后必须再 fork，子进程才真正在容器 pidns 里
    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            // 把「宿主视角」的 grandchild pid 回传
            // 注意：在 pidns setns 之后，fork 返回的 child 在本进程视角是容器内 pid，
            // 但 waitpid 仍可用；父进程（miko CLI）需要的是宿主 pid。
            // 中间进程仍在宿主 pidns 的视角下？实际上 setns(CLONE_NEWPID) 后
            // *当前进程* 仍属旧 pidns，只有 *子进程* 属于新 pidns。
            // 因此这里 child 的 raw 值就是宿主可见的 pid。正确。
            let pid = child.as_raw();
            write_all(pid_report_fd, &pid.to_le_bytes())?;
            unsafe {
                let _ = close(pid_report_fd);
            }

            // 可选：把进程放入容器 cgroup
            if let Some(procs) = cgroup_procs {
                let _ = fs::write(procs, pid.to_string());
            }

            // 等待最终进程结束（非 detach 时由最外层 wait；这里做回收避免僵尸）
            // detach 时中间进程直接退出，由 init 收养
            if !args.detach {
                loop {
                    match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, code)) => unsafe { libc::_exit(code) },
                        Ok(WaitStatus::Signaled(_, sig, _)) => {
                            unsafe { libc::_exit(128 + sig as i32) };
                        }
                        Ok(_) => continue,
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(e) => {
                            eprintln!("miko: waitpid 失败: {e}");
                            unsafe { libc::_exit(1) };
                        }
                    }
                }
            }
            Ok(())
        }
        ForkResult::Child => {
            unsafe {
                let _ = close(pid_report_fd);
            }

            // 加入 cgroup（子进程自己写也行）
            if let Some(procs) = cgroup_procs {
                let _ = fs::write(procs, std::process::id().to_string());
            }

            // TTY：使用宿主侧已打开的 slave fd（跨 mnt ns 仍然有效）
            if let Some(sfd) = slave_fd {
                setup_tty_slave_fd(sfd)?;
            } else if !args.interactive {
                // 非交互：stdin 接到 /dev/null，避免读宿主终端
                let null = OpenOptions::new().read(true).write(true).open("/dev/null")?;
                unsafe {
                    libc::dup2(null.as_raw_fd(), 0);
                }
            }

            // 工作目录
            if !cwd.is_empty() {
                if let Err(e) = std::env::set_current_dir(cwd) {
                    // 容器内路径可能不存在，给出明确错误
                    bail!("切换工作目录 {cwd:?} 失败: {e}");
                }
            }

            // 用户
            if uid != 0 || gid != 0 {
                nix::unistd::setgroups(&[]).context("setgroups 失败")?;
                nix::unistd::setresgid(Gid::from_raw(gid), Gid::from_raw(gid), Gid::from_raw(gid))
                    .context("setresgid 失败")?;
                nix::unistd::setresuid(Uid::from_raw(uid), Uid::from_raw(uid), Uid::from_raw(uid))
                    .context("setresuid 失败")?;
            }

            // 非 privileged：保持容器默认能力边界（已在 init 时裁过）；
            // exec 进程是新进程，capability 从当前（root 或已降权）继承。
            // --privileged 时确保有效 capability 全集（尽力而为）。
            if args.privileged {
                // 在已加入的 userns 里尽量恢复能力；失败不致命
                let _ = raise_all_caps();
            }

            do_execve(&args.command, env)?;
            unreachable!()
        }
    }
}

fn do_execve(command: &[String], env: &[String]) -> Result<()> {
    let path = resolve_path(&command[0], env);
    let cpath = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("命令路径含 NUL: {}", path.display()))?;

    let argv: Vec<CString> = command
        .iter()
        .map(|a| CString::new(a.as_str()).map_err(|e| anyhow::anyhow!("参数含 NUL: {e}")))
        .collect::<Result<Vec<_>>>()?;
    let envc: Vec<CString> = env
        .iter()
        .map(|e| CString::new(e.as_str()).map_err(|e| anyhow::anyhow!("环境变量含 NUL: {e}")))
        .collect::<Result<Vec<_>>>()?;

    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_p.push(ptr::null());
    let mut env_p: Vec<*const libc::c_char> = envc.iter().map(|s| s.as_ptr()).collect();
    env_p.push(ptr::null());

    unsafe { libc::execve(cpath.as_ptr(), argv_p.as_ptr(), env_p.as_ptr()) };
    bail!(
        "execve {} 失败: {}",
        path.display(),
        io::Error::last_os_error()
    )
}

fn resolve_path(cmd: &str, env: &[String]) -> PathBuf {
    if cmd.contains('/') {
        return PathBuf::from(cmd);
    }
    let path = env
        .iter()
        .find_map(|e| e.strip_prefix("PATH=").map(|s| s.to_string()))
        .unwrap_or_else(|| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    for dir in path.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(cmd);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(cmd)
}

fn merge_env(base: &[String], extra: &[String]) -> Vec<String> {
    let mut out = base.to_vec();
    for e in extra {
        let key = e.split_once('=').map(|(k, _)| k).unwrap_or(e.as_str());
        out.retain(|x| !x.starts_with(&format!("{key}=")) && x != key);
        if e.contains('=') {
            out.push(e.clone());
        }
    }
    out
}

fn resolve_exec_user(user: Option<&str>, spec: &OciSpec, bundle: &Path) -> Result<(u32, u32)> {
    match user {
        None => Ok((spec.process.user.uid, spec.process.user.gid)),
        Some(u) => {
            // 复用 spec 里的解析逻辑：需要 rootfs 路径
            let rootfs = bundle.join("rootfs");
            // parse_user 是 private，这里内联一个精简版
            parse_user_spec(u, &rootfs)
        }
    }
}

fn parse_user_spec(spec: &str, rootfs: &Path) -> Result<(u32, u32)> {
    if let Ok(uid) = spec.parse::<u32>() {
        return Ok((uid, uid));
    }
    if let Some((u, g)) = spec.split_once(':') {
        if let (Ok(uid), Ok(gid)) = (u.parse::<u32>(), g.parse::<u32>()) {
            return Ok((uid, gid));
        }
        // 名字:名字 或 名字:gid
        let uid = lookup_passwd(rootfs, u)?.0;
        let gid = if let Ok(n) = g.parse::<u32>() {
            n
        } else {
            lookup_group(rootfs, g)?
        };
        return Ok((uid, gid));
    }
    // 纯用户名
    let (uid, gid) = lookup_passwd(rootfs, spec)?;
    Ok((uid, gid))
}

fn lookup_passwd(rootfs: &Path, name: &str) -> Result<(u32, u32)> {
    let text = fs::read_to_string(rootfs.join("etc/passwd"))
        .with_context(|| format!("读取 {}/etc/passwd 失败", rootfs.display()))?;
    for line in text.lines() {
        let p: Vec<&str> = line.split(':').collect();
        if p.len() >= 4 && p[0] == name {
            let uid: u32 = p[2].parse().context("passwd uid")?;
            let gid: u32 = p[3].parse().context("passwd gid")?;
            return Ok((uid, gid));
        }
    }
    bail!("容器内找不到用户 {name:?}");
}

fn lookup_group(rootfs: &Path, name: &str) -> Result<u32> {
    let text = fs::read_to_string(rootfs.join("etc/group"))
        .with_context(|| format!("读取 {}/etc/group 失败", rootfs.display()))?;
    for line in text.lines() {
        let p: Vec<&str> = line.split(':').collect();
        if p.len() >= 3 && p[0] == name {
            return p[2].parse().context("group gid");
        }
    }
    bail!("容器内找不到组 {name:?}");
}

fn open_namespaces(init_pid: i32) -> Result<Vec<NsTarget>> {
    let types = [
        ("user", libc::CLONE_NEWUSER),
        ("mnt", libc::CLONE_NEWNS),
        ("uts", libc::CLONE_NEWUTS),
        ("ipc", libc::CLONE_NEWIPC),
        ("net", libc::CLONE_NEWNET),
        ("cgroup", libc::CLONE_NEWCGROUP),
        ("pid", libc::CLONE_NEWPID),
    ];
    let mut out = Vec::with_capacity(types.len());
    for (name, flag) in types {
        let path = format!("/proc/{init_pid}/ns/{name}");
        let self_path = format!("/proc/self/ns/{name}");
        // 某些内核/配置可能没有 cgroup ns
        if !Path::new(&path).exists() {
            out.push(NsTarget {
                name,
                flag,
                skip: true,
                fd: None,
            });
            continue;
        }
        let same = match (fs::read_link(&path), fs::read_link(&self_path)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if same {
            out.push(NsTarget {
                name,
                flag,
                skip: true,
                fd: None,
            });
            continue;
        }
        let f = File::open(&path).with_context(|| format!("打开 {path} 失败"))?;
        out.push(NsTarget {
            name,
            flag,
            skip: false,
            fd: Some(f.into_raw_fd()),
        });
    }
    Ok(out)
}

fn setns_fd(fd: RawFd, flag: libc::c_int) -> Result<()> {
    if unsafe { libc::setns(fd, flag) } != 0 {
        bail!("{}", io::Error::last_os_error());
    }
    Ok(())
}

fn find_cgroup_procs(id: &str) -> Option<PathBuf> {
    let p = PathBuf::from(format!("/sys/fs/cgroup/miko-{id}/cgroup.procs"));
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

// ---------------- PTY ----------------

struct Pty {
    master: RawFd,
    /// 在宿主 mnt ns 打开的 slave；setns 后仍可 dup2 / TIOCSCTTY
    slave: RawFd,
}

fn open_pty() -> Result<Pty> {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        bail!("posix_openpt: {}", io::Error::last_os_error());
    }
    if unsafe { libc::grantpt(master) } != 0 {
        unsafe {
            close(master).ok();
        }
        bail!("grantpt: {}", io::Error::last_os_error());
    }
    if unsafe { libc::unlockpt(master) } != 0 {
        unsafe {
            close(master).ok();
        }
        bail!("unlockpt: {}", io::Error::last_os_error());
    }
    // c_char 在不同目标上可能是 i8 或 u8，统一用 libc::c_char
    let mut buf = [0 as libc::c_char; 64];
    if unsafe { libc::ptsname_r(master, buf.as_mut_ptr(), buf.len()) } != 0 {
        unsafe {
            close(master).ok();
        }
        bail!("ptsname_r: {}", io::Error::last_os_error());
    }
    let path = unsafe { CStr::from_ptr(buf.as_ptr() as *const _) }
        .to_string_lossy()
        .into_owned();
    // 关键：在宿主命名空间打开 slave。进入容器 mnt ns 后再 open 路径会 ENOENT。
    let slave = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(f) => f.into_raw_fd(),
        Err(e) => {
            unsafe {
                close(master).ok();
            }
            bail!("打开 pty slave {path} 失败: {e}");
        }
    };
    Ok(Pty { master, slave })
}

fn setup_tty_slave_fd(sfd: RawFd) -> Result<()> {
    // 新会话 + 控制终端；sfd 是宿主侧打开的，跨 mnt ns 仍然有效
    unsafe {
        if libc::setsid() < 0 {
            // 已是 session leader 时可能失败，不致命
        }
        // TIOCSCTTY：把 slave 设为控制终端
        if libc::ioctl(sfd, libc::TIOCSCTTY as _, 0) != 0 {
            // 某些环境无控制终端权限时失败，仍继续 dup stdio
            let err = io::Error::last_os_error();
            eprintln!("miko: TIOCSCTTY 警告: {err}");
        }
        libc::dup2(sfd, 0);
        libc::dup2(sfd, 1);
        libc::dup2(sfd, 2);
        if sfd > 2 {
            libc::close(sfd);
        }
    }
    Ok(())
}

/// 转发 PTY master ↔ 宿主终端，直到业务进程（宿主 pid）退出。
/// 不能 waitpid 该 pid（不是自己的子进程），用 kill(pid, 0) / /proc 探测。
fn relay_pty_until(master: RawFd, exec_pid: i32, interactive: bool) -> Result<i32> {
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty_fd = if unsafe { libc::isatty(0) } == 1 {
        0
    } else if unsafe { libc::isatty(1) } == 1 {
        1
    } else {
        -1
    };
    if tty_fd >= 0 {
        unsafe {
            libc::tcgetattr(tty_fd, &mut old);
            let mut raw = old;
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(tty_fd, libc::TCSANOW, &raw);
        }
    }

    set_nonblock(master, true)?;
    if interactive && unsafe { libc::isatty(0) } == 1 {
        set_nonblock(0, true)?;
    }

    let mut stdin_buf = [0u8; 4096];
    let mut master_buf = [0u8; 4096];
    loop {
        if !state::alive(exec_pid) {
            // 进程已退出；读走 master 残留输出后返回
            while let Ok(n) = read_fd(master, &mut master_buf) {
                if n == 0 {
                    break;
                }
                let _ = io::stdout().write_all(&master_buf[..n]);
            }
            let _ = io::stdout().flush();
            break;
        }

        let mut fds = [
            libc::pollfd {
                fd: if interactive && unsafe { libc::isatty(0) } == 1 {
                    0
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let pr = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 200) };
        if pr < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            bail!("poll: {err}");
        }

        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match read_fd(0, &mut stdin_buf) {
                Ok(0) => {}
                Ok(n) => {
                    let _ = write_all(master, &stdin_buf[..n]);
                }
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {}
                Err(_) => {}
            }
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match read_fd(master, &mut master_buf) {
                Ok(0) => thread::sleep(Duration::from_millis(20)),
                Ok(n) => {
                    let _ = io::stdout().write_all(&master_buf[..n]);
                    let _ = io::stdout().flush();
                }
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {}
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    if tty_fd >= 0 {
        unsafe {
            libc::tcsetattr(tty_fd, libc::TCSANOW, &old);
        }
    }
    unsafe {
        let _ = close(master);
    }
    // 退出码由中间进程 wait 后传递；这里用 0 占位，外层会再 wait 中间进程
    // 实际上中间进程 exit code 才是业务进程的。调用方应优先采用 wait(中间进程)。
    Ok(0)
}

fn wait_for_pid(pid: i32) -> Result<i32> {
    loop {
        match waitpid(Pid::from_raw(pid), None) {
            Ok(WaitStatus::Exited(_, c)) => return Ok(c),
            Ok(WaitStatus::Signaled(_, s, _)) => return Ok(128 + s as i32),
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => return Ok(0),
            Err(e) => bail!("waitpid({pid}): {e}"),
        }
    }
}

fn set_nonblock(fd: RawFd, on: bool) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        bail!("fcntl F_GETFL: {}", io::Error::last_os_error());
    }
    let new = if on {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, new) } < 0 {
        bail!("fcntl F_SETFL: {}", io::Error::last_os_error());
    }
    Ok(())
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn read_full(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        let n = read_fd(fd, &mut buf[off..]).context("读 pipe 失败")?;
        if n == 0 {
            break;
        }
        off += n;
        if off >= 4 {
            break;
        }
    }
    Ok(off)
}

fn write_all(fd: RawFd, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const _, data.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            bail!("write: {err}");
        }
        data = &data[n as usize..];
    }
    Ok(())
}

fn raise_all_caps() -> Result<()> {
    // 尽力把 permitted/effective 拉满；不保证成功（可能已无 CAP_SETPCAP）
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const V3: u32 = 0x2008_0522;
    let mut hdr = CapHeader {
        version: V3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: !0,
        permitted: !0,
        inheritable: 0,
    }; 2];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut hdr as *mut _ as *mut libc::c_void,
            data.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if rc != 0 {
        // 忽略
    }
    Ok(())
}
