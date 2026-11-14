//! run 编排：镜像 -> rootfs -> config.json -> 网络 / cgroup -> clone -> wait -> 清理。
//!
//! 拆成 prepare / start_once 两段：前台 run 直接跑一次；-d 时 supervisor
//! 复用同一份 Prepared 反复 start_once，实现 restart policy。

use anyhow::{bail, Context, Result};
use nix::errno::Errno;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{close, Pid};
use std::fs;
use std::io;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::thread;

use crate::cli::RunArgs;
use crate::network::DriverKind;
use crate::options::{FirewallBackend, RestartPolicy, RuntimeOptions, SeccompMode, UsernsRoot};
use crate::spec::{self, Limits, OciSpec};
use crate::{image, network, runtime, state, supervisor};

/// prepare 失败时自动清理半成品 bundle（--keep 时不清理，便于排查）。
struct BundleCleanup {
    path: PathBuf,
    armed: bool,
}

impl Drop for BundleCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// 一次容器生命周期的全部静态信息（重启时复用同一份 rootfs）。
#[derive(Debug, Clone)]
pub struct Prepared {
    pub id: String,
    pub bundle: PathBuf,
    pub cfg: OciSpec,
    pub opts: RuntimeOptions,
    pub args: RunArgs,
    pub limits: Limits,
    pub state_root: PathBuf,
    /// 前台 run 需要把容器输出 tee 到日志文件；-d 由 supervisor 直接重定向
    pub tee_log: bool,
}

/// 前台 run 的日志 tee：容器 init 及其后代的 1/2 接到 pipe，
/// 父进程一边写 <state>/containers/<id>/log，一边原样输出到终端。
/// -d 模式不创建它（supervisor 已 dup2 整个进程的 1/2 到日志文件）。
struct LogTee {
    read_fd: Option<i32>,
    write_fd: Option<i32>,
    log: Option<fs::File>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LogTee {
    fn new(state_root: &Path, id: &str) -> Result<Self> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            bail!("创建日志 pipe 失败: {}", io::Error::last_os_error());
        }
        let path = state::log_path(state_root, id);
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("创建日志 {} 失败", path.display()))?;
        Ok(Self {
            read_fd: Some(fds[0]),
            write_fd: Some(fds[1]),
            log: Some(log),
            handle: None,
        })
    }

    /// 传给 SpawnConfig：子进程把它 dup2 到 stdout/stderr。
    fn stdout_fd(&self) -> Option<i32> {
        self.write_fd
    }

    /// spawn 成功后立刻调用：父进程关掉写端（否则永远等不到 EOF），起读线程。
    fn spawn_reader(&mut self) {
        let (Some(read_fd), Some(mut log)) = (self.read_fd.take(), self.log.take()) else {
            return;
        };
        if let Some(w) = self.write_fd.take() {
            let _ = close(w);
        }
        self.handle = Some(thread::spawn(move || {
            use std::io::{Read, Write};
            // SAFETY: read_fd 是本结构体持有的 pipe 读端，只在此线程使用一次。
            let mut reader = unsafe { fs::File::from_raw_fd(read_fd) };
            let mut stdout = io::stdout();
            let mut buf = [0u8; 8192];
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                let _ = log.write_all(&buf[..n]);
                let _ = log.flush();
                let _ = stdout.write_all(&buf[..n]);
                let _ = stdout.flush();
            }
        }));
    }

    /// 容器退出后等待 tee 线程写完尾部，保证 logs 能看到完整输出。
    fn finish(&mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for LogTee {
    fn drop(&mut self) {
        // 异常路径只关 fd、不 join：进程可能正在退出，不能卡在等 EOF 上。
        if let Some(r) = self.read_fd.take() {
            let _ = close(r);
        }
        if let Some(w) = self.write_fd.take() {
            let _ = close(w);
        }
    }
}

pub fn run(args: &RunArgs, state_root: &Path, concurrency: usize) -> Result<i32> {
    let p = prepare(args, state_root, concurrency)?;

    if p.opts.detach {
        return supervisor::spawn_supervisor(p);
    }

    {
        let _g = state::lock(state_root)?;
        let mut s = state::load(state_root, &p.id)?;
        s.status = "running".into();
        s.started_at = Some(state::now());
        state::save(state_root, &s)?;
    }

    // 端口转发器随进程常驻；前台进程退出时线程自然终止
    let _forwarders = runtime::network::PortForwarders::start(&p.opts.ports, p.opts.container_ip)?;

    let result = start_once(&p, &|| false);
    let code = match result {
        Ok(c) => c,
        Err(e) => {
            // 启动失败也要收尾：清理 bundle 并把状态标成 exited
            cleanup_bundle(&p);
            {
                let _g = state::lock(state_root)?;
                if let Ok(mut s) = state::load(state_root, &p.id) {
                    s.status = "exited".into();
                    s.finished_at = Some(state::now());
                    let _ = state::save(state_root, &s);
                }
            }
            return Err(e);
        }
    };

    {
        let _g = state::lock(state_root)?;
        let mut s = state::load(state_root, &p.id)?;
        s.status = "exited".into();
        s.exit_code = Some(code);
        s.finished_at = Some(state::now());
        state::save(state_root, &s)?;
    }
    // 不删除 bundle：对齐 docker，退出后仍可 `miko start`，只有 `miko rm` 清理。
    Ok(code)
}

/// 从已有 state + bundle 重建 Prepared，供 `miko start` 使用。
pub fn prepare_from_state(state_root: &Path, s: &state::ContainerState) -> Result<Prepared> {
    if !s.bundle.is_dir() {
        bail!(
            "容器 {} 的 bundle 不存在（{}）；可能已被清理，无法 start",
            s.id,
            s.bundle.display()
        );
    }
    let cfg = spec::read(&s.bundle)
        .with_context(|| format!("读取 {}/config.json 失败", s.bundle.display()))?;

    let driver = DriverKind::parse(if cfg.miko.driver.is_empty() {
        "bridge"
    } else {
        &cfg.miko.driver
    })
    .unwrap_or(DriverKind::Bridge);

    let container_ip = s
        .ip
        .as_deref()
        .and_then(|ip| ip.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

    let restart = parse_restart_policy(&s.restart_policy);
    let seccomp = match cfg.miko.seccomp.as_str() {
        "unconfined" => SeccompMode::Unconfined,
        _ => SeccompMode::Default,
    };
    let apparmor = if cfg.miko.apparmor.is_empty() {
        None
    } else {
        Some(cfg.miko.apparmor.clone())
    };

    let limits = Limits {
        memory: cfg
            .linux
            .resources
            .as_ref()
            .and_then(|r| r.memory.as_ref().map(|m| m.limit)),
        cpus: cfg.linux.resources.as_ref().and_then(|r| {
            r.cpu.as_ref().and_then(|c| {
                if c.period > 0 && c.quota > 0 {
                    Some(c.quota as f64 / c.period as f64)
                } else {
                    None
                }
            })
        }),
        pids: cfg.linux.resources.as_ref().and_then(|r| {
            r.pids.as_ref().and_then(|p| {
                if p.limit > 0 {
                    Some(p.limit as u32)
                } else {
                    None
                }
            })
        }),
    };

    let opts = RuntimeOptions {
        driver,
        network_ref: cfg.miko.net_mode.clone(),
        network_name: s.network_name.clone().unwrap_or_else(|| cfg.miko.net_mode.clone()),
        container_ip,
        endpoint_ip: s.ip.as_deref().and_then(|ip| ip.parse().ok()),
        mac: None,
        aliases: Vec::new(),
        nat: cfg.miko.nat,
        dns: cfg.miko.dns.clone(),
        dns_search: cfg.miko.dns_search.clone(),
        dns_opts: cfg.miko.dns_opts.clone(),
        extra_hosts: cfg.miko.extra_hosts.clone(),
        ports: s.ports.clone(),
        seccomp,
        apparmor,
        userns: cfg.miko.userns,
        userns_root: if cfg.miko.userns_chroot {
            UsernsRoot::Chroot
        } else {
            UsernsRoot::Pivot
        },
        uid_maps: cfg.miko.uid_maps.clone(),
        gid_maps: cfg.miko.gid_maps.clone(),
        restart,
        detach: true, // start 始终后台
        platform: crate::arch::host().unwrap_or(crate::arch::HostArch::Amd64),
        firewall: FirewallBackend::Auto,
        state_root: state_root.to_path_buf(),
    };

    // start_once 只用到 args.no_cgroup / keep；其余填占位
    let args = RunArgs {
        image: s.image.clone(),
        name: Some(s.id.clone()),
        hostname: None,
        memory: None,
        cpus: None,
        pids: None,
        no_cgroup: limits.is_empty(),
        envs: Vec::new(),
        workdir: None,
        user: None,
        no_cap_drop: false,
        readonly_rootfs: false,
        bundle_dir: Some(s.bundle.clone()),
        keep: true, // start 后仍保留，交给 rm
        insecure_registry: false,
        pull: false,
        platform: None,
        firewall_backend: "auto".into(),
        detach: true,
        restart: s.restart_policy.clone(),
        volumes: Vec::new(),
        publish: Vec::new(),
        net: opts.network_ref.clone(),
        nat: opts.nat,
        ip: s.ip.clone(),
        mac_address: None,
        network_alias: Vec::new(),
        dns: Vec::new(),
        dns_search: Vec::new(),
        dns_opt: Vec::new(),
        add_host: Vec::new(),
        userns: opts.userns,
        userns_root: if opts.userns_root == UsernsRoot::Chroot {
            "chroot".into()
        } else {
            "pivot".into()
        },
        uid_map: None,
        gid_map: None,
        security_opt: Vec::new(),
        command: s.command.clone(),
    };

    Ok(Prepared {
        id: s.id.clone(),
        bundle: s.bundle.clone(),
        cfg,
        opts,
        args,
        limits,
        state_root: state_root.to_path_buf(),
        tee_log: false,
    })
}

fn parse_restart_policy(s: &str) -> RestartPolicy {
    match s {
        "always" => RestartPolicy::Always,
        "unless-stopped" => RestartPolicy::UnlessStopped,
        "on-failure" => RestartPolicy::OnFailure(None),
        x if x.starts_with("on-failure:") => {
            let n = x["on-failure:".len()..].parse().ok();
            RestartPolicy::OnFailure(n)
        }
        _ => RestartPolicy::No,
    }
}

pub fn prepare(args: &RunArgs, state_root: &Path, concurrency: usize) -> Result<Prepared> {
    let id = args.name.clone().unwrap_or_else(state::gen_id);
    state::validate_id(&id)?;
    if state::container_dir(state_root, &id)
        .join("state.json")
        .exists()
    {
        bail!("容器 {id} 已存在（用 --name 指定别的名字，或先 miko rm {id}）");
    }

    let mut opts = RuntimeOptions::parse(args, &id, state_root)?;
    // 网络 endpoint 先分配并持久化；prepare 后续任何一步失败都由 guard 回滚 IPAM。
    let (attachment, mut endpoint_guard) = network::create_run_endpoint(
        state_root,
        &opts.network_ref,
        &id,
        &id,
        opts.endpoint_ip,
        opts.mac.clone(),
        opts.aliases.clone(),
    )?;
    opts.container_ip = attachment.ip.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
    let bundle = args
        .bundle_dir
        .clone()
        .unwrap_or_else(|| state::bundle_path(state_root, &id));
    fs::create_dir_all(&bundle)
        .with_context(|| format!("创建 bundle {} 失败", bundle.display()))?;
    let mut guard = BundleCleanup {
        path: bundle.clone(),
        armed: !args.keep,
    };
    let rootfs = bundle.join("rootfs");

    // 镜像一律经本地缓存：tag 命中零网络，rootfs 按 diff_ids 复用已合并快照。
    let store = image::store::Store::new(state_root);
    let resolved = store.resolve(
        &args.image,
        args.insecure_registry,
        opts.platform,
        args.pull,
        concurrency,
    )?;
    let img = &resolved.image;
    println!(
        "miko: cache  = {} 层 / {} bytes / {}",
        resolved.record.layers.len(),
        resolved.record.size,
        resolved.record.platform
    );
    store.materialize_rootfs(&resolved, &rootfs)?;
    if opts.userns {
        image::layer::remap_owners(&rootfs, &opts.uid_maps, &opts.gid_maps)
            .context("按 userns 映射调整 rootfs owner 失败")?;
    }

    let limits = spec::parse_limits(args)?;
    let cfg = spec::build(img, args, &id, &rootfs, &limits, &opts)?;
    spec::write(&bundle, &cfg)?;
    println!("miko: bundle = {}", bundle.display());
    println!("miko: exec   = {:?}", cfg.process.args);
    println!(
        "miko: net    = {}, namespaces = {:?}, seccomp = {}, userns = {}",
        opts.net_label(),
        cfg.linux
            .namespaces
            .iter()
            .map(|n| n.typ.as_str())
            .collect::<Vec<_>>(),
        cfg.miko.seccomp,
        opts.userns
    );
    println!(
        "miko: arch   = {}, firewall = {}",
        opts.platform.label(),
        opts.firewall.label()
    );
    if opts.userns && opts.userns_root == UsernsRoot::Chroot {
        println!(
            "miko: WARN  = 嵌套 userns 兼容模式：父进程预挂 + chroot；\
             /proc 为宿主 pidns 视图，且不做 pivot_root，隔离弱于标准 userns 路径"
        );
    }

    {
        let _g = state::lock(state_root)?;
        state::ensure_dirs(state_root, &id)?;
        state::clear_stop_marker(state_root, &id);
        state::save(
            state_root,
            &state::ContainerState {
                id: id.clone(),
                image: args.image.clone(),
                command: cfg.process.args.clone(),
                status: "created".into(),
                pid: 0,
                supervisor_pid: None,
                created_at: state::now(),
                started_at: None,
                finished_at: None,
                exit_code: None,
                restarts: 0,
                restart_policy: opts.restart.label(),
                detached: opts.detach,
                bundle: bundle.clone(),
                net_mode: opts.net_label(),
                ports: opts.ports.clone(),
                keep: args.keep,
                stop_signal: state::normalize_stop_signal(&img.config.config.stop_signal),
                network_id: Some(attachment.network_id.clone()),
                network_name: Some(attachment.network_name.clone()),
                endpoint_id: Some(attachment.endpoint_id.clone()),
                ip: attachment.ip.map(|i| i.to_string()),
                host_ifaces: if attachment.needs_link() {
                    vec![attachment.host_iface.clone()]
                } else {
                    Vec::new()
                },
            },
        )?;
    }

    guard.armed = false;
    endpoint_guard.disarm();
    Ok(Prepared {
        id,
        bundle,
        cfg,
        opts,
        args: args.clone(),
        limits,
        state_root: state_root.to_path_buf(),
        tee_log: !args.detach,
    })
}

/// 启动一次容器并等待其退出；stop() 为真时说明收到外部停止请求。
pub fn start_once(p: &Prepared, stop: &dyn Fn() -> bool) -> Result<i32> {
    // 前台 run：额外一根日志 pipe；-d 时 supervisor 已把自身 1/2 重定向到 log 文件
    let mut log_tee = if p.tee_log {
        Some(LogTee::new(&p.state_root, &p.id)?)
    } else {
        None
    };

    let cgroup = if p.args.no_cgroup {
        None
    } else {
        runtime::cgroup::create(&p.id, &p.limits)?
    };

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("创建同步 pipe 失败: {}", io::Error::last_os_error());
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    runtime::install_signal_forwarder()?;
    // 标准 userns 路径由 __init 自己挂载 + pivot_root（真实内核可用）；
    // 嵌套 userns 内核下只能由父进程预挂、__init 改用 chroot（显式 --userns-root）。
    let pre_mounted = p.opts.userns && p.opts.userns_root == UsernsRoot::Chroot;
    // 每次启动都从 networks.json 读取当前全部 endpoint：network connect / disconnect
    // 之后即使 supervisor 自动重启，也能按最新网络拓扑建接口。
    let attachments = network::attachments_for_container(&p.state_root, &p.id)?;
    let new_net = attachments.iter().any(|a| a.driver.needs_netns());
    let spawn_cfg = runtime::SpawnConfig {
        new_net,
        new_user: p.opts.userns,
        uid_maps: p.opts.uid_maps.clone(),
        gid_maps: p.opts.gid_maps.clone(),
        pre_mounted,
        stdout_fd: log_tee.as_ref().and_then(|t| t.stdout_fd()),
    };

    // userns 下 proc/sysfs 无法在子 userns 内挂载，改由父进程（初始 userns）预挂。
    // PreMounted 必须一直持有到容器退出，Drop 会清理父进程 mount ns 里的挂载点。
    let mut pre_mounted = if spawn_cfg.pre_mounted {
        Some(runtime::pre_mount_standard(&p.bundle, &p.cfg)?)
    } else {
        None
    };

    let pid = match runtime::spawn(&p.bundle, read_fd, write_fd, &spawn_cfg) {
        Ok(p) => p,
        Err(e) => {
            let _ = close(read_fd);
            let _ = close(write_fd);
            if let Some(cg) = &cgroup {
                cg.cleanup();
            }
            return Err(e);
        }
    };
    runtime::set_child_pid(pid);
    // 立刻关掉父进程的写端并起 tee 线程，后续任何步骤失败都不会让日志丢在半路
    if let Some(t) = &mut log_tee {
        t.spawn_reader();
    }

    if spawn_cfg.new_user {
        runtime::write_id_maps(pid, &spawn_cfg)?;
    }

    let mut parent_net = runtime::network::ParentNet::setup(
        &attachments,
        pid.as_raw(),
        p.opts.firewall,
        p.opts.nat,
    )?;
    if let Some(cg) = &cgroup {
        cg.attach(pid.as_raw())?;
    }

    // 记录 init pid，供 ps / kill 使用
    {
        let _g = state::lock(&p.state_root)?;
        let mut s = state::load(&p.state_root, &p.id)?;
        s.pid = pid.as_raw();
        state::save(&p.state_root, &s)?;
    }

    let _ = close(read_fd);
    // 通知 __init：cgroup / 网络 / id map 全部就绪，可以开始挂载与 exec
    let n = unsafe { libc::write(write_fd, b"G".as_ptr() as *const libc::c_void, 1) };
    if n != 1 {
        bail!("向容器 init 发送 GO 失败: {}", io::Error::last_os_error());
    }
    let _ = close(write_fd);

    let code = wait_loop(pid, stop)?;
    // 等 tee 线程写完尾部：此后 miko logs 能看到完整输出
    if let Some(t) = &mut log_tee {
        t.finish();
    }

    if let Some(pm) = pre_mounted.as_mut() {
        pm.cleanup();
    }
    drop(pre_mounted);
    parent_net.cleanup();
    if let Some(cg) = &cgroup {
        cg.cleanup();
    }
    Ok(code)
}

fn wait_loop(pid: Pid, stop: &dyn Fn() -> bool) -> Result<i32> {
    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
            Ok(_) => continue,
            Err(Errno::EINTR) => {
                // 信号已由 forward_signal 转给容器 init；继续等它自然退出
                let _ = stop();
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

pub fn cleanup_bundle(p: &Prepared) {
    if p.args.keep {
        println!("miko: 保留 bundle {}", p.bundle.display());
        return;
    }
    if let Err(e) = fs::remove_dir_all(&p.bundle) {
        eprintln!("miko: 清理 bundle {} 失败: {e}", p.bundle.display());
    }
}
