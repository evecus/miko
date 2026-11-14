//! 容器安全收窄：seccomp（手写 classic BPF）+ AppArmor profile。
//!
//! 不引入 libseccomp / seccompiler：BPF 指令是固定结构，直接构造更可控，
//! 也避免让依赖替我们理解「允许什么、拒绝什么」。
//!
//! 策略：**默认 ALLOW + 显式拒绝危险 syscall 集合**，并对架构做硬校验。
//! 过滤器在 x86_64 / aarch64 上同样生效：syscall 编号取自 `libc::SYS_*`（按
//! 目标架构条件编译），audit arch 常量由 `arch::HostArch` 提供。

use anyhow::{bail, Context, Result};
use std::fs;
use std::io;
use std::path::Path;

use crate::spec::OciSpec;

// classic BPF 指令码
const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

// seccomp 返回动作
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// audit arch 常量见 crate::arch（x86_64 / aarch64）
const PR_SET_SECCOMP: i32 = 22;
const SECCOMP_MODE_FILTER: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

fn ld(k: u32) -> SockFilter {
    SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jeq(k: u32) -> SockFilter {
    // 相等 -> 下一条就是 RET(ERRNO)；不等 -> 跳过它继续比较
    SockFilter {
        code: BPF_JMP_JEQ_K,
        jt: 0,
        jf: 1,
        k,
    }
}

fn ret(k: u32) -> SockFilter {
    SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k,
    }
}

/// 明确拒绝的 syscall（容器进程没有任何理由调用它们）。
/// 编号用 `libc::SYS_*`：libc 在 x86_64 与 aarch64 上分别给出各自正确的值，
/// 因此这份列表是跨架构的，不需要维护两套编号表。
fn denied_syscalls() -> Result<Vec<u32>> {
    // 其他架构（riscv 等）既不提供 audit arch 也不保证 libc 常量齐全，直接拒绝启动。
    crate::arch::host()?;
    Ok(vec![
        libc::SYS_add_key as u32,
        libc::SYS_request_key as u32,
        libc::SYS_keyctl as u32,
        libc::SYS_init_module as u32,
        libc::SYS_delete_module as u32,
        libc::SYS_finit_module as u32,
        libc::SYS_kexec_load as u32,
        libc::SYS_kexec_file_load as u32,
        libc::SYS_open_by_handle_at as u32,
        libc::SYS_name_to_handle_at as u32,
        libc::SYS_perf_event_open as u32,
        libc::SYS_ptrace as u32,
        libc::SYS_syslog as u32,
        libc::SYS_userfaultfd as u32,
        libc::SYS_bpf as u32,
        libc::SYS_mount as u32,
        libc::SYS_umount2 as u32,
        libc::SYS_pivot_root as u32,
        libc::SYS_swapon as u32,
        libc::SYS_swapoff as u32,
        libc::SYS_reboot as u32,
        libc::SYS_sethostname as u32,
        libc::SYS_setdomainname as u32,
        libc::SYS_setns as u32,
        libc::SYS_unshare as u32,
        libc::SYS_acct as u32,
        libc::SYS_clock_settime as u32,
        libc::SYS_settimeofday as u32,
        libc::SYS_adjtimex as u32,
    ])
}

fn build_program() -> Result<Vec<SockFilter>> {
    let mut p = vec![
        // 0: A = seccomp_data.arch (offset 4)
        ld(4),
        // 1: arch == 宿主 audit_arch ? 跳到 3 : 落到 2
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 1,
            jf: 0,
            k: crate::arch::host()?.audit_arch(),
        },
        // 2: 非预期架构直接杀掉（防止 32 位 compat syscall 绕过过滤）
        ret(SECCOMP_RET_KILL_PROCESS),
        // 3: A = seccomp_data.nr (offset 0)
        ld(0),
    ];
    let errno_eperm = SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xffff);
    for nr in denied_syscalls()? {
        p.push(jeq(nr));
        p.push(ret(errno_eperm));
    }
    p.push(ret(SECCOMP_RET_ALLOW));
    Ok(p)
}

fn install_seccomp() -> Result<()> {
    let filters = build_program()?;
    let prog = SockFprog {
        len: u16::try_from(filters.len()).context("BPF 指令数超过 u16")?,
        filter: filters.as_ptr(),
    };
    // 需要 no_new_privileges（security::apply 已设置），否则要 CAP_SYS_ADMIN。
    let rc = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const SockFprog as libc::c_ulong,
            0,
            0,
        )
    };
    if rc != 0 {
        bail!(
            "prctl(PR_SET_SECCOMP, MODE_FILTER) 失败: {}",
            io::Error::last_os_error()
        );
    }
    Ok(())
}

fn apply_apparmor(profile: &str) -> Result<()> {
    let profiles = Path::new("/sys/kernel/security/apparmor/profiles");
    if !profiles.is_file() {
        bail!(
            "AppArmor 未启用（{} 不存在）；显式指定 apparmor={profile:?} 无法生效。\
             可用 --security-opt apparmor=unconfined 关闭",
            profiles.display()
        );
    }
    let loaded = fs::read_to_string(profiles).context("读取 AppArmor profile 列表失败")?;
    if !loaded
        .lines()
        .any(|l| l.split_whitespace().next() == Some(profile))
    {
        bail!("AppArmor profile {profile:?} 未在内核中加载");
    }
    // 新内核用 /proc/thread-self/attr/exec，旧内核用 /proc/self/attr/exec
    let mut written = false;
    for path in [
        "/proc/thread-self/attr/exec",
        "/proc/self/attr/exec",
        "/proc/self/attr/apparmor/exec",
    ] {
        if Path::new(path).exists() {
            fs::write(path, format!("exec {profile}"))
                .with_context(|| format!("写 {path} 失败"))?;
            written = true;
            break;
        }
    }
    if !written {
        bail!("找不到可用的 AppArmor exec attr 接口");
    }
    Ok(())
}

/// 在用户子进程 execve 之前调用。
pub fn apply(spec: &OciSpec) -> Result<()> {
    match spec.miko.seccomp.as_str() {
        "" | "default" => install_seccomp().context("安装 seccomp 过滤器失败")?,
        "unconfined" => {}
        other => bail!("未知的 seccomp 模式 {other:?}"),
    }
    if !spec.miko.apparmor.is_empty() {
        apply_apparmor(&spec.miko.apparmor).context("应用 AppArmor profile 失败")?;
    }
    Ok(())
}
