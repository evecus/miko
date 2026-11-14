//! 容器内的安全收窄：hostname、rlimits、capability bounding set、uid/gid。

use anyhow::{bail, Context, Result};
use nix::sys::resource::{setrlimit, Resource};
use nix::unistd::{setgroups, sethostname, setresgid, setresuid, Gid, Uid};
use std::io;

use crate::spec::{self, OciSpec};

const PR_SET_KEEPCAPS: i32 = 8;
const PR_CAPBSET_DROP: i32 = 24;
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_CAP_AMBIENT: i32 = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: i32 = 4;
const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn apply(spec: &OciSpec) -> Result<()> {
    sethostname(&spec.hostname).context("sethostname 失败（需要 CAP_SYS_ADMIN）")?;

    for r in &spec.process.rlimits {
        let res = match r.typ.as_str() {
            "RLIMIT_NOFILE" => Resource::RLIMIT_NOFILE,
            other => bail!("不支持的 rlimit 类型 {other:?}"),
        };
        setrlimit(res, r.soft, r.hard).with_context(|| format!("setrlimit {} 失败", r.typ))?;
    }

    let caps = spec
        .process
        .capabilities
        .as_ref()
        .context("config.json 缺少 process.capabilities")?;
    let keep = cap_mask(&caps.bounding);
    let effective = cap_mask(&caps.effective);
    let permitted = cap_mask(&caps.permitted);

    // 1. bounding set 必须在降权（setuid）之前裁剪，需要 CAP_SETPCAP
    for cap in 0..=spec::last_cap() {
        if keep & (1u64 << cap) == 0 {
            let rc = unsafe { libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
            if rc != 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINVAL) {
                    bail!("PR_CAPBSET_DROP({cap}) 失败: {err}");
                }
            }
        }
    }

    let user = &spec.process.user;
    if user.uid != 0 {
        // 保住 capability 跨越 setuid，随后显式收敛 effective/permitted
        prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0).context("PR_SET_KEEPCAPS(1) 失败")?;
        setgroups(&[]).context("setgroups([]) 失败")?;
        setresgid(
            Gid::from_raw(user.gid),
            Gid::from_raw(user.gid),
            Gid::from_raw(user.gid),
        )
        .context("setresgid 失败")?;
        setresuid(
            Uid::from_raw(user.uid),
            Uid::from_raw(user.uid),
            Uid::from_raw(user.uid),
        )
        .context("setresuid 失败")?;
    }

    capset(effective, permitted, 0).context("capset 失败")?;

    if user.uid != 0 {
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0).context("PR_SET_KEEPCAPS(0) 失败")?;
    }
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL as u64, 0, 0, 0)
        .context("清空 ambient capabilities 失败")?;

    if spec.process.no_new_privileges {
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).context("PR_SET_NO_NEW_PRIVS 失败")?;
    }
    Ok(())
}

fn cap_mask(names: &[String]) -> u64 {
    names
        .iter()
        .filter_map(|n| spec::cap_number(n))
        .fold(0u64, |m, c| m | (1u64 << c))
}

fn prctl(option: i32, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<()> {
    let rc = unsafe {
        libc::prctl(
            option,
            a2 as libc::c_ulong,
            a3 as libc::c_ulong,
            a4 as libc::c_ulong,
            a5 as libc::c_ulong,
        )
    };
    if rc != 0 {
        bail!("prctl({option}) 失败: {}", io::Error::last_os_error());
    }
    Ok(())
}

fn capset(effective: u64, permitted: u64, inheritable: u64) -> Result<()> {
    let hdr = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_2,
        pid: 0,
    };
    let data = [
        CapUserData {
            effective: effective as u32,
            permitted: permitted as u32,
            inheritable: inheritable as u32,
        },
        CapUserData {
            effective: (effective >> 32) as u32,
            permitted: (permitted >> 32) as u32,
            inheritable: (inheritable >> 32) as u32,
        },
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr()) };
    if rc != 0 {
        bail!("capset 失败: {}", io::Error::last_os_error());
    }
    Ok(())
}
