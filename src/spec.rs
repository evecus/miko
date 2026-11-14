//! image config -> OCI Runtime Spec (`config.json`)。
//!
//! 这份 config.json 是**唯一配置来源**：父进程生成，`__init` 反序列化后执行。
//! 只实现 OCI runtime-spec 的一个子集，不引入 oci-spec crate，也不调用 runc。

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::cli::RunArgs;
use crate::image::Image;
use crate::options::RuntimeOptions;

pub const OCI_VERSION: &str = "1.0.2";

/// Linux capability 编号表（0..=40，见 linux/capability.h）
pub const CAP_NAMES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// docker 默认授予容器的 14 项 capability
pub const DEFAULT_CAPS: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

pub fn cap_number(name: &str) -> Option<u32> {
    CAP_NAMES.iter().position(|n| *n == name).map(|i| i as u32)
}

pub fn cap_name(n: u32) -> Option<&'static str> {
    CAP_NAMES.get(n as usize).copied()
}

pub fn last_cap() -> u32 {
    fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(CAP_NAMES.len() as u32 - 1)
}

// ---------------------------------------------------------------- OCI spec

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OciSpec {
    pub oci_version: String,
    pub process: Process,
    pub root: Root,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    pub linux: Linux,
    /// miko 自有扩展：网络/安全/userns 的运行时控制信息
    #[serde(default)]
    pub miko: MikoConfig,
}

/// 绑定到 config.json 的运行时扩展（不是 OCI 标准字段）。
/// 网络接口/IP 不写死在这里：__init 从 <state_root>/networks.json 动态读取当前
/// 容器的全部 endpoint，这样 `network connect` 之后重启无需重建 bundle。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MikoConfig {
    /// 初始网络的驱动名（bridge / macvlan / none / host）
    #[serde(default)]
    pub driver: String,
    /// 初始网络名（兼容旧字段名，供日志/诊断用）
    #[serde(default)]
    pub net_mode: String,
    /// 网络对象数据库所在目录（__init 在 pivot_root 之前读取）
    #[serde(default)]
    pub state_root: String,
    #[serde(default)]
    pub container_id: String,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub dns_search: Vec<String>,
    #[serde(default)]
    pub dns_opts: Vec<String>,
    /// 已格式化成 /etc/hosts 行
    #[serde(default)]
    pub extra_hosts: Vec<String>,
    #[serde(default)]
    pub seccomp: String,
    #[serde(default)]
    pub apparmor: String,
    #[serde(default)]
    pub userns: bool,
    #[serde(default)]
    pub userns_chroot: bool,
    #[serde(default)]
    pub uid_maps: Vec<Mapping>,
    #[serde(default)]
    pub gid_maps: Vec<Mapping>,
    #[serde(default)]
    pub nat: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VolumeSpec {
    pub source: std::path::PathBuf,
    pub destination: String,
    pub read_only: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PortSpec {
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    #[serde(default)]
    pub terminal: bool,
    pub user: User,
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default = "default_cwd")]
    pub cwd: String,
    #[serde(default)]
    pub rlimits: Vec<Rlimit>,
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
    #[serde(default)]
    pub no_new_privileges: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    #[serde(default)]
    pub additional_gids: Vec<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rlimit {
    #[serde(rename = "type")]
    pub typ: String,
    pub hard: u64,
    pub soft: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Capabilities {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
    pub inheritable: Vec<String>,
    pub ambient: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Root {
    pub path: String,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub typ: String,
    pub source: String,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    pub namespaces: Vec<Namespace>,
    #[serde(default)]
    pub uid_mappings: Vec<Mapping>,
    #[serde(default)]
    pub gid_mappings: Vec<Mapping>,
    #[serde(default)]
    pub resources: Option<Resources>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Namespace {
    #[serde(rename = "type")]
    pub typ: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Mapping {
    #[serde(rename = "containerID")]
    pub container_id: u32,
    #[serde(rename = "hostID")]
    pub host_id: u32,
    pub size: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Resources {
    #[serde(default)]
    pub memory: Option<Memory>,
    #[serde(default)]
    pub cpu: Option<Cpu>,
    #[serde(default)]
    pub pids: Option<Pids>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Memory {
    pub limit: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cpu {
    pub quota: i64,
    pub period: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Pids {
    pub limit: i64,
}

fn default_cwd() -> String {
    "/".to_string()
}

// ---------------------------------------------------------------- 资源限额

#[derive(Debug, Clone, Default)]
pub struct Limits {
    pub memory: Option<u64>,
    pub cpus: Option<f64>,
    pub pids: Option<u32>,
}

impl Limits {
    pub fn is_empty(&self) -> bool {
        self.memory.is_none() && self.cpus.is_none() && self.pids.is_none()
    }
}

pub fn parse_limits(args: &RunArgs) -> Result<Limits> {
    let memory = match &args.memory {
        Some(s) => Some(parse_size(s)?),
        None => None,
    };
    if let Some(c) = args.cpus {
        if !(c.is_finite() && c > 0.0) {
            bail!("--cpus 必须是正数，收到 {c}");
        }
    }
    Ok(Limits {
        memory,
        cpus: args.cpus,
        pids: args.pids,
    })
}

fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num
        .parse()
        .with_context(|| format!("无法解析内存大小 {s:?}"))?;
    let mul: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        _ => bail!("未知内存单位 {unit:?}"),
    };
    let v = (n * mul) as u64;
    if v == 0 {
        bail!("内存上限不能为 0");
    }
    Ok(v)
}

// ---------------------------------------------------------------- 构建 spec

pub fn build(
    image: &Image,
    args: &RunArgs,
    id: &str,
    rootfs: &Path,
    limits: &Limits,
    opts: &RuntimeOptions,
) -> Result<OciSpec> {
    let cfg = &image.config.config;

    // Entrypoint + (CMD | -- 覆盖)
    let mut cmd_args: Vec<String> = cfg.entrypoint.clone().unwrap_or_default();
    if !args.command.is_empty() {
        cmd_args.extend(args.command.iter().cloned());
    } else if let Some(cmd) = &cfg.cmd {
        cmd_args.extend(cmd.iter().cloned());
    }
    if cmd_args.is_empty() {
        bail!("镜像未指定 Entrypoint/Cmd，请用 `-- <命令>` 显式指定");
    }

    // env：镜像 env 打底，-e 同名覆盖
    let mut env: Vec<String> = cfg.env.clone();
    for item in &args.envs {
        if !item.contains('=') {
            bail!("-e 需要 KEY=VALUE 格式，收到 {item:?}");
        }
        let key = item.split('=').next().unwrap();
        env.retain(|e| e.split('=').next().unwrap_or("") != key);
        env.push(item.clone());
    }
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
    }

    let cwd = args
        .workdir
        .clone()
        .or_else(|| {
            let w = cfg.working_dir.trim();
            (!w.is_empty()).then(|| w.to_string())
        })
        .unwrap_or_else(|| "/".to_string());

    let user_spec = args.user.as_deref().unwrap_or(&cfg.user);
    let (uid, gid) = parse_user(user_spec, rootfs)?;

    let caps: Vec<String> = if args.no_cap_drop {
        (0..=last_cap())
            .filter_map(cap_name)
            .map(String::from)
            .collect()
    } else {
        DEFAULT_CAPS.iter().map(|s| s.to_string()).collect()
    };

    let resources = (!limits.is_empty()).then(|| Resources {
        memory: limits.memory.map(|l| Memory { limit: l }),
        cpu: limits.cpus.map(|c| Cpu {
            quota: (c * 100_000.0) as i64,
            period: 100_000,
        }),
        pids: limits.pids.map(|p| Pids { limit: p as i64 }),
    });

    let mut annotations = BTreeMap::new();
    annotations.insert("miko.image".to_string(), image.description.clone());
    annotations.insert("miko.net".to_string(), opts.net_label());

    let mut ns_types = vec!["pid", "mount", "uts", "ipc"];
    if opts.driver.needs_netns() {
        ns_types.push("network");
    }
    if opts.userns {
        ns_types.push("user");
    }
    let namespaces = ns_types
        .iter()
        .map(|t| Namespace { typ: t.to_string() })
        .collect();

    let mut mounts = default_mounts();
    for v in &opts.volumes {
        mounts.push(Mount {
            destination: v.destination.clone(),
            typ: "bind".into(),
            source: v.source.to_string_lossy().into_owned(),
            options: if v.read_only {
                vec!["rbind".into(), "ro".into()]
            } else {
                vec!["rbind".into()]
            },
        });
    }

    Ok(OciSpec {
        oci_version: OCI_VERSION.to_string(),
        process: Process {
            terminal: false,
            user: User {
                uid,
                gid,
                additional_gids: vec![],
            },
            args: cmd_args,
            env,
            cwd,
            rlimits: vec![Rlimit {
                typ: "RLIMIT_NOFILE".to_string(),
                hard: 1_048_576,
                soft: 1024,
            }],
            capabilities: Some(Capabilities {
                bounding: caps.clone(),
                effective: caps.clone(),
                permitted: caps,
                inheritable: vec![],
                ambient: vec![],
            }),
            no_new_privileges: true,
        },
        root: Root {
            path: "rootfs".to_string(),
            readonly: args.readonly_rootfs,
        },
        hostname: args.hostname.clone().unwrap_or_else(|| id.to_string()),
        mounts,
        annotations,
        linux: Linux {
            namespaces,
            uid_mappings: if opts.userns {
                opts.uid_maps.clone()
            } else {
                vec![]
            },
            gid_mappings: if opts.userns {
                opts.gid_maps.clone()
            } else {
                vec![]
            },
            resources,
        },
        miko: opts.miko_config(id),
    })
}

fn default_mounts() -> Vec<Mount> {
    vec![
        Mount {
            destination: "/proc".into(),
            typ: "proc".into(),
            source: "proc".into(),
            options: vec!["nosuid".into(), "noexec".into(), "nodev".into()],
        },
        Mount {
            destination: "/dev".into(),
            typ: "tmpfs".into(),
            source: "tmpfs".into(),
            options: vec![
                "nosuid".into(),
                "strictatime".into(),
                "mode=755".into(),
                "size=65536k".into(),
            ],
        },
        Mount {
            destination: "/dev/pts".into(),
            typ: "devpts".into(),
            source: "devpts".into(),
            options: vec![
                "nosuid".into(),
                "noexec".into(),
                "newinstance".into(),
                "ptmxmode=0666".into(),
                "mode=0620".into(),
            ],
        },
        Mount {
            destination: "/sys".into(),
            typ: "sysfs".into(),
            source: "sysfs".into(),
            options: vec![
                "ro".into(),
                "nosuid".into(),
                "noexec".into(),
                "nodev".into(),
            ],
        },
    ]
}

pub fn write(bundle: &Path, spec: &OciSpec) -> Result<()> {
    let data = serde_json::to_vec_pretty(spec)?;
    fs::write(bundle.join("config.json"), data)?;
    Ok(())
}

pub fn read(bundle: &Path) -> Result<OciSpec> {
    let data = fs::read(bundle.join("config.json"))?;
    Ok(serde_json::from_slice(&data)?)
}

/// 解析 `uid[:gid]` 或用户名；用户名查 rootfs 内的 /etc/passwd、/etc/group。
fn parse_user(spec: &str, rootfs: &Path) -> Result<(u32, u32)> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok((0, 0));
    }
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    if user.is_empty() {
        bail!("用户名为空: {spec:?}");
    }

    let uid = match user.parse::<u32>() {
        Ok(v) => v,
        Err(_) => passwd_field(rootfs, user, 2).with_context(|| {
            format!("用户 {user:?} 既不是数字 uid，也不在 rootfs 的 /etc/passwd 中")
        })?,
    };
    let gid = match group {
        Some("") => passwd_field(rootfs, user, 3).unwrap_or(uid),
        Some(g) => match g.parse::<u32>() {
            Ok(v) => v,
            Err(_) => group_field(rootfs, g).with_context(|| {
                format!("组 {g:?} 既不是数字 gid，也不在 rootfs 的 /etc/group 中")
            })?,
        },
        None => passwd_field(rootfs, user, 3).unwrap_or(uid),
    };
    Ok((uid, gid))
}

fn passwd_field(rootfs: &Path, name: &str, idx: usize) -> Option<u32> {
    let text = fs::read_to_string(rootfs.join("etc/passwd")).ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() > idx && f[0] == name {
            return f[idx].parse().ok();
        }
    }
    None
}

fn group_field(rootfs: &Path, name: &str) -> Option<u32> {
    let text = fs::read_to_string(rootfs.join("etc/group")).ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() > 2 && f[0] == name {
            return f[2].parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size("256m").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_size("1g").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512k").unwrap(), 512 * 1024);
        assert_eq!(parse_size("1073741824").unwrap(), 1_073_741_824);
        assert!(parse_size("0").is_err());
        assert!(parse_size("10t").is_err());
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn caps_table_is_consistent() {
        assert_eq!(cap_number("CAP_SYS_ADMIN"), Some(21));
        assert_eq!(cap_name(21), Some("CAP_SYS_ADMIN"));
        assert_eq!(DEFAULT_CAPS.len(), 14);
        assert!(DEFAULT_CAPS.iter().all(|c| cap_number(c).is_some()));
    }

    #[test]
    fn user_parsing() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n",
        )
        .unwrap();
        fs::write(tmp.path().join("etc/group"), "nogroup:x:65534:\n").unwrap();

        assert_eq!(parse_user("", tmp.path()).unwrap(), (0, 0));
        assert_eq!(parse_user("1000:1000", tmp.path()).unwrap(), (1000, 1000));
        assert_eq!(parse_user("nobody", tmp.path()).unwrap(), (65534, 65534));
        assert_eq!(
            parse_user("nobody:nogroup", tmp.path()).unwrap(),
            (65534, 65534)
        );
        assert!(parse_user("ghost", tmp.path()).is_err());
    }
}
