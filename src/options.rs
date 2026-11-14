//! CLI 参数 -> 运行时配置的结构化解析。所有非法组合都 fail-fast，不静默降级。
//!
//! 网络部分改为「先解析网络对象、再由 network 模块分配 endpoint」：
//! `--net` 可以是内置网络名（bridge / host / none）、用户网络名或网络 id。

use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use crate::arch::{self, HostArch};
use crate::cli::RunArgs;
use crate::network::{model, DriverKind};
use crate::spec::{Mapping, MikoConfig, PortSpec, VolumeSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompMode {
    Default,
    Unconfined,
}

/// `--nat` / 网络规则使用的防火墙后端选择，语义对齐 docker 的 `--firewall-backend`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Auto,
    Nftables,
    Iptables,
}

impl FirewallBackend {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(FirewallBackend::Auto),
            "nftables" | "nft" => Ok(FirewallBackend::Nftables),
            "iptables" => Ok(FirewallBackend::Iptables),
            other => bail!("--firewall-backend 只支持 auto / nftables / iptables，收到 {other:?}"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            FirewallBackend::Auto => "auto",
            FirewallBackend::Nftables => "nftables",
            FirewallBackend::Iptables => "iptables",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernsRoot {
    Pivot,
    Chroot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartPolicy {
    No,
    OnFailure(Option<u32>),
    Always,
    UnlessStopped,
}

impl RestartPolicy {
    pub fn label(&self) -> String {
        match self {
            RestartPolicy::No => "no".into(),
            RestartPolicy::OnFailure(None) => "on-failure".into(),
            RestartPolicy::OnFailure(Some(n)) => format!("on-failure:{n}"),
            RestartPolicy::Always => "always".into(),
            RestartPolicy::UnlessStopped => "unless-stopped".into(),
        }
    }

    pub fn should_restart(&self, exit_code: i32, manual_stop: bool) -> bool {
        if manual_stop {
            return false;
        }
        match self {
            RestartPolicy::No => false,
            RestartPolicy::OnFailure(_) => exit_code != 0,
            RestartPolicy::Always | RestartPolicy::UnlessStopped => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    /// run 时初始接入的网络驱动（多网络由 networks.json 动态补全）
    pub driver: DriverKind,
    pub network_ref: String,
    pub network_name: String,
    /// 端口转发器的目标 IP（prepare 分配 endpoint 后填入；不可发布时为 0.0.0.0）
    pub container_ip: Ipv4Addr,
    pub endpoint_ip: Option<Ipv4Addr>,
    pub mac: Option<String>,
    pub aliases: Vec<String>,
    pub nat: bool,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub dns_opts: Vec<String>,
    /// 已格式化成 `/etc/hosts` 行的 --add-host
    pub extra_hosts: Vec<String>,
    pub ports: Vec<PortSpec>,
    pub volumes: Vec<VolumeSpec>,
    pub seccomp: SeccompMode,
    pub apparmor: Option<String>,
    pub userns: bool,
    pub userns_root: UsernsRoot,
    pub uid_maps: Vec<Mapping>,
    pub gid_maps: Vec<Mapping>,
    pub restart: RestartPolicy,
    pub detach: bool,
    pub platform: HostArch,
    pub firewall: FirewallBackend,
    pub state_root: PathBuf,
}

impl RuntimeOptions {
    pub fn parse(args: &RunArgs, _id: &str, state_root: &Path) -> Result<Self> {
        // `veth` 是旧版「每容器独占 /24」模式的名字，现在统一映射到默认 bridge 网络。
        let net_ref = match args.net.as_str() {
            "veth" => "bridge".to_string(),
            other => other.to_string(),
        };
        let net = crate::network::network_by_ref(state_root, &net_ref)?;
        let driver = net.driver;

        if args.nat && driver != DriverKind::Bridge {
            bail!(
                "--nat 只对 bridge 网络有意义（{} 网络不经过宿主转发）",
                driver.label()
            );
        }
        let ports = parse_ports(&args.publish, driver)?;
        let volumes = parse_volumes(&args.volumes)?;

        let endpoint_ip = args
            .ip
            .as_deref()
            .map(|s| s.parse::<Ipv4Addr>())
            .transpose()
            .context("解析 --ip 失败")?;
        if let Some(mac) = &args.mac_address {
            model::parse_mac(mac).with_context(|| format!("--mac-address {mac:?} 非法"))?;
        }
        if endpoint_ip.is_some() && !driver.supports_ipam() {
            bail!("{} 网络不支持 --ip", driver.label());
        }
        if args.mac_address.is_some() && !driver.supports_ipam() {
            bail!("{} 网络不支持 --mac-address", driver.label());
        }

        let dns = args
            .dns
            .iter()
            .map(|s| {
                s.parse::<IpAddr>()
                    .with_context(|| format!("--dns {s:?} 需要合法 IP 地址"))?;
                Ok(s.clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let extra_hosts = parse_add_hosts(&args.add_host)?;

        let (mut seccomp, mut apparmor) = (SeccompMode::Default, None);
        for opt in &args.security_opt {
            let (k, v) = opt
                .split_once('=')
                .with_context(|| format!("--security-opt 需要 KEY=VALUE，收到 {opt:?}"))?;
            match k {
                "seccomp" => {
                    seccomp = match v {
                        "default" => SeccompMode::Default,
                        "unconfined" => SeccompMode::Unconfined,
                        other => bail!("seccomp 只支持 default / unconfined，收到 {other:?}"),
                    }
                }
                "apparmor" => {
                    apparmor = match v {
                        "unconfined" | "" => None,
                        p => Some(p.to_string()),
                    }
                }
                other => bail!("未知 --security-opt key {other:?}（支持 seccomp / apparmor）"),
            }
        }

        let userns_root = match args.userns_root.as_str() {
            "pivot" => UsernsRoot::Pivot,
            "chroot" => UsernsRoot::Chroot,
            other => bail!("--userns-root 只支持 pivot / chroot，收到 {other:?}"),
        };
        if userns_root == UsernsRoot::Chroot && !args.userns {
            bail!("--userns-root chroot 需要同时指定 --userns");
        }
        if (args.uid_map.is_some() || args.gid_map.is_some()) && !args.userns {
            bail!("--uid-map / --gid-map 需要同时指定 --userns");
        }
        let uid_maps = match &args.uid_map {
            Some(s) => vec![parse_mapping(s)?],
            None => vec![Mapping {
                container_id: 0,
                host_id: 0,
                size: 1,
            }],
        };
        let gid_maps = match &args.gid_map {
            Some(s) => vec![parse_mapping(s)?],
            None => vec![Mapping {
                container_id: 0,
                host_id: 0,
                size: 1,
            }],
        };

        let restart = parse_restart(&args.restart)?;
        if restart != RestartPolicy::No && !args.detach {
            bail!("--restart 需要 -d/--detach（前台 run 没有 supervisor，无法自动重启）");
        }
        let platform = match &args.platform {
            Some(s) => arch::parse_platform(s)?,
            None => arch::host()?,
        };
        let firewall = FirewallBackend::parse(&args.firewall_backend)?;

        Ok(Self {
            driver,
            network_ref: net_ref,
            network_name: net.name.clone(),
            container_ip: Ipv4Addr::UNSPECIFIED,
            endpoint_ip,
            mac: args.mac_address.clone(),
            aliases: args.network_alias.clone(),
            nat: args.nat,
            dns,
            dns_search: args.dns_search.clone(),
            dns_opts: args.dns_opt.clone(),
            extra_hosts,
            ports,
            volumes,
            seccomp,
            apparmor,
            userns: args.userns,
            userns_root,
            uid_maps,
            gid_maps,
            restart,
            detach: args.detach,
            platform,
            firewall,
            state_root: state_root.to_path_buf(),
        })
    }

    /// config.json 的网络/安全扩展。接口与 IP 由 __init 从 networks.json 动态读取，
    /// 因此这里只需带上状态目录与容器 id（connect 之后重启也能自动生效）。
    pub fn miko_config(&self, id: &str) -> MikoConfig {
        MikoConfig {
            driver: self.driver.label().into(),
            net_mode: self.network_name.clone(),
            state_root: self.state_root.to_string_lossy().into_owned(),
            container_id: id.to_string(),
            dns: self.dns.clone(),
            dns_search: self.dns_search.clone(),
            dns_opts: self.dns_opts.clone(),
            extra_hosts: self.extra_hosts.clone(),
            seccomp: match self.seccomp {
                SeccompMode::Default => "default".into(),
                SeccompMode::Unconfined => "unconfined".into(),
            },
            apparmor: self.apparmor.clone().unwrap_or_default(),
            userns: self.userns,
            userns_chroot: self.userns_root == UsernsRoot::Chroot,
            uid_maps: self.uid_maps.clone(),
            gid_maps: self.gid_maps.clone(),
            nat: self.nat,
        }
    }

    pub fn net_label(&self) -> String {
        format!("{} ({})", self.network_name, self.driver.label())
    }
}

fn parse_restart(s: &str) -> Result<RestartPolicy> {
    match s {
        "no" | "" => Ok(RestartPolicy::No),
        "always" => Ok(RestartPolicy::Always),
        "unless-stopped" => Ok(RestartPolicy::UnlessStopped),
        "on-failure" => Ok(RestartPolicy::OnFailure(None)),
        _ => {
            if let Some(n) = s.strip_prefix("on-failure:") {
                let max: u32 = n.parse().with_context(|| format!("非法重试次数 {n:?}"))?;
                return Ok(RestartPolicy::OnFailure(Some(max)));
            }
            bail!("未知 --restart 策略 {s:?}")
        }
    }
}

fn parse_mapping(s: &str) -> Result<Mapping> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        bail!("映射需要 container:host:size 三段，收到 {s:?}");
    }
    let num = |v: &str| -> Result<u32> {
        v.parse().with_context(|| format!("映射段 {v:?} 不是 u32"))
    };
    let m = Mapping {
        container_id: num(parts[0])?,
        host_id: num(parts[1])?,
        size: num(parts[2])?,
    };
    if m.size == 0 {
        bail!("映射 size 不能为 0");
    }
    if m.container_id.checked_add(m.size).is_none() || m.host_id.checked_add(m.size).is_none() {
        bail!("映射范围溢出: {s:?}");
    }
    Ok(m)
}

fn parse_add_hosts(items: &[String]) -> Result<Vec<String>> {
    items
        .iter()
        .map(|s| {
            let (host, ip) = s
                .split_once(':')
                .with_context(|| format!("--add-host 需要 HOST:IP，收到 {s:?}"))?;
            if host.is_empty() || host.contains(char::is_whitespace) {
                bail!("--add-host 的主机名非法: {host:?}");
            }
            let ip: Ipv4Addr = ip
                .parse()
                .with_context(|| format!("--add-host 的 IP {ip:?} 非法"))?;
            Ok(format!("{ip}   {host}"))
        })
        .collect()
}

fn parse_volumes(items: &[String]) -> Result<Vec<VolumeSpec>> {
    items
        .iter()
        .map(|s| {
            let mut parts = s.split(':');
            let src = parts.next().unwrap_or("");
            let dst = parts
                .next()
                .with_context(|| format!("-v 需要 HOST:CONTAINER[:ro] 格式，收到 {s:?}"))?;
            let mode = parts.next();
            if parts.next().is_some() {
                bail!("-v 最多三段 HOST:CONTAINER[:ro]，收到 {s:?}");
            }
            let read_only = match mode {
                None | Some("rw") => false,
                Some("ro") => true,
                Some(other) => bail!("-v 只支持 ro / rw，收到 {other:?}"),
            };
            let source = PathBuf::from(src);
            if !source.is_absolute() {
                bail!("-v 的宿主路径必须是绝对路径: {src:?}");
            }
            if !source.exists() {
                bail!("-v 的宿主路径不存在: {src:?}");
            }
            if !dst.starts_with('/') || dst.contains("..") {
                bail!("-v 的容器路径必须是无 '..' 的绝对路径: {dst:?}");
            }
            Ok(VolumeSpec {
                source,
                destination: dst.trim_end_matches('/').to_string(),
                read_only,
            })
        })
        .collect()
}

fn parse_ports(items: &[String], driver: DriverKind) -> Result<Vec<PortSpec>> {
    if !items.is_empty() && !driver.supports_publish() {
        bail!(
            "-p/--publish 只支持 bridge 网络（{} 网络不经过宿主转发，docker 同样不支持）",
            driver.label()
        );
    }
    items
        .iter()
        .map(|s| {
            let (base, proto) = match s.rsplit_once('/') {
                Some((b, p)) => (b, p.to_ascii_lowercase()),
                None => (s.as_str(), "tcp".to_string()),
            };
            if proto != "tcp" && proto != "udp" {
                bail!("-p 只支持 /tcp 或 /udp，收到 {proto:?}");
            }
            let segs: Vec<&str> = base.split(':').collect();
            let (host_ip, hp, cp) = match segs.as_slice() {
                [hp, cp] => ("0.0.0.0".to_string(), *hp, *cp),
                [ip, hp, cp] => ((*ip).to_string(), *hp, *cp),
                _ => bail!("-p 格式应为 [HOST_IP:]HOST_PORT:CONTAINER_PORT[/tcp]，收到 {s:?}"),
            };
            if host_ip.parse::<Ipv4Addr>().is_err() {
                bail!("-p 的 HOST_IP 必须是 IPv4 地址，收到 {host_ip:?}");
            }
            let host_port: u16 = hp.parse().with_context(|| format!("非法宿主端口 {hp:?}"))?;
            let container_port: u16 = cp.parse().with_context(|| format!("非法容器端口 {cp:?}"))?;
            if host_port == 0 || container_port == 0 {
                bail!("-p 端口不能为 0");
            }
            Ok(PortSpec {
                host_ip,
                host_port,
                container_port,
                protocol: proto,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_policy_parsing_and_decision() {
        assert_eq!(parse_restart("no").unwrap(), RestartPolicy::No);
        assert_eq!(parse_restart("always").unwrap(), RestartPolicy::Always);
        assert_eq!(
            parse_restart("on-failure:3").unwrap(),
            RestartPolicy::OnFailure(Some(3))
        );
        assert!(parse_restart("sometimes").is_err());
        assert!(!RestartPolicy::Always.should_restart(0, true));
        assert!(RestartPolicy::OnFailure(None).should_restart(1, false));
        assert_eq!(RestartPolicy::OnFailure(Some(5)).label(), "on-failure:5");
    }

    #[test]
    fn mapping_parsing() {
        let m = parse_mapping("0:100000:1").unwrap();
        assert_eq!((m.container_id, m.host_id, m.size), (0, 100000, 1));
        assert!(parse_mapping("0:0").is_err());
        assert!(parse_mapping("4294967295:0:2").is_err());
    }

    #[test]
    fn volume_parsing() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().to_string_lossy().into_owned();
        let v = parse_volumes(&[format!("{src}:/data:ro")]).unwrap();
        assert!(v[0].read_only);
        assert_eq!(v[0].destination, "/data");
        assert!(parse_volumes(&["relative:/data".into()]).is_err());
    }

    #[test]
    fn port_parsing_is_driver_aware() {
        let ports = parse_ports(
            &["8080:80".into(), "127.0.0.1:53:53/udp".into()],
            DriverKind::Bridge,
        )
        .unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[1].protocol, "udp");
        for driver in [DriverKind::Host, DriverKind::None, DriverKind::Macvlan] {
            assert!(parse_ports(&["8080:80".into()], driver).is_err());
        }
        assert!(parse_ports(&["0:80".into()], DriverKind::Bridge).is_err());
        assert!(parse_ports(&["8080:80/sctp".into()], DriverKind::Bridge).is_err());
    }

    #[test]
    fn add_hosts_and_firewall_backend() {
        let lines = parse_add_hosts(&["db:10.0.0.9".into()]).unwrap();
        assert_eq!(lines[0], "10.0.0.9   db");
        assert!(parse_add_hosts(&["db:not-an-ip".into()]).is_err());
        assert_eq!(
            FirewallBackend::parse("nft").unwrap(),
            FirewallBackend::Nftables
        );
        assert!(FirewallBackend::parse("ufw").is_err());
    }
}
