//! 网络编排：父进程按驱动建设备 / NAT，__init 在容器 netns 内配接口与 /etc 文件。
//!
//! 端口映射刻意不依赖 iptables DNAT：在宿主 netns 起 TCP/UDP 转发器连到容器 IP，
//! 只需要普通 socket 权限，rootless / 受限内核也能工作。出网 NAT 是网络级规则。

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::netdrv;
use crate::network::model::{Attachment, DriverKind};
use crate::options::FirewallBackend;
use crate::spec::{OciSpec, PortSpec};

/// 父进程侧网络资源，Drop 时清理宿主侧设备（网络级 NAT 规则不随容器退出撤销）。
pub struct ParentNet {
    joined: Vec<Attachment>,
}

impl ParentNet {
    /// 按容器当前的全部网络 endpoint 建立内核设备。
    /// `netns_fd` 直接由 child_pid 的 `/proc/<pid>/ns/net` 得到；
    /// host / none 驱动不创建设备，none 只需一个新 netns（由 clone 决定）。
    pub fn setup(
        attachments: &[Attachment],
        child_pid: i32,
        backend: FirewallBackend,
        force_nat: bool,
    ) -> Result<Self> {
        let mut me = Self { joined: Vec::new() };
        let needs_netns = attachments.iter().any(|a| a.driver.needs_netns());
        if !needs_netns {
            return Ok(me);
        }

        let fd = netdrv::open_netns(child_pid)?;
        let result = (|| -> Result<()> {
            for att in attachments {
                netdrv::join_host_side(att, fd, backend, force_nat).with_context(|| {
                    format!(
                        "接入网络 {}（驱动 {}）失败",
                        att.network_name,
                        att.driver.label()
                    )
                })?;
                me.joined.push(att.clone());
                match att.driver {
                    DriverKind::Bridge => println!(
                        "miko: net    = {} bridge {} veth {} -> {} ({}/{}) gw {}",
                        att.network_name,
                        att.net.bridge_name(),
                        att.host_iface,
                        att.target_iface,
                        att.ip.map(|i| i.to_string()).unwrap_or_default(),
                        att.prefix,
                        att.gateway
                            .map(|g| g.to_string())
                            .unwrap_or_else(|| "-".into()),
                    ),
                    DriverKind::Macvlan => println!(
                        "miko: net    = {} macvlan parent={} mode={} -> {} ({}/{})",
                        att.network_name,
                        att.net.macvlan_parent().unwrap_or("-"),
                        att.net.macvlan_mode().map(|m| m.label()).unwrap_or("-"),
                        att.target_iface,
                        att.ip.map(|i| i.to_string()).unwrap_or_default(),
                        att.prefix,
                    ),
                    DriverKind::None => println!(
                        "miko: net    = {} none（仅 loopback）",
                        att.network_name
                    ),
                    DriverKind::Host => {}
                }
            }
            Ok(())
        })();
        netdrv::close_netns(fd);
        result?;
        Ok(me)
    }

    pub fn cleanup(&mut self) {
        for att in self.joined.drain(..).rev() {
            if let Err(e) = netdrv::leave_host_side(&att) {
                eprintln!(
                    "miko: 清理 {} 的设备 {} 失败: {e:#}",
                    att.network_name, att.host_iface
                );
            }
        }
    }
}

impl Drop for ParentNet {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ---------------------------------------------------------------- 容器端（__init）

/// __init 从 networks.json 动态读取当前容器的全部 endpoint。
/// config.json 只存 state_root / container_id，因此 `network connect` 之后重启容器
/// 无需重写 bundle，也能自动接入新增的网络。
pub fn container_attachments(spec: &OciSpec) -> Result<Vec<Attachment>> {
    let root = Path::new(&spec.miko.state_root);
    crate::network::attachments_for_container(root, &spec.miko.container_id)
}

/// 在 __init 里、pivot_root 之前调用：配 loopback 与各网络接口。
pub fn setup_container(_spec: &OciSpec, attachments: &[Attachment]) -> Result<()> {
    if attachments.iter().all(|a| a.driver == DriverKind::Host) {
        // host 模式共享宿主 netns，不能碰宿主网络栈。
        return Ok(());
    }
    netdrv::setup_loopback();
    for att in attachments {
        netdrv::configure_container_side(att)
            .with_context(|| format!("配置容器接口 {} 失败", att.target_iface))?;
    }
    Ok(())
}

/// 生成容器自己的 /etc/resolv.conf 与 /etc/hosts（所有驱动都生成，不 bind 宿主文件）。
/// hosts 里写入同网络其它容器的名字 / 别名，提供 docker 风格的名字发现。
pub fn prepare_rootfs_etc(bundle: &Path, spec: &OciSpec, attachments: &[Attachment]) -> Result<()> {
    let etc = bundle.join(&spec.root.path).join("etc");
    fs::create_dir_all(&etc)?;

    let mini = &spec.miko;
    let nameservers: Vec<String> = if mini.dns.is_empty() {
        host_nameservers()
    } else {
        mini.dns.clone()
    };
    let mut resolv = String::from("# Generated by miko\n");
    if !mini.dns_search.is_empty() {
        resolv.push_str(&format!("search {}\n", mini.dns_search.join(" ")));
    }
    for ns in &nameservers {
        resolv.push_str(&format!("nameserver {ns}\n"));
    }
    if resolv
        .lines()
        .filter(|l| l.starts_with("nameserver"))
        .count()
        == 0
    {
        // none 网络 / 宿主无 DNS 时给一个可解析的兜底，避免程序因空 resolv.conf 直接失败
        resolv.push_str("nameserver 8.8.8.8\nnameserver 1.1.1.1\n");
    }
    for opt in &mini.dns_opts {
        resolv.push_str(&format!("options {opt}\n"));
    }
    write_etc(&etc.join("resolv.conf"), &resolv)?;

    let self_ip = attachments
        .iter()
        .find_map(|a| a.ip)
        .unwrap_or(Ipv4Addr::LOCALHOST);
    let mut local_names = vec![spec.hostname.clone(), mini.container_id.clone()];
    for att in attachments {
        local_names.extend(att.aliases.iter().cloned());
    }
    local_names.sort();
    local_names.dedup();

    let mut hosts = format!(
        "127.0.0.1   localhost localhost.localdomain\n\
         {self_ip}   {}\n\
         ::1         localhost ip6-localhost ip6-loopback\n",
        local_names.join(" ")
    );
    for line in &mini.extra_hosts {
        hosts.push_str(line);
        hosts.push('\n');
    }
    // 同一网络内其它容器：名字 / 短 id / --network-alias 全部指向其 IP。
    let mut seen = HashMap::new();
    for att in attachments {
        for ep in att.net.endpoints.values() {
            if ep.container_id == mini.container_id || ep.ip.is_empty() {
                continue;
            }
            let mut names = vec![ep.container_name.clone(), ep.id.chars().take(12).collect()];
            names.extend(ep.aliases.iter().cloned());
            names.sort();
            names.dedup();
            seen.entry(ep.ip.clone()).or_insert(names);
        }
    }
    let mut peer_lines: Vec<(String, Vec<String>)> = seen.into_iter().collect();
    peer_lines.sort_by(|a, b| a.0.cmp(&b.0));
    if !peer_lines.is_empty() {
        hosts.push_str("# miko: 同网络容器\n");
        for (ip, names) in peer_lines {
            hosts.push_str(&format!("{ip}   {}\n", names.join(" ")));
        }
    }
    write_etc(&etc.join("hosts"), &hosts)?;
    Ok(())
}

/// 镜像里 /etc/resolv.conf、/etc/hosts 常是符号链接（systemd-resolved 等），
/// 直接写会写到宿主路径。这里先删掉符号链接再写普通文件。
fn write_etc(path: &Path, content: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            fs::remove_file(path)?;
        }
    }
    fs::write(path, content).with_context(|| format!("写 {} 失败", path.display()))?;
    Ok(())
}

fn host_nameservers() -> Vec<String> {
    let Ok(text) = fs::read_to_string("/etc/resolv.conf") else {
        return vec![];
    };
    text.lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            if p.next() == Some("nameserver") {
                p.next().map(String::from)
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------- 端口映射转发器

pub struct PortForwarders {
    _handles: Vec<JoinHandle<()>>,
}

impl PortForwarders {
    /// 在宿主 netns 常驻：容器重启时 IP 不变，转发器无需重建。
    pub fn start(ports: &[PortSpec], container_ip: Ipv4Addr) -> Result<Self> {
        let mut handles = Vec::new();
        for p in ports {
            let bind = SocketAddr::new(
                p.host_ip
                    .parse::<IpAddr>()
                    .with_context(|| format!("非法 host_ip {:?}", p.host_ip))?,
                p.host_port,
            );
            let target = SocketAddr::new(IpAddr::V4(container_ip), p.container_port);
            let handle = match p.protocol.as_str() {
                "tcp" => tcp_forward(bind, target)
                    .with_context(|| format!("启动 TCP 端口映射 {bind} -> {target} 失败"))?,
                "udp" => udp_forward(bind, target)
                    .with_context(|| format!("启动 UDP 端口映射 {bind} -> {target} 失败"))?,
                other => bail!("不支持的端口协议 {other:?}"),
            };
            handles.push(handle);
            println!(
                "miko: port   = {}/{} {} -> {}",
                bind,
                p.protocol,
                bind.port(),
                target
            );
        }
        Ok(Self { _handles: handles })
    }
}

fn tcp_forward(bind: SocketAddr, target: SocketAddr) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(bind).with_context(|| format!("监听 {bind} 失败"))?;
    Ok(thread::spawn(move || {
        for conn in listener.incoming() {
            let down = match conn {
                Ok(s) => s,
                Err(_) => continue,
            };
            // 容器网络可能还没配好 / 刚重启，做有限重试
            let mut up = None;
            for _ in 0..25 {
                if let Ok(s) = TcpStream::connect_timeout(&target, Duration::from_millis(400)) {
                    up = Some(s);
                    break;
                }
                thread::sleep(Duration::from_millis(200));
            }
            if let Some(up) = up {
                thread::spawn(move || pump(down, up));
            }
        }
    }))
}

fn pump(down: TcpStream, up: TcpStream) {
    let (Ok(mut dr), Ok(mut dw)) = (down.try_clone(), down.try_clone()) else {
        return;
    };
    let (Ok(mut ur), Ok(mut uw)) = (up.try_clone(), up.try_clone()) else {
        return;
    };
    let h = thread::spawn(move || {
        let _ = io::copy(&mut dr, &mut uw);
        let _ = uw.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut ur, &mut dw);
    let _ = dw.shutdown(Shutdown::Write);
    let _ = h.join();
}

fn udp_forward(bind: SocketAddr, target: SocketAddr) -> Result<JoinHandle<()>> {
    let sock = UdpSocket::bind(bind).with_context(|| format!("监听 UDP {bind} 失败"))?;
    Ok(thread::spawn(move || {
        let mut clients: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
        let mut buf = [0u8; 65535];
        loop {
            let (n, src) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let entry = match clients.get(&src) {
                Some(u) => u.clone(),
                None => {
                    let Ok(up) = UdpSocket::bind("0.0.0.0:0") else {
                        continue;
                    };
                    if up.connect(target).is_err() {
                        continue;
                    }
                    let _ = up.set_read_timeout(Some(Duration::from_secs(120)));
                    let arc = Arc::new(up);
                    let rx = arc.clone();
                    if let Ok(reply_sock) = sock.try_clone() {
                        thread::spawn(move || {
                            let mut b = [0u8; 65535];
                            while let Ok(m) = rx.recv(&mut b) {
                                if reply_sock.send_to(&b[..m], src).is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    clients.insert(src, arc.clone());
                    arc
                }
            };
            let _ = entry.send(&buf[..n]);
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_nameservers_are_well_formed() {
        for ns in host_nameservers() {
            assert!(ns.parse::<IpAddr>().is_ok() || ns.contains(':'));
        }
    }

    #[test]
    fn loopback_is_not_needed_for_host_driver() {
        assert!(!DriverKind::Host.needs_netns());
        assert!(DriverKind::None.needs_netns());
        assert!(DriverKind::Bridge.needs_netns());
    }
}
