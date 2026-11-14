//! 四种网络驱动的内核侧实现，对齐 libnetwork 的 Driver / Join / Leave 分层。
//!
//! - `bridge`  : Linux bridge + veth pair（宿主端 enslave，容器端落进 netns），
//!   网络级 MASQUERADE / ICC 规则，容器之间通过二层互通。
//! - `macvlan` : 在 `-o parent` 指定的宿主接口上创建 macvlan 子接口直接放进容器 netns，
//!   支持 bridge / private / vepa / passthru 四种模式，无宿主 NAT。
//! - `none`    : 只新建 netns 并启用 loopback，不创建任何设备。
//! - `host`    : 不新建 netns，直接共享宿主网络栈。
//!
//! `ensure_network` 是幂等的「网络级资源重建」：miko 无常驻 daemon，机器重启后
//! bridge 设备与防火墙规则会消失，每次容器启动（或 network create）都重新补齐，
//! 这与 libnetwork 在 daemon 启动时 restore networks 的语义一致。

use anyhow::{bail, Context, Result};
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use super::{firewall, netlink};
use crate::network::model::{Attachment, DriverKind, Network};
use crate::options::FirewallBackend;

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

/// 幂等补齐一条网络的宿主侧资源（bridge 设备 / 网关地址 / ip_forward / NAT / ICC / vlan parent）。
/// `force_nat` 对应 `run --nat`：显式要求出网时覆盖网络的 enable_ip_masquerade。
pub fn ensure_network(net: &Network, backend: FirewallBackend, force_nat: bool) -> Result<()> {
    match net.driver {
        DriverKind::Bridge => {
            let bridge = net.bridge_name();
            let subnet = net.subnet_cidr().context("bridge 网络缺少合法 subnet")?;
            let gateway = net.ipam.gateway_ip()?;
            if !netlink::link_exists(&bridge) {
                netlink::create_bridge(&bridge, None)?;
            }
            netlink::addr_add_idempotent(&bridge, gateway, subnet.prefix())?;
            netlink::link_up(&bridge)?;
            enable_ip_forward();
            let cfg = firewall::FirewallConfig {
                network_id: &net.id,
                subnet: &net.ipam.subnet,
                bridge: &bridge,
                masquerade: net.enable_masquerade() || force_nat,
                icc: net.enable_icc(),
                backend,
            };
            firewall::ensure(&cfg)?;
        }
        DriverKind::Macvlan => {
            ensure_macvlan_parent(net)?;
        }
        DriverKind::None | DriverKind::Host => {}
    }
    Ok(())
}

/// 删除一条网络的宿主侧资源（network rm / prune 时调用）。
pub fn teardown_network(net: &Network) -> Result<()> {
    match net.driver {
        DriverKind::Bridge => {
            let bridge = net.bridge_name();
            let cfg = firewall::FirewallConfig {
                network_id: &net.id,
                subnet: &net.ipam.subnet,
                bridge: &bridge,
                masquerade: true,
                icc: true,
                backend: FirewallBackend::Auto,
            };
            let _ = firewall::remove(&cfg);
            // 先删各 endpoint 的宿主 veth，再删 bridge 自身。
            for ep in net.endpoints.values() {
                if !ep.host_iface.is_empty() {
                    let _ = netlink::delete_link(&ep.host_iface);
                }
            }
            netlink::delete_link(&bridge)?;
        }
        DriverKind::Macvlan => {
            // 只删除由我们按 `iface.vlan` 规则自动创建的 parent 子接口，物理接口不动。
            if let Some(parent) = net.macvlan_parent() {
                if parse_vlan_parent(parent).is_some() {
                    let _ = netlink::delete_link(parent);
                }
            }
        }
        DriverKind::None | DriverKind::Host => {}
    }
    Ok(())
}

/// 父进程侧：为 endpoint 创建内核设备并放进容器 netns。
/// `netns_fd` 由调用方打开（`/proc/<pid>/ns/net`），host/none 驱动不需要它。
pub fn join_host_side(
    att: &Attachment,
    netns_fd: i32,
    backend: FirewallBackend,
    force_nat: bool,
) -> Result<()> {
    ensure_network(&att.net, backend, force_nat)?;
    match att.driver {
        DriverKind::Bridge => {
            let bridge = att.net.bridge_name();
            // 重启 / 崩溃残留：同名设备先清掉（不存在视为成功）
            netlink::delete_link(&att.host_iface)?;
            netlink::create_veth(&att.host_iface, &att.container_iface, netns_fd)?;
            let master = netlink::ifindex(&bridge)?;
            netlink::set_master(&att.host_iface, master)?;
            if att.mtu != 1500 {
                netlink::link_set_mtu(&att.host_iface, att.mtu)?;
            }
            netlink::link_up(&att.host_iface)?;
        }
        DriverKind::Macvlan => {
            let parent = att
                .net
                .macvlan_parent()
                .context("macvlan 网络缺少 -o parent")?;
            let parent_idx = netlink::ifindex(parent)?;
            let mode = att.net.macvlan_mode()?;
            netlink::delete_link(&att.host_iface)?;
            netlink::create_macvlan(
                &att.host_iface,
                parent_idx,
                mode.value(),
                att.mac.as_ref(),
                Some(att.mtu),
                netns_fd,
            )?;
        }
        DriverKind::None | DriverKind::Host => {}
    }
    Ok(())
}

/// 删除 endpoint 的宿主侧设备（容器 netns 里的那一端会随 pair 一起消失）。
pub fn leave_host_side(att: &Attachment) -> Result<()> {
    if att.needs_link() {
        netlink::delete_link(&att.host_iface)?;
    }
    Ok(())
}

/// 容器 netns 内：重命名接口、设 MAC / IP / MTU、up、按需加默认路由。
/// 由 __init（启动时）与 network connect（热插拔，在 setns 之后）共用。
pub fn configure_container_side(att: &Attachment) -> Result<()> {
    setup_loopback();
    if att.driver == DriverKind::Host || !att.needs_link() {
        return Ok(());
    }
    let target = &att.target_iface;
    if att.container_iface != *target {
        netlink::link_rename(&att.container_iface, target)?;
    }
    if let Some(mac) = &att.mac {
        // macvlan passthru 模式不允许改 MAC，失败只告警，不阻断启动。
        if let Err(e) = netlink::link_set_mac(target, mac) {
            eprintln!("miko: 设置 {target} MAC 失败（忽略）: {e:#}");
        }
    }
    if let Some(ip) = att.ip {
        netlink::addr_add(target, ip, att.prefix)?;
    }
    if att.mtu != 1500 {
        netlink::link_set_mtu(target, att.mtu)?;
    }
    netlink::link_up(target)?;
    if att.default_route {
        if let Some(gw) = att.gateway {
            netlink::route_add_default(target, gw)?;
        }
    }
    Ok(())
}

pub fn setup_loopback() {
    if let Err(e) = netlink::link_up("lo") {
        eprintln!("miko: 启用 lo 失败（忽略）: {e:#}");
    }
}

// ---------------------------------------------------------------- 运行中热插拔

/// 打开某个进程的 network namespace fd。
pub fn open_netns(pid: i32) -> Result<i32> {
    let path = format!("/proc/{pid}/ns/net");
    let c = std::ffi::CString::new(path.as_str())?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        bail!("打开 {path} 失败: {}", io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn close_netns(fd: i32) {
    unsafe { libc::close(fd) };
}

/// 切回宿主 netns 的 guard：无论闭包成功失败都恢复，避免污染 CLI 进程自身网络栈。
struct NetnsGuard {
    host_fd: i32,
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        unsafe {
            libc::setns(self.host_fd, libc::CLONE_NEWNET);
            libc::close(self.host_fd);
        }
    }
}

/// 在目标 netns 内执行闭包（只切换调用线程的 netns）。
fn with_netns<R>(fd: i32, f: impl FnOnce() -> Result<R>) -> Result<R> {
    let c = std::ffi::CString::new("/proc/self/ns/net")?;
    let host_fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if host_fd < 0 {
        bail!("打开当前 netns 失败: {}", io::Error::last_os_error());
    }
    if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(host_fd) };
        bail!("setns 进入容器 netns 失败: {err}");
    }
    let _guard = NetnsGuard { host_fd };
    f()
}

/// network connect 到运行中容器：创建接口 + 进 netns + 配 IP，无需重启容器。
pub fn hotplug_join(
    att: &Attachment,
    pid: i32,
    backend: FirewallBackend,
    force_nat: bool,
) -> Result<()> {
    let fd = open_netns(pid)?;
    let result = (|| {
        join_host_side(att, fd, backend, force_nat)?;
        with_netns(fd, || configure_container_side(att))
    })();
    close_netns(fd);
    result
}

/// network disconnect：在容器 netns 内删除接口（veth peer / macvlan），宿主侧兜底清理。
pub fn hotplug_leave(att: &Attachment, pid: i32) -> Result<()> {
    let fd = open_netns(pid)?;
    let target = att.target_iface.clone();
    let result = with_netns(fd, || netlink::delete_link(&target));
    close_netns(fd);
    result?;
    leave_host_side(att)
}

// ---------------------------------------------------------------- macvlan parent

fn ensure_macvlan_parent(net: &Network) -> Result<()> {
    let parent = net
        .macvlan_parent()
        .context("macvlan 网络缺少 -o parent=<宿主接口>")?;
    if parent == "lo" {
        bail!("loopback 不能作为 macvlan parent（libnetwork 同样拒绝）");
    }
    if netlink::link_exists(parent) {
        return Ok(());
    }
    if let Some((base, vid)) = parse_vlan_parent(parent) {
        let base_idx = netlink::ifindex(base)?;
        netlink::create_vlan(parent, base_idx, vid)?;
        netlink::link_up(parent)?;
        return Ok(());
    }
    bail!(
        "macvlan parent {parent:?} 在宿主上不存在（可显式创建，或用 -o parent=eth0.10 让 miko 建 VLAN 子接口）"
    )
}

/// 解析 `eth0.10` 形式的 VLAN 子接口名。
fn parse_vlan_parent(s: &str) -> Option<(&str, u16)> {
    let (base, vid) = s.rsplit_once('.')?;
    if base.is_empty() || vid.is_empty() || !vid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let id: u16 = vid.parse().ok()?;
    if !(1..=4094).contains(&id) {
        return None;
    }
    Some((base, id))
}

/// 宿主默认网关（读 /proc/net/route），供 macvlan 未显式指定 --gateway 时推断。
pub fn host_default_gateway() -> Option<Ipv4Addr> {
    let text = fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || f[1] != "00000000" {
            continue;
        }
        let raw = u32::from_str_radix(f[2], 16).ok()?;
        let ip = Ipv4Addr::from(raw.swap_bytes());
        if ip != Ipv4Addr::UNSPECIFIED {
            return Some(ip);
        }
    }
    None
}

fn enable_ip_forward() {
    if let Err(e) = fs::write(Path::new(IP_FORWARD), "1\n") {
        eprintln!("miko: 无法启用 {IP_FORWARD}（容器出网可能不可用）: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::model::{Endpoint, IpamConfig, MacvlanMode};
    use std::collections::BTreeMap;

    fn bridge_net() -> Network {
        Network {
            id: "net000000042".into(),
            name: "test".into(),
            driver: DriverKind::Bridge,
            builtin: false,
            internal: false,
            attachable: false,
            created_at: 1,
            labels: BTreeMap::new(),
            options: BTreeMap::new(),
            ipam: IpamConfig {
                driver: "default".into(),
                subnet: "172.18.0.0/16".into(),
                gateway: "172.18.0.1".into(),
                ip_range: None,
                aux_addresses: BTreeMap::new(),
            },
            endpoints: BTreeMap::new(),
        }
    }

    fn attachment(net: &Network) -> Attachment {
        let ep = Endpoint {
            id: "ep000000001".into(),
            container_id: "c1".into(),
            container_name: "c1".into(),
            ip: "172.18.0.2".into(),
            mac: "02:42:ac:12:00:02".into(),
            aliases: vec![],
            host_iface: "mkv0000042".into(),
            container_iface: "mkc0000042".into(),
            created_at: 1,
        };
        Attachment::new(net, &ep, 0, true).unwrap()
    }

    #[test]
    fn vlan_parent_parsing() {
        assert_eq!(parse_vlan_parent("eth0.10"), Some(("eth0", 10)));
        assert_eq!(parse_vlan_parent("enp1s0.4094"), Some(("enp1s0", 4094)));
        assert_eq!(parse_vlan_parent("eth0.0"), None);
        assert_eq!(parse_vlan_parent("eth0.4095"), None);
        assert_eq!(parse_vlan_parent("eth0"), None);
        assert_eq!(parse_vlan_parent("eth0.x"), None);
    }

    #[test]
    fn macvlan_mode_values_match_kernel() {
        assert_eq!(MacvlanMode::Private.value(), 1);
        assert_eq!(MacvlanMode::Vepa.value(), 2);
        assert_eq!(MacvlanMode::Bridge.value(), 4);
        assert_eq!(MacvlanMode::Passthru.value(), 8);
    }

    #[test]
    fn attachment_carries_runtime_network_settings() {
        let net = bridge_net();
        let a = attachment(&net);
        assert_eq!(a.driver, DriverKind::Bridge);
        assert_eq!(a.ip.unwrap().to_string(), "172.18.0.2");
        assert_eq!(a.prefix, 16);
        assert_eq!(a.gateway.unwrap().to_string(), "172.18.0.1");
        assert_eq!(a.target_iface, "eth0");
        assert!(a.default_route);
        assert_eq!(a.mtu, 1500);
        assert!(a.needs_link());
    }

    #[test]
    fn internal_network_has_no_default_route() {
        let mut net = bridge_net();
        net.internal = true;
        let a = attachment(&net);
        assert!(a.gateway.is_none());
        assert!(!a.default_route);
    }
}
