//! 原始 NETLINK_ROUTE 报文（零 crate 依赖）。
//!
//! 除原有的 veth / 地址 / 路由外，网络驱动还需要：bridge / macvlan / vlan 设备创建、
//! 把接口挂到 bridge（IFLA_MASTER）、移入 netns（IFLA_NET_NS_FD）、设置 MAC / MTU。
//! 所有请求都带 NLM_F_ACK，失败时把内核返回的 -errno 翻成可读错误，绝不静默忽略。

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;

const NETLINK_ROUTE: i32 = 0;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// linux/if_link.h
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_VLAN_ID: u16 = 1;
const IFLA_MACVLAN_MODE: u16 = 1;
const VETH_INFO_PEER: u16 = 1;
const NLA_F_NESTED: u16 = 0x8000;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const IFF_UP: u32 = 1;

pub struct NlSocket {
    fd: i32,
    seq: u32,
}

impl NlSocket {
    pub fn open() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            bail!("创建 netlink socket 失败: {}", io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            unsafe { libc::close(fd) };
            bail!("bind netlink socket 失败: {}", io::Error::last_os_error());
        }
        Ok(Self { fd, seq: 1 })
    }

    /// 返回内核的 -errno（0 表示成功）。供需要区分 EEXIST 的幂等操作使用。
    fn request_raw(&mut self, typ: u16, extra_flags: u16, payload: &[u8]) -> Result<i32> {
        let len = 16 + payload.len();
        let mut buf = Vec::with_capacity((len + 3) & !3);
        buf.extend_from_slice(&(len as u32).to_ne_bytes());
        buf.extend_from_slice(&typ.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | extra_flags).to_ne_bytes());
        buf.extend_from_slice(&self.seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
        buf.extend_from_slice(payload);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        self.seq = self.seq.wrapping_add(1);

        let sent =
            unsafe { libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
        if sent < 0 {
            bail!("netlink send 失败: {}", io::Error::last_os_error());
        }

        let mut reply = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::recv(
                    self.fd,
                    reply.as_mut_ptr() as *mut libc::c_void,
                    reply.len(),
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                bail!("netlink recv 失败: {e}");
            }
            if n < 16 {
                bail!("netlink 响应过短 ({n} bytes)");
            }
            let msg_type = u16::from_ne_bytes(reply[4..6].try_into().unwrap());
            if msg_type == NLMSG_ERROR {
                return Ok(i32::from_ne_bytes(reply[16..20].try_into().unwrap()));
            }
            if msg_type == NLMSG_DONE {
                return Ok(0);
            }
        }
    }

    fn request(&mut self, typ: u16, extra_flags: u16, payload: &[u8]) -> Result<()> {
        let err = self.request_raw(typ, extra_flags, payload)?;
        if err != 0 {
            bail!(
                "netlink 请求(type={typ}) 被内核拒绝: {}",
                io::Error::from_raw_os_error(-err)
            );
        }
        Ok(())
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// ---------------------------------------------------------------- 报文构造

fn attr(typ: u16, data: &[u8]) -> Vec<u8> {
    let len = 4 + data.len();
    let mut v = Vec::with_capacity((len + 3) & !3);
    v.extend_from_slice(&(len as u16).to_ne_bytes());
    v.extend_from_slice(&typ.to_ne_bytes());
    v.extend_from_slice(data);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

fn nested(typ: u16, children: Vec<u8>) -> Vec<u8> {
    attr(typ | NLA_F_NESTED, &children)
}

fn zstring(s: &str) -> Vec<u8> {
    let mut v = Vec::from(s.as_bytes());
    v.push(0);
    v
}

/// struct ifinfomsg（16 字节）
fn ifinfomsg(index: i32, flags: u32, change: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.push(AF_UNSPEC); // ifi_family
    v.push(0); // pad
    v.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    v.extend_from_slice(&index.to_ne_bytes());
    v.extend_from_slice(&flags.to_ne_bytes());
    v.extend_from_slice(&change.to_ne_bytes());
    v
}

/// struct ifaddrmsg（8 字节）
fn ifaddrmsg(index: u32, prefix: u8) -> Vec<u8> {
    vec![
        AF_INET,
        prefix,
        0,
        0,
        index.to_ne_bytes()[0],
        index.to_ne_bytes()[1],
        index.to_ne_bytes()[2],
        index.to_ne_bytes()[3],
    ]
}

/// struct rtmsg（12 字节）
fn rtmsg() -> Vec<u8> {
    vec![
        AF_INET, // rtm_family
        0,       // rtm_dst_len（默认路由）
        0,       // rtm_src_len
        0,       // rtm_tos
        RT_TABLE_MAIN,
        RTPROT_STATIC,
        RT_SCOPE_UNIVERSE,
        RTN_UNICAST,
        0,
        0,
        0,
        0, // rtm_flags
    ]
}

pub fn ifindex(name: &str) -> Result<u32> {
    ifindex_opt(name).with_context(|| format!("找不到网络设备 {name:?}"))
}

pub fn ifindex_opt(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(idx)
}

pub fn link_exists(name: &str) -> bool {
    ifindex_opt(name).is_some()
}

/// 创建 veth pair，peer 通过 netns_fd 直接落在目标 net namespace 里。
pub fn create_veth(host: &str, peer: &str, netns_fd: i32) -> Result<()> {
    let mut peer_attrs = Vec::new();
    peer_attrs.extend(attr(IFLA_IFNAME, &zstring(peer)));
    peer_attrs.extend(attr(IFLA_NET_NS_FD, &(netns_fd as u32).to_ne_bytes()));
    // VETH_INFO_PEER 的 payload 以 ifinfomsg 开头，后面才是嵌套属性
    let mut peer_payload = ifinfomsg(0, 0, 0);
    peer_payload.extend(peer_attrs);
    let peer_attr = attr(VETH_INFO_PEER, &peer_payload);

    let mut linkinfo = Vec::new();
    linkinfo.extend(attr(IFLA_INFO_KIND, &zstring("veth")));
    linkinfo.extend(nested(IFLA_INFO_DATA, peer_attr));

    let mut attrs = Vec::new();
    attrs.extend(attr(IFLA_IFNAME, &zstring(host)));
    attrs.extend(nested(IFLA_LINKINFO, linkinfo));

    let mut payload = ifinfomsg(0, 0, 0);
    payload.extend(attrs);

    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &payload)
        .with_context(|| format!("创建 veth {host} <-> {peer} 失败"))
}

/// 创建 Linux bridge（可指定 MAC）。已存在时由调用方先 link_exists 跳过。
pub fn create_bridge(name: &str, mac: Option<&[u8; 6]>) -> Result<()> {
    let mut linkinfo = Vec::new();
    linkinfo.extend(attr(IFLA_INFO_KIND, &zstring("bridge")));
    linkinfo.extend(nested(IFLA_INFO_DATA, Vec::new()));

    let mut attrs = Vec::new();
    attrs.extend(attr(IFLA_IFNAME, &zstring(name)));
    if let Some(m) = mac {
        attrs.extend(attr(IFLA_ADDRESS, m));
    }
    attrs.extend(nested(IFLA_LINKINFO, linkinfo));

    let mut payload = ifinfomsg(0, 0, 0);
    payload.extend(attrs);
    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &payload)
        .with_context(|| format!("创建 bridge {name} 失败"))
}

/// 创建 macvlan 子接口，并通过 netns_fd 直接落到容器 netns。
/// mode 取 MacvlanMode::value()（MACVLAN_MODE_*）。
pub fn create_macvlan(
    name: &str,
    parent_index: u32,
    mode: u32,
    mac: Option<&[u8; 6]>,
    mtu: Option<u16>,
    netns_fd: i32,
) -> Result<()> {
    let mut data = Vec::new();
    data.extend(attr(IFLA_MACVLAN_MODE, &mode.to_ne_bytes()));
    let mut linkinfo = Vec::new();
    linkinfo.extend(attr(IFLA_INFO_KIND, &zstring("macvlan")));
    linkinfo.extend(nested(IFLA_INFO_DATA, data));

    let mut attrs = Vec::new();
    attrs.extend(attr(IFLA_IFNAME, &zstring(name)));
    attrs.extend(attr(IFLA_LINK, &parent_index.to_ne_bytes()));
    attrs.extend(attr(IFLA_NET_NS_FD, &(netns_fd as u32).to_ne_bytes()));
    if let Some(m) = mac {
        attrs.extend(attr(IFLA_ADDRESS, m));
    }
    if let Some(m) = mtu {
        attrs.extend(attr(IFLA_MTU, &(m as u32).to_ne_bytes()));
    }
    attrs.extend(nested(IFLA_LINKINFO, linkinfo));

    let mut payload = ifinfomsg(0, 0, 0);
    payload.extend(attrs);
    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &payload)
        .with_context(|| format!("创建 macvlan {name} 失败"))
}

/// 创建 802.1Q vlan 子接口（-o parent=eth0.10）。
pub fn create_vlan(name: &str, parent_index: u32, vlan_id: u16) -> Result<()> {
    let mut data = Vec::new();
    data.extend(attr(IFLA_VLAN_ID, &vlan_id.to_ne_bytes()));
    let mut linkinfo = Vec::new();
    linkinfo.extend(attr(IFLA_INFO_KIND, &zstring("vlan")));
    linkinfo.extend(nested(IFLA_INFO_DATA, data));

    let mut attrs = Vec::new();
    attrs.extend(attr(IFLA_IFNAME, &zstring(name)));
    attrs.extend(attr(IFLA_LINK, &parent_index.to_ne_bytes()));
    attrs.extend(nested(IFLA_LINKINFO, linkinfo));

    let mut payload = ifinfomsg(0, 0, 0);
    payload.extend(attrs);
    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &payload)
        .with_context(|| format!("创建 vlan 子接口 {name} 失败"))
}

/// 把设备挂到 bridge（等价于 `ip link set dev X master BR`）。
pub fn set_master(dev: &str, master_index: u32) -> Result<()> {
    let idx = ifindex(dev)? as i32;
    let mut payload = ifinfomsg(idx, 0, 0);
    payload.extend(attr(IFLA_MASTER, &master_index.to_ne_bytes()));
    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWLINK, 0, &payload)
        .with_context(|| format!("把 {dev} 挂到 bridge(ifindex={master_index}) 失败"))
}

pub fn link_set_mac(name: &str, mac: &[u8; 6]) -> Result<()> {
    let idx = ifindex(name)? as i32;
    let mut payload = ifinfomsg(idx, 0, 0);
    payload.extend(attr(IFLA_ADDRESS, mac));
    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWLINK, 0, &payload)
        .with_context(|| format!("设置 {name} 的 MAC 失败"))
}

pub fn link_set_mtu(name: &str, mtu: u16) -> Result<()> {
    let idx = ifindex(name)? as i32;
    let mut payload = ifinfomsg(idx, 0, 0);
    payload.extend(attr(IFLA_MTU, &(mtu as u32).to_ne_bytes()));
    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWLINK, 0, &payload)
        .with_context(|| format!("设置 {name} 的 MTU={mtu} 失败"))
}

pub fn delete_link(name: &str) -> Result<()> {
    let idx = match ifindex_opt(name) {
        Some(i) => i,
        None => return Ok(()), // 不存在视为已清理
    };
    let mut sock = NlSocket::open()?;
    sock.request(RTM_DELLINK, 0, &ifinfomsg(idx as i32, 0, 0))
        .with_context(|| format!("删除网络设备 {name} 失败"))
}

pub fn link_up(name: &str) -> Result<()> {
    let idx = ifindex(name)? as i32;
    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWLINK, 0, &ifinfomsg(idx, IFF_UP, IFF_UP))
        .with_context(|| format!("启用网络设备 {name} 失败"))
}

pub fn link_rename(old: &str, new: &str) -> Result<()> {
    let idx = ifindex(old)? as i32;
    let mut payload = ifinfomsg(idx, 0, 0);
    payload.extend(attr(IFLA_IFNAME, &zstring(new)));
    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWLINK, 0, &payload)
        .with_context(|| format!("重命名 {old} -> {new} 失败"))
}

pub fn addr_add(dev: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    let idx = ifindex(dev)?;
    let oct = ip.octets();
    let mut payload = ifaddrmsg(idx, prefix);
    payload.extend(attr(IFA_LOCAL, &oct));
    payload.extend(attr(IFA_ADDRESS, &oct));
    let mut sock = NlSocket::open()?;
    sock.request(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &payload)
        .with_context(|| format!("给 {dev} 添加地址 {ip}/{prefix} 失败"))
}

/// 幂等版：地址已存在（EEXIST）视为成功，供网络级资源重建使用。
pub fn addr_add_idempotent(dev: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    let idx = ifindex(dev)?;
    let oct = ip.octets();
    let mut payload = ifaddrmsg(idx, prefix);
    payload.extend(attr(IFA_LOCAL, &oct));
    payload.extend(attr(IFA_ADDRESS, &oct));
    let mut sock = NlSocket::open()?;
    let err = sock.request_raw(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &payload)?;
    if err == 0 || err == -libc::EEXIST {
        return Ok(());
    }
    bail!(
        "给 {dev} 添加地址 {ip}/{prefix} 失败: {}",
        io::Error::from_raw_os_error(-err)
    )
}

pub fn route_add_default(dev: &str, gateway: Ipv4Addr) -> Result<()> {
    let idx = ifindex(dev)?;
    let mut payload = rtmsg();
    payload.extend(attr(RTA_GATEWAY, &gateway.octets()));
    payload.extend(attr(RTA_OIF, &idx.to_ne_bytes()));
    let mut sock = NlSocket::open()?;
    let err = sock.request_raw(RTM_NEWROUTE, NLM_F_CREATE, &payload)?;
    if err == 0 || err == -libc::EEXIST {
        return Ok(());
    }
    bail!(
        "给 {dev} 添加默认路由 via {gateway} 失败: {}",
        io::Error::from_raw_os_error(-err)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_encoding_is_4byte_aligned() {
        let a = attr(IFLA_IFNAME, &zstring("mkbr0"));
        assert_eq!(u16::from_ne_bytes(a[0..2].try_into().unwrap()), 10);
        assert_eq!(u16::from_ne_bytes(a[2..4].try_into().unwrap()), 3);
        assert_eq!(&a[4..9], b"mkbr0");
        assert_eq!(a.len() % 4, 0);
    }

    #[test]
    fn link_lookup_is_graceful_for_missing_devices() {
        assert!(!link_exists("definitely-not-a-real-iface"));
        assert!(ifindex("definitely-not-a-real-iface").is_err());
    }
}
